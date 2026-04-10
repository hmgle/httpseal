package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/hmgle/httpseal/internal/config"
	"github.com/hmgle/httpseal/pkg/cert"
	"github.com/hmgle/httpseal/pkg/dns"
	"github.com/hmgle/httpseal/pkg/logger"
	"github.com/hmgle/httpseal/pkg/mirror"
)

// Server implements an HTTPS/HTTP proxy server for traffic interception
type Server struct {
	port          int
	listener      net.Listener
	ca            *cert.CA
	dnsServer     *dns.Server
	logger        logger.Logger
	trafficLogger logger.TrafficLogger
	mirrorServer  *mirror.Server
	wg            sync.WaitGroup
	stopCh        chan struct{}
	isHTTPS       bool           // true for HTTPS, false for HTTP
	config        *config.Config // Configuration for SOCKS5 proxy support
	httpClient    *http.Client   // Standard HTTP client
	socks5Client  *http.Client   // SOCKS5-enabled HTTP client
}

// NewServer creates a new HTTPS proxy server
func NewServer(port int, ca *cert.CA, dnsServer *dns.Server, trafficLogger logger.TrafficLogger, mirrorServer *mirror.Server, cfg *config.Config) (*Server, error) {
	if err := prepareBodySpoolDir(); err != nil {
		return nil, err
	}
	s := &Server{
		port:          port,
		ca:            ca,
		dnsServer:     dnsServer,
		logger:        trafficLogger, // TrafficLogger implements Logger interface
		trafficLogger: trafficLogger,
		mirrorServer:  mirrorServer,
		stopCh:        make(chan struct{}),
		isHTTPS:       true,
		config:        cfg,
	}
	var err error
	s.httpClient, err = createHTTPClient(cfg, false, trafficLogger)
	if err != nil {
		return nil, err
	}
	s.socks5Client, err = createHTTPClient(cfg, true, trafficLogger)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// NewHTTPServer creates a new HTTP proxy server
func NewHTTPServer(port int, dnsServer *dns.Server, trafficLogger logger.TrafficLogger, mirrorServer *mirror.Server, cfg *config.Config) (*Server, error) {
	if err := prepareBodySpoolDir(); err != nil {
		return nil, err
	}
	s := &Server{
		port:          port,
		ca:            nil, // No CA needed for HTTP
		dnsServer:     dnsServer,
		logger:        trafficLogger, // TrafficLogger implements Logger interface
		trafficLogger: trafficLogger,
		mirrorServer:  mirrorServer,
		stopCh:        make(chan struct{}),
		isHTTPS:       false,
		config:        cfg,
	}
	var err error
	s.httpClient, err = createHTTPClient(cfg, false, trafficLogger)
	if err != nil {
		return nil, err
	}
	s.socks5Client, err = createHTTPClient(cfg, true, trafficLogger)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// createHTTPClient creates a reusable HTTP client with optional SOCKS5 proxy
func createHTTPClient(cfg *config.Config, useSocks5 bool, log logger.Logger) (*http.Client, error) {
	tlsConfig, err := buildUpstreamTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		// Use the default dialer
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}

	// Configure SOCKS5 proxy if enabled and requested
	if useSocks5 && cfg.SOCKS5Enabled && cfg.SOCKS5Address != "" {
		var auth *proxy.Auth
		if cfg.SOCKS5Username != "" && cfg.SOCKS5Password != "" {
			auth = &proxy.Auth{
				User:     cfg.SOCKS5Username,
				Password: cfg.SOCKS5Password,
			}
		}

		// Create SOCKS5 dialer
		socks5Dialer, err := proxy.SOCKS5("tcp", cfg.SOCKS5Address, auth, proxy.Direct)
		if err != nil {
			log.Error("Failed to create SOCKS5 dialer, SOCKS5 will be disabled: %v", err)
		} else {
			transport.DialContext = socks5Dialer.(proxy.ContextDialer).DialContext
			log.Debug("SOCKS5 proxy configured for http client")
		}
	}

	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects - return them as-is to maintain transparency
			return http.ErrUseLastResponse
		},
	}, nil
}

func buildUpstreamTLSConfig(cfg *config.Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.UpstreamInsecureSkipVerify,
	}

	if cfg.UpstreamServerName != "" {
		tlsConfig.ServerName = cfg.UpstreamServerName
	}

	if cfg.UpstreamCAFile != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system certificate pool: %w", err)
		}
		if pool == nil {
			pool = x509.NewCertPool()
		}

		caPEM, err := os.ReadFile(cfg.UpstreamCAFile)
		if err != nil {
			return nil, fmt.Errorf("read upstream CA bundle %s: %w", cfg.UpstreamCAFile, err)
		}
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("append upstream CA bundle %s: no certificates found", cfg.UpstreamCAFile)
		}
		tlsConfig.RootCAs = pool
	}

	if cfg.UpstreamClientCert != "" || cfg.UpstreamClientKey != "" {
		clientCert, err := tls.LoadX509KeyPair(cfg.UpstreamClientCert, cfg.UpstreamClientKey)
		if err != nil {
			return nil, fmt.Errorf(
				"load upstream client certificate %s and key %s: %w",
				cfg.UpstreamClientCert,
				cfg.UpstreamClientKey,
				err,
			)
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}

	return tlsConfig, nil
}

// Start starts the HTTPS proxy server
func (s *Server) Start() error {
	// Listen on all interfaces to catch redirected traffic from all 127.x.x.x addresses
	var err error
	s.listener, err = net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", s.port, err)
	}

	if s.isHTTPS {
		s.logger.Debug("HTTPS proxy server started on 0.0.0.0:%d", s.port)
	} else {
		s.logger.Debug("HTTP proxy server started on 0.0.0.0:%d", s.port)
	}

	go s.acceptLoop()
	return nil
}

// Stop stops the HTTPS proxy server
func (s *Server) Stop() error {
	close(s.stopCh)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	return nil
}

// acceptLoop accepts incoming connections
func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				s.logger.Error("Error accepting connection: %v", err)
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single client connection
func (s *Server) handleConnection(clientConn net.Conn) {
	defer s.wg.Done()
	defer clientConn.Close()

	// Get the local address (the IP the client connected to - this is our mapped IP)
	localAddr := clientConn.LocalAddr().(*net.TCPAddr)
	destIP := localAddr.IP.String()

	// Look up the real domain from our DNS mapping
	realDomain, exists := s.dnsServer.GetDomainForIP(destIP)
	if !exists {
		s.logger.Warn("No domain mapping found for destination IP %s", destIP)
		return
	}

	if s.isHTTPS {
		s.logger.Debug("Accepted HTTPS connection for %s (mapped from %s)", realDomain, destIP)
		s.handleHTTPSConnection(clientConn, realDomain)
	} else {
		s.logger.Debug("Accepted HTTP connection for %s (mapped from %s)", realDomain, destIP)
		s.handleHTTPConnection(clientConn, realDomain)
	}
}

// handleHTTPSConnection handles HTTPS connections with TLS
func (s *Server) handleHTTPSConnection(clientConn net.Conn, realDomain string) {
	// Create TLS configuration with dynamic certificate
	tlsConfig, err := s.createTLSConfig(realDomain)
	if err != nil {
		s.logger.Error("Failed to create TLS config for %s: %v", realDomain, err)
		return
	}

	// Wrap the connection with TLS
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		s.logger.Error("TLS handshake failed for %s: %v", realDomain, err)
		return
	}

	// Handle HTTP requests over this TLS connection
	s.handleHTTPRequests(tlsConn, realDomain, "https")
}

// handleHTTPConnection handles plain HTTP connections
func (s *Server) handleHTTPConnection(clientConn net.Conn, realDomain string) {
	// Handle HTTP requests directly (no TLS)
	s.handleHTTPRequests(clientConn, realDomain, "http")
}

// handleHTTPRequests handles HTTP requests over the given connection
func (s *Server) handleHTTPRequests(conn net.Conn, realDomain string, scheme string) {
	// Get connection timeout from configuration (default 30 seconds)
	connectionTimeout := time.Duration(s.config.ConnectionTimeout) * time.Second
	if connectionTimeout <= 0 {
		connectionTimeout = 30 * time.Second // fallback default
	}

	reader := bufio.NewReader(conn)

	for {
		// Set read deadline to detect idle connections
		conn.SetReadDeadline(time.Now().Add(connectionTimeout))

		// Parse the HTTP request
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "client closed connection") {
				s.logger.Debug("Client closed connection.")
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.logger.Debug("Connection timeout waiting for request.")
			} else {
				s.logger.Error("Failed to parse HTTP request: %v", err)
			}
			break // Exit loop on any read error
		}

		// Clear read deadline for request processing
		conn.SetReadDeadline(time.Time{})

		// Spool the request body to disk and capture only the configured prefix
		requestBody, err := spoolBody(req.Body, int64(s.config.CaptureBodyLimit))
		if err != nil {
			s.logger.Error("Failed to spool request body: %v", err)
			return
		}

		// Forward the request to the real server
		startTime := time.Now()
		resp, err := s.forwardRequest(req, realDomain, requestBody, scheme)
		duration := time.Since(startTime)

		if err != nil {
			s.logger.Error("Failed to forward request to %s: %v", realDomain, err)
			s.respondWithProxyError(conn, req, realDomain, scheme, duration, requestBody, http.StatusBadGateway, "Failed to reach upstream server.", err)
			break
		}

		// Spool the response body to disk and capture only the configured prefix.
		responseBody, err := spoolBody(resp.Body, int64(s.config.CaptureBodyLimit))
		if err != nil {
			s.logger.Error("Failed to spool response body: %v", err)
			s.respondWithProxyError(conn, req, realDomain, scheme, duration, requestBody, http.StatusBadGateway, "Failed to capture upstream response.", err)
			break
		}

		trafficRecord := s.createTrafficRecord(req, resp, realDomain, scheme, duration, requestBody, responseBody)
		logger.RedactTrafficRecord(trafficRecord, s.config.NoRedact)

		// Log the traffic record
		if err := s.trafficLogger.LogTraffic(trafficRecord); err != nil {
			s.logger.Error("Failed to log traffic: %v", err)
		}

		// Mirror the traffic for Wireshark analysis (if mirror server is enabled)
		if s.mirrorServer != nil {
			requestBodyText, reqErr := bodyCaptureString(requestBody)
			if reqErr != nil {
				s.logger.Warn("Failed to read request body for mirroring: %v", reqErr)
			}
			responseBodyText, respErr := bodyCaptureString(responseBody)
			if respErr != nil {
				s.logger.Warn("Failed to read response body for mirroring: %v", respErr)
			}
			s.mirrorServer.MirrorTraffic(
				realDomain,
				req.Method,
				req.URL.String(),
				requestBodyText,
				responseBodyText,
				resp.StatusCode,
				req.Header,
				resp.Header,
			)
		}

		// Normalize response to HTTP/1.1 to fix HTTP/2 compatibility issues
		s.normalizeResponseForHTTP11(resp, responseBody.size)

		// Write the standardized response back to the client
		resp.Body, err = openBodyCaptureReader(responseBody)
		if err != nil {
			s.logger.Error("Failed to reopen response body for client write: %v", err)
			if cleanupErr := responseBody.Cleanup(); cleanupErr != nil {
				s.logger.Warn("Failed to clean up response spool file: %v", cleanupErr)
			}
			s.respondWithProxyError(conn, req, realDomain, scheme, duration, requestBody, http.StatusBadGateway, "Failed to replay captured upstream response.", err)
			break
		}
		writeErr := resp.Write(conn)
		if cleanupErr := responseBody.Cleanup(); cleanupErr != nil {
			s.logger.Warn("Failed to clean up response spool file: %v", cleanupErr)
		}
		if cleanupErr := requestBody.Cleanup(); cleanupErr != nil {
			s.logger.Warn("Failed to clean up request spool file: %v", cleanupErr)
		}
		if writeErr != nil {
			s.logger.Error("Failed to write response to client: %v", writeErr)
			break // Break connection on write error
		}

		// HTTP connection persistence logic
		if req.Close || resp.Close {
			s.logger.Debug("Closing connection as requested by headers.")
			break
		}
	}
}

func (s *Server) newProxyErrorResponse(req *http.Request, statusCode int, message string, cause error) (*http.Response, string) {
	body := message
	if cause != nil && (s.config.Verbose || s.config.ExtraVerbose) {
		body = fmt.Sprintf("%s\n\n%s", message, cause.Error())
	}
	body += "\n"

	resp := &http.Response{
		StatusCode:    statusCode,
		Status:        fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
		Request:       req,
	}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("Connection", "close")
	return resp, body
}

func (s *Server) writeProxyErrorResponse(conn net.Conn, req *http.Request, statusCode int, message string, cause error) {
	resp, _ := s.newProxyErrorResponse(req, statusCode, message, cause)
	if err := resp.Write(conn); err != nil {
		s.logger.Error("Failed to write proxy error response: %v", err)
	}
}

func (s *Server) respondWithProxyError(conn net.Conn, req *http.Request, realDomain, scheme string, duration time.Duration, requestBody *bodyCapture, statusCode int, message string, cause error) {
	resp, body := s.newProxyErrorResponse(req, statusCode, message, cause)
	responseBody := &bodyCapture{
		memory: []byte(body),
		size:   int64(len(body)),
	}

	trafficRecord := s.createTrafficRecord(req, resp, realDomain, scheme, duration, requestBody, responseBody)
	logger.RedactTrafficRecord(trafficRecord, s.config.NoRedact)
	if err := s.trafficLogger.LogTraffic(trafficRecord); err != nil {
		s.logger.Error("Failed to log traffic: %v", err)
	}

	if s.mirrorServer != nil {
		requestBodyText, reqErr := bodyCaptureString(requestBody)
		if reqErr != nil {
			s.logger.Warn("Failed to read request body for mirroring: %v", reqErr)
		}
		s.mirrorServer.MirrorTraffic(
			realDomain,
			req.Method,
			req.URL.String(),
			requestBodyText,
			body,
			statusCode,
			req.Header,
			resp.Header,
		)
	}

	if err := resp.Write(conn); err != nil {
		s.logger.Error("Failed to write proxy error response: %v", err)
	}
	if cleanupErr := requestBody.Cleanup(); cleanupErr != nil {
		s.logger.Warn("Failed to clean up request spool file: %v", cleanupErr)
	}
}

// createTLSConfig creates TLS configuration with dynamic certificate for the domain
func (s *Server) createTLSConfig(domain string) (*tls.Config, error) {
	cert, err := s.ca.GenerateCertForDomain(domain)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		ServerName:   domain,
	}, nil
}

// forwardRequest forwards the request to the real server
func (s *Server) forwardRequest(req *http.Request, realDomain string, requestBody *bodyCapture, scheme string) (*http.Response, error) {
	var body io.Reader
	if requestBody != nil {
		reader, err := openBodyCaptureReader(requestBody)
		if err != nil {
			return nil, fmt.Errorf("open captured request body: %w", err)
		}
		body = reader
	}

	// Create a new request to avoid modifying the original
	newReq, err := http.NewRequest(req.Method, req.URL.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create new request: %w", err)
	}

	// Copy headers
	for name, values := range req.Header {
		for _, value := range values {
			newReq.Header.Add(name, value)
		}
	}

	// Update the request to target the real domain
	newReq.Host = realDomain
	newReq.URL.Host = realDomain
	newReq.URL.Scheme = scheme
	if requestBody != nil && requestBody.size > 0 {
		newReq.ContentLength = requestBody.size
	}

	// Clear RequestURI as it's not allowed in client requests
	newReq.RequestURI = ""

	// Choose the appropriate, pre-configured HTTP client
	var client *http.Client
	if s.config.SOCKS5Enabled {
		s.logger.Debug("Using SOCKS5 proxy %s for connection to %s", s.config.SOCKS5Address, realDomain)
		client = s.socks5Client
	} else {
		client = s.httpClient
	}

	return client.Do(newReq)
}

// createTrafficRecord converts captured request/response data into a traffic record.
func (s *Server) createTrafficRecord(req *http.Request, resp *http.Response, domain, scheme string, duration time.Duration, requestBodyCapture, responseBodyCapture *bodyCapture) *logger.TrafficRecord {
	requestBody := ""
	requestBodySize := 0
	requestBodyTruncated := false
	if requestBodyCapture != nil {
		requestBody = string(requestBodyCapture.captured)
		requestBodySize = int(requestBodyCapture.size)
		requestBodyTruncated = requestBodyCapture.truncated
	}

	responseBody := ""
	contentEncoding := resp.Header.Get("Content-Encoding")
	responseBodySize := 0
	responseBodyTruncated := false
	if responseBodyCapture != nil {
		responseBody = string(responseBodyCapture.captured)
		responseBodySize = int(responseBodyCapture.size)
		responseBodyTruncated = responseBodyCapture.truncated
	}

	// Try to decompress the response body if it's compressed (based on configuration)
	if contentEncoding != "" && s.config.DecompressResponse {
		if responseBodyTruncated {
			responseBody = fmt.Sprintf(
				"[Compressed %s content truncated at capture limit: stored %d of %d bytes]",
				contentEncoding,
				len(responseBodyCapture.captured),
				responseBodySize,
			)
		} else if decompressed, err := logger.DecompressResponse(responseBodyCapture.captured, contentEncoding); err == nil {
			// Successfully decompressed - use decompressed content for display
			responseBody = string(decompressed)
			s.logger.Debug("Decompressed %s content: %d -> %d bytes", contentEncoding, len(responseBodyCapture.captured), len(decompressed))
		} else {
			// Decompression failed - log the error and use original body
			s.logger.Debug("Failed to decompress %s content: %v", contentEncoding, err)
			// For binary/compressed content, show a more helpful message
			if !logger.IsTextLikeContent(responseBodyCapture.captured, resp.Header.Get("Content-Type")) {
				responseBody = fmt.Sprintf(
					"[Compressed %s content - captured %d of %d bytes - decompression failed: %v]",
					contentEncoding,
					len(responseBodyCapture.captured),
					responseBodySize,
					err,
				)
			}
		}
	} else if contentEncoding != "" && !s.config.DecompressResponse {
		// Decompression is disabled - show a helpful message for compressed content
		if !logger.IsTextLikeContent(responseBodyCapture.captured, resp.Header.Get("Content-Type")) {
			responseBody = fmt.Sprintf(
				"[Compressed %s content - captured %d of %d bytes - decompression disabled]",
				contentEncoding,
				len(responseBodyCapture.captured),
				responseBodySize,
			)
		}
	}

	// Create traffic record
	record := &logger.TrafficRecord{
		Timestamp:  time.Now(),
		Domain:     domain,
		Scheme:     scheme,
		Duration:   duration,
		DurationMs: duration.Milliseconds(),
		Request: logger.HTTPRequest{
			Method:        req.Method,
			URL:           req.URL.String(),
			Proto:         req.Proto,
			Host:          req.Host,
			Headers:       logger.HeadersToMap(req.Header),
			Body:          requestBody,
			BodyTruncated: requestBodyTruncated,
			BodySize:      requestBodySize,
		},
		Response: logger.HTTPResponse{
			Proto:         resp.Proto,
			Status:        resp.Status,
			StatusCode:    resp.StatusCode,
			Headers:       logger.HeadersToMap(resp.Header),
			Body:          responseBody,
			BodyTruncated: responseBodyTruncated,
			BodySize:      responseBodySize,
			ContentType:   resp.Header.Get("Content-Type"),
		},
	}

	return record
}

func openBodyCaptureReader(capture *bodyCapture) (io.ReadCloser, error) {
	if capture == nil || capture.size == 0 {
		return nil, nil
	}
	if capture.path != "" {
		file, err := os.Open(capture.path)
		if err != nil {
			return nil, fmt.Errorf("open spooled body %s: %w", capture.path, err)
		}
		return file, nil
	}
	return io.NopCloser(bytes.NewReader(capture.memory)), nil
}

func bodyCaptureString(capture *bodyCapture) (string, error) {
	if capture == nil {
		return "", nil
	}
	body, err := capture.ReadAll()
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// normalizeResponseForHTTP11 standardizes HTTP response to HTTP/1.1 for client compatibility
func (s *Server) normalizeResponseForHTTP11(resp *http.Response, bodySize int64) {
	// Force HTTP/1.1 protocol version to fix HTTP/2 compatibility issues
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1

	// Set correct Content-Length based on the spooled response size
	resp.ContentLength = bodySize
	resp.Header.Set("Content-Length", strconv.FormatInt(bodySize, 10))

	// Remove Transfer-Encoding since we have complete body and explicit Content-Length
	resp.Header.Del("Transfer-Encoding")

	// Remove HTTP/2 specific headers that might cause issues
	resp.Header.Del("Alt-Svc")

	s.logger.Debug("Normalized response to HTTP/1.1 with Content-Length: %d", bodySize)
}
