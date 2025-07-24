package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hmgle/httpseal/pkg/cert"
	"github.com/hmgle/httpseal/pkg/dns"
	"github.com/hmgle/httpseal/pkg/logger"
	"github.com/hmgle/httpseal/pkg/mirror"
)

// Server implements an HTTPS/HTTP proxy server for traffic interception
type Server struct {
	port         int
	listener     net.Listener
	ca           *cert.CA
	dnsServer    *dns.Server
	logger       logger.Logger
	trafficLogger logger.TrafficLogger
	mirrorServer *mirror.Server
	wg           sync.WaitGroup
	stopCh       chan struct{}
	isHTTPS      bool // true for HTTPS, false for HTTP
}

// NewServer creates a new HTTPS proxy server
func NewServer(port int, ca *cert.CA, dnsServer *dns.Server, trafficLogger logger.TrafficLogger, mirrorServer *mirror.Server) *Server {
	return &Server{
		port:         port,
		ca:           ca,
		dnsServer:    dnsServer,
		logger:       trafficLogger, // TrafficLogger implements Logger interface
		trafficLogger: trafficLogger,
		mirrorServer: mirrorServer,
		stopCh:       make(chan struct{}),
		isHTTPS:      true,
	}
}

// NewHTTPServer creates a new HTTP proxy server
func NewHTTPServer(port int, dnsServer *dns.Server, trafficLogger logger.TrafficLogger, mirrorServer *mirror.Server) *Server {
	return &Server{
		port:         port,
		ca:           nil, // No CA needed for HTTP
		dnsServer:    dnsServer,
		logger:       trafficLogger, // TrafficLogger implements Logger interface
		trafficLogger: trafficLogger,
		mirrorServer: mirrorServer,
		stopCh:       make(chan struct{}),
		isHTTPS:      false,
	}
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
		s.logger.Info(">> HTTPS Connection to %s (mapped from %s)", realDomain, destIP)
		s.handleHTTPSConnection(clientConn, realDomain)
	} else {
		s.logger.Info(">> HTTP Connection to %s (mapped from %s)", realDomain, destIP)
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
	for {
		// Create a buffered reader for parsing HTTP requests
		reader := bufio.NewReader(conn)
		
		// Parse the HTTP request
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err == io.EOF {
				break // Client closed connection
			}
			s.logger.Error("Failed to parse HTTP request: %v", err)
			return
		}

		// Read and preserve request body for logging and forwarding  
		var requestBody []byte
		if req.Body != nil {
			requestBody, err = io.ReadAll(req.Body)
			if err != nil {
				s.logger.Error("Failed to read request body: %v", err)
				return
			}
			req.Body.Close()
		}

		// Log the request with body
		s.logRequestWithBody(req, realDomain, requestBody)

		// Forward the request to the real server
		startTime := time.Now()
		resp, err := s.forwardRequest(req, realDomain, requestBody, scheme)
		duration := time.Since(startTime)
		
		if err != nil {
			s.logger.Error("Failed to forward request to %s: %v", realDomain, err)
			return
		}

		// Capture response and create traffic record
		bodyBytes, trafficRecord, err := s.captureTrafficAndCreateRecord(req, resp, realDomain, duration, requestBody)
		if err != nil {
			s.logger.Error("Failed to capture response: %v", err)
			return
		}

		// Log the traffic record
		if err := s.trafficLogger.LogTraffic(trafficRecord); err != nil {
			s.logger.Error("Failed to log traffic: %v", err)
		}

		// Mirror the traffic for Wireshark analysis (if mirror server is enabled)
		if s.mirrorServer != nil {
			s.mirrorServer.MirrorTraffic(
				realDomain,
				trafficRecord.Request.Method,
				trafficRecord.Request.URL,
				trafficRecord.Request.Body,
				trafficRecord.Response.Body,
				trafficRecord.Response.StatusCode,
				resp.Header,
			)
		}

		// Send the response back to the client
		if err := s.writeResponseWithBody(conn, resp, bodyBytes); err != nil {
			s.logger.Error("Failed to write response: %v", err)
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		// If this was not a keep-alive connection, close it
		if req.Header.Get("Connection") == "close" || req.Proto == "HTTP/1.0" {
			break
		}
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
func (s *Server) forwardRequest(req *http.Request, realDomain string, requestBody []byte, scheme string) (*http.Response, error) {
	// Create a new request body from the preserved request body bytes
	var body io.Reader
	if len(requestBody) > 0 {
		body = bytes.NewReader(requestBody)
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
	
	// Clear RequestURI as it's not allowed in client requests
	newReq.RequestURI = ""

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}

	return client.Do(newReq)
}

// logRequestWithBody logs the HTTP request details including body
func (s *Server) logRequestWithBody(req *http.Request, domain string, requestBody []byte) {
	s.logger.Info(">> Request to %s", domain)
	s.logger.Info("%s %s %s", req.Method, req.URL.Path, req.Proto)
	s.logger.Info("Host: %s", req.Host)
	s.logger.Info("User-Agent: %s", req.UserAgent())
	
	for name, values := range req.Header {
		for _, value := range values {
			s.logger.Debug("%s: %s", name, value)
		}
	}
	
	// Log request body if present
	if len(requestBody) > 0 {
		s.logger.Info("Request body (%d bytes):", len(requestBody))
		s.logger.Debug("Body content: %s", string(requestBody))
	}
	
	s.logger.Info("")
}

// captureTrafficAndCreateRecord captures the response and creates a traffic record
func (s *Server) captureTrafficAndCreateRecord(req *http.Request, resp *http.Response, domain string, duration time.Duration, requestBodyBytes []byte) ([]byte, *logger.TrafficRecord, error) {
	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Use pre-read request body
	requestBody := string(requestBodyBytes)
	requestBodySize := len(requestBodyBytes)

	// Extract response body content with size limit
	responseBody := string(bodyBytes)
	
	// Create traffic record
	record := &logger.TrafficRecord{
		Timestamp: time.Now(),
		Domain:    domain,
		Duration:  duration,
		Request: logger.HTTPRequest{
			Method:   req.Method,
			URL:      req.URL.String(),
			Proto:    req.Proto,
			Host:     req.Host,
			Headers:  logger.HeadersToMap(req.Header),
			Body:     requestBody,
			BodySize: requestBodySize,
		},
		Response: logger.HTTPResponse{
			Proto:       resp.Proto,
			Status:      resp.Status,
			StatusCode:  resp.StatusCode,
			Headers:     logger.HeadersToMap(resp.Header),
			Body:        responseBody,
			BodySize:    len(bodyBytes),
			ContentType: resp.Header.Get("Content-Type"),
		},
	}

	return bodyBytes, record, nil
}

// writeResponseWithBody writes the HTTP response back to the client with captured body
func (s *Server) writeResponseWithBody(conn net.Conn, resp *http.Response, bodyBytes []byte) error {
	// Write status line
	if _, err := fmt.Fprintf(conn, "%s %s\r\n", resp.Proto, resp.Status); err != nil {
		return err
	}

	// Write headers
	if err := resp.Header.Write(conn); err != nil {
		return err
	}

	// Write blank line
	if _, err := conn.Write([]byte("\r\n")); err != nil {
		return err
	}

	// Write captured body
	_, err := conn.Write(bodyBytes)
	return err
}

