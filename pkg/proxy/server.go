package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/httpseal/httpseal/pkg/cert"
	"github.com/httpseal/httpseal/pkg/dns"
	"github.com/httpseal/httpseal/pkg/logger"
)

// Server implements an HTTPS proxy server for traffic interception
type Server struct {
	port         int
	listener     net.Listener
	ca           *cert.CA
	dnsServer    *dns.Server
	logger       logger.Logger
	trafficLogger logger.TrafficLogger
	wg           sync.WaitGroup
	stopCh       chan struct{}
}

// NewServer creates a new HTTPS proxy server
func NewServer(port int, ca *cert.CA, dnsServer *dns.Server, trafficLogger logger.TrafficLogger) *Server {
	return &Server{
		port:         port,
		ca:           ca,
		dnsServer:    dnsServer,
		logger:       trafficLogger, // TrafficLogger implements Logger interface
		trafficLogger: trafficLogger,
		stopCh:       make(chan struct{}),
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

	s.logger.Debug("HTTPS proxy server started on 0.0.0.0:%d", s.port)

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

	s.logger.Info(">> Connection to %s (mapped from %s)", realDomain, destIP)

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
	for {
		// Parse the HTTP request
		req, err := http.ReadRequest(bufio.NewReader(tlsConn))
		if err != nil {
			if err == io.EOF {
				break // Client closed connection
			}
			s.logger.Error("Failed to parse HTTP request: %v", err)
			return
		}

		// Log the request
		s.logRequest(req, realDomain)

		// Log and forward the request to the real server
		startTime := time.Now()
		resp, err := s.forwardRequest(req, realDomain)
		duration := time.Since(startTime)
		
		if err != nil {
			s.logger.Error("Failed to forward request to %s: %v", realDomain, err)
			return
		}

		// Capture response and create traffic record
		bodyBytes, trafficRecord, err := s.captureTrafficAndCreateRecord(req, resp, realDomain, duration)
		if err != nil {
			s.logger.Error("Failed to capture response: %v", err)
			return
		}

		// Log the traffic record
		if err := s.trafficLogger.LogTraffic(trafficRecord); err != nil {
			s.logger.Error("Failed to log traffic: %v", err)
		}

		// Send the response back to the client
		if err := s.writeResponseWithBody(tlsConn, resp, bodyBytes); err != nil {
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
func (s *Server) forwardRequest(req *http.Request, realDomain string) (*http.Response, error) {
	// Create a new request to avoid modifying the original
	newReq, err := http.NewRequest(req.Method, req.URL.String(), req.Body)
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
	newReq.URL.Scheme = "https"
	
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

// logRequest logs the HTTP request details
func (s *Server) logRequest(req *http.Request, domain string) {
	s.logger.Info(">> Request to %s", domain)
	s.logger.Info("%s %s %s", req.Method, req.URL.Path, req.Proto)
	s.logger.Info("Host: %s", req.Host)
	s.logger.Info("User-Agent: %s", req.UserAgent())
	
	for name, values := range req.Header {
		for _, value := range values {
			s.logger.Debug("%s: %s", name, value)
		}
	}
	s.logger.Info("")
}

// captureTrafficAndCreateRecord captures the response and creates a traffic record
func (s *Server) captureTrafficAndCreateRecord(req *http.Request, resp *http.Response, domain string, duration time.Duration) ([]byte, *logger.TrafficRecord, error) {
	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Read request body if present
	var requestBody string
	var requestBodySize int
	if req.Body != nil {
		reqBodyBytes, _ := io.ReadAll(req.Body)
		requestBody = string(reqBodyBytes)
		requestBodySize = len(reqBodyBytes)
	}

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

