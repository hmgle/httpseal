package mirror

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hmgle/httpseal/pkg/logger"
)

// TrafficRecord represents a mirrored HTTP exchange
type TrafficRecord struct {
	ID           uint64
	Timestamp    time.Time
	OriginalHost string
	Method       string
	URL          string
	RequestBody  string
	ResponseBody string
	StatusCode   int
	Headers      http.Header
}

// Server implements an HTTP mirror server for Wireshark analysis
type Server struct {
	port      int
	listener  net.Listener
	logger    logger.Logger
	wg        sync.WaitGroup
	stopCh    chan struct{}
	connID    uint64
	exchanges chan *TrafficRecord
	responses map[uint64]*TrafficRecord // Store responses by ID
	respMutex sync.RWMutex
}

// NewServer creates a new HTTP mirror server
func NewServer(port int, logger logger.Logger) *Server {
	return &Server{
		port:      port,
		logger:    logger,
		stopCh:    make(chan struct{}),
		exchanges: make(chan *TrafficRecord, 100),
		responses: make(map[uint64]*TrafficRecord),
	}
}

// Start starts the HTTP mirror server
func (s *Server) Start() error {
	var err error
	s.listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen on mirror port %d: %w", s.port, err)
	}

	s.logger.Info("HTTP Mirror Server started on 127.0.0.1:%d", s.port)
	s.logger.Info("Configure Wireshark to capture on interface 'lo' with filter 'tcp port %d'", s.port)

	go s.acceptLoop()
	go s.processExchanges()
	return nil
}

// Stop stops the HTTP mirror server
func (s *Server) Stop() error {
	close(s.stopCh)
	if s.listener != nil {
		s.listener.Close()
	}
	close(s.exchanges)
	s.wg.Wait()
	return nil
}

// MirrorTraffic mirrors an HTTP exchange for Wireshark analysis
func (s *Server) MirrorTraffic(originalHost, method, url, requestBody, responseBody string, statusCode int, headers http.Header) {
	record := &TrafficRecord{
		ID:           atomic.AddUint64(&s.connID, 1),
		Timestamp:    time.Now(),
		OriginalHost: originalHost,
		Method:       method,
		URL:          url,
		RequestBody:  requestBody,
		ResponseBody: responseBody,
		StatusCode:   statusCode,
		Headers:      headers,
	}

	// Store the response for later retrieval
	s.respMutex.Lock()
	s.responses[record.ID] = record
	s.respMutex.Unlock()

	select {
	case s.exchanges <- record:
	case <-s.stopCh:
	default:
		s.logger.Warn("Mirror exchange buffer full, dropping record")
	}
}

// acceptLoop accepts incoming connections (for health checks or manual testing)
func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				s.logger.Error("Error accepting mirror connection: %v", err)
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection handles incoming HTTP connections and returns mirrored responses
func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	// Parse HTTP request
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		s.logger.Error("Failed to parse mirror HTTP request: %v", err)
		return
	}

	// Extract Mirror-ID from headers
	mirrorIDStr := req.Header.Get("X-HTTPSeal-Mirror-ID")
	if mirrorIDStr == "" {
		// Health check or unknown request
		s.sendHealthCheckResponse(conn)
		return
	}

	mirrorID, err := strconv.ParseUint(mirrorIDStr, 10, 64)
	if err != nil {
		s.logger.Error("Invalid Mirror-ID: %s", mirrorIDStr)
		s.sendErrorResponse(conn, 400, "Invalid Mirror-ID")
		return
	}

	// Find corresponding response
	s.respMutex.RLock()
	record, exists := s.responses[mirrorID]
	s.respMutex.RUnlock()

	if !exists {
		s.logger.Warn("No response found for Mirror-ID: %d", mirrorID)
		s.sendErrorResponse(conn, 404, "Response not found")
		return
	}

	// Send the mirrored response
	s.sendMirroredResponse(conn, record)

	// Clean up the response record to save memory
	s.respMutex.Lock()
	delete(s.responses, mirrorID)
	s.respMutex.Unlock()
}

// sendHealthCheckResponse sends a health check response
func (s *Server) sendHealthCheckResponse(conn net.Conn) {
	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: 47\r\n" +
		"X-HTTPSeal-Mirror: true\r\n" +
		"\r\n" +
		"HTTPSeal Mirror Server - Ready for Wireshark"
	conn.Write([]byte(response))
}

// sendErrorResponse sends an HTTP error response
func (s *Server) sendErrorResponse(conn net.Conn, statusCode int, message string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, http.StatusText(statusCode))
	response += "Content-Type: text/plain\r\n"
	response += fmt.Sprintf("Content-Length: %d\r\n", len(message))
	response += "X-HTTPSeal-Mirror: true\r\n"
	response += "\r\n"
	response += message
	conn.Write([]byte(response))
}

// sendMirroredResponse sends the stored mirrored response
func (s *Server) sendMirroredResponse(conn net.Conn, record *TrafficRecord) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\n", record.StatusCode, http.StatusText(record.StatusCode))
	response += "X-HTTPSeal-Original-Host: " + record.OriginalHost + "\r\n"
	response += "X-HTTPSeal-Mirror-ID: " + strconv.FormatUint(record.ID, 10) + "\r\n"
	response += "X-HTTPSeal-Timestamp: " + record.Timestamp.Format(time.RFC3339) + "\r\n"

	// Add original response headers (filtered)
	for name, values := range record.Headers {
		// Skip connection-specific headers
		lowerName := strings.ToLower(name)
		if lowerName == "connection" || lowerName == "content-length" || lowerName == "transfer-encoding" {
			continue
		}
		for _, value := range values {
			response += fmt.Sprintf("%s: %s\r\n", name, value)
		}
	}

	if record.ResponseBody != "" {
		response += fmt.Sprintf("Content-Length: %d\r\n", len(record.ResponseBody))
		response += "\r\n"
		response += record.ResponseBody
	} else {
		response += "\r\n"
	}

	conn.Write([]byte(response))
}

// processExchanges processes mirrored traffic records
func (s *Server) processExchanges() {
	for record := range s.exchanges {
		if err := s.simulateHTTPExchange(record); err != nil {
			s.logger.Error("Failed to simulate HTTP exchange: %v", err)
		}
	}
}

// simulateHTTPExchange creates a real HTTP exchange for Wireshark to capture
func (s *Server) simulateHTTPExchange(record *TrafficRecord) error {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		
		// Create actual TCP connection to the mirror server
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
		if err != nil {
			s.logger.Error("Failed to connect to mirror server: %v", err)
			return
		}
		defer conn.Close()
		
		// Send HTTP request
		request := fmt.Sprintf("%s %s HTTP/1.1\r\n", record.Method, record.URL)
		request += fmt.Sprintf("Host: %s\r\n", record.OriginalHost)
		request += "X-HTTPSeal-Original-Host: " + record.OriginalHost + "\r\n"
		request += "X-HTTPSeal-Mirror-ID: " + strconv.FormatUint(record.ID, 10) + "\r\n"
		request += "X-HTTPSeal-Timestamp: " + record.Timestamp.Format(time.RFC3339) + "\r\n"
		request += "Connection: close\r\n"
		
		// Add filtered original headers
		for name, values := range record.Headers {
			// Skip connection-specific and problematic headers
			lowerName := strings.ToLower(name)
			if lowerName == "connection" || lowerName == "content-length" || 
			   lowerName == "transfer-encoding" || lowerName == "host" {
				continue
			}
			for _, value := range values {
				request += fmt.Sprintf("%s: %s\r\n", name, value)
			}
		}
		
		if record.RequestBody != "" {
			request += fmt.Sprintf("Content-Length: %d\r\n", len(record.RequestBody))
			request += "\r\n"
			request += record.RequestBody
		} else {
			request += "\r\n"
		}
		
		// Send request
		if _, err := conn.Write([]byte(request)); err != nil {
			s.logger.Error("Failed to send mirror request: %v", err)
			return
		}
		
		// Read response to complete the exchange
		io.Copy(io.Discard, conn)
	}()
	
	return nil
}

// GetPort returns the port the mirror server is listening on
func (s *Server) GetPort() int {
	return s.port
}