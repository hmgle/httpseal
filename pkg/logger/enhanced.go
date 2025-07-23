package logger

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/httpseal/httpseal/internal/config"
)

// TrafficLogger handles traffic logging with various output formats and filtering
type TrafficLogger interface {
	Logger
	LogTraffic(record *TrafficRecord) error
	Close() error
}

// EnhancedLogger implements both Logger and TrafficLogger interfaces
type EnhancedLogger struct {
	*StandardLogger
	config     *config.Config
	outputFile *os.File
	csvWriter  *csv.Writer
	sessionID  string
}

// NewEnhanced creates a new enhanced logger with traffic logging capabilities
func NewEnhanced(cfg *config.Config) (TrafficLogger, error) {
	// Create base logger
	baseLogger := &StandardLogger{
		verbose: cfg.Verbose && !cfg.Quiet,
		logger:  nil,
	}
	
	// Setup console output (disabled in quiet mode)
	if !cfg.Quiet {
		baseLogger.logger = log.New(os.Stdout, "", 0)
	}
	
	enhanced := &EnhancedLogger{
		StandardLogger: baseLogger,
		config:         cfg,
		sessionID:      generateSessionID(),
	}
	
	// Setup file output if specified
	if cfg.OutputFile != "" {
		if err := enhanced.setupFileOutput(); err != nil {
			return nil, fmt.Errorf("failed to setup file output: %w", err)
		}
	}
	
	return enhanced, nil
}

// setupFileOutput initializes file output based on format
func (l *EnhancedLogger) setupFileOutput() error {
	var err error
	l.outputFile, err = os.OpenFile(l.config.OutputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	
	// Initialize format-specific writers
	switch l.config.OutputFormat {
	case config.FormatCSV:
		l.csvWriter = csv.NewWriter(l.outputFile)
		// Write CSV header
		header := []string{"timestamp", "session_id", "domain", "method", "url", "status_code", "status", "content_type", "request_size", "response_size", "duration_ms"}
		if err := l.csvWriter.Write(header); err != nil {
			return err
		}
		l.csvWriter.Flush()
	case config.FormatJSON:
		// JSON format doesn't need special initialization
	case config.FormatText:
		// Text format doesn't need special initialization
	}
	
	return nil
}

// LogTraffic logs a traffic record based on configuration
func (l *EnhancedLogger) LogTraffic(record *TrafficRecord) error {
	// Apply filtering
	if !l.shouldLogTraffic(record) {
		return nil
	}
	
	// Set session ID
	record.SessionID = l.sessionID
	
	// Log to console (if not quiet)
	if !l.config.Quiet {
		l.logTrafficToConsole(record)
	}
	
	// Log to file (if configured)
	if l.outputFile != nil {
		return l.logTrafficToFile(record)
	}
	
	return nil
}

// shouldLogTraffic checks if traffic should be logged based on filters
func (l *EnhancedLogger) shouldLogTraffic(record *TrafficRecord) bool {
	// Check log level
	if l.config.LogLevel == config.LogLevelNone {
		return false
	}
	
	// Check domain filter
	if len(l.config.FilterDomains) > 0 {
		found := false
		for _, domain := range l.config.FilterDomains {
			if strings.Contains(record.Domain, domain) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check content type exclusion
	contentType := strings.ToLower(record.Response.ContentType)
	for _, excludeType := range l.config.ExcludeContentTypes {
		if strings.Contains(contentType, strings.ToLower(excludeType)) {
			return false
		}
	}
	
	return true
}

// logTrafficToConsole logs traffic to console based on log level
func (l *EnhancedLogger) logTrafficToConsole(record *TrafficRecord) {
	switch l.config.LogLevel {
	case config.LogLevelMinimal:
		l.Info(">> %s %s", record.Request.Method, record.Request.URL)
		l.Info("<< %s %s", record.Response.Proto, record.Response.Status)
	case config.LogLevelNormal:
		l.Info(">> Request to %s", record.Domain)
		l.Info("%s %s %s", record.Request.Method, record.Request.URL, record.Request.Proto)
		l.Info("Host: %s", record.Request.Host)
		l.Info("User-Agent: %s", record.Request.Headers["User-Agent"])
		l.Info("")
		l.Info("<< Response from %s", record.Domain)
		l.Info("%s %s", record.Response.Proto, record.Response.Status)
		l.Info("Content-Type: %s", record.Response.ContentType)
		l.Info("Content-Length: %d", record.Response.BodySize)
		l.Info("")
	case config.LogLevelVerbose:
		l.logTrafficVerbose(record)
	}
}

// logTrafficVerbose logs full traffic details including headers and bodies
func (l *EnhancedLogger) logTrafficVerbose(record *TrafficRecord) {
	l.Info(">> Request to %s", record.Domain)
	l.Info("%s %s %s", record.Request.Method, record.Request.URL, record.Request.Proto)
	l.Info("Host: %s", record.Request.Host)
	
	// Log request headers
	for name, value := range record.Request.Headers {
		if name == "Host" {
			l.Info("%s: %s", name, value)
		} else {
			l.Debug("%s: %s", name, value)
		}
	}
	
	// Log request body if present (with size limit)
	if record.Request.Body != "" {
		body := record.Request.Body
		if l.config.MaxBodySize > 0 && len(body) > l.config.MaxBodySize {
			body = body[:l.config.MaxBodySize] + "... (truncated)"
		}
		l.Info("Request body (%d bytes):", record.Request.BodySize)
		l.Info("%s", body)
	}
	
	l.Info("")
	
	l.Info("<< Response from %s", record.Domain)
	l.Info("%s %s", record.Response.Proto, record.Response.Status)
	
	// Log response headers
	for name, value := range record.Response.Headers {
		if name == "Content-Type" || name == "Content-Length" {
			l.Info("%s: %s", name, value)
		} else {
			l.Debug("%s: %s", name, value)
		}
	}
	
	// Log response body if present (with size limit and content type filtering)
	if record.Response.Body != "" {
		contentType := strings.ToLower(record.Response.ContentType)
		
		// Check if content should be logged based on type
		isTextContent := strings.Contains(contentType, "text/") ||
			strings.Contains(contentType, "application/json") ||
			strings.Contains(contentType, "application/xml") ||
			strings.Contains(contentType, "application/javascript") ||
			strings.Contains(contentType, "application/x-www-form-urlencoded")
		
		if isTextContent || contentType == "" {
			body := record.Response.Body
			if l.config.MaxBodySize > 0 && len(body) > l.config.MaxBodySize {
				body = body[:l.config.MaxBodySize] + "... (truncated)"
			}
			l.Info("Response body (%d bytes):", record.Response.BodySize)
			l.Info("%s", body)
		} else {
			l.Info("Response body: %d bytes of binary data (%s)", record.Response.BodySize, record.Response.ContentType)
		}
	}
	
	l.Info("")
}

// logTrafficToFile logs traffic to file in the specified format
func (l *EnhancedLogger) logTrafficToFile(record *TrafficRecord) error {
	switch l.config.OutputFormat {
	case config.FormatJSON:
		return l.logTrafficAsJSON(record)
	case config.FormatCSV:
		return l.logTrafficAsCSV(record)
	case config.FormatText:
		return l.logTrafficAsText(record)
	}
	return nil
}

// logTrafficAsJSON logs traffic as JSON format
func (l *EnhancedLogger) logTrafficAsJSON(record *TrafficRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = l.outputFile.Write(append(data, '\n'))
	return err
}

// logTrafficAsCSV logs traffic as CSV format
func (l *EnhancedLogger) logTrafficAsCSV(record *TrafficRecord) error {
	row := []string{
		record.Timestamp.Format(time.RFC3339),
		record.SessionID,
		record.Domain,
		record.Request.Method,
		record.Request.URL,
		strconv.Itoa(record.Response.StatusCode),
		record.Response.Status,
		record.Response.ContentType,
		strconv.Itoa(record.Request.BodySize),
		strconv.Itoa(record.Response.BodySize),
		strconv.FormatInt(record.Duration.Milliseconds(), 10),
	}
	
	if err := l.csvWriter.Write(row); err != nil {
		return err
	}
	l.csvWriter.Flush()
	return nil
}

// logTrafficAsText logs traffic as human-readable text
func (l *EnhancedLogger) logTrafficAsText(record *TrafficRecord) error {
	text := fmt.Sprintf("[%s] %s -> %s %s %s -> %s %s (%s, %d bytes, %v)\n",
		record.Timestamp.Format("15:04:05"),
		record.SessionID,
		record.Domain,
		record.Request.Method,
		record.Request.URL,
		record.Response.Proto,
		record.Response.Status,
		record.Response.ContentType,
		record.Response.BodySize,
		record.Duration,
	)
	
	_, err := l.outputFile.WriteString(text)
	return err
}

// Close closes the traffic logger and flushes any buffered data
func (l *EnhancedLogger) Close() error {
	if l.csvWriter != nil {
		l.csvWriter.Flush()
	}
	if l.outputFile != nil {
		return l.outputFile.Close()
	}
	return nil
}

// Helper functions

// generateSessionID generates a unique session ID for this run
func generateSessionID() string {
	return fmt.Sprintf("tb_%d", time.Now().Unix())
}

// HeadersToMap converts http.Header to map[string]string
func HeadersToMap(headers http.Header) map[string]string {
	result := make(map[string]string)
	for name, values := range headers {
		if len(values) > 0 {
			result[name] = values[0] // Take first value
		}
	}
	return result
}