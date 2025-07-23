package logger

import (
	"time"
)

// TrafficRecord represents a single HTTP request/response pair
type TrafficRecord struct {
	Timestamp   time.Time         `json:"timestamp"`
	SessionID   string            `json:"session_id"`
	Domain      string            `json:"domain"`
	Request     HTTPRequest       `json:"request"`
	Response    HTTPResponse      `json:"response"`
	Duration    time.Duration     `json:"duration_ms"`
}

// HTTPRequest represents HTTP request details
type HTTPRequest struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Proto       string            `json:"proto"`
	Host        string            `json:"host"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body,omitempty"`
	BodySize    int               `json:"body_size"`
}

// HTTPResponse represents HTTP response details
type HTTPResponse struct {
	Proto       string            `json:"proto"`
	Status      string            `json:"status"`
	StatusCode  int               `json:"status_code"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body,omitempty"`
	BodySize    int               `json:"body_size"`
	ContentType string            `json:"content_type"`
}