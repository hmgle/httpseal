package logger

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// HAR represents the root HAR object following the W3C specification
type HAR struct {
	Log HARLog `json:"log"`
}

// HARLog represents the log object containing all HTTP transaction data
type HARLog struct {
	Version string     `json:"version"`
	Creator HARCreator `json:"creator"`
	Browser HARBrowser `json:"browser,omitempty"`
	Pages   []HARPage  `json:"pages"` // Required by HAR 1.2 spec, must not use omitempty
	Entries []HAREntry `json:"entries"`
}

// HARCreator represents the application that created the HAR file
type HARCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Comment string `json:"comment,omitempty"`
}

// HARBrowser represents the browser information
type HARBrowser struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Comment string `json:"comment,omitempty"`
}

// HARPage represents a page (optional in HAR)
type HARPage struct {
	StartedDateTime time.Time  `json:"startedDateTime"`
	ID              string     `json:"id"`
	Title           string     `json:"title"`
	PageTimings     HARTimings `json:"pageTimings"`
	Comment         string     `json:"comment,omitempty"`
}

// HAREntry represents a single HTTP transaction
type HAREntry struct {
	Pageref         string      `json:"pageref,omitempty"`
	StartedDateTime time.Time   `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         HARRequest  `json:"request"`
	Response        HARResponse `json:"response"`
	Cache           HARCache    `json:"cache"`
	Timings         HARTimings  `json:"timings"`
	ServerIPAddress string      `json:"serverIPAddress,omitempty"`
	Connection      string      `json:"connection,omitempty"`
	Comment         string      `json:"comment,omitempty"`
}

// HARRequest represents the HTTP request details
type HARRequest struct {
	Method      string         `json:"method"`
	URL         string         `json:"url"`
	HTTPVersion string         `json:"httpVersion"`
	Cookies     []HARCookie    `json:"cookies"`
	Headers     []HARNameValue `json:"headers"`
	QueryString []HARNameValue `json:"queryString"`
	PostData    *HARPostData   `json:"postData,omitempty"`
	HeadersSize int            `json:"headersSize"`
	BodySize    int            `json:"bodySize"`
	Comment     string         `json:"comment,omitempty"`
}

// HARResponse represents the HTTP response details
type HARResponse struct {
	Status      int            `json:"status"`
	StatusText  string         `json:"statusText"`
	HTTPVersion string         `json:"httpVersion"`
	Cookies     []HARCookie    `json:"cookies"`
	Headers     []HARNameValue `json:"headers"`
	Content     HARContent     `json:"content"`
	RedirectURL string         `json:"redirectURL"`
	HeadersSize int            `json:"headersSize"`
	BodySize    int            `json:"bodySize"`
	Comment     string         `json:"comment,omitempty"`
}

// HARCookie represents a cookie
type HARCookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Path     string    `json:"path,omitempty"`
	Domain   string    `json:"domain,omitempty"`
	Expires  time.Time `json:"expires,omitempty"`
	HTTPOnly bool      `json:"httpOnly,omitempty"`
	Secure   bool      `json:"secure,omitempty"`
	Comment  string    `json:"comment,omitempty"`
}

// HARNameValue represents a name-value pair for headers, query parameters, etc.
type HARNameValue struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Comment string `json:"comment,omitempty"`
}

// HARPostData represents POST data
type HARPostData struct {
	MimeType string         `json:"mimeType"`
	Params   []HARPostParam `json:"params"`
	Text     string         `json:"text"`
	Comment  string         `json:"comment,omitempty"`
}

// HARPostParam represents a POST parameter
type HARPostParam struct {
	Name        string `json:"name"`
	Value       string `json:"value,omitempty"`
	FileName    string `json:"fileName,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	Comment     string `json:"comment,omitempty"`
}

// HARContent represents response content
type HARContent struct {
	Size        int    `json:"size"`
	Compression int    `json:"compression,omitempty"`
	MimeType    string `json:"mimeType"`
	Text        string `json:"text,omitempty"`
	Encoding    string `json:"encoding,omitempty"`
	Comment     string `json:"comment,omitempty"`
}

// HARCache represents cache information
type HARCache struct {
	BeforeRequest *HARCacheState `json:"beforeRequest,omitempty"`
	AfterRequest  *HARCacheState `json:"afterRequest,omitempty"`
	Comment       string         `json:"comment,omitempty"`
}

// HARCacheState represents cache state
type HARCacheState struct {
	Expires    time.Time `json:"expires,omitempty"`
	LastAccess time.Time `json:"lastAccess"`
	ETag       string    `json:"eTag"`
	HitCount   int       `json:"hitCount"`
	Comment    string    `json:"comment,omitempty"`
}

// HARTimings represents timing information
type HARTimings struct {
	Blocked int    `json:"blocked"`           // Required by HAR 1.2 spec, must not use omitempty
	DNS     int    `json:"dns"`               // Required by HAR 1.2 spec, must not use omitempty
	Connect int    `json:"connect"`           // Required by HAR 1.2 spec, must not use omitempty
	Send    int    `json:"send"`              // Required by HAR 1.2 spec, must not use omitempty
	Wait    int    `json:"wait"`              // Required by HAR 1.2 spec, must not use omitempty
	Receive int    `json:"receive"`           // Required by HAR 1.2 spec, must not use omitempty
	SSL     int    `json:"ssl,omitempty"`     // Optional field
	Comment string `json:"comment,omitempty"` // Optional field
}

// NewHAR creates a new HAR structure with proper initialization
func NewHAR() *HAR {
	return &HAR{
		Log: HARLog{
			Version: "1.2",
			Creator: HARCreator{
				Name:    "HTTPSeal",
				Version: "1.0.0",
				Comment: "HTTPS/HTTP traffic interceptor with process isolation",
			},
			Pages:   []HARPage{},
			Entries: []HAREntry{},
		},
	}
}

// ConvertTrafficRecordToHAREntry converts a TrafficRecord to a HAR entry
func ConvertTrafficRecordToHAREntry(record *TrafficRecord) HAREntry {
	// Convert headers from map to HAR format
	requestHeaders := make([]HARNameValue, 0, len(record.Request.Headers))
	for name, value := range record.Request.Headers {
		requestHeaders = append(requestHeaders, HARNameValue{
			Name:  name,
			Value: value,
		})
	}

	responseHeaders := make([]HARNameValue, 0, len(record.Response.Headers))
	for name, value := range record.Response.Headers {
		responseHeaders = append(responseHeaders, HARNameValue{
			Name:  name,
			Value: value,
		})
	}

	// Parse query string from URL
	queryString := []HARNameValue{}
	// Note: For simplicity, we're not parsing URL query parameters here
	// This could be enhanced to parse the URL and extract query parameters

	// Handle POST data
	var postData *HARPostData
	if record.Request.Method == "POST" && record.Request.Body != "" {
		contentType := record.Request.Headers["Content-Type"]
		if contentType == "" {
			contentType = "application/octet-stream"
		}

		postData = &HARPostData{
			MimeType: contentType,
			Params:   []HARPostParam{}, // Could be enhanced to parse form data
			Text:     record.Request.Body,
		}
	}

	// Build absolute URL for HAR compliance
	absoluteURL := buildAbsoluteURL(record.Domain, record.Request.URL, record.Request.Headers)

	// Create HAR entry
	entry := HAREntry{
		StartedDateTime: record.Timestamp,
		Time:            float64(record.Duration.Milliseconds()),
		Request: HARRequest{
			Method:      record.Request.Method,
			URL:         absoluteURL,
			HTTPVersion: convertProtoToVersion(record.Request.Proto),
			Cookies:     []HARCookie{}, // Could be enhanced to parse cookies
			Headers:     requestHeaders,
			QueryString: queryString,
			PostData:    postData,
			HeadersSize: calculateHeadersSize(record.Request.Headers),
			BodySize:    record.Request.BodySize,
		},
		Response: HARResponse{
			Status:      record.Response.StatusCode,
			StatusText:  extractStatusText(record.Response.Status),
			HTTPVersion: convertProtoToVersion(record.Response.Proto),
			Cookies:     []HARCookie{}, // Could be enhanced to parse Set-Cookie headers
			Headers:     responseHeaders,
			Content: HARContent{
				Size:     record.Response.BodySize,
				MimeType: record.Response.ContentType,
				Text:     record.Response.Body,
			},
			RedirectURL: "",
			HeadersSize: calculateHeadersSize(record.Response.Headers),
			BodySize:    record.Response.BodySize,
		},
		Cache: HARCache{
			// Default empty cache info
		},
		Timings: HARTimings{
			// Complete HAR 1.2 compliant timings object
			Blocked: 0,  // Not measured, using 0
			DNS:     -1, // Not applicable for intercepted traffic
			Connect: -1, // Not applicable for intercepted traffic
			Send:    0,  // Not measured separately, using 0
			Wait:    int(record.Duration.Milliseconds()),
			Receive: 0, // Not measured separately, using 0
		},
		ServerIPAddress: "", // Could be populated if available
		Connection:      "", // Could be populated if connection reuse info is available
	}

	return entry
}

// Helper functions

// buildAbsoluteURL constructs an absolute URL from domain and request URL
func buildAbsoluteURL(domain, requestURL string, headers map[string]string) string {
	// If the requestURL is already absolute, return it as-is
	if strings.HasPrefix(requestURL, "http://") || strings.HasPrefix(requestURL, "https://") {
		return requestURL
	}

	// Determine scheme based on context or headers
	scheme := "https" // Default to HTTPS for HTTPSeal

	// Check if we can determine the scheme from headers or other context
	// For HTTPSeal, we primarily intercept HTTPS traffic
	if headers != nil {
		// We could check for specific headers that indicate HTTP vs HTTPS
		// But for HTTPSeal's use case, HTTPS is the primary protocol
	}

	// Ensure requestURL starts with /
	if !strings.HasPrefix(requestURL, "/") {
		requestURL = "/" + requestURL
	}

	// Construct the absolute URL
	return fmt.Sprintf("%s://%s%s", scheme, domain, requestURL)
}

// convertProtoToVersion converts HTTP protocol string to version
func convertProtoToVersion(proto string) string {
	switch proto {
	case "HTTP/1.0":
		return "1.0"
	case "HTTP/1.1":
		return "1.1"
	case "HTTP/2.0", "HTTP/2":
		return "2.0"
	default:
		return "1.1" // default fallback
	}
}

// extractStatusText extracts status text from status string like "200 OK"
func extractStatusText(status string) string {
	parts := strings.SplitN(status, " ", 2)
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}

// calculateHeadersSize estimates headers size (rough calculation)
func calculateHeadersSize(headers map[string]string) int {
	size := 0
	for name, value := range headers {
		size += len(name) + len(value) + 4 // name: value\r\n
	}
	return size
}

// ToJSON converts HAR to JSON bytes
func (h *HAR) ToJSON() ([]byte, error) {
	return json.MarshalIndent(h, "", "  ")
}

