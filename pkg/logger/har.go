package logger

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
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
	requestHeaders := flattenHeaders(record.Request.Headers)
	responseHeaders := flattenHeaders(record.Response.Headers)

	// Handle POST data
	var postData *HARPostData
	if record.Request.Body != "" {
		contentType := firstHeaderValue(record.Request.Headers, "Content-Type")
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
	absoluteURL := buildAbsoluteURL(record.Scheme, record.Domain, record.Request.URL)
	queryString := parseQueryString(absoluteURL)

	// Create HAR entry
	entry := HAREntry{
		StartedDateTime: record.Timestamp,
		Time:            float64(record.DurationMs),
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
				Size:        record.Response.BodySize,
				Compression: calculateCompressionSavings(record.Response.Headers, record.Response.Body),
				MimeType:    record.Response.ContentType,
				Text:        record.Response.Body,
				Encoding:    determineContentEncoding(record.Response.Body),
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
			Wait:    int(record.DurationMs),
			Receive: 0, // Not measured separately, using 0
		},
		ServerIPAddress: "", // Could be populated if available
		Connection:      "", // Could be populated if connection reuse info is available
	}

	return entry
}

// Helper functions

func flattenHeaders(headers map[string][]string) []HARNameValue {
	count := 0
	for _, values := range headers {
		count += len(values)
	}

	flattened := make([]HARNameValue, 0, count)
	for name, values := range headers {
		for _, value := range values {
			flattened = append(flattened, HARNameValue{
				Name:  name,
				Value: value,
			})
		}
	}

	return flattened
}

// buildAbsoluteURL constructs an absolute URL from domain and request URL.
func buildAbsoluteURL(scheme, domain, requestURL string) string {
	// If the requestURL is already absolute, return it as-is
	if strings.HasPrefix(requestURL, "http://") || strings.HasPrefix(requestURL, "https://") {
		return requestURL
	}

	if scheme == "" {
		scheme = "https"
	}

	// Ensure requestURL starts with /
	if !strings.HasPrefix(requestURL, "/") {
		requestURL = "/" + requestURL
	}

	// Construct the absolute URL
	return fmt.Sprintf("%s://%s%s", scheme, domain, requestURL)
}

func parseQueryString(absoluteURL string) []HARNameValue {
	parsedURL, err := url.Parse(absoluteURL)
	if err != nil {
		return []HARNameValue{}
	}

	queryString := []HARNameValue{}
	for name, values := range parsedURL.Query() {
		for _, value := range values {
			queryString = append(queryString, HARNameValue{
				Name:  name,
				Value: value,
			})
		}
	}

	return queryString
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
func calculateHeadersSize(headers map[string][]string) int {
	size := 0
	for name, values := range headers {
		for _, value := range values {
			size += len(name) + len(value) + 4 // name: value\r\n
		}
	}
	return size
}

// calculateCompressionSavings calculates compression savings for HAR format
func calculateCompressionSavings(headers map[string][]string, decompressedBody string) int {
	contentEncoding := firstHeaderValue(headers, "Content-Encoding")
	if contentEncoding == "" {
		return 0
	}

	// If the body was successfully decompressed, we can estimate the compression savings
	// by comparing the original size (from headers) with the decompressed size
	contentLength := firstHeaderValue(headers, "Content-Length")
	if contentLength != "" {
		if originalSize, err := strconv.Atoi(contentLength); err == nil {
			decompressedSize := len(decompressedBody)
			if decompressedSize > originalSize {
				// We have decompressed content, so the compression savings is the difference
				return decompressedSize - originalSize
			}
		}
	}

	return 0
}

// determineContentEncoding determines the encoding used for the response body content
func determineContentEncoding(body string) string {
	// If body appears to be decompressed text, it's likely UTF-8
	// If body starts with our compression failure message, it's binary
	if strings.HasPrefix(body, "[Compressed ") {
		return "base64" // Indicate that binary content would need base64 encoding
	}

	// For text content, assume UTF-8
	return ""
}

// ToJSON converts HAR to JSON bytes
func (h *HAR) ToJSON() ([]byte, error) {
	return json.MarshalIndent(h, "", "  ")
}
