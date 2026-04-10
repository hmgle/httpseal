package logger

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hmgle/httpseal/internal/config"
)

func TestCSVOutputDoesNotRewriteHeaderWhenAppending(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "traffic.csv")
	header := "timestamp,session_id,domain,method,url,status_code,status,content_type,request_size,response_size,duration_ms,request_headers,response_headers,request_body,response_body\n"
	existingRow := "2024-01-01T00:00:00Z,old,example.com,GET,/,200,200 OK,text/plain,0,2,10,{}, {},,\n"
	if err := os.WriteFile(outputPath, []byte(header+existingRow), 0644); err != nil {
		t.Fatalf("write existing csv: %v", err)
	}

	log, err := NewEnhanced(&config.Config{
		OutputFile:   outputPath,
		OutputFormat: config.FormatCSV,
		LogLevel:     config.LogLevelNone,
		FileLogLevel: config.LogLevelMinimal,
		Quiet:        true,
	})
	if err != nil {
		t.Fatalf("new enhanced logger: %v", err)
	}

	if err := log.LogTraffic(sampleTrafficRecord()); err != nil {
		t.Fatalf("log traffic: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read csv output: %v", err)
	}

	if strings.Count(string(content), header) != 1 {
		t.Fatalf("expected exactly one csv header, got:\n%s", string(content))
	}
}

func TestHAROutputRewritesFileWithValidDocument(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "traffic.har")
	if err := os.WriteFile(outputPath, []byte("stale"), 0644); err != nil {
		t.Fatalf("write stale har: %v", err)
	}

	log, err := NewEnhanced(&config.Config{
		OutputFile:   outputPath,
		OutputFormat: config.FormatHAR,
		LogLevel:     config.LogLevelNone,
		FileLogLevel: config.LogLevelMinimal,
		Quiet:        true,
	})
	if err != nil {
		t.Fatalf("new enhanced logger: %v", err)
	}

	if err := log.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read har output: %v", err)
	}
	if strings.Contains(string(content), "stale") {
		t.Fatalf("expected har output to replace stale content, got:\n%s", string(content))
	}

	var har HAR
	if err := json.Unmarshal(content, &har); err != nil {
		t.Fatalf("unmarshal har output: %v", err)
	}
	if har.Log.Version != "1.2" {
		t.Fatalf("unexpected har version: %q", har.Log.Version)
	}
}

func TestJSONOutputPreservesHeaderArraysAndDurationMs(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "traffic.json")

	log, err := NewEnhanced(&config.Config{
		OutputFile:   outputPath,
		OutputFormat: config.FormatJSON,
		LogLevel:     config.LogLevelNone,
		FileLogLevel: config.LogLevelMinimal,
		Quiet:        true,
	})
	if err != nil {
		t.Fatalf("new enhanced logger: %v", err)
	}

	record := sampleTrafficRecord()
	record.Request.Headers["X-Test"] = []string{"one", "two"}
	record.Response.Headers["Set-Cookie"] = []string{"a=1", "b=2"}

	if err := log.LogTraffic(record); err != nil {
		t.Fatalf("log traffic: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read json output: %v", err)
	}

	var decoded TrafficRecord
	if err := json.Unmarshal(bytes.TrimSpace(content), &decoded); err != nil {
		t.Fatalf("unmarshal traffic json: %v", err)
	}

	if decoded.DurationMs != 15 {
		t.Fatalf("expected duration_ms 15, got %d", decoded.DurationMs)
	}
	if len(decoded.Request.Headers["X-Test"]) != 2 {
		t.Fatalf("expected repeated request headers to survive, got %#v", decoded.Request.Headers["X-Test"])
	}
	if len(decoded.Response.Headers["Set-Cookie"]) != 2 {
		t.Fatalf("expected repeated response headers to survive, got %#v", decoded.Response.Headers["Set-Cookie"])
	}
}

func TestConvertTrafficRecordToHAREntryUsesSchemeQueryAndRepeatedHeaders(t *testing.T) {
	record := sampleTrafficRecord()
	record.Request.URL = "/search?q=seal&q=http"
	record.Request.Headers["X-Test"] = []string{"one", "two"}

	entry := ConvertTrafficRecordToHAREntry(record)

	if entry.Request.URL != "http://example.com/search?q=seal&q=http" {
		t.Fatalf("unexpected HAR request URL: %q", entry.Request.URL)
	}
	if len(entry.Request.QueryString) != 2 {
		t.Fatalf("expected query string to preserve repeated params, got %#v", entry.Request.QueryString)
	}

	xTestCount := 0
	for _, header := range entry.Request.Headers {
		if header.Name == "X-Test" {
			xTestCount++
		}
	}
	if xTestCount != 2 {
		t.Fatalf("expected repeated HAR headers, got %d copies", xTestCount)
	}
}

func TestRedactTrafficRecordRedactsSensitiveHeadersURLAndBody(t *testing.T) {
	record := sampleTrafficRecord()
	record.Request.URL = "/login?token=abc123"
	record.Request.Headers["Authorization"] = []string{"Bearer abc123"}
	record.Request.Headers["Cookie"] = []string{"session=abcdef"}
	record.Request.Body = `{"access_token":"abc123","password":"secret"}`
	record.Response.Headers["Set-Cookie"] = []string{"session=abcdef"}
	record.Response.Body = `{"refresh_token":"def456"}`

	RedactTrafficRecord(record, false)

	if got := firstHeaderValue(record.Request.Headers, "Authorization"); got != redactedValue {
		t.Fatalf("expected authorization header to be redacted, got %q", got)
	}
	if got := firstHeaderValue(record.Response.Headers, "Set-Cookie"); got != redactedValue {
		t.Fatalf("expected set-cookie header to be redacted, got %q", got)
	}
	if strings.Contains(record.Request.URL, "abc123") {
		t.Fatalf("expected sensitive query value to be redacted, got %q", record.Request.URL)
	}
	if strings.Contains(record.Request.Body, "abc123") || strings.Contains(record.Request.Body, "secret") {
		t.Fatalf("expected sensitive request body fields to be redacted, got %q", record.Request.Body)
	}
	if strings.Contains(record.Response.Body, "def456") {
		t.Fatalf("expected sensitive response body fields to be redacted, got %q", record.Response.Body)
	}
}

func TestShouldLogTrafficHonorsHostMethodStatusAndPathFilters(t *testing.T) {
	record := sampleTrafficRecord()
	record.Domain = "api.example.com"
	record.Request.Method = "POST"
	record.Request.URL = "/v1/tokens"
	record.Response.StatusCode = 201

	log, err := NewEnhanced(&config.Config{
		LogLevel:          config.LogLevelMinimal,
		FilterHostSuffix:  []string{"example.com"},
		FilterMethods:     []string{"POST"},
		FilterStatusCodes: []int{201},
		FilterPaths:       []string{"/v1/"},
	})
	if err != nil {
		t.Fatalf("new enhanced logger: %v", err)
	}

	enhanced := log.(*EnhancedLogger)
	if !enhanced.shouldLogTraffic(record) {
		t.Fatal("expected record to match the configured filters")
	}

	enhanced.config.FilterMethods = []string{"GET"}
	if enhanced.shouldLogTraffic(record) {
		t.Fatal("expected method filter mismatch to suppress traffic")
	}
}

func sampleTrafficRecord() *TrafficRecord {
	return &TrafficRecord{
		Timestamp:  time.Unix(0, 0),
		Domain:     "example.com",
		Scheme:     "http",
		Duration:   15 * time.Millisecond,
		DurationMs: 15,
		Request: HTTPRequest{
			Method:   "GET",
			URL:      "/",
			Proto:    "HTTP/1.1",
			Host:     "example.com",
			Headers:  map[string][]string{"User-Agent": []string{"test"}},
			BodySize: 0,
		},
		Response: HTTPResponse{
			Proto:       "HTTP/1.1",
			Status:      "200 OK",
			StatusCode:  200,
			Headers:     map[string][]string{"Content-Type": []string{"text/plain"}},
			Body:        "ok",
			BodySize:    2,
			ContentType: "text/plain",
		},
	}
}
