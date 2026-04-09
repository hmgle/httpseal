package logger

import (
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

func sampleTrafficRecord() *TrafficRecord {
	return &TrafficRecord{
		Timestamp: time.Unix(0, 0),
		Domain:    "example.com",
		Duration:  15 * time.Millisecond,
		Request: HTTPRequest{
			Method:   "GET",
			URL:      "/",
			Proto:    "HTTP/1.1",
			Host:     "example.com",
			Headers:  map[string]string{"User-Agent": "test"},
			BodySize: 0,
		},
		Response: HTTPResponse{
			Proto:       "HTTP/1.1",
			Status:      "200 OK",
			StatusCode:  200,
			Headers:     map[string]string{"Content-Type": "text/plain"},
			Body:        "ok",
			BodySize:    2,
			ContentType: "text/plain",
		},
	}
}
