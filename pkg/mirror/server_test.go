package mirror

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

type noopLogger struct{}

func (noopLogger) Debug(string, ...interface{}) {}
func (noopLogger) Info(string, ...interface{})  {}
func (noopLogger) Warn(string, ...interface{})  {}
func (noopLogger) Error(string, ...interface{}) {}

func TestMirrorTrafficCleansUpDroppedRecord(t *testing.T) {
	server := NewServer(8080, noopLogger{})
	server.exchanges = make(chan *TrafficRecord)

	server.MirrorTraffic(
		"example.com",
		http.MethodGet,
		"/",
		"",
		"ok",
		http.StatusOK,
		http.Header{},
		http.Header{},
	)

	server.respMutex.RLock()
	defer server.respMutex.RUnlock()
	if len(server.responses) != 0 {
		t.Fatalf("expected dropped record to be removed, got %d", len(server.responses))
	}
}

func TestMirrorTrafficReturnsAfterStop(t *testing.T) {
	server := NewServer(8080, noopLogger{})

	if err := server.Stop(); err != nil {
		t.Fatalf("stop mirror server: %v", err)
	}

	server.MirrorTraffic(
		"example.com",
		http.MethodGet,
		"/",
		"",
		"ok",
		http.StatusOK,
		http.Header{},
		http.Header{},
	)

	server.respMutex.RLock()
	defer server.respMutex.RUnlock()
	if len(server.responses) != 0 {
		t.Fatalf("expected stopped server to reject records, got %d", len(server.responses))
	}
}

func TestMirrorTrafficClonesRequestAndResponseHeadersSeparately(t *testing.T) {
	server := NewServer(8080, noopLogger{})
	server.exchanges = make(chan *TrafficRecord, 1)

	requestHeaders := http.Header{"Authorization": []string{"Bearer abc"}}
	responseHeaders := http.Header{"Set-Cookie": []string{"session=abc"}}

	server.MirrorTraffic(
		"example.com",
		http.MethodPost,
		"/login",
		"body",
		"ok",
		http.StatusOK,
		requestHeaders,
		responseHeaders,
	)

	record := <-server.exchanges
	requestHeaders.Set("Authorization", "changed")
	responseHeaders.Set("Set-Cookie", "changed")

	if got := record.RequestHeaders.Get("Authorization"); got != "Bearer abc" {
		t.Fatalf("expected original request headers to be cloned, got %q", got)
	}
	if got := record.ResponseHeaders.Get("Set-Cookie"); got != "session=abc" {
		t.Fatalf("expected original response headers to be cloned, got %q", got)
	}
}

func TestBuildMirrorRequestUsesRequestHeaders(t *testing.T) {
	record := &TrafficRecord{
		ID:              1,
		Timestamp:       time.Unix(0, 0).UTC(),
		OriginalHost:    "example.com",
		Method:          http.MethodPost,
		URL:             "/login",
		RequestBody:     "body",
		RequestHeaders:  http.Header{"Authorization": []string{"Bearer abc"}},
		ResponseHeaders: http.Header{"Set-Cookie": []string{"session=abc"}},
	}

	request := buildMirrorRequest(record)

	if !strings.Contains(request, "Authorization: Bearer abc\r\n") {
		t.Fatalf("expected mirror request to include request headers, got:\n%s", request)
	}
	if strings.Contains(request, "Set-Cookie: session=abc\r\n") {
		t.Fatalf("did not expect mirror request to include response headers, got:\n%s", request)
	}
}

func TestBuildMirroredResponseUsesResponseHeaders(t *testing.T) {
	record := &TrafficRecord{
		ID:              1,
		Timestamp:       time.Unix(0, 0).UTC(),
		OriginalHost:    "example.com",
		StatusCode:      http.StatusOK,
		ResponseBody:    "ok",
		RequestHeaders:  http.Header{"Authorization": []string{"Bearer abc"}},
		ResponseHeaders: http.Header{"Set-Cookie": []string{"session=abc"}},
	}

	response := buildMirroredResponse(record)

	if !strings.Contains(response, "Set-Cookie: session=abc\r\n") {
		t.Fatalf("expected mirrored response to include response headers, got:\n%s", response)
	}
	if strings.Contains(response, "Authorization: Bearer abc\r\n") {
		t.Fatalf("did not expect mirrored response to include request headers, got:\n%s", response)
	}
}
