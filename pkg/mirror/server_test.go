package mirror

import (
	"net/http"
	"testing"
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
	)

	server.respMutex.RLock()
	defer server.respMutex.RUnlock()
	if len(server.responses) != 0 {
		t.Fatalf("expected stopped server to reject records, got %d", len(server.responses))
	}
}
