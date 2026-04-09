package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hmgle/httpseal/internal/config"
	"github.com/hmgle/httpseal/pkg/logger"
)

type noopTrafficLogger struct{}

func (noopTrafficLogger) Debug(string, ...interface{})           {}
func (noopTrafficLogger) Info(string, ...interface{})            {}
func (noopTrafficLogger) Warn(string, ...interface{})            {}
func (noopTrafficLogger) Error(string, ...interface{})           {}
func (noopTrafficLogger) LogTraffic(*logger.TrafficRecord) error { return nil }
func (noopTrafficLogger) Close() error                           { return nil }

func TestHandleHTTPRequestsKeepsHTTP11ConnectionsAlive(t *testing.T) {
	requestCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, r.URL.Path)
	}))
	defer upstream.Close()

	realDomain := strings.TrimPrefix(upstream.URL, "http://")
	cfg := &config.Config{ConnectionTimeout: 1}
	server := NewHTTPServer(80, nil, noopTrafficLogger{}, nil, cfg)

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		server.handleHTTPRequests(proxyConn, realDomain, "http")
		close(done)
	}()

	requests := strings.Join([]string{
		"GET /first HTTP/1.1\r\nHost: " + realDomain + "\r\n\r\n",
		"GET /second HTTP/1.1\r\nHost: " + realDomain + "\r\nConnection: close\r\n\r\n",
	}, "")
	if _, err := clientConn.Write([]byte(requests)); err != nil {
		t.Fatalf("write pipelined requests: %v", err)
	}

	reader := bufio.NewReader(clientConn)
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))

	firstResp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read first response: %v", err)
	}
	firstBody, err := io.ReadAll(firstResp.Body)
	if err != nil {
		t.Fatalf("read first body: %v", err)
	}
	firstResp.Body.Close()
	if string(firstBody) != "/first" {
		t.Fatalf("unexpected first body: %q", string(firstBody))
	}

	secondResp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read second response: %v", err)
	}
	secondBody, err := io.ReadAll(secondResp.Body)
	if err != nil {
		t.Fatalf("read second body: %v", err)
	}
	secondResp.Body.Close()
	if string(secondBody) != "/second" {
		t.Fatalf("unexpected second body: %q", string(secondBody))
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not finish after Connection: close")
	}

	if requestCount != 2 {
		t.Fatalf("expected 2 upstream requests, got %d", requestCount)
	}
}
