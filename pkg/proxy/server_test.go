package proxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hmgle/httpseal/internal/config"
	"github.com/hmgle/httpseal/pkg/cert"
	"github.com/hmgle/httpseal/pkg/logger"
)

type noopTrafficLogger struct{}

func (noopTrafficLogger) Debug(string, ...interface{})           {}
func (noopTrafficLogger) Info(string, ...interface{})            {}
func (noopTrafficLogger) Warn(string, ...interface{})            {}
func (noopTrafficLogger) Error(string, ...interface{})           {}
func (noopTrafficLogger) LogTraffic(*logger.TrafficRecord) error { return nil }
func (noopTrafficLogger) Close() error                           { return nil }

type spyTrafficLogger struct {
	infoCount    int
	debugCount   int
	warnCount    int
	errorCount   int
	trafficCount int
}

func (l *spyTrafficLogger) Debug(string, ...interface{}) {
	l.debugCount++
}

func (l *spyTrafficLogger) Info(string, ...interface{}) {
	l.infoCount++
}

func (l *spyTrafficLogger) Warn(string, ...interface{}) {
	l.warnCount++
}

func (l *spyTrafficLogger) Error(string, ...interface{}) {
	l.errorCount++
}

func (l *spyTrafficLogger) LogTraffic(*logger.TrafficRecord) error {
	l.trafficCount++
	return nil
}

func (l *spyTrafficLogger) Close() error {
	return nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type errorCloseBody struct {
	reader io.Reader
}

func (b *errorCloseBody) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

func (b *errorCloseBody) Close() error {
	return errors.New("close failed")
}

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
	server, err := NewHTTPServer(80, nil, noopTrafficLogger{}, nil, cfg)
	if err != nil {
		t.Fatalf("new http server: %v", err)
	}

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

func TestHandleHTTPRequestsStillWritesResponseWhenUpstreamCloseFails(t *testing.T) {
	cfg := &config.Config{ConnectionTimeout: 1}
	server, err := NewHTTPServer(80, nil, noopTrafficLogger{}, nil, cfg)
	if err != nil {
		t.Fatalf("new http server: %v", err)
	}
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Status:        "200 OK",
				StatusCode:    http.StatusOK,
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        http.Header{"Content-Type": []string{"text/plain"}},
				Body:          &errorCloseBody{reader: strings.NewReader("ok")},
				ContentLength: 2,
				Close:         true,
				Request:       req,
			}, nil
		}),
	}
	server.httpClient = client
	server.socks5Client = client

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer proxyConn.Close()
		server.handleHTTPRequests(proxyConn, "example.com", "http")
		close(done)
	}()

	request := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	if _, err := clientConn.Write([]byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	reader := bufio.NewReader(clientConn)
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))

	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	resp.Body.Close()

	if string(body) != "ok" {
		t.Fatalf("unexpected response body: %q", string(body))
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not finish after response write")
	}
}

func TestHandleHTTPRequestsOnlyEmitTrafficViaTrafficLogger(t *testing.T) {
	cfg := &config.Config{ConnectionTimeout: 1}
	log := &spyTrafficLogger{}
	server, err := NewHTTPServer(80, nil, log, nil, cfg)
	if err != nil {
		t.Fatalf("new http server: %v", err)
	}
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Status:        "200 OK",
				StatusCode:    http.StatusOK,
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        http.Header{"Content-Type": []string{"text/plain"}},
				Body:          io.NopCloser(strings.NewReader("ok")),
				ContentLength: 2,
				Close:         true,
				Request:       req,
			}, nil
		}),
	}
	server.httpClient = client
	server.socks5Client = client

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer proxyConn.Close()
		server.handleHTTPRequests(proxyConn, "example.com", "http")
		close(done)
	}()

	request := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	if _, err := clientConn.Write([]byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	reader := bufio.NewReader(clientConn)
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))

	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	resp.Body.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not finish after response write")
	}

	if log.trafficCount != 1 {
		t.Fatalf("expected 1 traffic record, got %d", log.trafficCount)
	}
	if log.infoCount != 0 {
		t.Fatalf("expected no direct info-level traffic logs, got %d", log.infoCount)
	}
	if log.errorCount != 0 {
		t.Fatalf("expected no error logs, got %d", log.errorCount)
	}
}

func TestHandleHTTPRequestsReturnsBadGatewayOnUpstreamError(t *testing.T) {
	cfg := &config.Config{ConnectionTimeout: 1}
	server, err := NewHTTPServer(80, nil, noopTrafficLogger{}, nil, cfg)
	if err != nil {
		t.Fatalf("new http server: %v", err)
	}
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("dial tcp 203.0.113.10:443: connect: connection refused")
		}),
	}
	server.httpClient = client
	server.socks5Client = client

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer proxyConn.Close()
		server.handleHTTPRequests(proxyConn, "example.com", "http")
		close(done)
	}()

	request := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	if _, err := clientConn.Write([]byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	reader := bufio.NewReader(clientConn)
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))

	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 response, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Failed to reach upstream server.") {
		t.Fatalf("unexpected error body: %q", string(body))
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not finish after writing 502 response")
	}
}

func TestBuildUpstreamTLSConfigRejectsInvalidCAFile(t *testing.T) {
	_, err := buildUpstreamTLSConfig(&config.Config{
		UpstreamCAFile: filepath.Join(t.TempDir(), "missing-ca.pem"),
	})
	if err == nil {
		t.Fatal("expected invalid upstream CA path to fail")
	}
}

func TestBuildUpstreamTLSConfigLoadsCustomCAAndTLSOverrides(t *testing.T) {
	caDir := t.TempDir()
	ca, err := cert.NewCA(caDir, noopTrafficLogger{})
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	if ca == nil {
		t.Fatal("expected CA instance")
	}

	tlsConfig, err := buildUpstreamTLSConfig(&config.Config{
		UpstreamCAFile:             filepath.Join(caDir, "ca.crt"),
		UpstreamServerName:         "api.internal.test",
		UpstreamInsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("build upstream tls config: %v", err)
	}

	if tlsConfig.RootCAs == nil {
		t.Fatal("expected custom upstream root CAs to be loaded")
	}
	if tlsConfig.ServerName != "api.internal.test" {
		t.Fatalf("unexpected upstream server name: %q", tlsConfig.ServerName)
	}
	if !tlsConfig.InsecureSkipVerify {
		t.Fatal("expected upstream insecure skip verify to be set")
	}
}
