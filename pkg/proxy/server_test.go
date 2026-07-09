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
	records      []*logger.TrafficRecord
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

func (l *spyTrafficLogger) LogTraffic(record *logger.TrafficRecord) error {
	l.trafficCount++
	l.records = append(l.records, record)
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
	realDomain := "example.com"
	cfg := &config.Config{ConnectionTimeout: 1}
	server, err := NewHTTPServer(80, nil, noopTrafficLogger{}, nil, cfg)
	if err != nil {
		t.Fatalf("new http server: %v", err)
	}
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requestCount++
			return &http.Response{
				Status:        "200 OK",
				StatusCode:    http.StatusOK,
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        http.Header{"Content-Type": []string{"text/plain"}},
				Body:          io.NopCloser(strings.NewReader(req.URL.Path)),
				ContentLength: int64(len(req.URL.Path)),
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
	log := &spyTrafficLogger{}
	cfg := &config.Config{ConnectionTimeout: 1}
	server, err := NewHTTPServer(80, nil, log, nil, cfg)
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
	if log.trafficCount != 1 {
		t.Fatalf("expected synthetic 502 to be logged once, got %d records", log.trafficCount)
	}
	if got := log.records[0].Response.StatusCode; got != http.StatusBadGateway {
		t.Fatalf("expected logged status 502, got %d", got)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not finish after writing 502 response")
	}
}

func TestHandleHTTPRequestsCaptureOnlySkipsUpstreamAndLogsRequest(t *testing.T) {
	log := &spyTrafficLogger{}
	cfg := &config.Config{
		ConnectionTimeout:  1,
		CaptureMode:        config.CaptureModeSynthetic,
		CaptureOnly:        true,
		CaptureOnlyStatus:  http.StatusNoContent,
		NoRedact:           true,
		CaptureBodyLimit:   1024,
		DecompressResponse: true,
	}
	server, err := NewHTTPServer(80, nil, log, nil, cfg)
	if err != nil {
		t.Fatalf("new http server: %v", err)
	}

	upstreamCalled := false
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			upstreamCalled = true
			return nil, errors.New("upstream should not be called in capture-only mode")
		}),
	}
	server.httpClient = client
	server.socks5Client = client

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer proxyConn.Close()
		server.handleHTTPRequests(proxyConn, "example.com", "https")
		close(done)
	}()

	request := "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"
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

	if upstreamCalled {
		t.Fatal("expected capture-only mode to skip upstream forwarding")
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 response, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-HTTPSeal-Capture-Only"); got != "" {
		t.Fatalf("expected no HTTPSeal response header, got %q", got)
	}
	if len(body) != 0 {
		t.Fatalf("expected empty response body, got %q", string(body))
	}
	if log.trafficCount != 1 {
		t.Fatalf("expected one logged traffic record, got %d", log.trafficCount)
	}
	record := log.records[0]
	if record.Request.Method != http.MethodPost {
		t.Fatalf("expected logged method POST, got %s", record.Request.Method)
	}
	if record.Request.Body != "payload" {
		t.Fatalf("expected logged request body, got %q", record.Request.Body)
	}
	if record.Response.StatusCode != http.StatusNoContent {
		t.Fatalf("expected logged status 204, got %d", record.Response.StatusCode)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not finish after capture-only response")
	}
}

func TestHandleHTTPRequestsCaptureOnlySyntheticKeepsAlive(t *testing.T) {
	log := &spyTrafficLogger{}
	cfg := &config.Config{
		ConnectionTimeout:  1,
		CaptureMode:        config.CaptureModeSynthetic,
		CaptureOnly:        true,
		CaptureOnlyStatus:  http.StatusNoContent,
		NoRedact:           true,
		CaptureBodyLimit:   1024,
		DecompressResponse: true,
	}
	server, err := NewHTTPServer(80, nil, log, nil, cfg)
	if err != nil {
		t.Fatalf("new http server: %v", err)
	}

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	if err := clientConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer proxyConn.Close()
		server.handleHTTPRequests(proxyConn, "example.com", "https")
		close(done)
	}()

	if _, err := clientConn.Write([]byte("GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatalf("write first request: %v", err)
	}

	reader := bufio.NewReader(clientConn)
	firstResp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read first response: %v", err)
	}
	if _, err := io.ReadAll(firstResp.Body); err != nil {
		t.Fatalf("read first response body: %v", err)
	}
	firstResp.Body.Close()

	if firstResp.Close {
		t.Fatal("expected first synthetic response to keep the connection alive")
	}
	if strings.EqualFold(firstResp.Header.Get("Connection"), "close") {
		t.Fatal("expected first synthetic response not to send Connection: close")
	}

	if _, err := clientConn.Write([]byte("GET /second HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write second request: %v", err)
	}

	secondResp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read second response: %v", err)
	}
	if _, err := io.ReadAll(secondResp.Body); err != nil {
		t.Fatalf("read second response body: %v", err)
	}
	secondResp.Body.Close()

	if !secondResp.Close {
		t.Fatal("expected second synthetic response to honor client close")
	}
	if log.trafficCount != 2 {
		t.Fatalf("expected two logged traffic records, got %d", log.trafficCount)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not finish after close request")
	}
}

func TestHandleHTTPRequestsCaptureOnlyUpstreamUsesResponder(t *testing.T) {
	var upstreamMethod string
	var upstreamHost string
	var upstreamPath string
	var upstreamRawQuery string
	var upstreamBody string
	var originalHost string
	var originalScheme string
	var originalURL string
	var captureOnlyHeader string

	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		upstreamMethod = r.Method
		upstreamHost = r.Host
		upstreamPath = r.URL.Path
		upstreamRawQuery = r.URL.RawQuery
		upstreamBody = string(body)
		originalHost = r.Header.Get("X-HTTPSeal-Original-Host")
		originalScheme = r.Header.Get("X-HTTPSeal-Original-Scheme")
		originalURL = r.Header.Get("X-HTTPSeal-Original-URL")
		captureOnlyHeader = r.Header.Get("X-HTTPSeal-Capture-Only")

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("mocked response"))
	}))
	defer responder.Close()
	upstreamRawURL := responder.URL + "/mock?base=1"
	upstreamURL, err := config.ParseCaptureOnlyUpstreamURL(upstreamRawURL)
	if err != nil {
		t.Fatalf("parse capture-only upstream: %v", err)
	}

	log := &spyTrafficLogger{}
	cfg := &config.Config{
		ConnectionTimeout:      1,
		CaptureMode:            config.CaptureModeUpstream,
		CaptureOnly:            true,
		CaptureOnlyUpstream:    upstreamRawURL,
		CaptureOnlyUpstreamURL: upstreamURL,
		NoRedact:               true,
		CaptureBodyLimit:       1024,
		DecompressResponse:     true,
		CaptureOnlyStatus:      http.StatusNoContent,
	}
	server, err := NewHTTPServer(80, nil, log, nil, cfg)
	if err != nil {
		t.Fatalf("new http server: %v", err)
	}

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer proxyConn.Close()
		server.handleHTTPRequests(proxyConn, "example.com", "https")
		close(done)
	}()

	request := "POST /api/users?x=1 HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"
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

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected responder status 201, got %d", resp.StatusCode)
	}
	if string(body) != "mocked response" {
		t.Fatalf("expected responder body, got %q", string(body))
	}
	if upstreamMethod != http.MethodPost {
		t.Fatalf("expected upstream method POST, got %s", upstreamMethod)
	}
	if upstreamHost != strings.TrimPrefix(responder.URL, "http://") {
		t.Fatalf("expected upstream host to target responder, got %q", upstreamHost)
	}
	if upstreamPath != "/mock/api/users" {
		t.Fatalf("expected joined upstream path, got %q", upstreamPath)
	}
	if upstreamRawQuery != "base=1&x=1" {
		t.Fatalf("expected combined upstream query, got %q", upstreamRawQuery)
	}
	if upstreamBody != "payload" {
		t.Fatalf("expected upstream request body, got %q", upstreamBody)
	}
	if originalHost != "example.com" {
		t.Fatalf("expected original host header, got %q", originalHost)
	}
	if originalScheme != "https" {
		t.Fatalf("expected original scheme header, got %q", originalScheme)
	}
	if originalURL != "https://example.com/api/users?x=1" {
		t.Fatalf("expected original URL header, got %q", originalURL)
	}
	if captureOnlyHeader != "upstream" {
		t.Fatalf("expected capture-only upstream header, got %q", captureOnlyHeader)
	}
	if log.trafficCount != 1 {
		t.Fatalf("expected one logged traffic record, got %d", log.trafficCount)
	}
	record := log.records[0]
	if record.Response.StatusCode != http.StatusCreated {
		t.Fatalf("expected logged responder status 201, got %d", record.Response.StatusCode)
	}
	if record.Response.Body != "mocked response" {
		t.Fatalf("expected logged responder body, got %q", record.Response.Body)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not finish after capture-only upstream response")
	}
}

func TestHandleHTTPRequestsCaptureOnlyUpstreamCanPreserveHost(t *testing.T) {
	var upstreamHost string
	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHost = r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer responder.Close()
	upstreamURL, err := config.ParseCaptureOnlyUpstreamURL(responder.URL)
	if err != nil {
		t.Fatalf("parse capture-only upstream: %v", err)
	}

	log := &spyTrafficLogger{}
	cfg := &config.Config{
		ConnectionTimeout:       1,
		CaptureMode:             config.CaptureModeUpstream,
		CaptureOnly:             true,
		CaptureOnlyUpstream:     responder.URL,
		CaptureOnlyUpstreamURL:  upstreamURL,
		CaptureOnlyPreserveHost: true,
		CaptureOnlyStatus:       http.StatusNoContent,
		NoRedact:                true,
		CaptureBodyLimit:        1024,
		DecompressResponse:      true,
	}
	server, err := NewHTTPServer(80, nil, log, nil, cfg)
	if err != nil {
		t.Fatalf("new http server: %v", err)
	}

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer proxyConn.Close()
		server.handleHTTPRequests(proxyConn, "example.com", "https")
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
	resp.Body.Close()

	if upstreamHost != "example.com" {
		t.Fatalf("expected original host to be preserved, got %q", upstreamHost)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not finish after capture-only upstream response")
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
