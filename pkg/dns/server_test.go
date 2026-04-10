package dns

import (
	"net"
	"testing"
)

type noopLogger struct{}

func (noopLogger) Debug(string, ...interface{}) {}
func (noopLogger) Info(string, ...interface{})  {}
func (noopLogger) Warn(string, ...interface{})  {}
func (noopLogger) Error(string, ...interface{}) {}

func TestStartReleasesUDPListenerWhenTCPBindFails(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer tcpListener.Close()

	port := tcpListener.Addr().(*net.TCPAddr).Port
	server := NewServer("127.0.0.1", port, "8.8.8.8:53", noopLogger{})

	if err := server.Start(); err == nil {
		t.Fatal("expected DNS start to fail when TCP port is occupied")
	}

	udpAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("udp listener leaked after failed start: %v", err)
	}
	udpConn.Close()
}

func TestNewServerUsesConfiguredUpstreamDNS(t *testing.T) {
	server := NewServer("127.0.0.1", 53, "10.0.0.53:5353", noopLogger{})

	if server.upstreamDNS != "10.0.0.53:5353" {
		t.Fatalf("expected configured upstream DNS, got %q", server.upstreamDNS)
	}
}
