package dns

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/hmgle/httpseal/pkg/logger"
	"github.com/miekg/dns"
)

const (
	// Base IP for local mapping. Using a less common range to avoid conflicts.
	baseIP = "127.0.1.1"
)

// Server implements a simple DNS server for hijacking domain lookups
type Server struct {
	ip            string
	port          int
	udpServer     *dns.Server
	tcpServer     *dns.Server
	logger        logger.Logger
	ipDomainMap   sync.Map // Maps assigned IP addresses back to domains
	domainIPMap   sync.Map // Maps domains to their assigned IP addresses
	nextIP        net.IP
	ipMutex       sync.Mutex
	upstreamDNS   string // Upstream DNS server for non-hijacked queries
}

// NewServer creates a new DNS server
func NewServer(ip string, port int, log logger.Logger) *Server {
	return &Server{
		ip:          ip,
		port:        port,
		logger:      log,
		nextIP:      net.ParseIP(baseIP),
		upstreamDNS: "8.8.8.8:53", // Default to Google DNS, can be made configurable
	}
}

// Start starts the DNS server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.ip, s.port)
	handler := dns.HandlerFunc(s.handleRequest)

	s.udpServer = &dns.Server{Addr: addr, Net: "udp", Handler: handler}
	s.tcpServer = &dns.Server{Addr: addr, Net: "tcp", Handler: handler}

	go func() {
		if err := s.udpServer.ListenAndServe(); err != nil {
			s.logger.Error("DNS UDP server failed: %v", err)
		}
	}()

	go func() {
		if err := s.tcpServer.ListenAndServe(); err != nil {
			s.logger.Error("DNS TCP server failed: %v", err)
		}
	}()

	s.logger.Debug("DNS server started on %s (UDP/TCP)", addr)
	return nil
}

// Stop stops the DNS server
func (s *Server) Stop() {
	if s.udpServer != nil {
		s.udpServer.Shutdown()
	}
	if s.tcpServer != nil {
		s.tcpServer.Shutdown()
	}
}

// handleRequest handles incoming DNS queries
func (s *Server) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 {
		m.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	// We only handle A and AAAA queries for domains we want to hijack
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
		s.handleHijackQuery(m, q)
	} else {
		// For other query types, forward to upstream DNS
		s.forwardQuery(w, r)
		return
	}

	if err := w.WriteMsg(m); err != nil {
		s.logger.Error("Failed to write DNS response: %v", err)
	}
}

// handleHijackQuery handles A and AAAA record queries for hijacking
func (s *Server) handleHijackQuery(m *dns.Msg, q dns.Question) {
	domain := strings.TrimSuffix(q.Name, ".")
	s.logger.Debug("Received DNS query for %s", domain)

	// Check if we have already assigned an IP for this domain
	var assignedIP net.IP
	if ip, ok := s.domainIPMap.Load(domain); ok {
		assignedIP = net.ParseIP(ip.(string))
	} else {
		// Assign a new IP address
		assignedIP = s.assignIP(domain)
	}

	// Create an A record answer for TypeA queries
	if q.Qtype == dns.TypeA {
		rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, assignedIP.String()))
		if err == nil {
			m.Answer = append(m.Answer, rr)
		}
	}
	// For AAAA, we return an empty success response to prevent IPv6 fallback issues
}

// assignIP assigns a new unique IP address to a domain
func (s *Server) assignIP(domain string) net.IP {
	s.ipMutex.Lock()
	defer s.ipMutex.Unlock()

	// Double-check in case another goroutine assigned it while waiting for the lock
	if ip, ok := s.domainIPMap.Load(domain); ok {
		return net.ParseIP(ip.(string))
	}

	// Get the next available IP
	currentIP := make(net.IP, len(s.nextIP))
	copy(currentIP, s.nextIP)

	// Increment the IP address for the next assignment
	ipv4 := s.nextIP.To4()
	for i := len(ipv4) - 1; i >= 1; i-- { // only increment last 3 octets
		ipv4[i]++
		if ipv4[i] != 0 {
			break
		}
	}
	// Ensure we stay in 127.0.0.0/8 range
	if ipv4[0] != 127 {
		s.nextIP = net.ParseIP(baseIP) // Reset if we somehow leave the 127/8 range
	}

	// Store the mapping
	ipStr := currentIP.String()
	s.domainIPMap.Store(domain, ipStr)
	s.ipDomainMap.Store(ipStr, domain)

	s.logger.Info("Mapped domain %s to local IP %s", domain, ipStr)
	return currentIP
}

// GetDomainForIP retrieves the original domain for a given IP address
func (s *Server) GetDomainForIP(ip string) (string, bool) {
	domain, ok := s.ipDomainMap.Load(ip)
	if !ok {
		return "", false
	}
	return domain.(string), true
}

// forwardQuery forwards queries that are not for A/AAAA records to an upstream DNS
func (s *Server) forwardQuery(w dns.ResponseWriter, r *dns.Msg) {
	c := new(dns.Client)
	resp, _, err := c.Exchange(r, s.upstreamDNS)
	if err != nil {
		s.logger.Error("Failed to forward DNS query to upstream %s: %v", s.upstreamDNS, err)
		dns.HandleFailed(w, r)
		return
	}

	if err := w.WriteMsg(resp); err != nil {
		s.logger.Error("Failed to write forwarded DNS response: %v", err)
	}
}
