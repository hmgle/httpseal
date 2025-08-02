package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hmgle/httpseal/pkg/logger"
	"github.com/miekg/dns"
)

const (
	// Start and end IP addresses for loopback range allocation
	// Using 127.0.0.1 to 127.255.255.254 to maximize available addresses
	startIPStr = "127.0.0.1"
	endIPStr   = "127.255.255.254"
)

// LoopbackGen manages the generation of loopback IP addresses with improved robustness
type LoopbackGen struct {
	counter   atomic.Uint64 // Use Uint64 to prevent overflow in practical scenarios
	startIP   uint32
	rangeSize uint32
}

// NewLoopbackGen creates and initializes a new LoopbackGen instance
func NewLoopbackGen() *LoopbackGen {
	startIP := binary.BigEndian.Uint32(net.ParseIP(startIPStr).To4())
	endIP := binary.BigEndian.Uint32(net.ParseIP(endIPStr).To4())

	return &LoopbackGen{
		startIP:   startIP,
		rangeSize: endIP - startIP + 1,
	}
}

// GetNextIP returns the next loopback IP address with improved safety
func (g *LoopbackGen) GetNextIP() net.IP {
	// Use atomic increment to get next offset safely
	offset := g.counter.Add(1)
	
	// Use modulo to cycle through the range safely, avoiding overflow issues
	// offset-1 ensures we start from startIP (not startIP+1) on first call
	ipVal := g.startIP + uint32((offset-1)%uint64(g.rangeSize))
	
	// Create IP directly from uint32 to avoid extra allocations
	ipBytes := [4]byte{}
	binary.BigEndian.PutUint32(ipBytes[:], ipVal)
	return net.IP(ipBytes[:])
}

// Server implements a simple DNS server for hijacking domain lookups
type Server struct {
	ip            string
	port          int
	udpServer     *dns.Server
	tcpServer     *dns.Server
	logger        logger.Logger
	ipDomainMap   sync.Map   // Maps assigned IP addresses back to domains
	domainIPMap   sync.Map   // Maps domains to their assigned IP addresses
	ipGen         *LoopbackGen // IP generator for efficient allocation
	upstreamDNS   string     // Upstream DNS server for non-hijacked queries
}

// NewServer creates a new DNS server
func NewServer(ip string, port int, log logger.Logger) *Server {
	return &Server{
		ip:          ip,
		port:        port,
		logger:      log,
		ipGen:       NewLoopbackGen(),
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

// assignIP assigns a new unique IP address to a domain using the improved LoopbackGen
func (s *Server) assignIP(domain string) net.IP {
	// Double-check without lock first (common case optimization)
	if ip, ok := s.domainIPMap.Load(domain); ok {
		return net.ParseIP(ip.(string))
	}

	// Use the IP generator to get the next IP
	currentIP := s.ipGen.GetNextIP()
	ipStr := currentIP.String()
	
	// Use LoadOrStore to handle race conditions elegantly
	if existingIP, loaded := s.domainIPMap.LoadOrStore(domain, ipStr); loaded {
		// Another goroutine already assigned an IP to this domain
		s.logger.Debug("Domain %s already mapped to %s by another goroutine", domain, existingIP.(string))
		return net.ParseIP(existingIP.(string))
	}
	
	// We successfully stored the new mapping, also store reverse mapping
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
