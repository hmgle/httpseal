package dns

import (
	"fmt"
	"net"
	"sync"

	"github.com/miekg/dns"
	"github.com/httpseal/httpseal/pkg/logger"
)

// Server implements a DNS server for domain-to-localhost mapping
type Server struct {
	dnsIP     string
	port      int
	server    *dns.Server
	logger    logger.Logger
	
	// Domain mapping: localhost IP -> real domain
	domainMap map[string]string
	// IP allocation tracking
	nextIP    net.IP
	mutex     sync.RWMutex
}

// NewServer creates a new DNS server
func NewServer(dnsIP string, port int, log logger.Logger) *Server {
	return &Server{
		dnsIP:     dnsIP,
		port:      port,
		logger:    log,
		domainMap: make(map[string]string),
		nextIP:    net.IPv4(127, 0, 0, 2), // Start from 127.0.0.2
	}
}

// Start starts the DNS server
func (s *Server) Start() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleDNSRequest)

	s.server = &dns.Server{
		Addr:    fmt.Sprintf("%s:%d", s.dnsIP, s.port),
		Net:     "udp",
		Handler: mux,
	}

	go func() {
		if err := s.server.ListenAndServe(); err != nil {
			s.logger.Error("DNS server error: %v", err)
		}
	}()

	s.logger.Debug("DNS server started on %s:%d", s.dnsIP, s.port)
	return nil
}

// Stop stops the DNS server
func (s *Server) Stop() error {
	if s.server != nil {
		return s.server.Shutdown()
	}
	return nil
}

// GetDomainForIP returns the real domain for a given localhost IP
func (s *Server) GetDomainForIP(ip string) (string, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	domain, exists := s.domainMap[ip]
	return domain, exists
}

// handleDNSRequest handles incoming DNS requests
func (s *Server) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, question := range r.Question {
		if question.Qtype == dns.TypeA {
			domain := question.Name
			// Remove trailing dot
			if len(domain) > 0 && domain[len(domain)-1] == '.' {
				domain = domain[:len(domain)-1]
			}

			// Allocate a new localhost IP for this domain
			ip := s.allocateIP(domain)
			
			s.logger.Debug("DNS query for %s -> %s", domain, ip)

			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP(ip),
			}
			msg.Answer = append(msg.Answer, rr)
		}
	}

	w.WriteMsg(msg)
}

// allocateIP allocates a new localhost IP for the given domain
func (s *Server) allocateIP(domain string) string {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if we already have an IP for this domain
	for ip, existingDomain := range s.domainMap {
		if existingDomain == domain {
			return ip
		}
	}

	// Allocate new IP
	ip := s.nextIP.String()
	s.domainMap[ip] = domain
	
	// Increment to next IP in 127.0.0.0/8 range
	s.nextIP = s.incrementIP(s.nextIP)
	
	return ip
}

// incrementIP increments an IP address within the 127.0.0.0/8 range
func (s *Server) incrementIP(ip net.IP) net.IP {
	nextIP := make(net.IP, len(ip))
	copy(nextIP, ip)
	
	// Increment the last octet, then propagate carry
	for i := len(nextIP) - 1; i >= 0; i-- {
		nextIP[i]++
		if nextIP[i] != 0 {
			break
		}
	}
	
	// Ensure we stay in 127.0.0.0/8 range
	if nextIP[0] != 127 {
		// Wrap around to 127.0.0.2
		nextIP = net.IPv4(127, 0, 0, 2)
	}
	
	return nextIP
}