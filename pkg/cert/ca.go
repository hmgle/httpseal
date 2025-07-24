package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CA represents a Certificate Authority for generating domain certificates
type CA struct {
	dir        string
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	certCache  map[string]*tls.Certificate
	cacheMutex sync.RWMutex
	isTempDir  bool // Track if this is a temporary directory that should always be cleaned up
}

// NewCA creates or loads a certificate authority
func NewCA(caDir string) (*CA, error) {
	// Detect if this is a temporary directory by checking if it's in temp dir
	// and has the httpseal-ca prefix
	isTempDir := strings.Contains(caDir, os.TempDir()) && strings.Contains(filepath.Base(caDir), "httpseal-ca-")
	
	ca := &CA{
		dir:       caDir,
		certCache: make(map[string]*tls.Certificate),
		isTempDir: isTempDir,
	}

	if err := os.MkdirAll(caDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create CA directory: %w", err)
	}

	// Load or create CA certificate and key
	if err := ca.loadOrCreateCA(); err != nil {
		return nil, fmt.Errorf("failed to initialize CA: %w", err)
	}

	return ca, nil
}

// loadOrCreateCA loads existing CA or creates a new one
func (ca *CA) loadOrCreateCA() error {
	caCertPath := filepath.Join(ca.dir, "ca.crt")

	// Check if CA files exist
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		return ca.createCA()
	}

	return ca.loadCA()
}

// createCA creates a new root CA certificate and private key
func (ca *CA) createCA() error {
	// Generate private key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"HTTPSeal CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour * 10), // 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	ca.caCert = cert
	ca.caKey = key

	// Save to files
	if err := ca.saveCACert(certDER); err != nil {
		return err
	}

	if err := ca.saveCAKey(key); err != nil {
		return err
	}

	fmt.Printf("Created new CA certificate: %s\n", filepath.Join(ca.dir, "ca.crt"))

	return nil
}

// loadCA loads existing CA certificate and key
func (ca *CA) loadCA() error {
	caCertPath := filepath.Join(ca.dir, "ca.crt")
	caKeyPath := filepath.Join(ca.dir, "ca.key")

	// Load certificate
	certPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Load private key
	keyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read CA private key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA private key PEM")
	}

	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %w", err)
	}

	ca.caCert = cert
	ca.caKey = key

	return nil
}

// GenerateCertForDomain generates a TLS certificate for the specified domain
func (ca *CA) GenerateCertForDomain(domain string) (*tls.Certificate, error) {
	ca.cacheMutex.RLock()
	if cert, exists := ca.certCache[domain]; exists {
		ca.cacheMutex.RUnlock()
		return cert, nil
	}
	ca.cacheMutex.RUnlock()

	// Generate new certificate
	cert, err := ca.generateCertificate(domain)
	if err != nil {
		return nil, err
	}

	// Cache the certificate
	ca.cacheMutex.Lock()
	ca.certCache[domain] = cert
	ca.cacheMutex.Unlock()

	return cert, nil
}

// generateCertificate creates a new certificate for the domain
func (ca *CA) generateCertificate(domain string) (*tls.Certificate, error) {
	// Generate private key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key for %s: %w", domain, err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization:  []string{"HTTPSeal"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		DNSNames:              []string{domain},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate signed by CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, ca.caCert, &key.PublicKey, ca.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate for %s: %w", domain, err)
	}

	// Create TLS certificate
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return tlsCert, nil
}

// saveCACert saves the CA certificate to file
func (ca *CA) saveCACert(certDER []byte) error {
	certPath := filepath.Join(ca.dir, "ca.crt")
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate file: %w", err)
	}
	defer certOut.Close()

	return pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

// saveCAKey saves the CA private key to file
func (ca *CA) saveCAKey(key *rsa.PrivateKey) error {
	keyPath := filepath.Join(ca.dir, "ca.key")
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create CA private key file: %w", err)
	}
	defer keyOut.Close()

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	return pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
}

// Cleanup removes the CA directory and all certificates if it's safe to do so
func (ca *CA) Cleanup() error {
	// Only cleanup if this is a temporary directory we created
	if !ca.isTempDir {
		return nil
	}

	// Clear in-memory cache first
	ca.cacheMutex.Lock()
	ca.certCache = make(map[string]*tls.Certificate)
	ca.cacheMutex.Unlock()

	// Remove the entire CA directory
	if err := os.RemoveAll(ca.dir); err != nil {
		return fmt.Errorf("failed to cleanup CA directory %s: %w", ca.dir, err)
	}

	return nil
}

// GetCACertPath returns the path to the CA certificate file
func (ca *CA) GetCACertPath() string {
	return filepath.Join(ca.dir, "ca.crt")
}

