package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hmgle/httpseal/pkg/logger"
)

const (
	caCertFile = "ca.crt"
	caKeyFile  = "ca.key"
	certTTL    = 24 * time.Hour * 365 // 1 year for generated certs
)

// CA handles certificate authority operations
type CA struct {
	caCert       *x509.Certificate
	caKey        *ecdsa.PrivateKey
	certCache    sync.Map // Caches generated certificates for domains
	caDir        string
	logger       logger.Logger
	certCacheDir string
}

// NewCA creates a new CA instance
func NewCA(caDir string, log logger.Logger) (*CA, error) {
	ca := &CA{
		caDir:        caDir,
		logger:       log,
		certCacheDir: filepath.Join(caDir, "certs"),
	}

	if err := os.MkdirAll(ca.certCacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cert cache directory: %w", err)
	}

	if err := ca.loadOrGenerateCA(); err != nil {
		return nil, err
	}

	return ca, nil
}

// loadOrGenerateCA loads an existing CA or generates a new one
func (ca *CA) loadOrGenerateCA() error {
	certPath := filepath.Join(ca.caDir, caCertFile)
	keyPath := filepath.Join(ca.caDir, caKeyFile)

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			// Both files exist, try to load them
			ca.logger.Info("Loading existing CA from %s", ca.caDir)
			return ca.loadCA(certPath, keyPath)
		}
	}

	// If loading failed or files don't exist, generate a new CA
	ca.logger.Info("Generating new CA in %s", ca.caDir)
	return ca.generateCA(certPath, keyPath)
}

// loadCA loads the CA certificate and private key from files
func (ca *CA) loadCA(certPath, keyPath string) error {
	// Load certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}
	ca.caCert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Load private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read CA private key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA private key PEM")
	}
	ca.caKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %w", err)
	}

	ca.logger.Debug("Successfully loaded CA certificate and key")
	return nil
}

// generateCA generates a new CA certificate and private key
func (ca *CA) generateCA(certPath, keyPath string) error {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	ca.caKey = privateKey

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"HTTPSeal"},
			CommonName:   "HTTPSeal Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(certTTL * 10), // 10 years for root CA
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	ca.caCert, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return fmt.Errorf("failed to parse generated CA certificate: %w", err)
	}

	// Save certificate to file
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate file: %w", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		certOut.Close()
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}
	if err := certOut.Close(); err != nil {
		return fmt.Errorf("failed to close CA certificate file: %w", err)
	}

	// Save private key to file
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create CA private key file: %w", err)
	}
	b, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		keyOut.Close()
		return fmt.Errorf("failed to marshal CA private key: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		keyOut.Close()
		return fmt.Errorf("failed to write CA private key: %w", err)
	}
	if err := keyOut.Close(); err != nil {
		return fmt.Errorf("failed to close CA private key file: %w", err)
	}

	ca.logger.Debug("Successfully generated and saved new CA")
	return nil
}

// GenerateCertForDomain generates a certificate for a specific domain, signed by the CA
func (ca *CA) GenerateCertForDomain(domain string) (*tls.Certificate, error) {
	// Check cache first
	if cert, ok := ca.certCache.Load(domain); ok {
		ca.logger.Debug("Loaded certificate for %s from memory cache", domain)
		return cert.(*tls.Certificate), nil
	}

	// Check file cache
	certPath := filepath.Join(ca.certCacheDir, domain+".crt")
	keyPath := filepath.Join(ca.certCacheDir, domain+".key")
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err == nil {
				// Manually parse leaf certificate to have it available in the struct
				cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					ca.logger.Warn("Failed to parse cached cert for %s: %v", domain, err)
				} else {
					ca.logger.Debug("Loaded certificate for %s from file cache", domain)
					ca.certCache.Store(domain, &cert)
					return &cert, nil
				}
			}
			ca.logger.Warn("Failed to load cached key pair for %s: %v", domain, err)
		}
	}

	// If not in cache, generate a new one
	ca.logger.Debug("Generating new certificate for %s", domain)

	// Generate private key for the domain certificate
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key for %s: %w", domain, err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number for %s: %w", domain, err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(certTTL),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Add domain and any IP addresses to SANs
	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{domain}
	}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, ca.caCert, &privateKey.PublicKey, ca.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate for %s: %w", domain, err)
	}

	// Save certificate to file cache
	certOut, err := os.Create(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert file for %s: %w", domain, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		certOut.Close()
		return nil, fmt.Errorf("failed to write cert file for %s: %w", domain, err)
	}
	if err := certOut.Close(); err != nil {
		return nil, fmt.Errorf("failed to close cert file for %s: %w", domain, err)
	}

	// Save private key to file cache
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create key file for %s: %w", domain, err)
	}
	b, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		keyOut.Close()
		return nil, fmt.Errorf("failed to marshal private key for %s: %w", domain, err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		keyOut.Close()
		return nil, fmt.Errorf("failed to write key file for %s: %w", domain, err)
	}
	if err := keyOut.Close(); err != nil {
		return nil, fmt.Errorf("failed to close key file for %s: %w", domain, err)
	}

	// Create tls.Certificate
	leaf, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate for %s: %w", domain, err)
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privateKey,
		Leaf:        leaf,
	}

	// Store in memory cache
	ca.certCache.Store(domain, cert)

	return cert, nil
}

// Cleanup removes the CA directory if it's temporary
func (ca *CA) Cleanup() error {
	ca.logger.Debug("Cleaning up CA directory: %s", ca.caDir)
	return os.RemoveAll(ca.caDir)
}