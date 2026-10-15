package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

// GenerateSelfSignedCert generates an in-memory TLS certificate valid for 10 years.
// No certificate or key files need to be written to disk.
func GenerateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Antigravity Community"},
			CommonName:   "Antigravity Secure Gateway",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years validity
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "antigravity.proxy", "*.local"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// GetOrGenerateCert loads existing certificate files if available,
// or automatically generates an in-memory certificate.
func GetOrGenerateCert(certPath, keyPath string) (tls.Certificate, error) {
	if certPath != "" && keyPath != "" {
		if _, err1 := os.Stat(certPath); err1 == nil {
			if _, err2 := os.Stat(keyPath); err2 == nil {
				log.Printf("[TLS] Loading certificate from %s and %s", certPath, keyPath)
				return tls.LoadX509KeyPair(certPath, keyPath)
			}
		}
	}

	log.Printf("[TLS] Generating high-entropy self-signed certificate in-memory (valid for 10 years)...")
	return GenerateSelfSignedCert()
}
