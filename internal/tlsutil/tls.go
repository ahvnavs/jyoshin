// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package tlsutil

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
	"sync"
	"time"
)

// DynamicCertificateHolder reloads TLS certificates dynamically when file mtime changes.
type DynamicCertificateHolder struct {
	mu       sync.RWMutex
	certPath string
	keyPath  string
	lastMod  time.Time
	cert     *tls.Certificate
}

// NewDynamicCertificateHolder creates an auto-reloading TLS certificate manager.
func NewDynamicCertificateHolder(certPath, keyPath string) (*DynamicCertificateHolder, error) {
	h := &DynamicCertificateHolder{
		certPath: certPath,
		keyPath:  keyPath,
	}
	if err := h.reload(); err != nil {
		return nil, err
	}
	return h, nil
}

// GetCertificate returns the active certificate, checking for on-disk renewals.
func (h *DynamicCertificateHolder) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	h.mu.RLock()
	cert := h.cert
	certPath := h.certPath
	lastMod := h.lastMod
	h.mu.RUnlock()

	// Check if file was renewed
	if fi, err := os.Stat(certPath); err == nil && fi.ModTime().After(lastMod) {
		if err := h.reload(); err == nil {
			h.mu.RLock()
			cert = h.cert
			h.mu.RUnlock()
		}
	}

	return cert, nil
}

func (h *DynamicCertificateHolder) reload() error {
	cert, err := tls.LoadX509KeyPair(h.certPath, h.keyPath)
	if err != nil {
		return fmt.Errorf("loading tls keypair: %w", err)
	}
	fi, _ := os.Stat(h.certPath)

	h.mu.Lock()
	h.cert = &cert
	if fi != nil {
		h.lastMod = fi.ModTime()
	}
	h.mu.Unlock()
	return nil
}

// GenerateSelfSigned produces an ephemeral ECDSA certificate for 'kazeshini open --tls'.
func GenerateSelfSigned(hostnames []string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Kazeshini Ephemeral Server"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hostnames {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	if len(template.IPAddresses) == 0 && len(template.DNSNames) == 0 {
		template.DNSNames = append(template.DNSNames, "localhost")
		template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}
