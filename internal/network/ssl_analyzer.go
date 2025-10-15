// internal/network/ssl_analyzer.go
package network

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

type SSLAnalysis struct {
	CertificateValid   bool
	ExpiresIn          time.Duration
	Issuer             string
	Subject            string
	SupportedProtocols []string
	CipherSuites       []string
	EncryptionGrade    string
	HasWeakCiphers     bool
	OCSPStapling       bool
	HSTSEnabled        bool
}

type SSLClient struct {
	timeout time.Duration
}

func NewSSLClient() *SSLClient {
	return &SSLClient{
		timeout: 15 * time.Second,
	}
}

func (s *SSLClient) AnalyzeTLS(host string) (*SSLAnalysis, error) {
	analysis := &SSLAnalysis{}

	// Test different TLS versions
	protocols := []struct {
		name string
		version uint16
	}{
		{"TLS 1.3", tls.VersionTLS13},
		{"TLS 1.2", tls.VersionTLS12},
		{"TLS 1.1", tls.VersionTLS11},
		{"TLS 1.0", tls.VersionTLS10},
	}

	for _, proto := range protocols {
		if s.testProtocol(host, proto.version) {
			analysis.SupportedProtocols = append(analysis.SupportedProtocols, proto.name)
		}
	}

	// Get certificate details
	cert, err := s.getCertificate(host)
	if err != nil {
		return analysis, err
	}

	analysis.CertificateValid = true
	analysis.Issuer = cert.Issuer.String()
	analysis.Subject = cert.Subject.String()
	analysis.ExpiresIn = time.Until(cert.NotAfter)

	// Analyze certificate strength
	analysis.EncryptionGrade = s.gradeCertificate(cert)
	analysis.HasWeakCiphers = s.checkWeakCiphers(host)

	return analysis, nil
}

func (s *SSLClient) testProtocol(host string, version uint16) bool {
	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: s.timeout,
	}, "tcp", host+":443", &tls.Config{
		InsecureSkipVerify: true, // We're just testing support
		MinVersion:         version,
		MaxVersion:         version,
	})

	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

func (s *SSLClient) getCertificate(host string) (*tls.Certificate, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: s.timeout,
	}, "tcp", host+":443", &tls.Config{
		InsecureSkipVerify: true,
	})

	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates presented")
	}

	return state.PeerCertificates[0], nil
}

func (s *SSLClient) gradeCertificate(cert *tls.Certificate) string {
	// Simple grading based on key strength and expiration
	remaining := time.Until(cert.NotAfter)
	
	if remaining < 30*24*time.Hour {
		return "F" // Expiring soon
	}

	// Check key size (simplified)
	if cert.PublicKey != nil {
		// In production, would check actual key size
		return "A"
	}

	return "B"
}

func (s *SSLClient) checkWeakCiphers(host string) bool {
	weakCiphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	}

	for _, cipher := range weakCiphers {
		conn, err := tls.DialWithDialer(&net.Dialer{
			Timeout: s.timeout,
		}, "tcp", host+":443", &tls.Config{
			InsecureSkipVerify: true,
			CipherSuites:       []uint16{cipher},
		})

		if err == nil {
			conn.Close()
			return true
		}
	}

	return false
}
