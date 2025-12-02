package network

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/rsa"
	"fmt"
	"net"
	"time"

	"net-zilla/internal/models" // Added import
	"net-zilla/internal/utils"  // Added import for Logger
)

// SSLAnalyzer performs comprehensive TLS/SSL analysis of a given host.
type SSLAnalyzer struct {
	logger  *utils.Logger
	timeout time.Duration
}

// NewSSLAnalyzer creates and initializes a new SSLAnalyzer.
func NewSSLAnalyzer(logger *utils.Logger) *SSLAnalyzer {
	return &SSLAnalyzer{
		logger:  logger,
		timeout: 15 * time.Second, // Default timeout for TLS handshakes
	}
}

// Analyze performs a comprehensive TLS/SSL analysis for the specified host.
func (sa *SSLAnalyzer) Analyze(ctx context.Context, host string) (*models.TLSAnalysis, error) {
	analysis := &models.TLSAnalysis{}

	// Test different TLS versions and collect supported protocols
	protocols := []struct {
		name    string
		version uint16
	}{
		{"TLS 1.3", tls.VersionTLS13},
		{"TLS 1.2", tls.VersionTLS12},
		{"TLS 1.1", tls.VersionTLS11},
		{"TLS 1.0", tls.VersionTLS10},
	}

	for _, proto := range protocols {
		if sa.testProtocol(ctx, host, proto.version) {
			analysis.SupportedProtocols = append(analysis.SupportedProtocols, proto.name)
		}
	}

	// Get certificate details
	cert, err := sa.getCertificate(ctx, host)
	if err != nil {
		sa.logger.Warn("Failed to get certificate for %s: %v", host, err)
		analysis.CertificateValid = false // Mark as invalid if we can't even get it
		return analysis, fmt.Errorf("failed to retrieve certificate: %w", err)
	}

	analysis.Issuer = cert.Issuer.String()
	analysis.Subject = cert.Subject.String()
	analysis.ExpiresIn = time.Until(cert.NotAfter)

	// Validate certificate (basic check for now)
	if time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
		analysis.CertificateValid = false
		analysis.Warnings = append(analysis.Warnings, "Certificate is expired or not yet valid")
	} else {
		analysis.CertificateValid = true
	}

	// Analyze certificate strength and grade
	analysis.EncryptionGrade = sa.gradeCertificate(cert)
	analysis.HasWeakCiphers = sa.checkWeakCiphers(ctx, host)
	if analysis.HasWeakCiphers {
		analysis.Warnings = append(analysis.Warnings, "Server supports weak cipher suites")
	}


	analysis.OCSPStapling = false // Default
	analysis.HSTSEnabled = false  // Default

	return analysis, nil
}

// testProtocol attempts to establish a TLS connection using a specific protocol version.
func (sa *SSLAnalyzer) testProtocol(ctx context.Context, host string, version uint16) bool {
	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: sa.timeout,
	}, "tcp", net.JoinHostPort(host, "443"), &tls.Config{
		InsecureSkipVerify: true, // We're just testing support, not validating
		MinVersion:         version,
		MaxVersion:         version,
	})

	if err != nil {
		// sa.logger.Debug("Failed to connect with TLS version %s for %s: %v", tls.VersionName(version), host, err)
		return false
	}
	defer conn.Close()

	return true
}

// getCertificate retrieves the server's primary SSL certificate.
func (sa *SSLAnalyzer) getCertificate(ctx context.Context, host string) (*tls.Certificate, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: sa.timeout,
	}, "tcp", net.JoinHostPort(host, "443"), &tls.Config{
		InsecureSkipVerify: false, // Verify certificate to retrieve it
	})

	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates presented by %s", host)
	}

	return state.PeerCertificates[0], nil
}

// gradeCertificate provides a simple grade based on certificate properties.
func (sa *SSLAnalyzer) gradeCertificate(cert *tls.Certificate) string {
	// Simple grading based on key strength and expiration
	remaining := time.Until(cert.NotAfter)

	if remaining < 30*24*time.Hour { // Expires in less than a month
		return "F" // Expiring soon
	}

	// Key size check (example)
	keySize := 0
	switch pk := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keySize = pk.N.BitLen()
	case *ecdsa.PublicKey:
		keySize = pk.Curve.Params().BitSize
	}

	if keySize < 2048 {
		return "C" // Weak key size
	}
	if keySize >= 4096 {
		return "A+"
	}

	// More advanced checks (e.g., signature algorithm, chain validity) would be added here
	return "A"
}

// checkWeakCiphers tests if the server supports known weak cipher suites.
func (sa *SSLAnalyzer) checkWeakCiphers(ctx context.Context, host string) bool {
	// WARNING: The cipher suites below are considered insecure.
	// They are used **only** for analyzing whether a remote host still allows connections with these weak ciphers.
	// DO NOT use these ciphers for normal communications.
	weakCiphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,       // RC4 is broken
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,  // 3DES is weak
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA, // RC4 is broken
	}

	for _, cipher := range weakCiphers {
		// Attempt to connect with the weak cipher suite
		conn, err := tls.DialWithDialer(&net.Dialer{
			Timeout: sa.timeout,
		}, "tcp", net.JoinHostPort(host, "443"), &tls.Config{
			InsecureSkipVerify: true, // Not verifying, just checking if connection establishes
			CipherSuites:       []uint16{cipher},
			MinVersion:         tls.VersionTLS10, // Some weak ciphers might only work with older TLS versions
			MaxVersion:         tls.VersionTLS12,
		})

		if err == nil {
			conn.Close()
			return true // Connection successful with a weak cipher
		}
	}

	return false
}