package analyzer

import (
	"crypto/x509"
	"fmt"
	"time"

	"net-zilla/internal/models"
	"net-zilla/internal/network"
)

type SSLAnalyzer struct {
	sslClient *network.SSLClient
}

type SSLReport struct {
	Domain           string
	Certificate      *x509.Certificate
	Valid            bool
	ExpiresIn        time.Duration
	Issuer           string
	Subject          string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	KeySize          int
	Protocols        []string
	CipherSuites     []string
	OCSPStapling     bool
	HSTSEnabled      bool
	Grade            string
	Vulnerabilities  []string
}

func NewSSLAnalyzer() *SSLAnalyzer {
	return &SSLAnalyzer{
		sslClient: network.NewSSLClient(),
	}
}

func (a *SSLAnalyzer) AnalyzeSSL(domain string) (*SSLReport, error) {
	report := &SSLReport{
		Domain: domain,
	}

	// Basic SSL analysis
	sslAnalysis, err := a.sslClient.AnalyzeTLS(domain)
	if err != nil {
		return report, fmt.Errorf("SSL analysis failed: %w", err)
	}

	// Get certificate details
	cert, err := a.sslClient.GetCertificate(domain)
	if err != nil {
		return report, fmt.Errorf("certificate retrieval failed: %w", err)
	}

	report.Certificate = cert
	report.Valid = a.validateCertificate(cert)
	report.ExpiresIn = time.Until(cert.NotAfter)
	report.Issuer = cert.Issuer.String()
	report.Subject = cert.Subject.String()
	report.SignatureAlgorithm = cert.SignatureAlgorithm.String()
	report.PublicKeyAlgorithm = cert.PublicKeyAlgorithm.String()
	report.KeySize = a.getKeySize(cert)
	report.Protocols = sslAnalysis.SupportedProtocols
	report.OCSPStapling = a.checkOCSPStapling(domain)
	report.HSTSEnabled = a.checkHSTS(domain)
	report.Grade = a.calculateGrade(report)
	report.Vulnerabilities = a.checkVulnerabilities(report)

	return report, nil
}

func (a *SSLAnalyzer) validateCertificate(cert *x509.Certificate) bool {
	now := time.Now()
	return now.After(cert.NotBefore) && now.Before(cert.NotAfter)
}

func (a *SSLAnalyzer) getKeySize(cert *x509.Certificate) int {
	switch key := cert.PublicKey.(type) {
	case *x509.RSA:
		return key.N.BitLen()
	case *x509.ECDSA:
		return key.Curve.Params().BitSize
	default:
		return 0
	}
}

func (a *SSLAnalyzer) checkOCSPStapling(domain string) bool {
	// Simplified OCSP stapling check
	// In production, would perform actual OCSP request
	return false // TODO: Implement actual SSL validation logic
}

func (a *SSLAnalyzer) checkHSTS(domain string) bool {
	// Check for HSTS header
	headers, err := a.sslClient.CheckSecurityHeaders(domain)
	if err != nil {
		return false
	}

	_, exists := headers["Strict-Transport-Security"]
	return exists
}

func (a *SSLAnalyzer) calculateGrade(report *SSLReport) string {
	score := 100

	// Deduct for weaknesses
	if report.KeySize < 2048 {
		score -= 20
	}

	if !contains(report.Protocols, "TLS 1.2") {
		score -= 30
	}

	if !contains(report.Protocols, "TLS 1.3") {
		score -= 10
	}

	if report.ExpiresIn < 30*24*time.Hour {
		score -= 15
	}

	if !report.OCSPStapling {
		score -= 10
	}

	if !report.HSTSEnabled {
		score -= 15
	}

	// Convert to letter grade
	switch {
	case score >= 90:
		return "A+"
	case score >= 80:
		return "A"
	case score >= 70:
		return "B"
	case score >= 60:
		return "C"
	case score >= 50:
		return "D"
	default:
		return "F"
	}
}

func (a *SSLAnalyzer) checkVulnerabilities(report *SSLReport) []string {
	var vulnerabilities []string

	// Check for weak protocols
	if contains(report.Protocols, "TLS 1.0") {
		vulnerabilities = append(vulnerabilities, "TLS 1.0 is deprecated and vulnerable")
	}

	if contains(report.Protocols, "TLS 1.1") {
		vulnerabilities = append(vulnerabilities, "TLS 1.1 has known vulnerabilities")
	}

	// Check certificate expiration
	if report.ExpiresIn < 7*24*time.Hour {
		vulnerabilities = append(vulnerabilities, "Certificate expires soon")
	}

	// Check key size
	if report.KeySize < 2048 {
		vulnerabilities = append(vulnerabilities, "Weak RSA key size")
	}

	return vulnerabilities
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
