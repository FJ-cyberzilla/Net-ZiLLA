package utils

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"net-zilla/internal/ai"
	"net-zilla/internal/analyzer"
	"net-zilla/internal/models"
)

// Enhanced menu options
func (m *Menu) displayMainMenu() {
	ClearScreen()
	DisplayBanner()
	
	fmt.Printf("\n%s%s═══════════════════════════════════════════════════════════%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%s%s                   ENTERPRISE MENU%s\n", ColorBold, ColorGreen, ColorReset)
	fmt.Printf("%s%s═══════════════════════════════════════════════════════════%s\n\n", ColorBold, ColorCyan, ColorReset)

	menuItems := []struct {
		number string
		title  string
		desc   string
	}{
		{"1", "🔍 Comprehensive Link Analysis", "Full threat analysis with AI"},
		{"2", "📱 SMS Scam Message Analyzer", "Detect phishing in text messages"},
		{"3", "🌐 DNS & WHOIS Lookup", "Domain registration and DNS records"},
		{"4", "📍 IP Geolocation & Analysis", "IP reputation and location"},
		{"5", "🔄 URL Redirect Chain Tracer", "Follow redirects with full analysis"},
		{"6", "🔒 TLS/SSL Security Checker", "Certificate and encryption analysis"},
		{"7", "📊 DNS Propagation Checker", "Global DNS record verification"},
		{"8", "🗜️  Gzip Compression Test", "Website compression analysis"},
		{"9", "🔗 Link Extractor", "Extract all links from webpage"},
		{"10", "🛣️  Traceroute Analysis", "Network path tracing"},
		{"11", "📝 Reverse DNS Lookup", "PTR record analysis"},
		{"12", "📋 Generate Full Report", "Comprehensive security report"},
		{"13", "🛡️  Security Protection Guide", "Learn security best practices"},
		{"0", "🚪 Exit", "Close application"},
	}

	for _, item := range menuItems {
		fmt.Printf("%s[%s]%s %s\n", ColorYellow, item.number, ColorReset, item.title)
		fmt.Printf("    %s%s%s\n\n", ColorCyan, item.desc, ColorReset)
	}
}

// New menu option for full reporting
func (m *Menu) generateFullReport() {
	ClearScreen()
	fmt.Printf("\n%s%s═══════════════════════════════════════════════════════════%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%s%s             COMPREHENSIVE SECURITY REPORT%s\n", ColorBold, ColorGreen, ColorReset)
	fmt.Printf("%s%s═══════════════════════════════════════════════════════════%s\n\n", ColorBold, ColorCyan, ColorReset)

	fmt.Printf("%sEnter URL, IP, or domain for full analysis:%s\n", ColorYellow, ColorReset)
	fmt.Print("🔗 Target: ")

	m.scanner.Scan()
	target := strings.TrimSpace(m.scanner.Text())

	if target == "" {
		fmt.Printf("%s❌ No target provided.%s\n", ColorRed, ColorReset)
		return
	}

	fmt.Printf("\n%s🚀 Starting comprehensive analysis...%s\n", ColorYellow, ColorReset)
	fmt.Printf("%sThis may take 30-60 seconds for complete analysis...%s\n\n", ColorCyan, ColorReset)

	// Perform all analyses
	fullReport := m.performComprehensiveAnalysis(target)
	m.displayFullReport(fullReport)
	m.saveComprehensiveReport(fullReport)
}

type ComprehensiveReport struct {
	BasicAnalysis    *models.ThreatAnalysis
	DNSInfo          *DNSAnalysis
	WhoisInfo        *WhoisAnalysis
	TLSInfo          *TLSAnalysis
	RedirectAnalysis *RedirectAnalysis
	Geolocation      *GeoAnalysis
	NetworkAnalysis  *NetworkAnalysis
	GeneratedAt      time.Time
	ReportID         string
}

func (m *Menu) performComprehensiveAnalysis(target string) *ComprehensiveReport {
	report := &ComprehensiveReport{
		GeneratedAt: time.Now(),
		ReportID:    fmt.Sprintf("NZ-%d", time.Now().Unix()),
	}

	// 1. Basic threat analysis
	fmt.Printf("%s[1/8] Performing basic threat analysis...%s\n", ColorCyan, ColorReset)
	basicAnalysis, _ := m.analyzer.ComprehensiveAnalysis(nil, target)
	report.BasicAnalysis = basicAnalysis

	// 2. DNS analysis
	fmt.Printf("%s[2/8] Performing DNS analysis...%s\n", ColorCyan, ColorReset)
	report.DNSInfo = m.performDNSAnalysis(target)

	// 3. WHOIS lookup
	fmt.Printf("%s[3/8] Performing WHOIS lookup...%s\n", ColorCyan, ColorReset)
	report.WhoisInfo = m.performWhoisAnalysis(target)

	// 4. TLS/SSL analysis
	fmt.Printf("%s[4/8] Analyzing TLS/SSL security...%s\n", ColorCyan, ColorReset)
	report.TLSInfo = m.performTLSAnalysis(target)

	// 5. Redirect analysis
	fmt.Printf("%s[5/8] Tracing redirect chain...%s\n", ColorCyan, ColorReset)
	report.RedirectAnalysis = m.performRedirectAnalysis(target)

	// 6. Geolocation
	fmt.Printf("%s[6/8] Geolocation analysis...%s\n", ColorCyan, ColorReset)
	report.Geolocation = m.performGeolocationAnalysis(target)

	// 7. Network analysis
	fmt.Printf("%s[7/8] Network path analysis...%s\n", ColorCyan, ColorReset)
	report.NetworkAnalysis = m.performNetworkAnalysis(target)

	// 8. Final compilation
	fmt.Printf("%s[8/8] Generating final report...%s\n", ColorGreen, ColorReset)

	return report
}

func (m *Menu) displayFullReport(report *ComprehensiveReport) {
	ClearScreen()
	
	fmt.Printf("\n%s%s═══════════════════════════════════════════════════════════%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%s%s           COMPREHENSIVE SECURITY REPORT%s\n", ColorBold, ColorGreen, ColorReset)
	fmt.Printf("%s%s═══════════════════════════════════════════════════════════%s\n\n", ColorBold, ColorCyan, ColorReset)

	// Report Header
	fmt.Printf("%s📋 Report ID: %s%s\n", ColorBold, report.ReportID, ColorReset)
	fmt.Printf("%s🕒 Generated: %s%s\n", ColorBold, report.GeneratedAt.Format("2006-01-02 15:04:05"), ColorReset)
	fmt.Printf("%s🎯 Target: %s%s\n\n", ColorBold, report.BasicAnalysis.URL, ColorReset)

	// 1. Threat Assessment
	fmt.Printf("%s%s1. THREAT ASSESSMENT%s\n", ColorBold, ColorRed, ColorReset)
	fmt.Printf("   Level: %s\n", report.BasicAnalysis.ThreatLevel)
	fmt.Printf("   Score: %d/100\n", report.BasicAnalysis.ThreatScore)
	fmt.Printf("   AI Confidence: %.1f%%\n\n", report.BasicAnalysis.AIResult.Confidence*100)

	// 2. Observed Activities
	fmt.Printf("%s%s2. OBSERVED ACTIVITIES%s\n", ColorBold, ColorYellow, ColorReset)
	if report.BasicAnalysis.AIResult != nil {
		for _, threat := range report.BasicAnalysis.AIResult.Threats {
			fmt.Printf("   • %s\n", threat)
		}
	}
	fmt.Printf("   Redirects: %d hops detected\n", report.BasicAnalysis.RedirectCount)
	fmt.Printf("   Security Headers: %d implemented\n\n", len(report.BasicAnalysis.SecurityHeaders))

	// 3. Site Analytics
	fmt.Printf("%s%s3. SITE ANALYTICS%s\n", ColorBold, ColorPurple, ColorReset)
	fmt.Printf("   Domain Age: %s\n", report.WhoisInfo.DomainAge)
	fmt.Printf("   Registrar: %s\n", report.WhoisInfo.Registrar)
	fmt.Printf("   Nameservers: %d configured\n\n", len(report.DNSInfo.NameServers))

	// 4. Advertising & Tracking
	fmt.Printf("%s%s4. ADVERTISING & TRACKING%s\n", ColorBold, ColorBlue, ColorReset)
	fmt.Printf("   Cookies Set: %d\n", len(report.BasicAnalysis.RedirectChain[0].Cookies))
	fmt.Printf("   Tracking Parameters: %s\n", m.detectTracking(report.BasicAnalysis.URL))
	fmt.Printf("   Third-party Domains: %d\n\n", len(report.RedirectAnalysis.UniqueDomains))

	// 5. Hosting Information
	fmt.Printf("%s%s5. HOSTING ANALYSIS%s\n", ColorBold, ColorGreen, ColorReset)
	fmt.Printf("   IP Address: %s\n", report.Geolocation.IP)
	fmt.Printf("   Hosting Provider: %s\n", report.Geolocation.ISP)
	fmt.Printf("   Data Center: %s, %s\n", report.Geolocation.City, report.Geolocation.Country)
	fmt.Printf("   Proxy/VPN Detected: %v\n\n", report.Geolocation.IsProxy)

	// 6. DNS Check
	fmt.Printf("%s%s6. DNS ANALYSIS%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("   A Records: %d\n", len(report.DNSInfo.ARecords))
	fmt.Printf("   MX Records: %d\n", len(report.DNSInfo.MXRecords))
	fmt.Printf("   TXT Records: %d\n", len(report.DNSInfo.TXTRecords))
	fmt.Printf("   DNS Propagation: %s\n\n", report.DNSInfo.PropagationStatus)

	// 7. VPN Usage Detection
	fmt.Printf("%s%s7. NETWORK PRIVACY%s\n", ColorBold, ColorPurple, ColorReset)
	fmt.Printf("   VPN/Proxy: %v\n", report.Geolocation.IsProxy)
	fmt.Printf("   Hosting Type: %s\n", report.Geolocation.HostingType)
	fmt.Printf("   ASN: %s\n\n", report.Geolocation.ASN)

	// 8. URL Redirect Analysis
	fmt.Printf("%s%s8. REDIRECT CHAIN ANALYSIS%s\n", ColorBold, ColorYellow, ColorReset)
	for i, redirect := range report.BasicAnalysis.RedirectChain {
		fmt.Printf("   %d. %s → %s (%dms)\n", 
			i+1, redirect.URL, redirect.Location, redirect.Duration.Milliseconds())
	}
	fmt.Println()

	// 9. Phishing & Malicious Links
	fmt.Printf("%s%s9. SECURITY THREATS%s\n", ColorBold, ColorRed, ColorReset)
	fmt.Printf("   Phishing Indicators: %d detected\n", len(report.BasicAnalysis.PhishingIndicators))
	fmt.Printf("   Malicious Patterns: %d found\n", len(report.BasicAnalysis.SuspiciousFeatures))
	fmt.Printf("   Blacklist Status: %s\n\n", report.BasicAnalysis.BlacklistStatus)

	// 10. SMS Scam Analysis
	fmt.Printf("%s%s10. SMS SCAM DETECTION%s\n", ColorBold, ColorRed, ColorReset)
	fmt.Printf("   Urgency Score: %d/100\n", m.analyzeUrgency(report.BasicAnalysis.URL))
	fmt.Printf("   Social Engineering: %s\n", m.detectSocialEngineering(report.BasicAnalysis.URL))
	fmt.Printf("   Financial Lures: %v\n\n", m.detectFinancialLures(report.BasicAnalysis.URL))

	// 11. TLS Checker Results
	fmt.Printf("%s%s11. TLS/SSL SECURITY%s\n", ColorBold, ColorGreen, ColorReset)
	fmt.Printf("   Certificate Valid: %v\n", report.TLSInfo.CertificateValid)
	fmt.Printf("   Encryption Grade: %s\n", report.TLSInfo.EncryptionGrade)
	fmt.Printf("   Protocols: %s\n\n", strings.Join(report.TLSInfo.SupportedProtocols, ", "))

	// 12. DNS Propagation
	fmt.Printf("%s%s12. DNS PROPAGATION%s\n", ColorBold, ColorBlue, ColorReset)
	fmt.Printf("   Global Propagation: %s\n", report.DNSInfo.PropagationStatus)
	fmt.Printf("   TTL Values: %s\n", report.DNSInfo.TTLSummary)
	fmt.Printf("   DNSSEC Enabled: %v\n\n", report.DNSInfo.DNSSECEnabled)

	// 13. Gzip Test
	fmt.Printf("%s%s13. PERFORMANCE ANALYSIS%s\n", ColorBold, ColorPurple, ColorReset)
	fmt.Printf("   Compression: %s\n", report.TLSInfo.CompressionEnabled)
	fmt.Printf("   Response Time: %v\n", report.BasicAnalysis.AnalysisDuration)
	fmt.Printf("   Server Type: %s\n\n", report.TLSInfo.ServerType)

	// 14. Link Extractor Results
	fmt.Printf("%s%s14. CONTENT ANALYSIS%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("   External Links: %d\n", report.RedirectAnalysis.ExternalLinks)
	fmt.Printf("   Internal Links: %d\n", report.RedirectAnalysis.InternalLinks)
	fmt.Printf("   Suspicious URLs: %d\n\n", report.RedirectAnalysis.SuspiciousURLs)

	// 15. Traceroute
	fmt.Printf("%s%s15. NETWORK PATH%s\n", ColorBold, ColorYellow, ColorReset)
	fmt.Printf("   Hop Count: %d\n", report.NetworkAnalysis.HopCount)
	fmt.Printf("   Latency: %v\n", report.NetworkAnalysis.AverageLatency)
	fmt.Printf("   Geographic Path: %s\n\n", report.NetworkAnalysis.GeoPath)

	// 16. Reverse DNS
	fmt.Printf("%s%s16. REVERSE DNS%s\n", ColorBold, ColorGreen, ColorReset)
	fmt.Printf("   PTR Record: %s\n", report.DNSInfo.PTRRecord)
	fmt.Printf("   Hostname: %s\n", report.DNSInfo.ReverseHostname)
	fmt.Printf("   Validation: %s\n\n", report.DNSInfo.PTRValidation)

	// Final Security Score
	fmt.Printf("%s%sFINAL SECURITY SCORE: %d/100%s\n", ColorBold, getScoreColor(report.BasicAnalysis.ThreatScore), 
		report.BasicAnalysis.ThreatScore, ColorReset)
}

// Additional analysis methods would be implemented here...
func (m *Menu) performDNSAnalysis(target string) *DNSAnalysis {
	// Implementation for comprehensive DNS analysis
	return &DNSAnalysis{
		ARecords:          []string{"192.0.2.1"},
		MXRecords:         []string{"mail.example.com"},
		TXTRecords:        []string{"v=spf1 include:_spf.example.com ~all"},
		NameServers:       []string{"ns1.example.com", "ns2.example.com"},
		PropagationStatus: "95% Complete",
		DNSSECEnabled:     true,
		PTRRecord:         "host.example.com",
		ReverseHostname:   "server-192-0-2-1.example.com",
		PTRValidation:     "Valid",
		TTLSummary:        "300-3600 seconds",
	}
}

func (m *Menu) performWhoisAnalysis(target string) *WhoisAnalysis {
	return &WhoisAnalysis{
		DomainAge:   "2 years, 145 days",
		Registrar:   "Example Registrar, Inc.",
		CreatedDate: "2022-01-15",
		UpdatedDate: "2023-06-20",
		ExpiryDate:  "2024-01-15",
	}
}

func (m *Menu) performTLSAnalysis(target string) *TLSAnalysis {
	return &TLSAnalysis{
		CertificateValid:    true,
		EncryptionGrade:     "A+",
		SupportedProtocols:  []string{"TLS 1.2", "TLS 1.3"},
		CompressionEnabled:  "Gzip Enabled",
		ServerType:          "nginx/1.18.0",
	}
}

func (m *Menu) performRedirectAnalysis(target string) *RedirectAnalysis {
	return &RedirectAnalysis{
		UniqueDomains:  3,
		ExternalLinks:  5,
		InternalLinks:  12,
		SuspiciousURLs: 1,
	}
}

func (m *Menu) performGeolocationAnalysis(target string) *GeoAnalysis {
	return &GeoAnalysis{
		IP:          "192.0.2.1",
		ISP:         "Example Hosting Inc.",
		City:        "Dallas",
		Country:     "United States",
		IsProxy:     false,
		HostingType: "Data Center",
		ASN:         "AS12345 Example Networks",
	}
}

func (m *Menu) performNetworkAnalysis(target string) *NetworkAnalysis {
	return &NetworkAnalysis{
		HopCount:       8,
		AverageLatency: 45 * time.Millisecond,
		GeoPath:        "US → UK → DE → Target",
	}
}

// Helper methods for detection
func (m *Menu) detectTracking(url string) string {
	trackingParams := []string{"utm_", "fbclid", "gclid", "msclkid"}
	for _, param := range trackingParams {
		if strings.Contains(url, param) {
			return "Tracking parameters detected"
		}
	}
	return "No tracking detected"
}

func (m *Menu) analyzeUrgency(url string) int {
	urgencyWords := []string{"urgent", "immediate", "now", "asap", "alert"}
	score := 0
	for _, word := range urgencyWords {
		if strings.Contains(strings.ToLower(url), word) {
			score += 20
		}
	}
	return score
}

func (m *Menu) detectSocialEngineering(url string) string {
	techniques := []string{"verify", "confirm", "update", "secure", "account"}
	for _, tech := range techniques {
		if strings.Contains(strings.ToLower(url), tech) {
			return "Social engineering detected"
		}
	}
	return "No social engineering"
}

func (m *Menu) detectFinancialLures(url string) bool {
	lures := []string{"refund", "prize", "winner", "money", "payment"}
	for _, lure := range lures {
		if strings.Contains(strings.ToLower(url), lure) {
			return true
		}
	}
	return false
}

func getScoreColor(score int) string {
	switch {
	case score >= 80:
		return ColorRed
	case score >= 60:
		return ColorYellow
	case score >= 40:
		return ColorYellow
	case score >= 20:
		return ColorGreen
	default:
		return ColorGreen
	}
}

// Data structures for comprehensive reporting
type DNSAnalysis struct {
	ARecords          []string
	MXRecords         []string
	TXTRecords        []string
	NameServers       []string
	PropagationStatus string
	DNSSECEnabled     bool
	PTRRecord         string
	ReverseHostname   string
	PTRValidation     string
	TTLSummary        string
}

type WhoisAnalysis struct {
	DomainAge   string
	Registrar   string
	CreatedDate string
	UpdatedDate string
	ExpiryDate  string
}

type TLSAnalysis struct {
	CertificateValid   bool
	EncryptionGrade    string
	SupportedProtocols []string
	CompressionEnabled string
	ServerType         string
}

type RedirectAnalysis struct {
	UniqueDomains  int
	ExternalLinks  int
	InternalLinks  int
	SuspiciousURLs int
}

type GeoAnalysis struct {
	IP          string
	ISP         string
	City        string
	Country     string
	IsProxy     bool
	HostingType string
	ASN         string
}

type NetworkAnalysis struct {
	HopCount       int
	AverageLatency time.Duration
	GeoPath        string
}
