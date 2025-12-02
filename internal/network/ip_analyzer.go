package network

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"net-zilla/internal/models"
	"net-zilla/internal/utils"
)

// IPAnalyzer performs IP address analysis, including geolocation and threat intelligence.
type IPAnalyzer struct {
	logger         *utils.Logger
	dnsClient      *DNSClient
	geoIPService   *GeoIPService   // Internal helper for GeoIP lookup
	threatIntelAPI *ThreatIntelAPI // Internal helper for Threat Intelligence lookup
}

// NewIPAnalyzer creates and initializes a new IPAnalyzer.
func NewIPAnalyzer(logger *utils.Logger) *IPAnalyzer {
	return &IPAnalyzer{
		logger:         logger,
		dnsClient:      NewDNSClient(logger), // Initialize DNSClient with logger
		geoIPService:   NewGeoIPService(logger),
		threatIntelAPI: NewThreatIntelAPI(logger),
	}
}

// GetGeolocation performs IP geolocation and other basic IP analysis.
// This method is called PerformIPGeolocation in ThreatAnalyzer.
func (ipa *IPAnalyzer) GetGeolocation(ctx context.Context, ip string) (*models.GeoAnalysis, error) {
	analysis := &models.GeoAnalysis{
		IP: ip,
	}

	// Basic IP validation
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Geolocation
	geo, err := ipa.geoIPService.Lookup(ctx, ip)
	if err != nil {
		ipa.logger.Warn("Geolocation lookup failed for %s: %v", ip, err)
		// Continue with analysis even if geolocation fails
	} else {
		analysis.City = geo.City
		analysis.Country = geo.Country
		analysis.ISP = geo.ISP
		analysis.ASN = geo.ASN
		analysis.Latitude = geo.Latitude
		analysis.Longitude = geo.Longitude
	}

	// Perform additional IP analysis (public/reserved, hosting type, VPN/Proxy detection)
	analysis.IsPublic = isPublicIP(parsedIP)
	analysis.IsReserved = isReservedIP(parsedIP)
	analysis.HostingType = ipa.detectHostingType(analysis)
	analysis.IsProxy = ipa.detectVPNOrProxy(ctx, analysis) // Consolidate VPN/Proxy detection

	// Threat Intelligence (optional, can be done in ComprehensiveAnalysis if preferred)
	threatData, err := ipa.threatIntelAPI.CheckIP(ctx, ip)
	if err != nil {
		ipa.logger.Warn("Threat intelligence check failed for %s: %v", ip, err)
	} else {
		analysis.ThreatScore = threatData.Score
		analysis.Reputation = threatData.Reputation
		analysis.AbuseHistory = threatData.AbuseReports
	}

	return analysis, nil
}

// isPublicIP checks if an IP address is publicly routable.
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		// Check private IPv4 ranges
		// 10.0.0.0/8
		// 172.16.0.0/12
		// 192.168.0.0/16
		// 100.64.0.0/10 (CGN)
		if ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168) ||
			(ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127) {
			return false
		}
	}
	// TODO: Add IPv6 private range checks if necessary
	return true
}

// isReservedIP checks if an IP address falls within reserved ranges.
func isReservedIP(ip net.IP) bool {
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsLoopback() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// Example: 0.0.0.0/8, 192.0.0.0/24, 192.0.2.0/24, 203.0.113.0/24, 240.0.0.0/4
		// More comprehensive list would be needed for full accuracy
		if ip4[0] == 0 ||
			(ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0) ||
			(ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2) ||
			(ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113) ||
			(ip4[0] >= 240 && ip4[0] <= 255) {
			return true
		}
	}
	return false
}

// detectHostingType infers the type of hosting based on ISP and ASN.
func (ipa *IPAnalyzer) detectHostingType(analysis *models.GeoAnalysis) string {
	ispLower := strings.ToLower(analysis.ISP)
	asnLower := strings.ToLower(analysis.ASN)

	// Keywords for hosting providers/data centers
	hostingKeywords := []string{
		"cloud", "host", "server", "data center", "dc",
		"amazon", "google", "microsoft", "digitalocean", "linode", "akamai",
	}
	for _, keyword := range hostingKeywords {
		if strings.Contains(ispLower, keyword) || strings.Contains(asnLower, keyword) {
			return "Hosting Provider / Data Center"
		}
	}

	// Keywords for residential ISPs
	residentialKeywords := []string{
		"comcast", "verizon", "att", "xfinity", "spectrum",
		"road runner", "cox", "centurylink", "frontier", "telekom", "vodafone",
	}
	for _, keyword := range residentialKeywords {
		if strings.Contains(ispLower, keyword) {
			return "Residential"
		}
	}

	// Generic business/enterprise keywords
	businessKeywords := []string{
		"inc.", "corp.", "llc", "ltd.", "university", "government",
	}
	for _, keyword := range businessKeywords {
		if strings.Contains(ispLower, keyword) || strings.Contains(asnLower, keyword) {
			return "Business / Enterprise"
		}
	}

	return "Unknown"
}

// detectVPNOrProxy detects if the IP is likely associated with a VPN or proxy service.
func (ipa *IPAnalyzer) detectVPNOrProxy(ctx context.Context, analysis *models.GeoAnalysis) bool {
	// Heuristic 1: Hosting Provider / Data Center IPs are often used by VPNs/Proxies
	if analysis.HostingType == "Hosting Provider / Data Center" {
		return true
	}

	// Heuristic 2: Check against known VPN/Proxy service names in ISP/ASN
	ispLower := strings.ToLower(analysis.ISP)
	asnLower := strings.ToLower(analysis.ASN)
	vpnProxyKeywords := []string{
		"vpn", "proxy", "tor", "expressvpn", "nordvpn", "pia",
		"private internet access", "protonvpn", "surfshark", "cyberghost",
		"hide.me", "windscribe", "shaddowsocks", "datacenter",
	}
	for _, keyword := range vpnProxyKeywords {
		if strings.Contains(ispLower, keyword) || strings.Contains(asnLower, keyword) {
			return true
		}
	}

	// Heuristic 3: Reverse DNS lookup patterns (less reliable, but can contribute)
	if len(analysis.IP) > 0 {
		hostname, err := ipa.dnsClient.ReverseDNSLookup(ctx, analysis.IP)
		if err == nil {
			hostnameLower := strings.ToLower(hostname)
			proxyPatterns := []string{
				"proxy", "vpn", "cloud", "host", "tunnel", "anon",
			}
			for _, pattern := range proxyPatterns {
				if strings.Contains(hostnameLower, pattern) {
					ipa.logger.Debug("Reverse DNS for %s (%s) matched VPN/Proxy pattern: %s", analysis.IP, hostname, pattern)
					return true
				}
			}
		} else {
			ipa.logger.Debug("Reverse DNS lookup failed for %s: %v", analysis.IP, err)
		}
	}

	return false
}

// GeoIPService is an internal helper for performing geographical IP lookups.
type GeoIPService struct {
	logger *utils.Logger
	// Potentially add API keys or client for an external GeoIP service like MaxMind, IPinfo.io
}

// NewGeoIPService creates a new GeoIPService.
func NewGeoIPService(logger *utils.Logger) *GeoIPService {
	return &GeoIPService{logger: logger}
}

// Lookup performs a geolocation lookup for an IP address.
func (gs *GeoIPService) Lookup(ctx context.Context, ip string) (*models.GeoAnalysis, error) {

	// In a real scenario, this would involve calling an external GeoIP API.
	// For now, return dummy data.
	gs.logger.Debug("Performing dummy GeoIP lookup for %s", ip)

	// Simulate some delay
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(50 * time.Millisecond):
	}

	if ip == "8.8.8.8" {
		return &models.GeoAnalysis{
			IP:          ip,
			Country:     "US",
			City:        "Mountain View",
			ISP:         "Google LLC",
			ASN:         "AS15169 Google LLC",
			Latitude:    37.40599,
			Longitude:   -122.07851,
			HostingType: "Hosting Provider / Data Center",
			IsProxy:     false,
			IsPublic:    true,
			IsReserved:  false,
		}, nil
	}
	// Generic dummy response for other IPs
	return &models.GeoAnalysis{
		IP:          ip,
		Country:     "Unknown",
		City:        "Unknown",
		ISP:         "Unknown",
		ASN:         "Unknown",
		Latitude:    0.0,
		Longitude:   0.0,
		HostingType: "Unknown",
		IsProxy:     false,
		IsPublic:    true,
		IsReserved:  false,
	}, nil
}

// ThreatIntelAPI is an internal helper for performing threat intelligence lookups.
type ThreatIntelAPI struct {
	logger *utils.Logger
	// Potentially add API keys or client for an external Threat Intelligence service
}

// NewThreatIntelAPI creates a new ThreatIntelAPI.
func NewThreatIntelAPI(logger *utils.Logger) *ThreatIntelAPI {
	return &ThreatIntelAPI{logger: logger}
}

// CheckIP performs a threat intelligence lookup for an IP address.
func (ti *ThreatIntelAPI) CheckIP(ctx context.Context, ip string) (*ThreatIntelData, error) {

	// For now, return dummy data.
	ti.logger.Debug("Performing dummy Threat Intelligence lookup for %s", ip)

	// Simulate some delay
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(50 * time.Millisecond):
	}

	if ip == "1.1.1.1" { // Example of a known "bad" IP in dummy data
		return &ThreatIntelData{
			Score:        75,
			Reputation:   "Bad (known malicious)",
			AbuseReports: []string{"Port scanning", "DDoS source"},
		}, nil
	}
	return &ThreatIntelData{
		Score:        0,
		Reputation:   "Clean",
		AbuseReports: []string{},
	}, nil
}

// ThreatIntelData is an internal struct to hold threat intelligence results.
type ThreatIntelData struct {
	Score        int
	Reputation   string
	AbuseReports []string
}
