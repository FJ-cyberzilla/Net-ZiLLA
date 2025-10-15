package analyzer

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"net-zilla/internal/models"
	"net-zilla/internal/network"
)

type IPAnalyzer struct {
	dnsClient   *network.DNSClient
	geoLookup   *GeoIPService
	threatIntel *ThreatIntelligence
}

type IPAnalysis struct {
	IP            string
	IsPublic      bool
	IsReserved    bool
	GeoLocation   *GeoLocation
	ISP           string
	ASN           string
	ThreatScore   int
	Reputation    string
	AbuseHistory  []string
	HostingType   string
	VPNDetection  bool
	ProxyDetection bool
}

func NewIPAnalyzer() *IPAnalyzer {
	return &IPAnalyzer{
		dnsClient:   network.NewDNSClient(),
		geoLookup:   NewGeoIPService(),
		threatIntel: NewThreatIntelligence(),
	}
}

func (a *IPAnalyzer) AnalyzeIP(ip string) (*IPAnalysis, error) {
	analysis := &IPAnalysis{
		IP: ip,
	}

	// Basic IP validation
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// IP type analysis
	analysis.IsPublic = a.isPublicIP(parsedIP)
	analysis.IsReserved = a.isReservedIP(parsedIP)

	// Geolocation
	if geo, err := a.geoLookup.Lookup(ip); err == nil {
		analysis.GeoLocation = geo
		analysis.ISP = geo.ISP
		analysis.ASN = geo.ASN
	}

	// Threat intelligence
	threatData, err := a.threatIntel.CheckIP(ip)
	if err == nil {
		analysis.ThreatScore = threatData.Score
		analysis.Reputation = threatData.Reputation
		analysis.AbuseHistory = threatData.AbuseReports
	}

	// Hosting and proxy detection
	analysis.HostingType = a.detectHostingType(analysis)
	analysis.VPNDetection = a.detectVPN(analysis)
	analysis.ProxyDetection = a.detectProxy(analysis)

	return analysis, nil
}

func (a *IPAnalyzer) isPublicIP(ip net.IP) bool {
	// Check if IP is in private ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

func (a *IPAnalyzer) isReservedIP(ip net.IP) bool {
	reservedRanges := []string{
		"0.0.0.0/8",
		"100.64.0.0/10",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"240.0.0.0/4",
	}

	for _, cidr := range reservedRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *IPAnalyzer) detectHostingType(analysis *IPAnalysis) string {
	// Analyze hosting provider patterns
	hostingKeywords := []string{
		"cloud", "host", "server", "data center", "dc", 
		"amazon", "google", "microsoft", "digitalocean", "linode",
	}

	ispLower := strings.ToLower(analysis.ISP)
	for _, keyword := range hostingKeywords {
		if strings.Contains(ispLower, keyword) {
			return "Hosting Provider"
		}
	}

	// Check for residential IP patterns
	residentialKeywords := []string{
		"comcast", "verizon", "att", "xfinity", "spectrum",
		"road runner", "cox", "centurylink", "frontier",
	}

	for _, keyword := range residentialKeywords {
		if strings.Contains(ispLower, keyword) {
			return "Residential"
		}
	}

	return "Business"
}

func (a *IPAnalyzer) detectVPN(analysis *IPAnalysis) bool {
	// Check for known VPN providers
	vpnProviders := []string{
		"vpn", "expressvpn", "nordvpn", "pia", "private internet access",
		"protonvpn", "surfshark", "cyberghost", "hotspot shield",
	}

	ispLower := strings.ToLower(analysis.ISP)
	for _, provider := range vpnProviders {
		if strings.Contains(ispLower, provider) {
			return true
		}
	}

	// Check for data center IPs (common with VPNs)
	if analysis.HostingType == "Hosting Provider" {
		return true
	}

	return false
}

func (a *IPAnalyzer) detectProxy(analysis *IPAnalysis) bool {
	// Check for known proxy services
	proxyKeywords := []string{
		"proxy", "squid", "haproxy", "nginx", "apache",
	}

	// Reverse DNS analysis
	hostname, err := a.dnsClient.ReverseDNSLookup(analysis.IP)
	if err == nil {
		hostnameLower := strings.ToLower(hostname)
		for _, keyword := range proxyKeywords {
			if strings.Contains(hostnameLower, keyword) {
				return true
			}
		}
	}

	return false
}

func (a *IPAnalyzer) AnalyzeIPRange(ip string) ([]string, error) {
	// Analyze nearby IPs in the same subnet
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP")
	}

	// Get /24 subnet
	mask := net.CIDRMask(24, 32)
	network := parsedIP.Mask(mask)

	var nearbyIPs []string
	for i := 1; i <= 10; i++ {
		newIP := make(net.IP, len(network))
		copy(newIP, network)
		newIP[3] += byte(i)
		nearbyIPs = append(nearbyIPs, newIP.String())
	}

	return nearbyIPs, nil
}
