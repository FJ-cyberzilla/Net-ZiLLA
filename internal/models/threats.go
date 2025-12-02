package models

import (
	"time"

	"net-zilla/internal/ai"
)

// ThreatAnalysis represents the comprehensive result of a security analysis.
type ThreatAnalysis struct {
	AnalysisID         string                 `json:"analysis_id"`
	URL                string                 `json:"url"`
	ThreatLevel        ThreatLevel            `json:"threat_level"`
	ThreatScore        int                    `json:"threat_score"`
	Warnings           []string               `json:"warnings"`
	SuspiciousFeatures []string               `json:"suspicious_features"`
	PhishingIndicators []string               `json:"phishing_indicators"`
	SafetyTips         []string               `json:"safety_tips"`
	SecurityHeaders    []string               `json:"security_headers"` // Changed from map[string]string for simplicity in CLI display

	RedirectChain      []RedirectDetail       `json:"redirect_chain"`
	RedirectCount      int                    `json:"redirect_count"`

	DNSInfo            *DNSAnalysis           `json:"dns_info"`
	WhoisInfo          *WhoisAnalysis         `json:"whois_info"`
	TLSInfo            *TLSAnalysis           `json:"tls_info"`
	GeoAnalysis        *GeoAnalysis           `json:"geo_analysis"`
	NetworkAnalysis    *NetworkAnalysis       `json:"network_analysis"`

	AIResult           *ai.AIAnalysisResult   `json:"ai_result"`
	AIOrchestration    *ai.OrchestrationResult `json:"ai_orchestration"`

	AnalyzedAt         time.Time              `json:"analyzed_at"`
	AnalysisDuration   time.Duration          `json:"analysis_duration"`
}

// ThreatLevel defines the severity of the detected threat.
type ThreatLevel string

const (
	ThreatLevelSafe     ThreatLevel = "🟢 SAFE"
	ThreatLevelLow      ThreatLevel = "🟡 LOW"
	ThreatLevelMedium   ThreatLevel = "🟠 MEDIUM"
	ThreatLevelHigh     ThreatLevel = "🔴 HIGH"
	ThreatLevelCritical ThreatLevel = "💀 CRITICAL"
)

// RedirectDetail captures information about a single step in a redirect chain.
type RedirectDetail struct {
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Location   string            `json:"location"`
	Headers    map[string]string `json:"headers"`
	Cookies    []CookieInfo      `json:"cookies"`
	Duration   time.Duration     `json:"duration"`
	IPAddress  string            `json:"ip_address"` // IP address of the server responding to this hop
	HopNumber  int               `json:"hop_number"`
	Warnings   []string          `json:"warnings,omitempty"` // Warnings specific to this redirect step
}

// CookieInfo details about an HTTP cookie.
type CookieInfo struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Expires  time.Time `json:"expires"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site"`
}

// DNSAnalysis results of a DNS lookup.
type DNSAnalysis struct {
	ARecords          []string `json:"a_records"`
	AAAARecords       []string `json:"aaaa_records"`
	MXRecords         []string `json:"mx_records"`
	NameServers       []string `json:"name_servers"`
	TXTRecords        []string `json:"txt_records"`
	CNAME             string   `json:"cname,omitempty"`
	PTRRecord         string   `json:"ptr_record,omitempty"`
	ReverseHostname   string   `json:"reverse_hostname,omitempty"`
	PTRValidation     string   `json:"ptr_validation,omitempty"`
	DNSSECEnabled     bool     `json:"dnssec_enabled"`
	PropagationStatus string   `json:"propagation_status,omitempty"`
	TTLSummary        string   `json:"ttl_summary,omitempty"`
	Warnings          []string `json:"warnings,omitempty"`
}

// WhoisAnalysis results of a WHOIS lookup.
type WhoisAnalysis struct {
	Domain      string    `json:"domain"`
	Registrar   string    `json:"registrar"`
	Registrant  string    `json:"registrant,omitempty"`
	CreatedDate string    `json:"created_date"` // Stored as string to avoid complex parsing
	UpdatedDate string    `json:"updated_date"` // Stored as string
	ExpiryDate  string    `json:"expiry_date"`  // Stored as string
	DomainAge   string    `json:"domain_age"`
	NameServers []string  `json:"name_servers"`
	Status      []string  `json:"status"`
	RawWhois    string    `json:"raw_whois,omitempty"`
	Warnings    []string  `json:"warnings,omitempty"`
}

// TLSAnalysis results of an SSL/TLS certificate analysis.
type TLSAnalysis struct {
	CertificateValid   bool     `json:"certificate_valid"`
	ExpiresIn          time.Duration `json:"expires_in"` // Duration until expiration
	Issuer             string   `json:"issuer"`
	Subject            string   `json:"subject"`
	SupportedProtocols []string `json:"supported_protocols"`
	CipherSuites       []string `json:"cipher_suites,omitempty"`
	EncryptionGrade    string   `json:"encryption_grade"`
	HasWeakCiphers     bool     `json:"has_weak_ciphers"`
	OCSPStapling       bool     `json:"ocsp_stapling"`
	HSTSEnabled        bool     `json:"hsts_enabled"`
	Warnings           []string `json:"warnings,omitempty"`
	CompressionEnabled string   `json:"compression_enabled,omitempty"` // From HTTP headers
	ServerType         string   `json:"server_type,omitempty"`         // From HTTP headers
}

// GeoAnalysis results of an IP geolocation lookup.
type GeoAnalysis struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	City        string  `json:"city,omitempty"`
	Region      string  `json:"region,omitempty"`
	ISP         string  `json:"isp"`
	ASN         string  `json:"asn"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	IsProxy     bool    `json:"is_proxy"`     // Indicates if IP is associated with proxy/VPN/TOR
	HostingType string  `json:"hosting_type"` // e.g., "Hosting Provider", "Residential", "Business"
	IsPublic    bool    `json:"is_public"`
	IsReserved  bool    `json:"is_reserved"`
	ThreatScore int     `json:"threat_score,omitempty"`
	Reputation  string  `json:"reputation,omitempty"`
	AbuseHistory []string `json:"abuse_history,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
}

// NetworkAnalysis results of network path analysis (e.g., traceroute).
type NetworkAnalysis struct {
	Target         string        `json:"target"`
	HopCount       int           `json:"hop_count"`
	Hops           []HopDetail   `json:"hops"`
	AverageLatency time.Duration `json:"average_latency"`
	MaxLatency     time.Duration `json:"max_latency"`
	MinLatency     time.Duration `json:"min_latency"`
	PacketLoss     float64       `json:"packet_loss"`
	GeoPath        string        `json:"geo_path,omitempty"` // E.g., "US -> EU -> AS"
	Warnings       []string      `json:"warnings,omitempty"`
}

// HopDetail for individual hops in a traceroute.
type HopDetail struct {
	Number  int           `json:"number"`
	IP      string        `json:"ip"`
	Host    string        `json:"host,omitempty"`
	Latency time.Duration `json:"latency"`
	Country string        `json:"country,omitempty"` // Geolocation for the hop
}

// IPData and DNSRecord are replaced by GeoAnalysis and DNSAnalysis.
// This ensures a consistent structure across the application.