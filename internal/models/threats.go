package models

import (
	"time"

	"net-zilla/internal/ai"
)

type ThreatAnalysis struct {
	AnalysisID        string          `json:"analysis_id"`
	URL               string          `json:"url"`
	ThreatLevel       ThreatLevel     `json:"threat_level"`
	ThreatScore       int             `json:"threat_score"`
	Warnings          []string        `json:"warnings"`
	SuspiciousFeatures []string       `json:"suspicious_features"`
	PhishingIndicators []string       `json:"phishing_indicators"`
	SafetyTips        []string        `json:"safety_tips"`
	IPInfo            *IPData         `json:"ip_info"`
	RedirectChain     []RedirectInfo  `json:"redirect_chain"`
	RedirectCount     int             `json:"redirect_count"`
	DNSRecords        []DNSRecord     `json:"dns_records"`
	SecurityHeaders   map[string]string `json:"security_headers"`
	AIResult          *ai.AIAnalysisResult `json:"ai_result"`
	AnalyzedAt        time.Time       `json:"analyzed_at"`
	AnalysisDuration  time.Duration   `json:"analysis_duration"`
}

type ThreatLevel string

const (
	ThreatLevelSafe     ThreatLevel = "🟢 SAFE"
	ThreatLevelLow      ThreatLevel = "🟡 LOW"
	ThreatLevelMedium   ThreatLevel = "🟠 MEDIUM" 
	ThreatLevelHigh     ThreatLevel = "🔴 HIGH"
	ThreatLevelCritical ThreatLevel = "💀 CRITICAL"
)

type RedirectInfo struct {
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Location   string            `json:"location"`
	Headers    map[string]string `json:"headers"`
	Cookies    []CookieInfo      `json:"cookies"`
	Duration   time.Duration     `json:"duration"`
	IPAddress  string            `json:"ip_address"`
	HopNumber  int               `json:"hop_number"`
}

type DNSRecord struct {
	Type   string   `json:"type"`
	Values []string `json:"values"`
	TTL    int      `json:"ttl"`
}
package models

import (
	"time"
	
	"net-zilla/internal/ai"
)

type ThreatAnalysis struct {
	AnalysisID        string                      `json:"analysis_id"`
	URL               string                      `json:"url"`
	ThreatLevel       ThreatLevel                 `json:"threat_level"`
	ThreatScore       int                         `json:"threat_score"`
	Warnings          []string                    `json:"warnings"`
	SuspiciousFeatures []string                   `json:"suspicious_features"`
	PhishingIndicators []string                   `json:"phishing_indicators"`
	SafetyTips        []string                    `json:"safety_tips"`
	IPInfo            *IPData                     `json:"ip_info"`
	RedirectChain     []RedirectInfo              `json:"redirect_chain"`
	RedirectCount     int                         `json:"redirect_count"`
	DNSRecords        []DNSRecord                 `json:"dns_records"`
	SecurityHeaders   map[string]string           `json:"security_headers"`
	AIResult          *ai.AIAnalysisResult        `json:"ai_result"`
	AIOrchestration   *ai.OrchestrationResult     `json:"ai_orchestration"` // NEW
	AnalyzedAt        time.Time                   `json:"analyzed_at"`
	AnalysisDuration  time.Duration               `json:"analysis_duration"`
}
// ... other model definitions
