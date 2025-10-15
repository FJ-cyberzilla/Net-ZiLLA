package analyzer

import (
	"net-zilla/internal/models"
	"time"
)

type CorrelationAnalyzer struct {
	thresholds CorrelationThresholds
}

type CorrelationThresholds struct {
	TimeWindow       time.Duration
	IPSimilarity     float64
	DomainSimilarity float64
	PatternThreshold int
}

type CorrelationAnalysis struct {
	RelatedAnalyses  []string
	CommonIPs        []string
	CommonDomains    []string
	CommonPatterns   []string
	ClusterScore     int
	ThreatCluster    bool
	Recommendations  []string
}

func NewCorrelationAnalyzer() *CorrelationAnalyzer {
	return &CorrelationAnalyzer{
		thresholds: CorrelationThresholds{
			TimeWindow:       24 * time.Hour,
			IPSimilarity:     0.8,
			DomainSimilarity: 0.7,
			PatternThreshold: 3,
		},
	}
}

func (c *CorrelationAnalyzer) AnalyzeCorrelations(analyses []*models.ThreatAnalysis) *CorrelationAnalysis {
	correlation := &CorrelationAnalysis{}

	if len(analyses) < 2 {
		return correlation
	}

	// Find common IPs
	correlation.CommonIPs = c.findCommonIPs(analyses)

	// Find common domains
	correlation.CommonDomains = c.findCommonDomains(analyses)

	// Find common patterns
	correlation.CommonPatterns = c.findCommonPatterns(analyses)

	// Calculate cluster score
	correlation.ClusterScore = c.calculateClusterScore(correlation)

	// Determine if this is a threat cluster
	correlation.ThreatCluster = c.isThreatCluster(correlation)

	// Generate recommendations
	correlation.Recommendations = c.generateRecommendations(correlation)

	return correlation
}

func (c *CorrelationAnalyzer) findCommonIPs(analyses []*models.ThreatAnalysis) []string {
	ipCount := make(map[string]int)
	
	for _, analysis := range analyses {
		if analysis.IPInfo != nil {
			ipCount[analysis.IPInfo.IP]++
		}
		
		// Check redirect chain IPs
		for _, redirect := range analysis.RedirectChain {
			if redirect.IPAddress != "" {
				ipCount[redirect.IPAddress]++
			}
		}
	}

	var commonIPs []string
	for ip, count := range ipCount {
		if count > 1 {
			commonIPs = append(commonIPs, ip)
		}
	}

	return commonIPs
}

func (c *CorrelationAnalyzer) findCommonDomains(analyses []*models.ThreatAnalysis) []string {
	domainCount := make(map[string]int)
	
	for _, analysis := range analyses {
		domain := extractDomain(analysis.URL)
		if domain != "" {
			domainCount[domain]++
		}
		
		// Check redirect domains
		for _, redirect := range analysis.RedirectChain {
			redirectDomain := extractDomain(redirect.URL)
			if redirectDomain != "" {
				domainCount[redirectDomain]++
			}
		}
	}

	var commonDomains []string
	for domain, count := range domainCount {
		if count > 1 {
			commonDomains = append(commonDomains, domain)
		}
	}

	return commonDomains
}

func (c *CorrelationAnalyzer) findCommonPatterns(analyses []*models.ThreatAnalysis) []string {
	patternCount := make(map[string]int)
	
	for _, analysis := range analyses {
		// Count phishing indicators
		for _, indicator := range analysis.PhishingIndicators {
			patternCount[indicator]++
		}
		
		// Count suspicious features
		for _, feature := range analysis.SuspiciousFeatures {
			patternCount[feature]++
		}
		
		// Count AI-detected threats
		if analysis.AIResult != nil {
			for _, threat := range analysis.AIResult.Threats {
				patternCount[threat]++
			}
		}
	}

	var commonPatterns []string
	for pattern, count := range patternCount {
		if count >= c.thresholds.PatternThreshold {
			commonPatterns = append(commonPatterns, pattern)
		}
	}

	return commonPatterns
}

func (c *CorrelationAnalyzer) calculateClusterScore(correlation *CorrelationAnalysis) int {
	score := 0

	// Score based on common IPs
	score += len(correlation.CommonIPs) * 10

	// Score based on common domains
	score += len(correlation.CommonDomains) * 8

	// Score based on common patterns
	score += len(correlation.CommonPatterns) * 5

	return score
}

func (c *CorrelationAnalyzer) isThreatCluster(correlation *CorrelationAnalysis) bool {
	if correlation.ClusterScore < 20 {
		return false
	}

	// High number of common IPs
	if len(correlation.CommonIPs) >= 2 {
		return true
	}

	// High number of common domains
	if len(correlation.CommonDomains) >= 3 {
		return true
	}

	// Multiple strong patterns
	if len(correlation.CommonPatterns) >= 3 {
		return true
	}

	return false
}

func (c *CorrelationAnalyzer) generateRecommendations(correlation *CorrelationAnalysis) []string {
	var recommendations []string

	if correlation.ThreatCluster {
		recommendations = append(recommendations,
			"🚨 Threat cluster detected - coordinated attack likely",
			"Investigate common IPs and domains for blocklisting",
			"Report coordinated activity to relevant authorities",
		)
	}

	if len(correlation.CommonIPs) > 0 {
		recommendations = append(recommendations,
			"Multiple analyses share common IP addresses",
			"Consider IP-based blocking for repeated offenders",
		)
	}

	if len(correlation.CommonDomains) > 0 {
		recommendations = append(recommendations,
			"Multiple analyses share common domain patterns",
			"Investigate domain registration patterns",
		)
	}

	if len(correlation.CommonPatterns) > 0 {
		recommendations = append(recommendations,
			"Common threat patterns detected across analyses",
			"Update detection rules based on common patterns",
		)
	}

	return recommendations
}
