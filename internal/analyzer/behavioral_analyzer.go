package analyzer

import (
	"time"

	"net-zilla/internal/models"
)

type BehavioralAnalyzer struct {
	thresholds BehavioralThresholds
}

type BehavioralThresholds struct {
	MaxRedirects        int
	MaxLoadTime         time.Duration
	MaxExternalDomains  int
	SuspiciousPatterns  []string
}

type BehavioralAnalysis struct {
	RedirectComplexity  int
	LoadTimeAnomaly     bool
	DomainDiversity     int
	GeographicSpread    int
	BehaviorScore       int
	Anomalies          []string
	Recommendations    []string
}

func NewBehavioralAnalyzer() *BehavioralAnalyzer {
	return &BehavioralAnalyzer{
		thresholds: BehavioralThresholds{
			MaxRedirects:       5,
			MaxLoadTime:        10 * time.Second,
			MaxExternalDomains: 10,
			SuspiciousPatterns: []string{
				"immediate", "urgent", "verify", "confirm", "limited",
			},
		},
	}
}

func (a *BehavioralAnalyzer) AnalyzeBehavior(analysis *models.ThreatAnalysis) *BehavioralAnalysis {
	behavioral := &BehavioralAnalysis{}

	// Analyze redirect complexity
	behavioral.RedirectComplexity = a.analyzeRedirectComplexity(analysis)

	// Check load time anomalies
	behavioral.LoadTimeAnomaly = a.analyzeLoadTime(analysis)

	// Analyze domain diversity
	behavioral.DomainDiversity = a.analyzeDomainDiversity(analysis)

	// Calculate overall behavior score
	behavioral.BehaviorScore = a.calculateBehaviorScore(behavioral)

	// Generate anomalies and recommendations
	behavioral.Anomalies = a.detectAnomalies(behavioral)
	behavioral.Recommendations = a.generateRecommendations(behavioral)

	return behavioral
}

func (a *BehavioralAnalyzer) analyzeRedirectComplexity(analysis *models.ThreatAnalysis) int {
	complexity := 0

	// Base complexity on number of redirects
	complexity += len(analysis.RedirectChain) * 10

	// Increase complexity for domain changes
	uniqueDomains := make(map[string]bool)
	for _, redirect := range analysis.RedirectChain {
		domain := a.extractDomain(redirect.URL)
		if domain != "" {
			uniqueDomains[domain] = true
		}
	}
	complexity += len(uniqueDomains) * 15

	// Increase for long redirect chains
	if len(analysis.RedirectChain) > a.thresholds.MaxRedirects {
		complexity += 25
	}

	return complexity
}

func (a *BehavioralAnalyzer) analyzeLoadTime(analysis *models.ThreatAnalysis) bool {
	return analysis.AnalysisDuration > a.thresholds.MaxLoadTime
}

func (a *BehavioralAnalyzer) analyzeDomainDiversity(analysis *models.ThreatAnalysis) int {
	domains := make(map[string]bool)

	// Count unique domains in redirect chain
	for _, redirect := range analysis.RedirectChain {
		domain := a.extractDomain(redirect.URL)
		if domain != "" {
			domains[domain] = true
		}
	}

	// Count unique domains in external resources (if available)
	if analysis.AIResult != nil {
		// Would analyze external domains from content analysis
	}

	return len(domains)
}

func (a *BehavioralAnalyzer) calculateBehaviorScore(behavioral *BehavioralAnalysis) int {
	score := 100

	// Deduct for redirect complexity
	if behavioral.RedirectComplexity > 50 {
		score -= 30
	} else if behavioral.RedirectComplexity > 25 {
		score -= 15
	}

	// Deduct for load time anomalies
	if behavioral.LoadTimeAnomaly {
		score -= 20
	}

	// Deduct for high domain diversity
	if behavioral.DomainDiversity > a.thresholds.MaxExternalDomains {
		score -= 25
	}

	return max(score, 0)
}

func (a *BehavioralAnalyzer) detectAnomalies(behavioral *BehavioralAnalysis) []string {
	var anomalies []string

	if behavioral.RedirectComplexity > 50 {
		anomalies = append(anomalies, "Highly complex redirect chain detected")
	}

	if behavioral.LoadTimeAnomaly {
		anomalies = append(anomalies, "Unusually long load time")
	}

	if behavioral.DomainDiversity > a.thresholds.MaxExternalDomains {
		anomalies = append(anomalies, "High number of external domains")
	}

	if behavioral.BehaviorScore < 50 {
		anomalies = append(anomalies, "Overall suspicious behavioral patterns")
	}

	return anomalies
}

func (a *BehavioralAnalyzer) generateRecommendations(behavioral *BehavioralAnalysis) []string {
	var recommendations []string

	if behavioral.RedirectComplexity > 25 {
		recommendations = append(recommendations, "Investigate redirect chain for potential tracking or malicious behavior")
	}

	if behavioral.LoadTimeAnomaly {
		recommendations = append(recommendations, "Check for resource-intensive scripts or potential DDoS protection")
	}

	if behavioral.DomainDiversity > a.thresholds.MaxExternalDomains {
		recommendations = append(recommendations, "Review external domain dependencies for security risks")
	}

	if behavioral.BehaviorScore < 70 {
		recommendations = append(recommendations, "Exercise caution - multiple behavioral red flags detected")
	}

	return recommendations
}

func (a *BehavioralAnalyzer) extractDomain(url string) string {
	// Simple domain extraction
	// In production, use proper URL parsing
	return "" // TODO: Implement actual behavioral analysis logic
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
