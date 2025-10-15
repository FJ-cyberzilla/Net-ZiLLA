// internal/processor/pattern_engine.go
package processor

import (
	"regexp"
	"strings"
)

type PatternEngine struct {
	phishingPatterns   []*regexp.Regexp
	malwarePatterns    []*regexp.Regexp
	trackingPatterns   []*regexp.Regexp
	socialEngineering  []*regexp.Regexp
}

type PatternMatch struct {
	Type        string
	Pattern     string
	Matches     []string
	Confidence  float64
}

func NewPatternEngine() *PatternEngine {
	return &PatternEngine{
		phishingPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)login.*verify`),
			regexp.MustCompile(`(?i)account.*secure`),
			regexp.MustCompile(`(?i)password.*reset`),
			regexp.MustCompile(`(?i)bank.*update`),
			regexp.MustCompile(`(?i)paypal.*confirm`),
		},
		malwarePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\.exe$`),
			regexp.MustCompile(`(?i)\.scr$`),
			regexp.MustCompile(`(?i)\.bat$`),
			regexp.MustCompile(`(?i)download.*file`),
			regexp.MustCompile(`(?i)install.*now`),
		},
		trackingPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)utm_`),
			regexp.MustCompile(`(?i)fbclid=`),
			regexp.MustCompile(`(?i)gclid=`),
			regexp.MustCompile(`(?i)msclkid=`),
		},
		socialEngineering: []*regexp.Regexp{
			regexp.MustCompile(`(?i)urgent`),
			regexp.MustCompile(`(?i)immediate`),
			regexp.MustCompile(`(?i)action.*required`),
			regexp.MustCompile(`(?i)your.*account`),
			regexp.MustCompile(`(?i)suspended`),
			regexp.MustCompile(`(?i)limited.*time`),
		},
	}
}

func (p *PatternEngine) AnalyzeText(text string) []PatternMatch {
	var matches []PatternMatch

	// Check all pattern categories
	matches = append(matches, p.checkPatterns(text, "phishing", p.phishingPatterns)...)
	matches = append(matches, p.checkPatterns(text, "malware", p.malwarePatterns)...)
	matches = append(matches, p.checkPatterns(text, "tracking", p.trackingPatterns)...)
	matches = append(matches, p.checkPatterns(text, "social_engineering", p.socialEngineering)...)

	return matches
}

func (p *PatternEngine) checkPatterns(text, category string, patterns []*regexp.Regexp) []PatternMatch {
	var matches []PatternMatch

	for _, pattern := range patterns {
		if found := pattern.FindAllString(text, -1); len(found) > 0 {
			confidence := p.calculateConfidence(category, found)
			matches = append(matches, PatternMatch{
				Type:       category,
				Pattern:    pattern.String(),
				Matches:    found,
				Confidence: confidence,
			})
		}
	}

	return matches
}

func (p *PatternEngine) calculateConfidence(category string, matches []string) float64 {
	baseConfidence := map[string]float64{
		"phishing":          0.8,
		"malware":           0.9,
		"tracking":          0.6,
		"social_engineering": 0.7,
	}

	confidence := baseConfidence[category]

	// Increase confidence based on match count
	if len(matches) > 1 {
		confidence += 0.1
	}

	// Increase for exact matches
	for _, match := range matches {
		if strings.ToLower(match) == match || strings.ToUpper(match) == match {
			confidence += 0.05
		}
	}

	return min(confidence, 1.0)
}

func (p *PatternEngine) AnalyzeURL(url string) []PatternMatch {
	// URL-specific pattern analysis
	var matches []PatternMatch

	// Check for data URIs
	if strings.HasPrefix(url, "data:") {
		matches = append(matches, PatternMatch{
			Type:       "malware",
			Pattern:    "data_uri",
			Matches:    []string{url},
			Confidence: 0.8,
		})
	}

	// Check for JavaScript URLs
	if strings.HasPrefix(url, "javascript:") {
		matches = append(matches, PatternMatch{
			Type:       "malware",
			Pattern:    "javascript_uri",
			Matches:    []string{url},
			Confidence: 0.9,
		})
	}

	// Check for excessive encoding
	if strings.Count(url, "%") > 5 {
		matches = append(matches, PatternMatch{
			Type:       "obfuscation",
			Pattern:    "excessive_encoding",
			Matches:    []string{url},
			Confidence: 0.7,
		})
	}

	return matches
}
