// internal/processor/url_parser.go
package processor

import (
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

type URLParser struct {
	shortenerPatterns []*regexp.Regexp
	obfuscationPatterns []*regexp.Regexp
}

type ParsedURL struct {
	Original     string
	Normalized   string
	Scheme       string
	Domain       string
	Subdomain    string
	TLD          string
	Path         string
	QueryParams  map[string]string
	IsShortened  bool
	IsObfuscated bool
	HasIP        bool
}

func NewURLParser() *URLParser {
	return &URLParser{
		shortenerPatterns: []*regexp.Regexp{
			regexp.MustCompile(`bit\.ly`),
			regexp.MustCompile(`tinyurl\.com`),
			regexp.MustCompile(`goo\.gl`),
			regexp.MustCompile(`ow\.ly`),
			regexp.MustCompile(`t\.co`),
			regexp.MustCompile(`buff\.ly`),
		},
		obfuscationPatterns: []*regexp.Regexp{
			regexp.MustCompile(`%[0-9A-Fa-f]{2}`), // URL encoding
			regexp.MustCompile(`@`),               // Userinfo obfuscation
			regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`), // IP address
		},
	}
}

func (p *URLParser) ParseAndAnalyze(rawURL string) (*ParsedURL, error) {
	parsed := &ParsedURL{
		Original:    rawURL,
		QueryParams: make(map[string]string),
	}

	// Normalize URL
	normalized, err := p.normalizeURL(rawURL)
	if err != nil {
		return nil, err
	}
	parsed.Normalized = normalized

	// Parse URL components
	u, err := url.Parse(normalized)
	if err != nil {
		return nil, err
	}

	parsed.Scheme = u.Scheme
	parsed.Domain = u.Hostname()
	parsed.Path = u.Path

	// Extract subdomain and TLD
	parsed.Subdomain, parsed.TLD = p.extractDomainParts(u.Hostname())

	// Parse query parameters
	p.parseQueryParams(u, parsed)

	// Analyze URL characteristics
	parsed.IsShortened = p.isShortenedURL(u)
	parsed.IsObfuscated = p.isObfuscatedURL(u)
	parsed.HasIP = p.containsIPAddress(u.Hostname())

	return parsed, nil
}

func (p *URLParser) normalizeURL(rawURL string) (string, error) {
	// Ensure scheme
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}

	// Parse to validate
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	// Normalize host to lowercase
	u.Host = strings.ToLower(u.Host)

	// Remove default ports
	u.Host = strings.TrimSuffix(u.Host, ":80")
	u.Host = strings.TrimSuffix(u.Host, ":443")

	return u.String(), nil
}

func (p *URLParser) extractDomainParts(host string) (string, string) {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return "", host
	}

	tld := parts[len(parts)-1]
	subdomain := ""

	if len(parts) > 2 {
		subdomain = strings.Join(parts[:len(parts)-2], ".")
	}

	return subdomain, tld
}

func (p *URLParser) parseQueryParams(u *url.URL, parsed *ParsedURL) {
	query := u.Query()
	for key, values := range query {
		if len(values) > 0 {
			parsed.QueryParams[key] = values[0]
		}
	}
}

func (p *URLParser) isShortenedURL(u *url.URL) bool {
	host := u.Hostname()
	for _, pattern := range p.shortenerPatterns {
		if pattern.MatchString(host) {
			return true
		}
	}
	return false
}

func (p *URLParser) isObfuscatedURL(u *url.URL) bool {
	fullURL := u.String()
	for _, pattern := range p.obfuscationPatterns {
		if pattern.MatchString(fullURL) {
			return true
		}
	}
	return false
}

func (p *URLParser) containsIPAddress(host string) bool {
	ipPattern := regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	return ipPattern.MatchString(host)
}

func (p *URLParser) CalculateEntropy(s string) float64 {
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}

	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		probability := count / length
		entropy -= probability * (probability)
	}

	return entropy
}

func (p *URLParser) DetectHomographAttack(domain string) bool {
	// Check for mixed scripts (Latin + Cyrillic, etc.)
	var hasLatin, hasCyrillic, hasGreek bool

	for _, r := range domain {
		switch {
		case unicode.Is(unicode.Latin, r):
			hasLatin = true
		case unicode.Is(unicode.Cyrillic, r):
			hasCyrillic = true
		case unicode.Is(unicode.Greek, r):
			hasGreek = true
		}
	}

	// If multiple scripts detected, potential homograph attack
	scriptCount := 0
	if hasLatin { scriptCount++ }
	if hasCyrillic { scriptCount++ }
	if hasGreek { scriptCount++ }

	return scriptCount > 1
}
