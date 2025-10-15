package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"net-zilla/internal/models"
	"net-zilla/internal/network"
	"net-zilla/internal/processor"
)

type ContentAnalyzer struct {
	httpClient    *network.SafeHTTPClient
	patternEngine *processor.PatternEngine
	urlParser     *processor.URLParser
}

type ContentAnalysis struct {
	Title          string
	MetaDescription string
	Keywords       []string
	Links          []Link
	Images         []Image
	Scripts        []Script
	Forms          []Form
	WordCount      int
	Language       string
	SuspiciousElements []string
	SecurityHeaders map[string]string
}

type Link struct {
	URL    string
	Text   string
	Rel    string
	Target string
}

type Image struct {
	Src    string
	Alt    string
	Width  string
	Height string
}

type Script struct {
	Src    string
	Type   string
	Async  bool
	Defer  bool
}

type Form struct {
	Action string
	Method string
	Inputs []FormInput
}

type FormInput struct {
	Name  string
	Type  string
	Value string
}

func NewContentAnalyzer() *ContentAnalyzer {
	return &ContentAnalyzer{
		httpClient:    network.NewSafeHTTPClient(),
		patternEngine: processor.NewPatternEngine(),
		urlParser:     processor.NewURLParser(),
	}
}

func (a *ContentAnalyzer) AnalyzeContent(url string) (*ContentAnalysis, error) {
	analysis := &ContentAnalysis{}

	// Fetch page content
	resp, err := a.httpClient.SafeGetRequest(url)
	if err != nil {
		return analysis, fmt.Errorf("failed to fetch content: %w", err)
	}

	// Extract security headers
	analysis.SecurityHeaders, _ = a.httpClient.CheckSecurityHeaders(url)

	// Parse HTML content (simplified - in production use goquery or similar)
	content := "" // Would be the actual HTML content
	a.analyzeHTMLContent(content, analysis)

	// Detect suspicious patterns
	a.detectSuspiciousElements(analysis, url)

	return analysis, nil
}

func (a *ContentAnalyzer) analyzeHTMLContent(html string, analysis *ContentAnalysis) {
	// Extract title
	titleRegex := regexp.MustCompile(`<title>(.*?)</title>`)
	if matches := titleRegex.FindStringSubmatch(html); len(matches) > 1 {
		analysis.Title = strings.TrimSpace(matches[1])
	}

	// Extract meta description
	descRegex := regexp.MustCompile(`<meta name="description" content="(.*?)"`)
	if matches := descRegex.FindStringSubmatch(html); len(matches) > 1 {
		analysis.MetaDescription = strings.TrimSpace(matches[1])
	}

	// Extract links
	linkRegex := regexp.MustCompile(`<a[^>]+href="([^"]*)"[^>]*>(.*?)</a>`)
	links := linkRegex.FindAllStringSubmatch(html, -1)
	for _, link := range links {
		if len(link) >= 3 {
			analysis.Links = append(analysis.Links, Link{
				URL:  strings.TrimSpace(link[1]),
				Text: strings.TrimSpace(link[2]),
			})
		}
	}

	// Extract images
	imgRegex := regexp.MustCompile(`<img[^>]+src="([^"]*)"[^>]*alt="([^"]*)"`)
	images := imgRegex.FindAllStringSubmatch(html, -1)
	for _, img := range images {
		if len(img) >= 3 {
			analysis.Images = append(analysis.Images, Image{
				Src: strings.TrimSpace(img[1]),
				Alt: strings.TrimSpace(img[2]),
			})
		}
	}

	// Extract scripts
	scriptRegex := regexp.MustCompile(`<script[^>]+src="([^"]*)"[^>]*>`)
	scripts := scriptRegex.FindAllStringSubmatch(html, -1)
	for _, script := range scripts {
		if len(script) >= 2 {
			analysis.Scripts = append(analysis.Scripts, Script{
				Src: strings.TrimSpace(script[1]),
			})
		}
	}

	// Word count (approximate)
	textOnly := a.extractText(html)
	analysis.WordCount = len(strings.Fields(textOnly))
}

func (a *ContentAnalyzer) extractText(html string) string {
	// Remove HTML tags
	tagRegex := regexp.MustCompile(`<[^>]*>`)
	text := tagRegex.ReplaceAllString(html, " ")
	
	// Remove extra whitespace
	spaceRegex := regexp.MustCompile(`\s+`)
	text = spaceRegex.ReplaceAllString(text, " ")
	
	return strings.TrimSpace(text)
}

func (a *ContentAnalyzer) detectSuspiciousElements(analysis *ContentAnalysis, url string) {
	var suspicious []string

	// Check for hidden elements
	if analysis.WordCount < 50 {
		suspicious = append(suspicious, "Low content - possible placeholder site")
	}

	// Check for excessive external links
	externalLinks := 0
	for _, link := range analysis.Links {
		if a.isExternalLink(link.URL, url) {
			externalLinks++
		}
	}

	if externalLinks > 20 {
		suspicious = append(suspicious, "High number of external links")
	}

	// Check for suspicious keywords in title and description
	suspiciousPatterns := a.patternEngine.AnalyzeText(analysis.Title + " " + analysis.MetaDescription)
	for _, pattern := range suspiciousPatterns {
		if pattern.Confidence > 0.7 {
			suspicious = append(suspicious, fmt.Sprintf("Suspicious %s pattern: %s", pattern.Type, pattern.Pattern))
		}
	}

	analysis.SuspiciousElements = suspicious
}

func (a *ContentAnalyzer) isExternalLink(linkURL, baseURL string) bool {
	linkDomain := a.extractDomain(linkURL)
	baseDomain := a.extractDomain(baseURL)
	
	return linkDomain != "" && baseDomain != "" && linkDomain != baseDomain
}

func (a *ContentAnalyzer) extractDomain(url string) string {
	parsed, err := a.urlParser.ParseAndAnalyze(url)
	if err != nil {
		return ""
	}
	return parsed.Domain
}
