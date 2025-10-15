package analyzer

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

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
	Title             string
	MetaDescription   string
	Keywords          []string
	Links             []Link
	Images            []Image
	Scripts           []Script
	Forms             []Form
	WordCount         int
	Language          string
	SuspiciousElements []string
	SecurityHeaders   map[string]string
	LoadTime          time.Duration
	ContentType       string
}

type Link struct {
	URL    string
	Text   string
	Rel    string
	Target string
	External bool
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
	Inline bool
}

type Form struct {
	Action string
	Method string
	Inputs []FormInput
}

type FormInput struct {
	Name     string
	Type     string
	Value    string
	Required bool
}

func NewContentAnalyzer() *ContentAnalyzer {
	return &ContentAnalyzer{
		httpClient:    network.NewSafeHTTPClient(),
		patternEngine: processor.NewPatternEngine(),
		urlParser:     processor.NewURLParser(),
	}
}

func (a *ContentAnalyzer) AnalyzeContent(url string) (*ContentAnalysis, error) {
	start := time.Now()
	analysis := &ContentAnalysis{}

	// Fetch page content safely
	resp, err := a.httpClient.SafeGetRequest(url)
	if err != nil {
		return analysis, fmt.Errorf("failed to fetch content: %w", err)
	}

	analysis.LoadTime = resp.LoadTime
	analysis.ContentType = resp.ContentType
	analysis.SecurityHeaders = resp.Headers

	// Parse HTML content (simplified - in production use goquery)
	htmlContent := "" // This would be the actual response body
	a.parseHTMLContent(htmlContent, analysis, url)

	// Detect suspicious patterns
	a.detectSuspiciousElements(analysis, url)

	// Analyze security headers
	a.analyzeSecurityHeaders(analysis)

	return analysis, nil
}

func (a *ContentAnalyzer) parseHTMLContent(html string, analysis *ContentAnalysis, baseURL string) {
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

	// Extract meta keywords
	keywordsRegex := regexp.MustCompile(`<meta name="keywords" content="(.*?)"`)
	if matches := keywordsRegex.FindStringSubmatch(html); len(matches) > 1 {
		analysis.Keywords = strings.Split(strings.TrimSpace(matches[1]), ",")
	}

	// Extract all links
	a.extractLinks(html, analysis, baseURL)

	// Extract images
	a.extractImages(html, analysis)

	// Extract scripts
	a.extractScripts(html, analysis)

	// Extract forms
	a.extractForms(html, analysis)

	// Calculate word count
	analysis.WordCount = a.calculateWordCount(html)

	// Detect language
	analysis.Language = a.detectLanguage(html)
}

func (a *ContentAnalyzer) extractLinks(html string, analysis *ContentAnalysis, baseURL string) {
	linkRegex := regexp.MustCompile(`<a[^>]+href="([^"]*)"[^>]*>(.*?)</a>`)
	links := linkRegex.FindAllStringSubmatch(html, -1)

	for _, link := range links {
		if len(link) >= 3 {
			url := strings.TrimSpace(link[1])
			text := strings.TrimSpace(link[2])

			// Determine if link is external
			isExternal := a.isExternalLink(url, baseURL)

			analysis.Links = append(analysis.Links, Link{
				URL:      url,
				Text:     text,
				External: isExternal,
			})
		}
	}
}

func (a *ContentAnalyzer) extractImages(html string, analysis *ContentAnalysis) {
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
}

func (a *ContentAnalyzer) extractScripts(html string, analysis *ContentAnalysis) {
	// External scripts
	scriptRegex := regexp.MustCompile(`<script[^>]+src="([^"]*)"[^>]*>`)
	scripts := scriptRegex.FindAllStringSubmatch(html, -1)

	for _, script := range scripts {
		if len(script) >= 2 {
			analysis.Scripts = append(analysis.Scripts, Script{
				Src:    strings.TrimSpace(script[1]),
				Inline: false,
			})
		}
	}

	// Inline scripts
	inlineScriptRegex := regexp.MustCompile(`<script[^>]*>(.*?)</script>`)
	inlineScripts := inlineScriptRegex.FindAllStringSubmatch(html, -1)

	for _, script := range inlineScripts {
		if len(script) >= 2 {
			analysis.Scripts = append(analysis.Scripts, Script{
				Inline: true,
				Type:   "inline",
			})
		}
	}
}

func (a *ContentAnalyzer) extractForms(html string, analysis *ContentAnalysis) {
	formRegex := regexp.MustCompile(`<form[^>]+action="([^"]*)"[^>]+method="([^"]*)"[^>]*>(.*?)</form>`)
	forms := formRegex.FindAllStringSubmatch(html, -1)

	for _, form := range forms {
		if len(form) >= 4 {
			formAnalysis := Form{
				Action: strings.TrimSpace(form[1]),
				Method: strings.TrimSpace(form[2]),
			}

			// Extract form inputs
			formAnalysis.Inputs = a.extractFormInputs(form[3])
			analysis.Forms = append(analysis.Forms, formAnalysis)
		}
	}
}

func (a *ContentAnalyzer) extractFormInputs(formHTML string) []FormInput {
	var inputs []FormInput

	inputRegex := regexp.MustCompile(`<input[^>]+name="([^"]*)"[^>]+type="([^"]*)"`)
	formInputs := inputRegex.FindAllStringSubmatch(formHTML, -1)

	for _, input := range formInputs {
		if len(input) >= 3 {
			inputs = append(inputs, FormInput{
				Name: strings.TrimSpace(input[1]),
				Type: strings.TrimSpace(input[2]),
			})
		}
	}

	return inputs
}

func (a *ContentAnalyzer) calculateWordCount(html string) int {
	// Remove HTML tags
	tagRegex := regexp.MustCompile(`<[^>]*>`)
	text := tagRegex.ReplaceAllString(html, " ")
	
	// Remove extra whitespace
	spaceRegex := regexp.MustCompile(`\s+`)
	text = spaceRegex.ReplaceAllString(text, " ")
	
	// Split into words and count
	words := strings.Fields(text)
	return len(words)
}

func (a *ContentAnalyzer) detectLanguage(html string) string {
	// Simple language detection based on common patterns
	langRegex := regexp.MustCompile(`<html[^>]+lang="([^"]*)"`)
	if matches := langRegex.FindStringSubmatch(html); len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}

	// Fallback: detect from content patterns
	if strings.Contains(html, " the ") || strings.Contains(html, " and ") {
		return "en"
	}

	return "unknown"
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

func (a *ContentAnalyzer) detectSuspiciousElements(analysis *ContentAnalysis, url string) {
	var suspicious []string

	// Check for low content
	if analysis.WordCount < 50 {
		suspicious = append(suspicious, "Very low content - possible placeholder or scam site")
	}

	// Check for excessive external links
	externalCount := 0
	for _, link := range analysis.Links {
		if link.External {
			externalCount++
		}
	}

	if externalCount > 20 {
		suspicious = append(suspicious, "High number of external links - potential link farm")
	}

	// Check for suspicious keywords in title/description
	suspiciousPatterns := a.patternEngine.AnalyzeText(analysis.Title + " " + analysis.MetaDescription)
	for _, pattern := range suspiciousPatterns {
		if pattern.Confidence > 0.7 {
			suspicious = append(suspicious, 
				fmt.Sprintf("Suspicious %s pattern: %s", pattern.Type, pattern.Pattern))
		}
	}

	// Check for hidden elements (invisible text, etc.)
	if a.detectHiddenContent(analysis) {
		suspicious = append(suspicious, "Possible hidden content detected")
	}

	analysis.SuspiciousElements = suspicious
}

func (a *ContentAnalyzer) detectHiddenContent(analysis *ContentAnalysis) bool {
	// Check for common hidden content patterns
	// This would be more sophisticated in production
	return false
}

func (a *ContentAnalyzer) analyzeSecurityHeaders(analysis *ContentAnalysis) {
	// Analyze security headers for best practices
	requiredHeaders := []string{
		"Content-Security-Policy",
		"X-Frame-Options", 
		"X-Content-Type-Options",
		"Strict-Transport-Security",
	}

	for _, header := range requiredHeaders {
		if _, exists := analysis.SecurityHeaders[header]; !exists {
			analysis.SuspiciousElements = append(analysis.SuspiciousElements,
				fmt.Sprintf("Missing security header: %s", header))
		}
	}
}
