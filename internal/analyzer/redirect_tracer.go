package analyzer

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"net-zilla/internal/models"
	"net-zilla/internal/utils"
)

type RedirectTracer struct {
	logger    *utils.Logger
	maxHops   int
	timeout   time.Duration
}

func NewRedirectTracer(logger *utils.Logger) *RedirectTracer {
	return &RedirectTracer{
		logger:  logger,
		maxHops: 10,
		timeout: 30 * time.Second,
	}
}

func (rt *RedirectTracer) TraceRedirects(ctx context.Context, startURL string) ([]models.RedirectInfo, int, error) {
	var redirects []models.RedirectInfo
	currentURL := startURL
	visited := make(map[string]bool)
	threatScore := 0

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow automatically
		},
		Timeout: rt.timeout,
	}

	for hop := 0; hop < rt.maxHops; hop++ {
		if visited[currentURL] {
			threatScore += 30 // Penalty for redirect loops
			rt.logger.Warn("Redirect loop detected at: %s", currentURL)
			break
		}
		visited[currentURL] = true

		startTime := time.Now()
		redirect, err := rt.traceSingleRedirect(client, currentURL, hop+1)
		duration := time.Since(startTime)

		if err != nil {
			rt.logger.Warn("Redirect tracing failed at hop %d: %v", hop+1, err)
			break
		}

		redirect.Duration = duration
		redirects = append(redirects, *redirect)

		// Analyze redirect for threats
		threatScore += rt.analyzeRedirectThreat(redirect, hop+1)

		// Check if we've reached final destination
		if redirect.StatusCode < 300 || redirect.StatusCode >= 400 || redirect.Location == "" {
			break
		}

		// Resolve next URL
		nextURL, err := rt.resolveNextURL(currentURL, redirect.Location)
		if err != nil {
			break
		}

		currentURL = nextURL
	}

	// Additional scoring based on redirect chain characteristics
	threatScore += rt.analyzeChainCharacteristics(redirects)

	return redirects, threatScore, nil
}

func (rt *RedirectTracer) traceSingleRedirect(client *http.Client, currentURL string, hop int) (*models.RedirectInfo, error) {
	req, err := http.NewRequest("GET", currentURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set secure headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; NetZilla-Security-Scanner/2.1)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Extract redirect information
	redirect := &models.RedirectInfo{
		URL:        currentURL,
		StatusCode: resp.StatusCode,
		Location:   resp.Header.Get("Location"),
		Headers:    make(map[string]string),
		HopNumber:  hop,
	}

	// Capture important headers
	securityHeaders := []string{
		"Content-Type", "Content-Security-Policy", "X-Frame-Options",
		"X-Content-Type-Options", "Strict-Transport-Security",
	}
	
	for _, header := range securityHeaders {
		if value := resp.Header.Get(header); value != "" {
			redirect.Headers[header] = value
		}
	}

	// Capture cookies
	for _, cookie := range resp.Cookies() {
		redirect.Cookies = append(redirect.Cookies, models.CookieInfo{
			Name:     cookie.Name,
			Domain:   cookie.Domain,
			Path:     cookie.Path,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			SameSite: cookie.SameSite.String(),
		})
	}

	return redirect, nil
}

func (rt *RedirectTracer) resolveNextURL(currentURL, location string) (string, error) {
	if location == "" {
		return "", fmt.Errorf("empty location header")
	}

	// Handle relative URLs
	if strings.HasPrefix(location, "/") {
		parsedCurrent, err := url.Parse(currentURL)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s://%s%s", parsedCurrent.Scheme, parsedCurrent.Host, location), nil
	}

	// Handle protocol-relative URLs
	if strings.HasPrefix(location, "//") {
		parsedCurrent, err := url.Parse(currentURL)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s:%s", parsedCurrent.Scheme, location), nil
	}

	// Absolute URL
	return location, nil
}

func (rt *RedirectTracer) analyzeRedirectThreat(redirect *models.RedirectInfo, hop int) int {
	score := 0

	// Status code analysis
	switch {
	case redirect.StatusCode >= 300 && redirect.StatusCode < 400:
		// Normal redirect, minimal penalty
		score += 5
	case redirect.StatusCode >= 400:
		// Error status codes
		score += 10
	}

	// Domain change analysis
	if hop > 1 {
		currentDomain := extractDomain(redirect.URL)
		nextDomain := extractDomain(redirect.Location)
		
		if currentDomain != "" && nextDomain != "" && currentDomain != nextDomain {
			score += 15 // Penalty for domain switching
			rt.logger.Info("Domain change detected: %s -> %s", currentDomain, nextDomain)
		}
	}

	// Suspicious location patterns
	location := strings.ToLower(redirect.Location)
	suspiciousPatterns := []string{
		"data:", "javascript:", "file:", "ftp:",
	}
	
	for _, pattern := range suspiciousPatterns {
		if strings.HasPrefix(location, pattern) {
			score += 40 // High penalty for dangerous schemes
			break
		}
	}

	// Cookie analysis
	if len(redirect.Cookies) > 3 {
		score += 10 // Multiple cookies set
	}

	// Security headers check
	if redirect.Headers["Strict-Transport-Security"] == "" {
		score += 5 // Missing HSTS
	}

	return score
}

func (rt *RedirectTracer) analyzeChainCharacteristics(redirects []models.RedirectInfo) int {
	score := 0

	// Chain length penalty
	chainLength := len(redirects)
	if chainLength > 5 {
		score += 20
	} else if chainLength > 3 {
		score += 10
	}

	// Multiple domain changes
	domains := make(map[string]bool)
	for _, redirect := range redirects {
		domain := extractDomain(redirect.URL)
		if domain != "" {
			domains[domain] = true
		}
	}
	
	if len(domains) > 3 {
		score += 15
	}

	return score
}

func extractDomain(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	
	host := parsed.Host
	// Remove port
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}
	
	return host
}
