package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"net-zilla/internal/models"
	"net-zilla/internal/utils"
)

// RedirectTracer traces URL redirect chains and analyzes them for potential threats.
type RedirectTracer struct {
	logger  *utils.Logger
	maxHops int
	timeout time.Duration
}

// NewRedirectTracer creates and initializes a new RedirectTracer.
func NewRedirectTracer(logger *utils.Logger) *RedirectTracer {
	return &RedirectTracer{
		logger:  logger,
		maxHops: 10, // Default max 10 redirects
		timeout: 30 * time.Second,
	}
}

// TraceRedirects traces the full redirect chain of a given URL, analyzing each step for threats.
func (rt *RedirectTracer) TraceRedirects(ctx context.Context, startURL string) ([]models.RedirectDetail, int, error) {
	var redirects []models.RedirectDetail
	currentURL := startURL
	visited := make(map[string]bool)
	threatScore := 0

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow automatically, we handle redirects manually
		},
		Timeout: rt.timeout,
	}

	for hop := 0; hop < rt.maxHops; hop++ {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		default:
			// Continue
		}

		if visited[currentURL] {
			threatScore += 30 // Penalty for redirect loops
			rt.logger.Warn("Redirect loop detected at: %s", currentURL)
			redirects = append(redirects, models.RedirectDetail{
				URL:      currentURL,
				Location: "LOOP_DETECTED",
				Warnings: []string{"Redirect loop detected"},
			})
			break
		}
		visited[currentURL] = true

		startTime := time.Now()
		req, err := http.NewRequestWithContext(ctx, "GET", currentURL, nil) // Use context with request
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create request for %s: %w", currentURL, err)
		}

		// Set secure headers
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; NetZilla-Security-Scanner/2.1)")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := client.Do(req)
		if err != nil {
			// Handle specific network errors
			if ue, ok := err.(*url.Error); ok && ue.Timeout() {
				rt.logger.Warn("Request to %s timed out: %v", currentURL, err)
				threatScore += 20 // Penalty for timeout
				redirects = append(redirects, models.RedirectDetail{
					URL:      currentURL,
					Warnings: []string{fmt.Sprintf("Request timed out after %v", rt.timeout)},
				})
				break
			}
			rt.logger.Warn("HTTP request failed for %s: %v", currentURL, err)
			threatScore += 25 // Penalty for request failure
			redirects = append(redirects, models.RedirectDetail{
				URL:      currentURL,
				Warnings: []string{fmt.Sprintf("HTTP request failed: %v", err)},
			})
			break
		}
		defer resp.Body.Close()

		// Extract redirect information
		redirectDetail := models.RedirectDetail{
			URL:        currentURL,
			StatusCode: resp.StatusCode,
			Location:   resp.Header.Get("Location"),
			Headers:    make(map[string]string),
			Duration:   time.Since(startTime),
		}

		// Capture important headers
		securityHeaders := []string{
			"Content-Type", "Content-Security-Policy", "X-Frame-Options",
			"X-Content-Type-Options", "Strict-Transport-Security", "Referrer-Policy",
			"Permissions-Policy", "X-Permitted-Cross-Domain-Policies",
		}

		for _, header := range securityHeaders {
			if value := resp.Header.Get(header); value != "" {
				redirectDetail.Headers[header] = value
			}
		}

		// Capture cookies
		for _, cookie := range resp.Cookies() {
			redirectDetail.Cookies = append(redirectDetail.Cookies, models.CookieInfo{
				Name:     cookie.Name,
				Domain:   cookie.Domain,
				Path:     cookie.Path,
				Secure:   cookie.Secure,
				HttpOnly: cookie.HttpOnly,
				SameSite: cookie.SameSite.String(),
			})
		}

		redirects = append(redirects, redirectDetail)

		// Analyze redirect for threats
		threatScore += rt.analyzeRedirectThreat(&redirectDetail, hop+1, redirects) // Pass redirects for domain comparison

		// Check if we've reached final destination (no more redirects or client error)
		if redirectDetail.StatusCode < 300 || redirectDetail.StatusCode >= 400 || redirectDetail.Location == "" {
			break
		}

		// Resolve next URL
		nextURL, err := rt.resolveNextURL(currentURL, redirectDetail.Location)
		if err != nil {
			rt.logger.Warn("Failed to resolve next URL for %s from location %s: %v", currentURL, redirectDetail.Location, err)
			threatScore += 10 // Penalty for unresolvable redirect
			break
		}

		currentURL = nextURL
	}

	// Additional scoring based on redirect chain characteristics
	threatScore += rt.analyzeChainCharacteristics(redirects)

	return redirects, threatScore, nil
}

// resolveNextURL resolves relative or absolute redirect URLs.
func (rt *RedirectTracer) resolveNextURL(baseURL, location string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL %s: %w", baseURL, err)
	}
	rel, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("invalid redirect location %s: %w", location, err)
	}
	return base.ResolveReference(rel).String(), nil
}

// analyzeRedirectThreat assesses a single redirect for suspicious characteristics.
func (rt *RedirectTracer) analyzeRedirectThreat(redirect *models.RedirectDetail, hop int, redirects []models.RedirectDetail) int {
	score := 0

	// Status code analysis
	switch {
	case redirect.StatusCode >= 300 && redirect.StatusCode < 400:
		// Normal redirect, minimal base penalty
		score += 2
	case redirect.StatusCode == http.StatusFound || redirect.StatusCode == http.StatusTemporaryRedirect:
		// Often used in legitimate scenarios, but can also be abused
		score += 5
	case redirect.StatusCode == http.StatusPermanentRedirect:
		// Stronger redirect, less common for transient phishing
		score += 1
	case redirect.StatusCode >= 400:
		// Error status codes - indicates a broken chain or server issue
		score += 15
		redirect.Warnings = append(redirect.Warnings, fmt.Sprintf("HTTP Error %d detected", redirect.StatusCode))
	}

	// Domain change analysis (if not first hop)
	if hop > 1 && len(redirects) >= 2 { // Ensure there's a previous redirect to compare against
		prevURL := redirects[len(redirects)-2].URL
		currentDomain := extractDomain(prevURL)
		nextDomain := extractDomain(redirect.URL) // The domain we are redirecting TO

		if currentDomain != "" && nextDomain != "" && currentDomain != nextDomain {
			score += 10 // Penalty for domain switching
			rt.logger.Info("Domain change detected in redirect chain: %s -> %s", currentDomain, nextDomain)
			redirect.Warnings = append(redirect.Warnings, fmt.Sprintf("Domain changed from %s to %s", currentDomain, nextDomain))
		}
	}

	// Suspicious location patterns (e.g., data:, javascript: schemes)
	locationLower := strings.ToLower(redirect.Location)
	suspiciousSchemePatterns := []string{
		"data:", "javascript:", "file:", "ftp:", "chrome-extension:", "moz-extension:",
	}

	for _, pattern := range suspiciousSchemePatterns {
		if strings.HasPrefix(locationLower, pattern) {
			score += 50 // Very high penalty for dangerous schemes
			rt.logger.Warn("Dangerous scheme detected in redirect location: %s", redirect.Location)
			redirect.Warnings = append(redirect.Warnings, fmt.Sprintf("Dangerous scheme detected: %s", pattern))
			break
		}
	}

	// Check for URL obfuscation (e.g., excessive encoding, many subdomains, IP as host)
	if isObfuscatedURL(redirect.Location) {
		score += 20
		redirect.Warnings = append(redirect.Warnings, "Possible URL obfuscation detected")
	}

	// Cookie analysis (excessive/suspicious cookies being set during redirect)
	if len(redirect.Cookies) > 5 { // Arbitrary threshold
		score += 5
		redirect.Warnings = append(redirect.Warnings, fmt.Sprintf("%d cookies set during redirect", len(redirect.Cookies)))
	}

	// Missing security headers (indicates poor security posture)
	if redirect.StatusCode == http.StatusOK { // Only check for final destination
		if _, ok := redirect.Headers["Strict-Transport-Security"]; !ok {
			score += 5 // Missing HSTS
			redirect.Warnings = append(redirect.Warnings, "Missing Strict-Transport-Security (HSTS) header")
		}
		if _, ok := redirect.Headers["Content-Security-Policy"]; !ok {
			score += 5 // Missing CSP
			redirect.Warnings = append(redirect.Warnings, "Missing Content-Security-Policy (CSP) header")
		}
	}

	return score
}

// analyzeChainCharacteristics assesses the entire redirect chain for macroscopic threats.
func (rt *RedirectTracer) analyzeChainCharacteristics(redirects []models.RedirectDetail) int {
	score := 0

	// Chain length penalty
	chainLength := len(redirects)
	if chainLength == 0 {
		return 0 // No chain to analyze
	}
	if chainLength > 7 { // Arbitrary threshold for long chains
		score += 15
		rt.logger.Info("Long redirect chain detected: %d hops", chainLength)
	} else if chainLength > 3 {
		score += 5
	}

	// Multiple domain changes in the chain
	domains := make(map[string]struct{})
	for _, redirect := range redirects {
		domain := extractDomain(redirect.URL)
		if domain != "" {
			domains[domain] = struct{}{}
		}
	}

	if len(domains) > 3 { // Arbitrary threshold for many distinct domains
		score += 15
		rt.logger.Info("Multiple distinct domains in redirect chain: %d unique domains", len(domains))
	} else if len(domains) > 1 {
		score += 5
	}

	// Mixed content (HTTP to HTTPS) or insecure redirects (HTTP 301/302 to HTTP)
	for i := 0; i < chainLength; i++ {
		currentURL := redirects[i].URL
		if i+1 < chainLength {
			nextURL := redirects[i+1].URL
			currentScheme := "http"
			if strings.HasPrefix(currentURL, "https://") {
				currentScheme = "https"
			}
			nextScheme := "http"
			if strings.HasPrefix(nextURL, "https://") {
				nextScheme = "https"
			}

			if currentScheme == "http" && nextScheme == "https" {
				// Upgrade to HTTPS is generally good, no penalty
			} else if currentScheme == "https" && nextScheme == "http" {
				score += 20 // Downgrade from HTTPS to HTTP
				rt.logger.Warn("HTTPS downgrade detected in redirect chain: %s -> %s", currentURL, nextURL)
				// Add warning to analysis.Warnings if appropriate
			} else if currentScheme == "http" && nextScheme == "http" && redirects[i].StatusCode >= 300 && redirects[i].StatusCode < 400 {
				score += 5 // Insecure redirect over HTTP
			}
		}
	}

	return score
}

// extractDomain extracts the domain from a URL string.
// This is a local helper and should be consolidated if used elsewhere.
func extractDomain(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}

	host := parsed.Hostname() // Use Hostname() for just the host, no port
	return host
}

// isObfuscatedURL checks for common URL obfuscation techniques.
func isObfuscatedURL(rawURL string) bool {
	// Check for excessive encoding (%25, %u)
	if strings.Contains(rawURL, "%25") || strings.Contains(rawURL, "%u") {
		return true
	}

	// Check for IP address as host (e.g., http://192.168.1.1/...)
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		if net.ParseIP(u.Hostname()) != nil {
			return true
		}
	}

	// Check for very long subdomains or unusual characters
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		parts := strings.Split(u.Hostname(), ".")
		for _, part := range parts {
			if len(part) > 20 || regexp.MustCompile(`[^a-zA-Z0-9-]`).MatchString(part) { // Unusual characters in subdomain
				return true
			}
		}
	}

	return false
}

// AnalyzeRedirectChain processes a slice of RedirectDetail and returns aggregated RedirectAnalysis data.
func AnalyzeRedirectChain(chain []models.RedirectDetail) *models.RedirectAnalysis {
	analysis := &models.RedirectAnalysis{
		Hops: len(chain),
	}

	domains := make(map[string]struct{})
	var externalLinksCount int
	var suspiciousURLsCount int

	// Determine base domain for external/internal link classification
	baseDomain := ""
	if len(chain) > 0 {
		baseDomain = extractDomain(chain[0].URL)
	}

	for _, detail := range chain {
		// Unique Domains
		domain := extractDomain(detail.URL)
		if domain != "" {
			domains[domain] = struct{}{}
		}

		// External and Internal Links
		// This is a basic implementation; a more robust one would involve fetching and parsing HTML
		// and comparing extracted links to the base domain.
		linkDomain := extractDomain(detail.URL)
		if linkDomain != "" && baseDomain != "" && linkDomain != baseDomain {
			externalLinksCount++
		} else if linkDomain == baseDomain {
			// This would count internal links on the *current* page of the redirect.
			// Accurate counting needs content parsing.
		}

		// Suspicious URLs
		lowerURL := strings.ToLower(detail.URL)
		if strings.Contains(lowerURL, "login.php") ||
			strings.Contains(lowerURL, "verify.html") ||
			strings.Contains(lowerURL, "update.php") ||
			strings.Contains(lowerURL, "account.html") ||
			isObfuscatedURL(detail.URL) {
			suspiciousURLsCount++
		}
	}

	analysis.UniqueDomains = len(domains)
	analysis.ExternalLinks = externalLinksCount
	analysis.SuspiciousURLs = suspiciousURLsCount

	return analysis
}