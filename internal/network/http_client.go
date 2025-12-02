package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"net-zilla/internal/utils" // Added import for Logger
)

// HTTPClient is a secure HTTP client with configurable timeouts and redirect handling.
type HTTPClient struct {
	client    *http.Client
	userAgent string
	logger    *utils.Logger
}

// HTTPResponse captures key details from an HTTP response.
type HTTPResponse struct {
	StatusCode    int
	Headers       map[string]string
	ContentType   string
	ContentLength int64
	Server        string
	Cookies       []*http.Cookie
	LoadTime      time.Duration
	TLS           *tls.ConnectionState // Optional TLS details
}

// NewHTTPClient creates and initializes a new HTTPClient.
func NewHTTPClient(logger *utils.Logger) *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			// No CheckRedirect function here, as redirects are handled by RedirectTracer
			Timeout: 30 * time.Second, // Default timeout for single requests
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false, // Always verify TLS certificates
					MinVersion:         tls.VersionTLS12,
				},
				MaxIdleConns:        100,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
				ForceAttemptHTTP2:   true, // Enable HTTP/2 where available
			},
		},
		userAgent: "Mozilla/5.0 (compatible; NetZilla-Security-Scanner/2.1; +https://netzilla.io)",
		logger:    logger,
	}
}

// SafeHeadRequest performs a HEAD request to the target URL.
func (hc *HTTPClient) SafeHeadRequest(ctx context.Context, targetURL string) (*HTTPResponse, error) {
	return hc.safeRequest(ctx, "HEAD", targetURL)
}

// SafeGetRequest performs a GET request to the target URL.
func (hc *HTTPClient) SafeGetRequest(ctx context.Context, targetURL string) (*HTTPResponse, error) {
	return hc.safeRequest(ctx, "GET", targetURL)
}

// safeRequest performs a generic HTTP request.
func (hc *HTTPClient) safeRequest(ctx context.Context, method, targetURL string) (*HTTPResponse, error) {
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		hc.logger.Error("Failed to create HTTP request for %s %s: %v", method, targetURL, err)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set secure headers
	req.Header.Set("User-Agent", hc.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br") // Add brotli
	req.Header.Set("Connection", "close")                 // Prevent connection reuse

	resp, err := hc.client.Do(req)
	if err != nil {
		hc.logger.Warn("HTTP request failed for %s %s: %v", method, targetURL, err)
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read limited content for GET requests to avoid downloading large files unnecessarily
	var contentLength int64 = -1 // Unknown by default
	if method == "GET" && resp.ContentLength != -1 {
		// Only read if content length is known and within limits
		if resp.ContentLength < 1*1024*1024 { // Read up to 1MB
			contentLength = resp.ContentLength
			io.CopyN(io.Discard, resp.Body, contentLength) // Read and discard
		} else {
			hc.logger.Debug("Skipping full body read for large response from %s (Content-Length: %d)", targetURL, resp.ContentLength)
			contentLength = resp.ContentLength
		}
	} else if method == "GET" {
		// If Content-Length is unknown, read a small buffer
		limitedReader := io.LimitReader(resp.Body, 16*1024) // Read first 16KB
		_, _ = io.ReadAll(limitedReader)
	}

	// Extract headers
	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	response := &HTTPResponse{
		StatusCode:    resp.StatusCode,
		Headers:       headers,
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: contentLength,
		Server:        resp.Header.Get("Server"),
		Cookies:       resp.Cookies(),
		LoadTime:      time.Since(start),
		TLS:           resp.TLS, // Capture TLS details if available
	}

	return response, nil
}

// CheckSecurityHeaders performs a HEAD request and evaluates critical security headers.
// It returns a slice of present security headers, a score based on their presence, and an error.
func (hc *HTTPClient) CheckSecurityHeaders(ctx context.Context, targetURL string) ([]string, int, error) {
	resp, err := hc.SafeHeadRequest(ctx, targetURL)
	if err != nil {
		return nil, 0, err
	}

	var presentHeaders []string
	score := 0
	importantHeaders := map[string]int{
		"Strict-Transport-Security":    20,
		"Content-Security-Policy":      30,
		"X-Frame-Options":              15,
		"X-Content-Type-Options":       10,
		"Referrer-Policy":              10,
		"Permissions-Policy":           10,
		"X-XSS-Protection":             5, // Less critical now, but still useful
	}

	for header, headerScore := range importantHeaders {
		if value := resp.Headers[header]; value != "" {
			presentHeaders = append(presentHeaders, fmt.Sprintf("%s: %s", header, value))
			score += headerScore
		}
	}

	// Deduct points for insecure headers or configurations
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		hc.logger.Warn("Insecure TLS version or no TLS for %s", targetURL)
		score -= 20
		if resp.TLS == nil {
			presentHeaders = append(presentHeaders, "Warning: No TLS connection established")
		} else {
			presentHeaders = append(presentHeaders, fmt.Sprintf("Warning: Insecure TLS version %s", tls.VersionName(resp.TLS.Version)))
		}
	}

	// Check for CSP bypasses or very permissive policies (basic check)
	if csp, ok := resp.Headers["Content-Security-Policy"]; ok {
		cspLower := strings.ToLower(csp)
		if strings.Contains(cspLower, "unsafe-inline") || strings.Contains(cspLower, "unsafe-eval") || strings.Contains(cspLower, "data:") || strings.Contains(cspLower, "'*'") {
			score -= 10 // Reduce score for weak CSP
			presentHeaders = append(presentHeaders, "Warning: Permissive Content-Security-Policy detected")
		}
	}

	// Ensure score doesn't go below zero
	if score < 0 {
		score = 0
	}

	return presentHeaders, score, nil
}