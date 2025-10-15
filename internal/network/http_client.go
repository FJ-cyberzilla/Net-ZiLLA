// internal/network/http_client.go
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
)

type SafeHTTPClient struct {
	client    *http.Client
	userAgent string
}

type HTTPResponse struct {
	StatusCode    int
	Headers       map[string]string
	ContentType   string
	ContentLength int64
	Server        string
	Cookies       []*http.Cookie
	Redirects     []string
	LoadTime      time.Duration
}

func NewSafeHTTPClient() *SafeHTTPClient {
	return &SafeHTTPClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Limit redirects
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
					MinVersion:         tls.VersionTLS12,
				},
				MaxIdleConns:        100,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
		userAgent: "Mozilla/5.0 (compatible; NetZilla-Security-Scanner/2.1)",
	}
}

func (s *SafeHTTPClient) SafeHeadRequest(targetURL string) (*HTTPResponse, error) {
	return s.safeRequest("HEAD", targetURL)
}

func (s *SafeHTTPClient) SafeGetRequest(targetURL string) (*HTTPResponse, error) {
	return s.safeRequest("GET", targetURL)
}

func (s *SafeHTTPClient) safeRequest(method, targetURL string) (*HTTPResponse, error) {
	start := time.Now()

	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set secure headers
	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "close") // Prevent connection reuse

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read limited content for GET requests
	var contentLength int64
	if method == "GET" {
		// Read only first few KB to determine content type
		limitedReader := io.LimitReader(resp.Body, 1024)
		_, _ = io.ReadAll(limitedReader)
		contentLength = resp.ContentLength
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
	}

	return response, nil
}

func (s *SafeHTTPClient) CheckSecurityHeaders(targetURL string) (map[string]string, error) {
	resp, err := s.SafeHeadRequest(targetURL)
	if err != nil {
		return nil, err
	}

	securityHeaders := make(map[string]string)
	importantHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
	}

	for _, header := range importantHeaders {
		if value, exists := resp.Headers[header]; exists {
			securityHeaders[header] = value
		}
	}

	return securityHeaders, nil
}

func (s *SafeHTTPClient) ExtractRedirectChain(targetURL string) ([]string, error) {
	var redirects []string
	currentURL := targetURL

	for i := 0; i < 10; i++ {
		resp, err := s.SafeHeadRequest(currentURL)
		if err != nil {
			return redirects, err
		}

		redirects = append(redirects, currentURL)

		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			break // Not a redirect
		}

		location := resp.Headers["Location"]
		if location == "" {
			break
		}

		// Resolve relative URLs
		base, err := url.Parse(currentURL)
		if err != nil {
			return redirects, err
		}

		next, err := url.Parse(location)
		if err != nil {
			return redirects, err
		}

		currentURL = base.ResolveReference(next).String()
	}

	return redirects, nil
}
