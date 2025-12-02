package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"log" // Using standard log for internal middleware logging, can be replaced by utils.Logger
	"net/http"
	"strings"
	"sync"
	"time"

	"net-zilla/internal/utils" // For logger
)

// Middleware is a function that takes an http.Handler and returns an http.Handler.
type Middleware func(http.Handler) http.Handler

// MiddlewareStack holds configured middleware services.
type MiddlewareStack struct {
	logger *utils.Logger
	// Add other services needed by middleware here (e.g., auth service, rate limiter service)
}

// NewMiddleware creates a new MiddlewareStack.
func NewMiddleware(logger *utils.Logger) *MiddlewareStack {
	return &MiddlewareStack{
		logger: logger,
	}
}

// Chain applies a list of middleware to a http.Handler.
func (ms *MiddlewareStack) Chain(h http.Handler, middleware ...Middleware) http.Handler {
	for i := len(middleware) - 1; i >= 0; i-- {
		h = middleware[i](h)
	}
	return h
}

// LoggerMiddleware logs incoming HTTP requests.
func LoggerMiddleware(logger *utils.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			logger.Info("HTTP Request: %s %s from %s took %v", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
		})
	}
}

// AuthMiddleware handles API key or token authentication.
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			RespondWithError(w, http.StatusUnauthorized, "Authorization token required")
			return
		}

		// TODO: Implement proper token validation logic using a real auth service
		if !isValidToken(token) { // Placeholder validation
			RespondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
			return
		}

		// If token is valid, potentially store user info in context
		ctx := context.WithValue(r.Context(), "user", "authenticated_user")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RateLimitMiddleware applies rate limiting based on client IP.
type RateLimiter struct {
	clients map[string]*Client
	mu      sync.Mutex
	rate    int           // requests per interval
	interval time.Duration // time interval for rate limiting
}

type Client struct {
	lastRequest time.Time
	requests    int
}

// NewRateLimiter creates a new RateLimiter.
func NewRateLimiter(rate int, interval time.Duration) *RateLimiter {
	return &RateLimiter{
		clients: make(map[string]*Client),
		rate: rate,
		interval: interval,
	}
}

// Allow checks if a client is allowed to make a request.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	client, found := rl.clients[ip]
	if !found {
		rl.clients[ip] = &Client{lastRequest: time.Now(), requests: 1}
		return true
	}

	if time.Since(client.lastRequest) > rl.interval {
		client.lastRequest = time.Now()
		client.requests = 1
		return true
	}

	if client.requests < rl.rate {
		client.requests++
		return true
	}

	return false
}

// RateLimitMiddleware applies rate limiting based on client IP.
func RateLimitMiddleware(rateLimit int) Middleware { // Rate limit configurable
	limiter := NewRateLimiter(rateLimit, time.Minute) // Default interval to 1 minute
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := getClientIP(r)
			if !limiter.Allow(clientIP) {
				RespondWithError(w, http.StatusTooManyRequests, "Rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CORSHeaderMiddleware adds CORS headers to responses.
func CORSHeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Helper functions (moved from old middleware.go or added)

func getClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0] // Take the first IP if multiple
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func isValidToken(token string) bool {
	// TODO: Implement proper token validation (e.g., JWT verification, API key lookup)
	return len(token) > 10 // Placeholder: basic length check
}

// RespondWithError sends a JSON error response.
func RespondWithError(w http.ResponseWriter, code int, message string) {
	RespondWithJSON(w, code, map[string]string{"error": message})
}

// RespondWithJSON sends a JSON response.
func RespondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"Failed to marshal JSON response"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}