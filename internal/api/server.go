// internal/api/server.go
package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"net-zilla/internal/analyzer"
	"net-zilla/internal/middleware"
)

type APIServer struct {
	server     *http.Server
	analyzer   *analyzer.ThreatAnalyzer
	middleware *middleware.Middleware
}

func NewAPIServer(analyzer *analyzer.ThreatAnalyzer) *APIServer {
	mux := http.NewServeMux()
	
	server := &APIServer{
		analyzer: analyzer,
		middleware: middleware.NewMiddleware(),
		server: &http.Server{
			Addr:         ":8080",
			Handler:      mux,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
	}

	server.setupRoutes(mux)
	return server
}

func (s *APIServer) setupRoutes(mux *http.ServeMux) {
	// Analysis endpoints
	mux.Handle("/api/v1/analyze/url", 
		s.middleware.Chain(http.HandlerFunc(s.analyzeURL), 
			middleware.Logger, middleware.Auth, middleware.RateLimit))
	
	mux.Handle("/api/v1/analyze/sms", 
		s.middleware.Chain(http.HandlerFunc(s.analyzeSMS),
			middleware.Logger, middleware.Auth, middleware.RateLimit))
	
	mux.Handle("/api/v1/analyze/batch", 
		s.middleware.Chain(http.HandlerFunc(s.batchAnalyze),
			middleware.Logger, middleware.Auth, middleware.RateLimit))

	// System endpoints
	mux.Handle("/api/v1/health", s.middleware.Chain(
		http.HandlerFunc(s.healthCheck), middleware.Logger))
	
	mux.Handle("/api/v1/metrics", s.middleware.Chain(
		http.HandlerFunc(s.getMetrics), middleware.Logger, middleware.Auth))
}

func (s *APIServer) Start() error {
	log.Printf("🚀 Net-Zilla API server starting on %s", s.server.Addr)
	return s.server.ListenAndServe()
}

func (s *APIServer) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
