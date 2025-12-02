package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"net-zilla/internal/analyzer"
	"net-zilla/internal/config"
	"net-zilla/internal/middleware"
	"net-zilla/internal/utils"
)

// APIServer represents the HTTP API server for Net-Zilla.
type APIServer struct {
	server         *http.Server
	threatAnalyzer *analyzer.ThreatAnalyzer
	logger         *utils.Logger
	config         *config.Config
	middleware     *middleware.MiddlewareStack
}

// NewServer creates and initializes a new APIServer instance.
func NewServer(threatAnalyzer *analyzer.ThreatAnalyzer, logger *utils.Logger, cfg *config.Config) *APIServer {
	mux := http.NewServeMux()

	serverAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	server := &APIServer{
		threatAnalyzer: threatAnalyzer,
		logger:         logger,
		config:         cfg,
		middleware:     middleware.NewMiddleware(logger),
		server: &http.Server{
			Addr:         serverAddr,
			Handler:      mux,
			ReadTimeout:  cfg.Security.RequestTimeout,
			WriteTimeout: cfg.Security.RequestTimeout,
			IdleTimeout:  cfg.Security.RequestTimeout * 2,
		},
	}

	server.setupRoutes(mux)
	return server
}

// setupRoutes configures the HTTP endpoints and applies middleware.
func (s *APIServer) setupRoutes(mux *http.ServeMux) {
	// Analysis endpoints
	mux.Handle("/api/v1/analyze/url",
		s.middleware.Chain(http.HandlerFunc(s.analyzeURLHandler),
			middleware.LoggerMiddleware(s.logger),
			middleware.AuthMiddleware,
			middleware.RateLimitMiddleware(s.config.Security.RateLimit)))

	mux.Handle("/api/v1/analyze/sms",
		s.middleware.Chain(http.HandlerFunc(s.analyzeSMSHandler),
			middleware.LoggerMiddleware(s.logger),
			middleware.AuthMiddleware,
			middleware.RateLimitMiddleware(s.config.Security.RateLimit)))

	// Assuming a batch analysis handler, if implemented
	mux.Handle("/api/v1/analyze/batch",
		s.middleware.Chain(http.HandlerFunc(s.batchAnalyzeHandler),
			middleware.LoggerMiddleware(s.logger),
			middleware.AuthMiddleware,
			middleware.RateLimitMiddleware(s.config.Security.RateLimit)))

	// System endpoints
	mux.Handle("/api/v1/health", s.middleware.Chain(
		http.HandlerFunc(s.healthCheckHandler), middleware.LoggerMiddleware(s.logger)))

	mux.Handle("/api/v1/metrics", s.middleware.Chain(
		http.HandlerFunc(s.getMetricsHandler), middleware.LoggerMiddleware(s.logger), middleware.AuthMiddleware))

	// Catch-all for undefined routes
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.logger.Warn("Unhandled API route: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	})
}

// Run starts the API server and listens for shutdown signals.
func (s *APIServer) Run(ctx context.Context) error {
	s.logger.Info("🚀 Net-Zilla API server starting on %s", s.server.Addr)

	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("API server failed to listen: %v", err)
		}
	}()

	// Wait for context cancellation (e.g., from graceful shutdown)
	<-ctx.Done()

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()

	s.logger.Info("Shutting down API server...")
	if err := s.server.Shutdown(shutdownCtx); err != nil {
		s.logger.Error("API server graceful shutdown failed: %v", err)
		return err
	}
	s.logger.Info("API server shut down gracefully.")
	return nil
}

// Placeholder HTTP Handlers (to be implemented)
func (s *APIServer) analyzeURLHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement actual URL analysis logic using s.threatAnalyzer
	middleware.RespondWithError(w, http.StatusNotImplemented, "URL analysis not yet fully implemented")
}

func (s *APIServer) analyzeSMSHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement actual SMS analysis logic using s.threatAnalyzer
	middleware.RespondWithError(w, http.StatusNotImplemented, "SMS analysis not yet fully implemented")
}

func (s *APIServer) batchAnalyzeHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement actual batch analysis logic
	middleware.RespondWithError(w, http.StatusNotImplemented, "Batch analysis not yet fully implemented")
}

func (s *APIServer) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement actual health check, potentially using s.threatAnalyzer.mlAgent.SystemDiagnostics
	middleware.RespondWithJSON(w, http.StatusOK, map[string]string{"status": "UP", "message": "API server is running"})
}

func (s *APIServer) getMetricsHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement metrics retrieval, possibly from internal/monitoring/metrics.go
	middleware.RespondWithError(w, http.StatusNotImplemented, "Metrics endpoint not yet implemented")
}