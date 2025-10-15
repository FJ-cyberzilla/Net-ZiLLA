package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Security SecurityConfig
	AI       AIConfig
	Analysis AnalysisConfig
	Output   OutputConfig
}

type SecurityConfig struct {
	SafeUserAgent    string
	RequestTimeout   time.Duration
	MaxRedirects     int
	EnableTLS        bool
	FollowRedirects  bool
}

type AIConfig struct {
	JuliaPath       string
	MLModelsPath    string
	EnableAI        bool
	ConfidenceThreshold float64
}

type AnalysisConfig struct {
	EnableDeepScan    bool
	CheckBlacklists   bool
	ValidateSSL       bool
	ScanForMalware    bool
	Timeout           time.Duration
}

type OutputConfig struct {
	SaveReports    bool
	ReportFormat   string
	ReportPath     string
	EnableColors   bool
	Verbose        bool
}

func Load() *Config {
	return &Config{
		Security: SecurityConfig{
			SafeUserAgent:   "Mozilla/5.0 (compatible; NetZilla-Security-Scanner/2.1)",
			RequestTimeout:  30 * time.Second,
			MaxRedirects:    10,
			EnableTLS:       true,
			FollowRedirects: true,
		},
		AI: AIConfig{
			JuliaPath:          getEnv("JULIA_PATH", "julia"),
			MLModelsPath:       getEnv("ML_MODELS_PATH", "./ml/models"),
			EnableAI:           getEnvBool("ENABLE_AI", true),
			ConfidenceThreshold: getEnvFloat("AI_CONFIDENCE_THRESHOLD", 0.7),
		},
		Analysis: AnalysisConfig{
			EnableDeepScan:   getEnvBool("DEEP_SCAN", true),
			CheckBlacklists:  getEnvBool("CHECK_BLACKLISTS", true),
			ValidateSSL:      getEnvBool("VALIDATE_SSL", true),
			ScanForMalware:   getEnvBool("SCAN_MALWARE", true),
			Timeout:          getEnvDuration("ANALYSIS_TIMEOUT", 60*time.Second),
		},
		Output: OutputConfig{
			SaveReports:  getEnvBool("SAVE_REPORTS", true),
			ReportFormat: getEnv("REPORT_FORMAT", "txt"),
			ReportPath:   getEnv("REPORT_PATH", "./reports"),
			EnableColors: getEnvBool("ENABLE_COLORS", true),
			Verbose:      getEnvBool("VERBOSE", false),
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getEnvFloat(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseFloat(value, 64); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}
