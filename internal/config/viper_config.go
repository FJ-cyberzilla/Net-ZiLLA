// internal/config/viper_config.go
package config

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all application configurations.
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Security SecurityConfig `mapstructure:"security"`
	Cache    CacheConfig    `mapstructure:"cache"`
	AI       AIConfig       `mapstructure:"ai"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Analysis AnalysisConfig `mapstructure:"analysis"` // Added from internal/ai/config/config.go
	Output   OutputConfig   `mapstructure:"output"`   // Added from internal/ai/config/config.go
}

// ServerConfig defines server-related configurations.
type ServerConfig struct {
	Host      string `mapstructure:"host"`
	Port      int    `mapstructure:"port"`
	Mode      string `mapstructure:"mode"` // development, production
	EnableAPI bool   `mapstructure:"enable_api"`
	EnableCLI bool   `mapstructure:"enable_cli"`
}

// DatabaseConfig defines database-related configurations.
type DatabaseConfig struct {
	Driver   string `mapstructure:"driver"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	Name     string `mapstructure:"name"`
	SSLMode  string `mapstructure:"ssl_mode"`
}

// SecurityConfig defines security-related configurations.
type SecurityConfig struct {
	RateLimit       int           `mapstructure:"rate_limit"`
	RequestTimeout  time.Duration `mapstructure:"request_timeout"` // From internal/ai/config/config.go
	MaxRedirects    int           `mapstructure:"max_redirects"`   // From internal/ai/config/config.go
	EnableTLS       bool          `mapstructure:"enable_tls"`      // From internal/ai/config/config.go
	FollowRedirects bool          `mapstructure:"follow_redirects"` // From internal/ai/config/config.go
	SafeUserAgent   string        `mapstructure:"safe_user_agent"`  // From internal/ai/config/config.go
}

// CacheConfig defines caching-related configurations.
type CacheConfig struct {
	Type     string `mapstructure:"type"` // redis, memory
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

// AIConfig defines AI-related configurations.
type AIConfig struct {
	EnableAI          bool    `mapstructure:"enable_ai"`
	JuliaPath         string  `mapstructure:"julia_path"`        // From internal/ai/config/config.go
	MLModelsPath      string  `mapstructure:"ml_models_path"`    // From internal/ai/config/config.go
	ConfidenceThreshold float64 `mapstructure:"confidence_threshold"`
}

// LoggingConfig defines logging-related configurations.
type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// AnalysisConfig defines analysis-specific configurations.
type AnalysisConfig struct {
	EnableDeepScan  bool          `mapstructure:"enable_deep_scan"`
	CheckBlacklists bool          `mapstructure:"check_blacklists"`
	ValidateSSL     bool          `mapstructure:"validate_ssl"`
	ScanForMalware  bool          `mapstructure:"scan_for_malware"`
	Timeout         time.Duration `mapstructure:"timeout"`
}

// OutputConfig defines output and reporting configurations.
type OutputConfig struct {
	SaveReports  bool   `mapstructure:"save_reports"`
	ReportFormat string `mapstructure:"report_format"`
	ReportPath   string `mapstructure:"report_path"`
	EnableColors bool   `mapstructure:"enable_colors"`
	Verbose      bool   `mapstructure:"verbose"`
}

// Load loads configuration from file, environment variables, and sets defaults.
func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/netzilla/")

	// Set defaults
	setDefaults()

	// Read environment variables
	viper.AutomaticEnv()
	viper.SetEnvPrefix("NETZILLA")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Println("No config file found, using defaults and environment variables")
		} else {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("unable to decode config: %w", err)
	}

	// Validate config
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

// setDefaults sets default values for all configuration fields.
func setDefaults() {
	viper.SetDefault("server.host", "localhost")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.mode", "development")
	viper.SetDefault("server.enable_api", true)
	viper.SetDefault("server.enable_cli", true)

	viper.SetDefault("database.driver", "sqlite3")
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.ssl_mode", "disable")

	viper.SetDefault("security.rate_limit", 100)
	viper.SetDefault("security.request_timeout", 30*time.Second) // New default
	viper.SetDefault("security.max_redirects", 10)               // New default
	viper.SetDefault("security.enable_tls", true)                // New default
	viper.SetDefault("security.follow_redirects", true)          // New default
	viper.SetDefault("security.safe_user_agent", "Mozilla/5.0 (compatible; NetZilla-Security-Scanner/2.1)") // New default

	viper.SetDefault("cache.type", "memory")
	viper.SetDefault("cache.host", "localhost")
	viper.SetDefault("cache.port", 6379)

	viper.SetDefault("ai.enable_ai", true)
	viper.SetDefault("ai.julia_path", "julia")           // New default
	viper.SetDefault("ai.ml_models_path", "./ml/models") // New default
	viper.SetDefault("ai.confidence_threshold", 0.7)

	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")

	viper.SetDefault("analysis.enable_deep_scan", true)
	viper.SetDefault("analysis.check_blacklists", true)
	viper.SetDefault("analysis.validate_ssl", true)
	viper.SetDefault("analysis.scan_for_malware", false) // Default to false for heavy operations
	viper.SetDefault("analysis.timeout", 60*time.Second)

	viper.SetDefault("output.save_reports", true)
	viper.SetDefault("output.report_format", "txt")
	viper.SetDefault("output.report_path", "./reports")
	viper.SetDefault("output.enable_colors", true)
	viper.SetDefault("output.verbose", false)
}

// validateConfig validates the loaded configuration values.
func validateConfig(config *Config) error {
	if config.Server.Port < 1 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	if config.Security.RateLimit < 1 {
		return fmt.Errorf("security.rate_limit must be positive")
	}
	if config.Security.RequestTimeout <= 0 {
		return fmt.Errorf("security.request_timeout must be positive")
	}
	if config.Security.MaxRedirects < 0 {
		return fmt.Errorf("security.max_redirects cannot be negative")
	}

	if config.AI.ConfidenceThreshold < 0 || config.AI.ConfidenceThreshold > 1 {
		return fmt.Errorf("ai.confidence_threshold must be between 0 and 1")
	}
	if config.AI.EnableAI && config.AI.JuliaPath == "" {
		return fmt.Errorf("ai.julia_path cannot be empty if AI is enabled")
	}
	if config.AI.EnableAI && config.AI.MLModelsPath == "" {
		return fmt.Errorf("ai.ml_models_path cannot be empty if AI is enabled")
	}

	if config.Analysis.Timeout <= 0 {
		return fmt.Errorf("analysis.timeout must be positive")
	}
	if config.Output.ReportPath == "" {
		return fmt.Errorf("output.report_path cannot be empty")
	}

	return nil
}