"""Configuration loader for Net-ZiLLA."""
import os
from typing import Any

import yaml


class Config:
    """Handles loading and accessing application configuration."""

    def __init__(self, config_path: str = "config.yaml"):
        """Initialize the Config instance."""
        self.config: dict[str, Any] = self._load_config(config_path)

    def _load_config(self, path: str) -> dict[str, Any]:
        """Load configuration from a YAML file, merging with defaults."""
        defaults = {
            "server": {
                "host": "localhost",
                "port": 8080,
                "mode": "development",
                "enable_api": True,
                "enable_cli": True,
            },
            "database": {
                "driver": "sqlite3",
                "host": "localhost",
                "port": 5432,
                "ssl_mode": "disable",
            },
            "security": {
                "rate_limit": 100,
                "request_timeout": 30,
                "max_redirects": 10,
                "enable_tls": True,
                "follow_redirects": True,
                "safe_user_agent": "Mozilla/5.0 (compatible; NetZilla-Security-Scanner/2.1)",
            },
            "cache": {"type": "memory", "host": "localhost", "port": 6379},
            "ai": {
                "enable_ai": True,
                "julia_path": "julia",
                "ml_models_path": "./ml/models",
                "confidence_threshold": 0.7,
            },
            "logging": {"level": "info", "format": "json"},
            "analysis": {
                "enable_deep_scan": True,
                "check_blacklists": True,
                "validate_ssl": True,
                "scan_for_malware": False,
                "timeout": 60,
            },
            "output": {
                "save_reports": True,
                "report_format": "txt",
                "report_path": "./reports",
                "enable_colors": True,
                "verbose": False,
            },
        }

        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if loaded:
                    self._merge_defaults(defaults, loaded)

        return defaults

    def _merge_defaults(self, base: dict[str, Any], overrides: dict[str, Any]) -> None:
        """Recursively merge overrides into the base dictionary."""
        for key, value in overrides.items():
            if isinstance(value, dict) and key in base:
                self._merge_defaults(base[key], value)
            else:
                base[key] = value

    def get(self, key_path: str, default: Any = None) -> Any:
        """Retrieve a configuration value using a dot-separated path."""
        keys = key_path.split(".")
        val: Any = self.config
        for key in keys:
            if isinstance(val, dict) and key in val:
                val = val[key]
            else:
                return default
        return val


# Global instance
config = Config()
