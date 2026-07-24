import os
import yaml
from typing import Any, Dict

class Config:
    def __init__(self, config_path: str = "config.yaml"):
        self.config: Dict[str, Any] = self._load_config(config_path)

    def _load_config(self, path: str) -> Dict[str, Any]:
        defaults = {
            "server": {"host": "localhost", "port": 8080, "mode": "development", "enable_api": True, "enable_cli": True},
            "database": {"driver": "sqlite3", "host": "localhost", "port": 5432, "ssl_mode": "disable"},
            "security": {
                "rate_limit": 100,
                "request_timeout": 30,
                "max_redirects": 10,
                "enable_tls": True,
                "follow_redirects": True,
                "safe_user_agent": "Mozilla/5.0 (compatible; NetZilla-Security-Scanner/2.1)"
            },
            "cache": {"type": "memory", "host": "localhost", "port": 6379},
            "ai": {
                "enable_ai": True,
                "julia_path": "julia",
                "ml_models_path": "./ml/models",
                "confidence_threshold": 0.7
            },
            "logging": {"level": "info", "format": "json"},
            "analysis": {
                "enable_deep_scan": True,
                "check_blacklists": True,
                "validate_ssl": True,
                "scan_for_malware": False,
                "timeout": 60
            },
            "output": {
                "save_reports": True,
                "report_format": "txt",
                "report_path": "./reports",
                "enable_colors": True,
                "verbose": False
            }
        }
        
        if os.path.exists(path):
            with open(path, 'r') as f:
                loaded = yaml.safe_load(f)
                if loaded:
                    self._merge_defaults(defaults, loaded)
        
        return defaults

    def _merge_defaults(self, base, overrides):
        for key, value in overrides.items():
            if isinstance(value, dict) and key in base:
                self._merge_defaults(base[key], value)
            else:
                base[key] = value

    def get(self, key_path: str, default: Any = None) -> Any:
        keys = key_path.split('.')
        val = self.config
        for key in keys:
            if isinstance(val, dict) and key in val:
                val = val[key]
            else:
                return default
        return val

# Global instance
config = Config()
