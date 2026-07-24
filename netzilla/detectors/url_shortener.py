"""
URL Shortener detector implementation.
Adheres to URLDetector protocol.
"""

import math
import re
from urllib.parse import urlparse

import structlog

from netzilla.interfaces import URLFeatures

logger = structlog.get_logger(__name__)

# Common URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly",
    "t.co",
    "goo.gl",
    "tinyurl.com",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "v.gd",
    "j.mp",
}

# Suspicious keywords for phishing/malware
SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "secure",
    "verify",
    "update",
    "account",
    "bank",
    "free",
    "winner",
    "prize",
]


class URLShortenerDetector:
    """Detects and analyzes shortened URLs."""

    def analyze(self, url: str) -> URLFeatures:
        """Extract all features from a URL."""
        logger.debug("Analyzing URL", url=url)
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        path = parsed.path

        # Calculate features
        length = len(url)
        has_ip = self._is_ip_address(domain)
        tld = self._get_tld(domain)

        features = URLFeatures(
            url=url,
            length=length,
            entropy=self._calculate_entropy(url),
            tld=tld,
            tld_risk=0.5 if tld in ["xyz", "top", "icu"] else 0.1,
            has_ip=has_ip,
            has_suspicious_tld=tld in ["xyz", "top", "icu"],
            special_char_count=len(re.findall(r"[^a-zA-Z0-9]", url)),
            digit_ratio=len(re.findall(r"\d", url)) / length if length > 0 else 0,
            subdomain_count=len(domain.split(".")) - 2 if "." in domain else 0,
            path_depth=len(path.strip("/").split("/")),
            has_redirect_param=any(q in url for q in ["redirect=", "url=", "next="]),
            suspicious_keywords=[kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()],
        )
        return features

    def score(self, features: URLFeatures) -> float:
        """Convert features to a risk score (0-100)."""
        score = 0.0

        # Shortener domains get a baseline risk
        if any(domain in features.url for domain in SHORTENER_DOMAINS):
            score += 40.0

        # Add risk based on other features
        if features.has_ip:
            score += 30.0
        if features.has_suspicious_tld:
            score += 20.0
        if features.has_redirect_param:
            score += 20.0

        return min(score, 100.0)

    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address."""
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))

    def _get_tld(self, domain: str) -> str:
        """Extract TLD from domain."""
        return domain.split(".")[-1] if "." in domain else ""

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        probabilities = [float(text.count(c)) / len(text) for c in dict.fromkeys(text)]
        entropy = -sum([p * math.log(p, 2) for p in probabilities])
        return entropy
