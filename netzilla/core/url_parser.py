"""URL analysis and feature extraction module for Net-ZiLLA."""

import math
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Tuple
from urllib.parse import parse_qsl, urlparse

from netzilla.interfaces import URLDetector, URLFeatures


@dataclass
class ParsedURL:
    """Representation of a parsed URL with extracted components."""

    original: str
    normalized: str
    scheme: str
    domain: str
    subdomain: str
    tld: str
    path: str
    query_params: dict[str, str] = field(default_factory=dict)
    is_shortened: bool = False
    is_obfuscated: bool = False
    has_ip: bool = False


class URLParser(URLDetector):
    """Detector implementation for analyzing URL features and assessing risk."""

    def __init__(self) -> None:
        self.shortener_patterns = [
            re.compile(r"^bit\.ly$"),
            re.compile(r"^tinyurl\.com$"),
            re.compile(r"^goo\.gl$"),
            re.compile(r"^ow\.ly$"),
            re.compile(r"^t\.co$"),
            re.compile(r"^buff\.ly$"),
        ]
        self.obfuscation_patterns = [
            re.compile(r"%[0-9A-Fa-f]{2}"),
            re.compile(r"@"),
            re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
        ]
        self.ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        self.suspicious_tlds = {"zip", "mov", "app", "run", "xyz", "top"}

    def analyze(self, url: str) -> URLFeatures:
        """Analyzes a URL and extracts security features."""
        normalized = self._normalize_url(url)
        u = urlparse(normalized)
        subdomain, tld = self._extract_domain_parts(u.hostname or "")

        # Calculate features
        entropy = self.calculate_entropy(url)
        has_ip = self._contains_ip_address(u.hostname or "")

        tld_risk, has_suspicious_tld = self._calculate_tld_features(tld)
        suspicious_keywords = self._calculate_keyword_features(url)
        has_redirect_param = self._calculate_redirect_features(u.query)

        return URLFeatures(
            url=normalized,
            length=len(url),
            entropy=entropy,
            tld=tld,
            tld_risk=tld_risk,
            has_ip=has_ip,
            has_suspicious_tld=has_suspicious_tld,
            special_char_count=sum(1 for c in url if not c.isalnum()),
            digit_ratio=sum(1 for c in url if c.isdigit()) / len(url) if url else 0.0,
            subdomain_count=len(subdomain.split(".")) if subdomain else 0,
            path_depth=len(u.path.strip("/").split("/")) if u.path.strip("/") else 0,
            has_redirect_param=has_redirect_param,
            suspicious_keywords=suspicious_keywords,
        )

    def _calculate_tld_features(self, tld: str) -> tuple[float, bool]:
        """Calculates risk features related to the TLD."""
        has_suspicious_tld = tld in self.suspicious_tlds
        return (0.8 if has_suspicious_tld else 0.1, has_suspicious_tld)

    def _calculate_keyword_features(self, url: str) -> list[str]:
        """Extracts suspicious keywords found in the URL."""
        keywords = ["login", "verify", "account", "bank", "secure", "update", "paypal"]
        return [kw for kw in keywords if kw in url.lower()]

    def _calculate_redirect_features(self, query: str) -> bool:
        """Checks for presence of common redirect parameters."""
        query_params = dict(parse_qsl(query))
        return any(k in ["url", "redirect", "next", "target"] for k in query_params)

    def score(self, features: URLFeatures) -> float:
        """Calculates a threat score based on extracted features."""
        score = 0.0
        if features.has_ip:
            score += 40
        if features.has_suspicious_tld:
            score += 30
        if features.entropy > 4.5:
            score += 20
        if features.has_redirect_param:
            score += 15
        score += len(features.suspicious_keywords) * 10
        if features.length > 100:
            score += 10

        return min(score, 100.0)

    def parse_and_analyze(self, raw_url: str) -> ParsedURL | None:
        """Parses and analyzes a raw URL string."""
        try:
            normalized = self._normalize_url(raw_url)
            u = urlparse(normalized)

            subdomain, tld = self._extract_domain_parts(u.hostname or "")

            parsed = ParsedURL(
                original=raw_url,
                normalized=normalized,
                scheme=u.scheme or "",
                domain=u.hostname or "",
                subdomain=subdomain,
                tld=tld,
                path=u.path or "",
                query_params=dict(parse_qsl(u.query)),
            )

            parsed.is_shortened = self._is_shortened_url(u.hostname or "")
            parsed.is_obfuscated = self._is_obfuscated_url(normalized)
            parsed.has_ip = self._contains_ip_address(u.hostname or "")

            return parsed
        except Exception:
            return None

    def _normalize_url(self, raw_url: str) -> str:
        """Normalizes a URL string."""
        if "://" not in raw_url:
            raw_url = "https://" + raw_url

        u = urlparse(raw_url)
        # Normalize host to lowercase
        host = u.hostname.lower() if u.hostname else ""

        # Remove default ports
        host = host.replace(":80", "").replace(":443", "")

        # Reconstruct URL (simplistic)
        return f"{u.scheme}://{host}{u.path}"

    def _extract_domain_parts(self, host: str) -> tuple[str, str]:
        """Extracts subdomain and TLD from a host string."""
        parts = host.split(".")
        if len(parts) < 2:
            return "", host

        tld = parts[-1]
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""

        return subdomain, tld

    def _is_shortened_url(self, host: str) -> bool:
        """Checks if the host is a known URL shortener."""
        for pattern in self.shortener_patterns:
            if pattern.match(host):
                return True
        return False

    def _is_obfuscated_url(self, full_url: str) -> bool:
        """Checks if the URL contains obfuscation patterns."""
        for pattern in self.obfuscation_patterns:
            if pattern.search(full_url):
                return True
        return False

    def _contains_ip_address(self, host: str) -> bool:
        """Checks if the host is an IP address."""
        return bool(self.ip_pattern.match(host))

    def calculate_entropy(self, s: str) -> float:
        """Calculates Shannon entropy of a string."""
        freq: dict[str, int] = {}
        for char in s:
            freq[char] = freq.get(char, 0) + 1

        entropy = 0.0
        length = float(len(s))
        for count in freq.values():
            prob = count / length
            entropy -= prob * math.log2(prob)

        return entropy

    def detect_homograph_attack(self, domain: str) -> bool:
        """Detects potential homograph attacks in a domain."""
        scripts = set()
        for char in domain:
            try:
                name = unicodedata.name(char)
                if "CYRILLIC" in name:
                    scripts.add("CYRILLIC")
                elif "GREEK" in name:
                    scripts.add("GREEK")
                elif "LATIN" in name:
                    scripts.add("LATIN")
            except ValueError:
                continue

        return len(scripts) > 1
