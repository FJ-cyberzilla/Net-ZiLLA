import re
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qsl
import unicodedata

@dataclass
class ParsedURL:
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

class URLParser:
    def __init__(self):
        self.shortener_patterns = [
            re.compile(r'^bit\.ly$'),
            re.compile(r'^tinyurl\.com$'),
            re.compile(r'^goo\.gl$'),
            re.compile(r'^ow\.ly$'),
            re.compile(r'^t\.co$'),
            re.compile(r'^buff\.ly$'),
        ]
        self.obfuscation_patterns = [
            re.compile(r'%[0-9A-Fa-f]{2}'),
            re.compile(r'@'),
            re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
        ]
        self.ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

    def parse_and_analyze(self, raw_url: str) -> ParsedURL | None:
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
                query_params=dict(parse_qsl(u.query))
            )
            
            parsed.is_shortened = self._is_shortened_url(u.hostname or "")
            parsed.is_obfuscated = self._is_obfuscated_url(normalized)
            parsed.has_ip = self._contains_ip_address(u.hostname or "")
            
            return parsed
        except Exception:
            return None

    def _normalize_url(self, raw_url: str) -> str:
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
        parts = host.split(".")
        if len(parts) < 2:
            return "", host
        
        tld = parts[-1]
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
        
        return subdomain, tld

    def _is_shortened_url(self, host: str) -> bool:
        for pattern in self.shortener_patterns:
            if pattern.match(host):
                return True
        return False

    def _is_obfuscated_url(self, full_url: str) -> bool:
        for pattern in self.obfuscation_patterns:
            if pattern.search(full_url):
                return True
        return False

    def _contains_ip_address(self, host: str) -> bool:
        return bool(self.ip_pattern.match(host))

    def calculate_entropy(self, s: str) -> float:
        freq = {}
        for char in s:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0.0
        length = float(len(s))
        for count in freq.values():
            prob = count / length
            entropy -= prob * prob
        
        return entropy

    def detect_homograph_attack(self, domain: str) -> bool:
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
