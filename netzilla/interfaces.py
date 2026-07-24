"""
All protocols (interfaces) for NetZilla.
No implementations - just contracts and data models.
"""

from datetime import datetime
from enum import Enum
from typing import Protocol, runtime_checkable, Any

from pydantic import BaseModel, Field

# ──────────────────────────────────────────────
# Domain Models (shared across all layers)
# ──────────────────────────────────────────────


class RiskLevel(str, Enum):
    """Represents the severity level of detected threats."""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class URLFeatures(BaseModel):
    """All extractable features from a URL."""

    url: str
    length: int = Field(gt=0)
    entropy: float = Field(ge=0.0)
    tld: str
    tld_risk: float = Field(ge=0.0, le=1.0)
    has_ip: bool
    has_suspicious_tld: bool
    special_char_count: int = Field(ge=0)
    digit_ratio: float = Field(ge=0.0, le=1.0)
    subdomain_count: int = Field(ge=0)
    path_depth: int = Field(ge=0)
    has_redirect_param: bool
    suspicious_keywords: list[str]


class CertificateInfo(BaseModel):
    """SSL/TLS certificate details."""

    verified: bool
    issuer: str
    subject: str
    valid_from: datetime
    valid_until: datetime
    days_until_expiry: int
    chain_valid: bool
    protocol: str
    cipher: str
    errors: list[str]


class DomainInfo(BaseModel):
    """Domain registration and DNS details."""

    domain: str
    registrar: str | None = None
    created_date: datetime | None = None
    expiry_date: datetime | None = None
    days_old: int | None = None
    is_newly_registered: bool
    nameservers: list[str]
    a_records: list[str]
    mx_records: list[str]
    txt_records: list[str]


class IPInfo(BaseModel):
    """IP address intelligence."""

    ip: str
    is_private: bool
    is_known_malicious: bool
    country: str | None = None
    asn: str | None = None
    hosting_provider: str | None = None
    is_proxy: bool
    is_vpn: bool
    is_tor: bool
    reputation_score: float = Field(ge=0.0, le=1.0)  # 0.0 (malicious) - 1.0 (trusted)


class RedirectHop(BaseModel):
    """Single hop in a redirect chain."""

    url: str
    status_code: int
    headers: dict[str, str]
    response_time_ms: float = Field(ge=0.0)


class ContentAnalysis(BaseModel):
    """Analysis of page content."""

    has_login_form: bool
    external_domains: list[str]
    mentioned_brands: list[str]
    obfuscated_scripts: bool
    iframe_count: int = Field(ge=0)
    form_actions: list[str]
    risk_indicators: list[str]
    word_count: int = Field(ge=0, default=0)
    language: str = "unknown"
    suspicious_elements: list[str] = Field(default_factory=list)
    security_headers: dict[str, str] = Field(default_factory=dict)
    load_time: float = Field(ge=0.0, default=0.0)
    content_type: str = ""


class AnalysisResult(BaseModel):
    """Final output from the analyzer aggregating all analysis data."""

    url: str
    normalized_url: str
    final_score: float = Field(ge=0.0, le=100.0)
    risk_level: RiskLevel
    is_safe: bool
    confidence: float = Field(ge=0.0, le=1.0)
    url_features: URLFeatures
    certificate: CertificateInfo | None = None
    domain: DomainInfo | None = None
    ip: IPInfo | None = None
    redirects: list[RedirectHop]
    content: ContentAnalysis | None = None
    threats: list[str]
    recommendations: list[str]
    analysis_duration_ms: float = Field(ge=0.0)
    timestamp: datetime


# ──────────────────────────────────────────────
# Detector Protocols
# ──────────────────────────────────────────────


@runtime_checkable
class URLDetector(Protocol):
    """Analyzes URL structure for threats."""

    def analyze(self, url: str) -> URLFeatures:
        """Extract all features from a URL."""

    def score(self, features: URLFeatures) -> float:
        """Convert features to a risk score (0-100)."""


@runtime_checkable
class PhishingDetector(Protocol):
    """Detects phishing attempts in URLs and content."""

    def analyze(
        self,
        url: str,
        content: str | None = None,
        redirects: list[RedirectHop] | None = None,
    ) -> float:
        """Return phishing probability score (0-100)."""
        raise NotImplementedError()

    def get_indicators(self, url: str) -> list[str]:
        """Return list of phishing indicators found."""
        raise NotImplementedError()


@runtime_checkable
class SMSDetector(Protocol):
    """Analyzes SMS messages for scams."""

    def analyze(self, message: str) -> float:
        """Return scam probability score (0-100)."""
        raise NotImplementedError()

    def extract_urls(self, message: str) -> list[str]:
        """Extract URLs from SMS text."""
        raise NotImplementedError()

    def classify_tactic(self, message: str) -> str:
        """Classify the scam tactic used."""
        raise NotImplementedError()


@runtime_checkable
class MalwareDetector(Protocol):
    """Detects malware indicators in URLs and downloads."""

    def analyze_url(self, url: str) -> float:
        """Check URL for malware patterns."""
        raise NotImplementedError()

    def analyze_file(self, file_path: str) -> float:
        """Scan file for malware signatures."""
        raise NotImplementedError()


@runtime_checkable
class BrandImpersonationDetector(Protocol):
    """Detects brand impersonation attempts."""

    def analyze(self, url: str, content: str | None = None) -> list[str]:
        """Return list of impersonated brands detected."""
        raise NotImplementedError()

    def similarity_score(self, url: str, brand: str) -> float:
        """Calculate visual similarity to a brand domain."""
        raise NotImplementedError()


# ──────────────────────────────────────────────
# Network Client Protocols
# ──────────────────────────────────────────────


@runtime_checkable
class DNSClient(Protocol):
    """DNS resolution and record lookup."""

    async def resolve_a(self, domain: str) -> list[str]:
        """Resolve A records."""
        raise NotImplementedError()

    async def resolve_mx(self, domain: str) -> list[str]:
        """Resolve MX records."""
        raise NotImplementedError()

    async def resolve_txt(self, domain: str) -> list[str]:
        """Resolve TXT records."""
        raise NotImplementedError()

    async def resolve_ns(self, domain: str) -> list[str]:
        """Resolve NS records."""
        raise NotImplementedError()


@runtime_checkable
class WHOISClient(Protocol):
    """WHOIS domain registration lookup."""

    async def lookup(self, domain: str) -> DomainInfo:
        """Get domain registration information."""
        raise NotImplementedError()


@runtime_checkable
class SSLClient(Protocol):
    """SSL/TLS certificate verification."""

    async def verify(self, hostname: str, port: int = 443) -> CertificateInfo:
        """Verify SSL certificate and return details."""
        raise NotImplementedError()


@runtime_checkable
class IPReputationClient(Protocol):
    """IP address reputation and intelligence."""

    async def check(self, ip: str) -> IPInfo:
        """Get IP reputation data."""
        raise NotImplementedError()


@runtime_checkable
class HTTPClient(Protocol):
    """HTTP client for fetching page content."""

    async def get(
        self, url: str, follow_redirects: bool = True
    ) -> tuple[str, list[RedirectHop]]:
        """Fetch URL content and return (body, redirect_chain)."""
        raise NotImplementedError()

    async def head(self, url: str) -> dict[str, str]:
        """Get HTTP headers only."""
        raise NotImplementedError()


# ──────────────────────────────────────────────
# Reporter Protocol
# ──────────────────────────────────────────────


@runtime_checkable
class Reporter(Protocol):
    """Generates analysis reports in various formats."""

    def generate(self, result: AnalysisResult) -> str:
        """Generate a report string."""
        raise NotImplementedError()

    def to_json(self, result: AnalysisResult) -> str:
        """Export as JSON."""
        raise NotImplementedError()

    def to_dict(self, result: AnalysisResult) -> dict[str, Any]:
        """Export as dictionary."""
        raise NotImplementedError()
