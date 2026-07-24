"""
Main orchestrator - composes all detectors and network clients.
Fully testable via dependency injection.
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import Any, Optional
from urllib.parse import urlparse

import structlog
from tldextract import extract

from netzilla.interfaces import (
    URLDetector,
    PhishingDetector,
    MalwareDetector,
    BrandImpersonationDetector,
    DNSClient,
    WHOISClient,
    SSLClient,
    IPReputationClient,
    HTTPClient,
    Reporter,
    AnalysisResult,
    RiskLevel,
    CertificateInfo,
    DomainInfo,
)
from netzilla.core.content_analyzer import ContentAnalyzer

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------
class NetzillaError(Exception):
    """Base exception for all Netzilla operations."""


class HttpRequestError(NetzillaError):
    """Raised when an HTTP request fails."""


class DNSResolutionError(NetzillaError):
    """Raised when a DNS lookup fails."""


# ---------------------------------------------------------------------------
# Grouped dependencies
# ---------------------------------------------------------------------------
@dataclass
class NetworkClients:
    """Optional network‑level clients."""
    dns: DNSClient | None = None
    whois: WHOISClient | None = None
    ssl: SSLClient | None = None
    ip: IPReputationClient | None = None


@dataclass
class Services:
    """All optional services."""
    malware_detector: MalwareDetector | None = None
    brand_detector: BrandImpersonationDetector | None = None
    content_analyzer: ContentAnalyzer | None = None
    http_client: HTTPClient | None = None
    reporter: Reporter | None = None
    network: NetworkClients = field(default_factory=NetworkClients)


# ---------------------------------------------------------------------------
# Context sub‑objects
# ---------------------------------------------------------------------------
@dataclass
class RiskAssessment:
    """Aggregated risk scores and classification."""
    url_score: float = 0.0
    phishing_score: float = 0.0
    malware_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.SAFE
    confidence: float = 0.5


@dataclass
class ThreatContext:
    """Collected threats and recommendations."""
    threats: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    impersonated_brands: list[str] = field(default_factory=list)


@dataclass
class NetworkContext:
    """Results of network checks."""
    cert_info: Optional[CertificateInfo] = None
    domain_info: Optional[DomainInfo] = None
    ip_info: Any = None


@dataclass
class PageContext:
    """Fetched page content and analysis."""
    content: str | None = None
    redirects: list[Any] = field(default_factory=list)
    content_analysis: Any = None


@dataclass
class AnalysisContext:
    """Holds all intermediate data collected during analysis."""
    url: str
    risk: RiskAssessment = field(default_factory=RiskAssessment)
    threats: ThreatContext = field(default_factory=ThreatContext)
    network: NetworkContext = field(default_factory=NetworkContext)
    page: PageContext = field(default_factory=PageContext)

    def to_result(self, features: Any, elapsed_ms: float) -> AnalysisResult:
        """Build the final AnalysisResult from gathered data."""
        return AnalysisResult(
            url=self.url,
            normalized_url=features.url,
            final_score=self.risk.url_score,
            risk_level=self.risk.risk_level,
            is_safe=self.risk.url_score < 30,
            confidence=self.risk.confidence,
            url_features=features,
            certificate=self.network.cert_info,
            domain=self.network.domain_info,
            ip=self.network.ip_info,
            redirects=self.page.redirects,
            content=self.page.content_analysis,
            threats=self.threats.threats,
            recommendations=self.threats.recommendations,
            analysis_duration_ms=elapsed_ms,
            timestamp=datetime.now(UTC),
        )


# ---------------------------------------------------------------------------
# Main Analyzer
# ---------------------------------------------------------------------------
class Analyzer:
    """Main analysis orchestrator with injected dependencies."""

    def __init__(self, url_detector: URLDetector, phishing_detector: PhishingDetector,
                 services: Services | None = None) -> None:
        self._url = url_detector
        self._phishing = phishing_detector
        self._services = services or Services()
        logger.debug("Analyzer initialized")

    async def analyze(self, url: str) -> AnalysisResult:
        """Run full analysis on a URL."""
        logger.info("Starting analysis", url=url)
        start_time = time.monotonic()

        ctx = AnalysisContext(url=url)
        await self._run_all_phases(url, ctx)

        elapsed = (time.monotonic() - start_time) * 1000
        logger.info("Analysis completed", score=ctx.risk.url_score,
                    risk=ctx.risk.risk_level, elapsed=elapsed)
        return ctx.to_result(self._url.analyze(url), elapsed)

    async def shutdown(self) -> None:
        """Clean up any resources."""
        logger.debug("Analyzer shutdown")

    # ------------------------------------------------------------------
    # Phase execution
    # ------------------------------------------------------------------
    async def _run_all_phases(self, url: str, ctx: AnalysisContext) -> None:
        """Execute analysis phases, updating context in place."""
        features = self._url.analyze(url)
        ctx.risk.url_score = self._url.score(features)
        self._collect_url_threats(features, ctx)

        domain = self._extract_domain(url)
        net_results = await self._perform_network_checks(domain, url)
        ctx.network.cert_info = self._safe_certificate(net_results.get("ssl"))
        ctx.network.domain_info = self._safe_domain_info(net_results.get("whois"))

        ctx.page.content, ctx.page.redirects = await self._fetch_page(url)
        await self._run_threat_detection(url, ctx)
        ctx.network.ip_info = await self._check_ip_reputation(net_results.get("dns"))
        ctx.page.content_analysis = await self._analyze_content(ctx.page.content, url)

        self._finalize_risk(ctx)
        self._build_recommendations(ctx)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _collect_url_threats(features, ctx: AnalysisContext) -> None:
        if features.has_ip:
            ctx.threats.threats.append("URL uses raw IP address instead of domain")
        if features.tld_risk > 0.7:
            ctx.threats.threats.append(f"High-risk TLD detected: {features.tld}")
        if features.entropy > 4.5:
            ctx.threats.threats.append("High URL entropy (possible obfuscation)")
        if features.has_redirect_param:
            ctx.threats.threats.append("URL contains open redirect parameters")
        if features.suspicious_keywords:
            ctx.threats.threats.append(
                f"Suspicious keywords: {', '.join(features.suspicious_keywords)}"
            )

    async def _perform_network_checks(self, domain: str, url: str) -> dict:
        tasks = {}
        net = self._services.network
        if net.ssl and url.startswith("https"):
            tasks["ssl"] = net.ssl.verify(domain)
        if net.dns:
            tasks["dns"] = net.dns.resolve_a(domain)
        if net.whois:
            tasks["whois"] = net.whois.lookup(domain)
        if not tasks:
            return {}
        logger.debug("Running network checks", tasks=list(tasks.keys()))
        completed = await asyncio.gather(*tasks.values(), return_exceptions=True)
        return dict(zip(tasks.keys(), completed))

    @staticmethod
    def _safe_certificate(result: Any) -> Optional[CertificateInfo]:
        if isinstance(result, Exception):
            logger.error("SSL check failed", error=str(result))
            return None
        return result

    @staticmethod
    def _safe_domain_info(result: Any) -> Optional[DomainInfo]:
        if isinstance(result, Exception):
            logger.error("WHOIS check failed", error=str(result))
            return None
        return result

    async def _fetch_page(self, url: str) -> tuple[str | None, list[Any]]:
        http = self._services.http_client
        if not http:
            return None, []
        try:
            return await http.get(url)
        except (HttpRequestError, NetzillaError, DNSResolutionError) as e:
            logger.warning("Failed to fetch content", error=str(e))
            return None, []

    async def _run_threat_detection(self, url: str, ctx: AnalysisContext) -> None:
        phishing_score = self._phishing.analyze(url, ctx.page.content,
                                                redirects=ctx.page.redirects)
        ctx.risk.phishing_score = phishing_score
        ctx.threats.threats.extend(self._phishing.get_indicators(url))

        if self._services.malware_detector:
            ctx.risk.malware_score = self._services.malware_detector.analyze_url(url)

        if self._services.brand_detector:
            ctx.threats.impersonated_brands = self._services.brand_detector.analyze(
                url, ctx.page.content
            )
            if ctx.threats.impersonated_brands:
                ctx.threats.threats.append(
                    f"Possible brand impersonation: "
                    f"{', '.join(ctx.threats.impersonated_brands)}"
                )

    async def _check_ip_reputation(self, dns_result: Any) -> Any:
        ip_client = self._services.network.ip
        if not ip_client or dns_result is None:
            return None
        if isinstance(dns_result, Exception) or not dns_result:
            return None
        return await ip_client.check(dns_result[0])

    async def _analyze_content(self, content: str | None, url: str) -> Any:
        if not self._services.content_analyzer or not content:
            return None
        return self._services.content_analyzer.analyze(content, url)

    def _finalize_risk(self, ctx: AnalysisContext) -> None:
        scores = [ctx.risk.url_score, ctx.risk.phishing_score]
        if self._services.malware_detector:
            scores.append(ctx.risk.malware_score)
        if ctx.network.ip_info and ctx.network.ip_info.reputation_score < 0.5:
            scores.append((1.0 - ctx.network.ip_info.reputation_score) * 100)

        base_score = sum(scores) / len(scores)
        threat_bonus = self._compute_threat_bonus(ctx.threats.threats)
        final_score = min(base_score + threat_bonus * 0.5, 100.0)

        ctx.risk.url_score = final_score
        ctx.risk.risk_level = self._classify_risk(final_score)
        ctx.risk.confidence = self._calculate_confidence(scores)

    @staticmethod
    def _compute_threat_bonus(threats: list[str]) -> float:
        weights = {"malware": 15, "phishing": 10,
                   "brand_impersonation": 8, "certificate": 10}
        bonus = 0.0
        for t in threats:
            lower = t.lower()
            if "malware" in lower:
                bonus += weights["malware"]
            elif "phishing" in lower:
                bonus += weights["phishing"]
            elif "impersonation" in lower:
                bonus += weights["brand_impersonation"]
            elif "certificate" in lower or "ssl" in lower:
                bonus += weights["certificate"]
            else:
                bonus += 3
        return bonus

    def _build_recommendations(self, ctx: AnalysisContext) -> None:
        if ctx.risk.url_score > 70:
            ctx.threats.recommendations.append("DO NOT visit this link")
        if ctx.network.cert_info and not ctx.network.cert_info.verified:
            ctx.threats.recommendations.append("Avoid entering credentials")
        if len(ctx.page.redirects) > 3:
            ctx.threats.recommendations.append("Suspicious redirect chain detected")
        if not ctx.threats.recommendations:
            ctx.threats.recommendations.append("No significant threats detected")

    @staticmethod
    def _classify_risk(score: float) -> RiskLevel:
        if score >= 80:
            return RiskLevel.CRITICAL
        if score >= 60:
            return RiskLevel.HIGH
        if score >= 40:
            return RiskLevel.MEDIUM
        if score >= 20:
            return RiskLevel.LOW
        return RiskLevel.SAFE

    @staticmethod
    def _calculate_confidence(scores: list[float]) -> float:
        if len(scores) < 2:
            return 0.5
        mean = sum(scores) / len(scores)
        variance = sum((s - mean) ** 2 for s in scores) / len(scores)
        confidence = 1.0 - min(variance / 1000, 0.9)
        return max(confidence, 0.1)

    @staticmethod
    def _extract_domain(url: str) -> str:
        if "://" not in url:
            url = f"https://{url}"
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        extracted = extract(hostname)
        return extracted.registered_domain or hostname
