"""
Main orchestrator - composes all detectors and network clients.
Fully testable via dependency injection.
"""
import asyncio
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import structlog

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
)
from netzilla.core.content_analyzer import ContentAnalyzer

logger = structlog.get_logger(__name__)


class Analyzer:
    """Main analysis orchestrator with injected dependencies."""

    def __init__(
        self,
        url_detector: URLDetector,
        phishing_detector: PhishingDetector,
        malware_detector: MalwareDetector | None = None,
        brand_detector: BrandImpersonationDetector | None = None,
        content_analyzer: ContentAnalyzer | None = None,
        dns_client: DNSClient | None = None,
        whois_client: WHOISClient | None = None,
        ssl_client: SSLClient | None = None,
        ip_client: IPReputationClient | None = None,
        http_client: HTTPClient | None = None,
        reporter: Reporter | None = None,
    ) -> None:
        self._url = url_detector
        self._phishing = phishing_detector
        self._malware = malware_detector
        self._brand = brand_detector
        self._content = content_analyzer
        self._dns = dns_client
        self._whois = whois_client
        self._ssl = ssl_client
        self._ip = ip_client
        self._http = http_client
        self._reporter = reporter
        logger.debug("Analyzer initialized")

    async def analyze(self, url: str) -> AnalysisResult:
        """
        Run full analysis on a URL.
        All network operations run concurrently where possible.
        """
        logger.info("Starting analysis", url=url)
        start_time = time.monotonic()
        threats: list[str] = []
        recommendations: list[str] = []

        # ── Phase 1: URL feature extraction (no network) ──
        features = self._url.analyze(url)
        url_score = self._url.score(features)

        if features.has_ip:
            threats.append("URL uses raw IP address instead of domain")
        if features.tld_risk > 0.7:
            threats.append(f"High-risk TLD detected: {features.tld}")
        if features.entropy > 4.5:
            threats.append("High URL entropy (possible obfuscation)")
        if features.has_redirect_param:
            threats.append("URL contains open redirect parameters")
        if features.suspicious_keywords:
            threats.append(
                f"Suspicious keywords: {', '.join(features.suspicious_keywords)}"
            )

        # ── Phase 2: Concurrent network checks ──
        domain = self._extract_domain(url)
        tasks = {}

        if self._ssl and url.startswith("https"):
            tasks["ssl"] = self._ssl.verify(domain)
        if self._dns:
            tasks["dns"] = self._dns.resolve_a(domain)
        if self._whois:
            tasks["whois"] = self._whois.lookup(domain)

        # Run network tasks concurrently
        results = {}
        if tasks:
            logger.debug("Running network checks", tasks=list(tasks.keys()))
            completed = await asyncio.gather(*tasks.values(), return_exceptions=True)
            results = dict(zip(tasks.keys(), completed))

        # ── Phase 3: Content analysis (fetches page) ──
        content = None
        redirects = []
        if self._http:
            try:
                content, redirects = await self._http.get(url)
            except Exception as e:
                logger.warning("Failed to fetch content", error=str(e))

        # ── Phase 4: Threat detectors ──
        phishing_score = self._phishing.analyze(url, content, redirects=redirects)
        phishing_indicators = self._phishing.get_indicators(url)

        if phishing_score > 50:
            threats.extend(phishing_indicators)
            recommendations.append("This URL shows strong phishing indicators")

        malware_score = 0.0
        if self._malware:
            malware_score = self._malware.analyze_url(url)
            if malware_score > 50:
                threats.append("Malware indicators detected")

        impersonated_brands = []
        if self._brand:
            impersonated_brands = self._brand.analyze(url, content)
            if impersonated_brands:
                threats.append(
                    f"Possible brand impersonation: {', '.join(impersonated_brands)}"
                )

        # ── Phase 4.1: Content analysis ──
        content_analysis = None
        if self._content and content:
            content_analysis = self._content.analyze(content, url)
            if content_analysis.has_login_form:
                threats.append("Page contains login form")
            if content_analysis.mentioned_brands:
                # Check if brands match the domain
                pass

        # ── Phase 5: SSL results ──
        cert_info = results.get("ssl")
        if isinstance(cert_info, Exception):
            logger.error("SSL check failed", error=str(cert_info))
            cert_info = None
        if cert_info and not cert_info.verified:
            threats.extend(cert_info.errors)
            recommendations.append("Do not enter sensitive data on this site")

        # ── Phase 6: Domain intelligence ──
        domain_info = results.get("whois")
        if isinstance(domain_info, Exception):
            logger.error("WHOIS check failed", error=str(domain_info))
            domain_info = None
        if domain_info and domain_info.is_newly_registered:
            threats.append(f"Domain registered {domain_info.days_old} days ago")
            recommendations.append("New domains require extra scrutiny")

        # ── Phase 7: IP reputation ──
        ip_info = None
        if self._ip and results.get("dns"):
            a_records = results["dns"]
            if not isinstance(a_records, Exception) and a_records:
                ip_info = await self._ip.check(a_records[0])
                if ip_info.reputation_score < 0.3:
                    threats.append(
                        f"IP {ip_info.ip} has poor reputation (score: {ip_info.reputation_score})"
                    )

        # ── Phase 8: Calculate final score ──
        scores = [url_score, phishing_score]
        if self._malware:
            scores.append(malware_score)
        if ip_info and ip_info.reputation_score < 0.5:
            scores.append((1.0 - ip_info.reputation_score) * 100)

        final_score = sum(scores) / len(scores)

        # Weight threats, not just count
        threat_weights = {
            "malware": 15,
            "phishing": 10,
            "brand_impersonation": 8,
            "certificate": 10,
            # default: 3
        }
        threat_bonus = sum(threat_weights.get(t, 3) for t in threats)
        final_score = min(final_score + threat_bonus * 0.5, 100.0)

        # ── Phase 9: Determine risk level ──
        risk_level = self._classify_risk(final_score)

        # ── Phase 10: Build recommendations ──
        if final_score > 70:
            recommendations.append("DO NOT visit this link")
        if cert_info and not cert_info.verified:
            recommendations.append("Avoid entering credentials")
        if len(redirects) > 3:
            recommendations.append("Suspicious redirect chain detected")
        if not recommendations:
            recommendations.append("No significant threats detected")

        elapsed = (time.monotonic() - start_time) * 1000
        logger.info("Analysis completed", score=final_score, risk=risk_level, elapsed=elapsed)

        return AnalysisResult(
            url=url,
            normalized_url=features.url,
            final_score=final_score,
            risk_level=risk_level,
            is_safe=final_score < 30,
            confidence=self._calculate_confidence(scores),
            url_features=features,
            certificate=cert_info,
            domain=domain_info,
            ip=ip_info,
            redirects=redirects,
            content=content_analysis,
            threats=threats,
            recommendations=recommendations,
            analysis_duration_ms=elapsed,
            timestamp=datetime.now(timezone.utc),
        )

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL using tldextract."""
        from tldextract import extract
        if "://" not in url:
            url = f"https://{url}"
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        # Use tldextract for proper domain extraction
        extracted = extract(hostname)
        return extracted.registered_domain or hostname

    def _classify_risk(self, score: float) -> RiskLevel:
        """Convert numerical score to risk level."""
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE

    def _calculate_confidence(self, scores: list[float]) -> float:
        """
        Calculate confidence based on agreement between detectors.
        High variance = low confidence.
        """
        if len(scores) < 2:
            return 0.5
        mean = sum(scores) / len(scores)
        variance = sum((s - mean) ** 2 for s in scores) / len(scores)
        # Lower variance = higher confidence
        confidence = 1.0 - min(variance / 1000, 0.9)
        return max(confidence, 0.1)
