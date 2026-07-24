"""Module for analyzing correlations between analysis results."""

from dataclasses import dataclass, field
from datetime import timedelta
from urllib.parse import urlparse

from netzilla.interfaces import AnalysisResult


@dataclass
class CorrelationThresholds:
    """Thresholds for correlation analysis."""

    time_window: timedelta = timedelta(hours=24)
    ip_similarity: float = 0.8
    domain_similarity: float = 0.7
    pattern_threshold: int = 3


@dataclass
class CorrelationAnalysis:
    """Results of correlation analysis."""

    related_analyses: list[str] = field(default_factory=list)
    common_ips: list[str] = field(default_factory=list)
    common_domains: list[str] = field(default_factory=list)
    common_patterns: list[str] = field(default_factory=list)
    cluster_score: int = 0
    threat_cluster: bool = False
    recommendations: list[str] = field(default_factory=list)


class CorrelationAnalyzer:
    """Analyzes correlations between multiple analysis results."""

    def __init__(self) -> None:
        """Initialize CorrelationAnalyzer."""
        self.thresholds = CorrelationThresholds()

    def analyze_correlations(
        self, analyses: list[AnalysisResult]
    ) -> CorrelationAnalysis:
        """Analyze correlations between multiple analysis results."""
        correlation = CorrelationAnalysis()

        if len(analyses) < 2:
            return correlation

        correlation.common_ips = self._find_common_ips(analyses)
        correlation.common_domains = self._find_common_domains(analyses)
        correlation.common_patterns = self._find_common_patterns(analyses)
        correlation.cluster_score = self._calculate_cluster_score(correlation)
        correlation.threat_cluster = self._is_threat_cluster(correlation)
        correlation.recommendations = self._generate_recommendations(correlation)

        return correlation

    def _find_common_ips(self, analyses: list[AnalysisResult]) -> list[str]:
        """Find common IP addresses in analyses."""
        ip_count: dict[str, int] = {}
        for analysis in analyses:
            if analysis.ip:
                ip_count[analysis.ip.ip] = ip_count.get(analysis.ip.ip, 0) + 1

            for redirect in analysis.redirects:
                # Assuming IP not directly in redirect hop, but we can look in headers
                # or just skip for now as interfaces didn't have IP in redirect
                pass

        return [ip for ip, count in ip_count.items() if count > 1]

    def _find_common_domains(self, analyses: list[AnalysisResult]) -> list[str]:
        """Find common domains in analyses."""
        domain_count: dict[str, int] = {}

        def extract_domain(url: str) -> str:
            """Extract domain from URL."""
            return urlparse(url).hostname or ""

        for analysis in analyses:
            domain = extract_domain(analysis.url)
            if domain:
                domain_count[domain] = domain_count.get(domain, 0) + 1

            for redirect in analysis.redirects:
                redirect_domain = extract_domain(redirect.url)
                if redirect_domain:
                    domain_count[redirect_domain] = (
                        domain_count.get(redirect_domain, 0) + 1
                    )

        return [domain for domain, count in domain_count.items() if count > 1]

    def _find_common_patterns(self, analyses: list[AnalysisResult]) -> list[str]:
        """Find common threat patterns in analyses."""
        pattern_count: dict[str, int] = {}
        for analysis in analyses:
            for indicator in analysis.threats:
                pattern_count[indicator] = pattern_count.get(indicator, 0) + 1

            if analysis.content:
                for element in analysis.content.suspicious_elements:
                    pattern_count[element] = pattern_count.get(element, 0) + 1

        return [
            pattern
            for pattern, count in pattern_count.items()
            if count >= self.thresholds.pattern_threshold
        ]

    def _calculate_cluster_score(self, correlation: CorrelationAnalysis) -> int:
        """Calculate cluster score."""
        score = 0
        score += len(correlation.common_ips) * 10
        score += len(correlation.common_domains) * 8
        score += len(correlation.common_patterns) * 5
        return score

    def _is_threat_cluster(self, correlation: CorrelationAnalysis) -> bool:
        """Determine if it is a threat cluster."""
        if correlation.cluster_score < 20:
            return False
        if len(correlation.common_ips) >= 2:
            return True
        if len(correlation.common_domains) >= 3:
            return True
        if len(correlation.common_patterns) >= 3:
            return True
        return False

    def _generate_recommendations(self, correlation: CorrelationAnalysis) -> list[str]:
        """Generate recommendations based on analysis."""
        recommendations = []
        if correlation.threat_cluster:
            recommendations.extend(
                [
                    "🚨 Threat cluster detected - coordinated attack likely",
                    "Investigate common IPs and domains for blocklisting",
                    "Report coordinated activity to relevant authorities",
                ]
            )
        if correlation.common_ips:
            recommendations.extend(
                [
                    "Multiple analyses share common IP addresses",
                    "Consider IP-based blocking for repeated offenders",
                ]
            )
        if correlation.common_domains:
            recommendations.extend(
                [
                    "Multiple analyses share common domain patterns",
                    "Investigate domain registration patterns",
                ]
            )
        if correlation.common_patterns:
            recommendations.extend(
                [
                    "Common threat patterns detected across analyses",
                    "Update detection rules based on common patterns",
                ]
            )
        return recommendations
