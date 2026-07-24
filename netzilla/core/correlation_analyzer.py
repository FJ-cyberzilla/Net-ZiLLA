from typing import List, Dict
from dataclasses import dataclass, field
from datetime import timedelta
from netzilla.models.threats import ThreatAnalysis

@dataclass
class CorrelationThresholds:
    time_window: timedelta = timedelta(hours=24)
    ip_similarity: float = 0.8
    domain_similarity: float = 0.7
    pattern_threshold: int = 3

@dataclass
class CorrelationAnalysis:
    related_analyses: List[str] = field(default_factory=list)
    common_ips: List[str] = field(default_factory=list)
    common_domains: List[str] = field(default_factory=list)
    common_patterns: List[str] = field(default_factory=list)
    cluster_score: int = 0
    threat_cluster: bool = False
    recommendations: List[str] = field(default_factory=list)

class CorrelationAnalyzer:
    def __init__(self):
        self.thresholds = CorrelationThresholds()

    def analyze_correlations(self, analyses: List[ThreatAnalysis]) -> CorrelationAnalysis:
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

    def _find_common_ips(self, analyses: List[ThreatAnalysis]) -> List[str]:
        ip_count: Dict[str, int] = {}
        for analysis in analyses:
            if analysis.ip_info:
                ip_count[analysis.ip_info.ip] = ip_count.get(analysis.ip_info.ip, 0) + 1
            
            for redirect in analysis.redirect_chain:
                if redirect.ip_address:
                    ip_count[redirect.ip_address] = ip_count.get(redirect.ip_address, 0) + 1
        
        return [ip for ip, count in ip_count.items() if count > 1]

    def _find_common_domains(self, analyses: List[ThreatAnalysis]) -> List[str]:
        domain_count: Dict[str, int] = {}
        from urllib.parse import urlparse

        def extract_domain(url: str) -> str:
            return urlparse(url).hostname or ""

        for analysis in analyses:
            domain = extract_domain(analysis.url)
            if domain:
                domain_count[domain] = domain_count.get(domain, 0) + 1
            
            for redirect in analysis.redirect_chain:
                redirect_domain = extract_domain(redirect.url)
                if redirect_domain:
                    domain_count[redirect_domain] = domain_count.get(redirect_domain, 0) + 1
        
        return [domain for domain, count in domain_count.items() if count > 1]

    def _find_common_patterns(self, analyses: List[ThreatAnalysis]) -> List[str]:
        pattern_count: Dict[str, int] = {}
        for analysis in analyses:
            for indicator in analysis.phishing_indicators:
                pattern_count[indicator] = pattern_count.get(indicator, 0) + 1
            
            for feature in analysis.suspicious_features:
                pattern_count[feature] = pattern_count.get(feature, 0) + 1
            
            if analysis.ai_result:
                for threat in analysis.ai_result.threats:
                    pattern_count[threat] = pattern_count.get(threat, 0) + 1
        
        return [pattern for pattern, count in pattern_count.items() if count >= self.thresholds.pattern_threshold]

    def _calculate_cluster_score(self, correlation: CorrelationAnalysis) -> int:
        score = 0
        score += len(correlation.common_ips) * 10
        score += len(correlation.common_domains) * 8
        score += len(correlation.common_patterns) * 5
        return score

    def _is_threat_cluster(self, correlation: CorrelationAnalysis) -> bool:
        if correlation.cluster_score < 20:
            return False
        if len(correlation.common_ips) >= 2:
            return True
        if len(correlation.common_domains) >= 3:
            return True
        if len(correlation.common_patterns) >= 3:
            return True
        return False

    def _generate_recommendations(self, correlation: CorrelationAnalysis) -> List[str]:
        recommendations = []
        if correlation.threat_cluster:
            recommendations.extend([
                "🚨 Threat cluster detected - coordinated attack likely",
                "Investigate common IPs and domains for blocklisting",
                "Report coordinated activity to relevant authorities",
            ])
        if correlation.common_ips:
            recommendations.extend([
                "Multiple analyses share common IP addresses",
                "Consider IP-based blocking for repeated offenders",
            ])
        if correlation.common_domains:
            recommendations.extend([
                "Multiple analyses share common domain patterns",
                "Investigate domain registration patterns",
            ])
        if correlation.common_patterns:
            recommendations.extend([
                "Common threat patterns detected across analyses",
                "Update detection rules based on common patterns",
            ])
        return recommendations
