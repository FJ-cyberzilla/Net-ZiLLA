import pytest
from datetime import datetime, UTC
from netzilla.core.correlation_analyzer import CorrelationAnalyzer
from netzilla.interfaces import AnalysisResult, RiskLevel, URLFeatures, IPInfo

def test_correlation_analyzer_no_correlation():
    analyzer = CorrelationAnalyzer()
    
    analysis1 = AnalysisResult(
        url="http://a.com",
        normalized_url="http://a.com",
        final_score=10.0,
        risk_level=RiskLevel.SAFE,
        is_safe=True,
        confidence=0.9,
        url_features=URLFeatures(
            url="http://a.com", length=10, entropy=2.0, tld="com", tld_risk=0.1,
            has_ip=False, has_suspicious_tld=False, special_char_count=0,
            digit_ratio=0.0, subdomain_count=0, path_depth=0,
            has_redirect_param=False, suspicious_keywords=[]
        ),
        redirects=[],
        threats=[],
        recommendations=[],
        analysis_duration_ms=10.0,
        timestamp=datetime.now(UTC),
    )
    
    result = analyzer.analyze_correlations([analysis1])
    
    assert result.cluster_score == 0
    assert result.threat_cluster is False

def test_correlation_analyzer_ip_correlation():
    analyzer = CorrelationAnalyzer()
    
    # Shared IP
    ip_info1 = IPInfo(
        ip="1.2.3.4", is_private=False, is_known_malicious=True,
        is_proxy=False, is_vpn=False, is_tor=False, reputation_score=0.1
    )
    ip_info2 = IPInfo(
        ip="5.6.7.8", is_private=False, is_known_malicious=True,
        is_proxy=False, is_vpn=False, is_tor=False, reputation_score=0.1
    )
    
    def create_analysis(url: str, ip: IPInfo):
        return AnalysisResult(
            url=url, normalized_url=url, final_score=50.0,
            risk_level=RiskLevel.HIGH, is_safe=False, confidence=0.8,
            url_features=URLFeatures(
                url=url, length=10, entropy=2.0, tld="com", tld_risk=0.1,
                has_ip=False, has_suspicious_tld=False, special_char_count=0,
                digit_ratio=0.0, subdomain_count=0, path_depth=0,
                has_redirect_param=False, suspicious_keywords=[]
            ),
            ip=ip,
            redirects=[], threats=[], recommendations=[],
            analysis_duration_ms=10.0, timestamp=datetime.now(UTC),
        )

    analysis1 = create_analysis("http://a.com", ip_info1)
    analysis2 = create_analysis("http://b.com", ip_info1)
    analysis3 = create_analysis("http://c.com", ip_info2)
    analysis4 = create_analysis("http://d.com", ip_info2)
    
    result = analyzer.analyze_correlations([analysis1, analysis2, analysis3, analysis4])
    
    assert "1.2.3.4" in result.common_ips
    assert "5.6.7.8" in result.common_ips
    assert result.cluster_score >= 20
    assert result.threat_cluster is True
