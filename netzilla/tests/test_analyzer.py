import pytest
from unittest.mock import MagicMock
from netzilla.core.analyzer import Analyzer, Services
from netzilla.interfaces import URLDetector, PhishingDetector, RiskLevel, URLFeatures

@pytest.mark.asyncio
async def test_analyzer_basic_analysis():
    # Mock dependencies
    url_detector = MagicMock(spec=URLDetector)
    phishing_detector = MagicMock(spec=PhishingDetector)
    services = Services()

    # Configure mocks
    url_features = URLFeatures(
        url="http://example.com",
        length=20,
        entropy=2.0,
        tld="com",
        tld_risk=0.1,
        has_ip=False,
        has_suspicious_tld=False,
        special_char_count=0,
        digit_ratio=0.0,
        subdomain_count=0,
        path_depth=0,
        has_redirect_param=False,
        suspicious_keywords=[]
    )

    url_detector.analyze.return_value = url_features
    url_detector.score.return_value = 10.0
    
    phishing_detector.analyze.return_value = 5.0
    phishing_detector.get_indicators.return_value = []

    # Create analyzer
    analyzer = Analyzer(url_detector, phishing_detector, services)

    # Run analysis
    result = await analyzer.analyze("http://example.com")

    # Verify
    assert result.url == "http://example.com"
    assert result.final_score < 30
    assert result.is_safe is True
    assert result.risk_level == RiskLevel.SAFE
