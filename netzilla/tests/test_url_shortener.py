import pytest
from netzilla.detectors.url_shortener import URLShortenerDetector
from netzilla.interfaces import URLFeatures

@pytest.fixture
def detector():
    return URLShortenerDetector()

def test_analyze_shortened_url(detector):
    url = "https://bit.ly/xyz123"
    features = detector.analyze(url)
    
    assert isinstance(features, URLFeatures)
    assert features.url == url
    assert "bit.ly" in features.url
    # Shortened URLs often have higher entropy
    assert features.entropy > 0

def test_score_shortened_url(detector):
    # Setup features for a shortened URL
    features = URLFeatures(
        url="https://bit.ly/xyz123",
        length=20,
        entropy=4.0,
        tld="ly",
        tld_risk=0.1,
        has_ip=False,
        has_suspicious_tld=False,
        special_char_count=2,
        digit_ratio=0.1,
        subdomain_count=1,
        path_depth=1,
        has_redirect_param=False,
        suspicious_keywords=[]
    )
    
    score = detector.score(features)
    # Based on current implementation, bit.ly in URL adds 40.0
    assert score == 40.0

def test_score_suspicious_url(detector):
    # Setup features for a suspicious URL
    features = URLFeatures(
        url="http://192.168.1.1/login",
        length=20,
        entropy=3.0,
        tld="1",
        tld_risk=0.1,
        has_ip=True,
        has_suspicious_tld=False,
        special_char_count=2,
        digit_ratio=0.5,
        subdomain_count=0,
        path_depth=1,
        has_redirect_param=True,
        suspicious_keywords=["login"]
    )
    
    score = detector.score(features)
    # has_ip (30) + has_redirect_param (20) = 50.0
    assert score == 50.0
