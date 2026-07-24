import pytest
from netzilla.detectors.phishing import PhishingDetectorImplementation
from netzilla.interfaces import RedirectHop

def test_phishing_detector_no_redirects():
    detector = PhishingDetectorImplementation()
    score = detector.analyze("http://example.com")
    assert score == 0.0

def test_phishing_detector_long_redirect_chain():
    detector = PhishingDetectorImplementation()
    # Create 4 redirect hops
    redirects = [
        RedirectHop(url="http://r1.com", status_code=301, headers={}, response_time_ms=10.0),
        RedirectHop(url="http://r2.com", status_code=301, headers={}, response_time_ms=10.0),
        RedirectHop(url="http://r3.com", status_code=301, headers={}, response_time_ms=10.0),
        RedirectHop(url="http://r4.com", status_code=301, headers={}, response_time_ms=10.0),
    ]
    score = detector.analyze("http://example.com", redirects=redirects)
    assert score == 20.0

def test_phishing_detector_no_indicators():
    detector = PhishingDetectorImplementation()
    indicators = detector.get_indicators("http://example.com")
    assert indicators == []
