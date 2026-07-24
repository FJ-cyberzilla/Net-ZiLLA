import pytest
from netzilla.detectors.brand_impersonation import BrandImpersonationDetector

def test_brand_impersonation_detector_detected():
    detector = BrandImpersonationDetector()
    data = "Visit our site at bank-of-america.secure-login.com"
    
    result = detector.detect(data)
    
    assert result["detected"] is True
    assert result["score"] == 95.0

def test_brand_impersonation_detector_safe():
    detector = BrandImpersonationDetector()
    data = "Visit our site at legit-site.com"
    
    result = detector.detect(data)
    
    assert result["detected"] is False
    assert result["score"] == 0.0
