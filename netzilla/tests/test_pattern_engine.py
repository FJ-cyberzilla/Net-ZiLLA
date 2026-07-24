import pytest
from netzilla.core.pattern_engine import PatternEngine

@pytest.fixture
def engine():
    return PatternEngine()

def test_analyze_text_phishing(engine):
    text = "Login to your account and verify your identity now."
    matches = engine.analyze_text(text)
    
    # Expect matches for "login...verify" and "your account"
    assert any(m.type == "phishing" for m in matches)
    assert any(m.type == "social_engineering" for m in matches)

def test_analyze_text_malware(engine):
    text = "Download this file and install now. setup.exe"
    matches = engine.analyze_text(text)
    
    assert any(m.type == "malware" for m in matches)

def test_analyze_url_malicious(engine):
    url = "javascript:alert('XSS')"
    matches = engine.analyze_url(url)
    
    assert any(m.type == "malware" and m.pattern == "javascript_uri" for m in matches)

def test_analyze_url_obfuscated(engine):
    url = "http://example.com/%20%20%20%20%20%20"
    matches = engine.analyze_url(url)
    
    assert any(m.type == "obfuscation" for m in matches)
