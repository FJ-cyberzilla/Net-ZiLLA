import pytest
from netzilla.detectors.sms_scam import SMSScamDetector

def test_sms_detector_prize_scam():
    detector = SMSScamDetector()
    message = "Congratulations! You have won a gift card. Click here: http://bit.ly/prize"
    
    score = detector.analyze(message)
    tactic = detector.classify_tactic(message)
    
    assert score > 50.0
    assert tactic == "prize_scam"

def test_sms_detector_credential_harvest():
    detector = SMSScamDetector()
    message = "Bank notice: Verify your account immediately at http://bank-secure.com"
    
    score = detector.analyze(message)
    tactic = detector.classify_tactic(message)
    
    assert score > 50.0
    assert tactic == "credential_harvest"

def test_sms_detector_safe_message():
    detector = SMSScamDetector()
    message = "Meeting at 5pm."
    
    score = detector.analyze(message)
    tactic = detector.classify_tactic(message)
    
    assert score == 0.0
    assert tactic == "generic_scam"

def test_sms_detector_extract_urls():
    detector = SMSScamDetector()
    message = "Check this out https://google.com and http://bit.ly/test"
    
    urls = detector.extract_urls(message)
    assert len(urls) == 2
    assert "https://google.com" in urls
    assert "http://bit.ly/test" in urls
