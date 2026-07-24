"""
Detectors module for identifying various threat types.
"""
from .base import Detector
from .brand_impersonation import BrandImpersonationDetector
from .malware import MalwareDetector
from .phishing import PhishingDetectorImplementation as PhishingDetector
from .sms_scam import SMSScamDetector
from .url_shortener import URLShortenerDetector

__all__ = [
    "Detector",
    "PhishingDetector",
    "MalwareDetector",
    "SMSScamDetector",
    "BrandImpersonationDetector",
    "URLShortenerDetector",
]
