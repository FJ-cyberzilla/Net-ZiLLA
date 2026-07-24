from .base import Detector
from .phishing import PhishingDetectorImplementation as PhishingDetector
from .malware import MalwareDetector
from .sms_scam import SMSScamDetector
from .brand_impersonation import BrandImpersonationDetector
from .url_shortener import URLShortenerDetector

__all__ = [
    "Detector",
    "PhishingDetector",
    "MalwareDetector",
    "SMSScamDetector",
    "BrandImpersonationDetector",
    "URLShortenerDetector",
]
