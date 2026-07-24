from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import List, Dict, Optional, Any

class ThreatLevel(StrEnum):
    SAFE = "🟢 SAFE"
    LOW = "🟡 LOW"
    MEDIUM = "🟠 MEDIUM"
    HIGH = "🔴 HIGH"
    CRITICAL = "💀 CRITICAL"

@dataclass
class CookieInfo:
    name: str
    value: str
    domain: str
    path: str
    expires: datetime
    secure: bool
    http_only: bool
    same_site: str

@dataclass
class RedirectDetail:
    url: str
    status_code: int
    location: str
    headers: Dict[str, str]
    cookies: List[CookieInfo]
    duration: timedelta
    ip_address: str
    hop_number: int
    warnings: List[str] = field(default_factory=list)

@dataclass
class DNSAnalysis:
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    name_servers: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    dnssec_enabled: bool = False
    cname: Optional[str] = None
    ptr_record: Optional[str] = None
    reverse_hostname: Optional[str] = None
    ptr_validation: Optional[str] = None
    propagation_status: Optional[str] = None
    ttl_summary: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

@dataclass
class WhoisAnalysis:
    domain: str
    registrar: str
    created_date: str
    updated_date: str
    expiry_date: str
    domain_age: str
    name_servers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    registrant: Optional[str] = None
    raw_whois: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

@dataclass
class TLSAnalysis:
    certificate_valid: bool
    expires_in: timedelta
    issuer: str
    subject: str
    supported_protocols: List[str]
    encryption_grade: str
    has_weak_ciphers: bool
    ocsp_stapling: bool
    hsts_enabled: bool
    cipher_suites: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    compression_enabled: Optional[str] = None
    server_type: Optional[str] = None

@dataclass
class GeoAnalysis:
    ip: str
    country: str
    isp: str
    asn: str
    is_proxy: bool
    hosting_type: str
    is_public: bool
    is_reserved: bool
    city: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    threat_score: Optional[int] = None
    reputation: Optional[str] = None
    abuse_history: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

@dataclass
class HopDetail:
    number: int
    ip: str
    latency: timedelta
    host: Optional[str] = None
    country: Optional[str] = None

@dataclass
class NetworkAnalysis:
    target: str
    hop_count: int
    hops: List[HopDetail]
    average_latency: timedelta
    max_latency: timedelta
    min_latency: timedelta
    packet_loss: float
    geo_path: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

@dataclass
class ThreatAnalysis:
    analysis_id: str
    url: str
    threat_level: ThreatLevel
    threat_score: int
    redirect_chain: List[RedirectDetail]
    redirect_count: int
    analyzed_at: datetime
    analysis_duration: timedelta
    warnings: List[str] = field(default_factory=list)
    suspicious_features: List[str] = field(default_factory=list)
    phishing_indicators: List[str] = field(default_factory=list)
    safety_tips: List[str] = field(default_factory=list)
    security_headers: List[str] = field(default_factory=list)
    dns_info: Optional[DNSAnalysis] = None
    whois_info: Optional[WhoisAnalysis] = None
    tls_info: Optional[TLSAnalysis] = None
    geo_analysis: Optional[GeoAnalysis] = None
    network_analysis: Optional[NetworkAnalysis] = None
    ai_result: Optional[Any] = None
    ai_orchestration: Optional[Any] = None
