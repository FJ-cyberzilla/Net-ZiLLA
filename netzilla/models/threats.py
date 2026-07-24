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
    headers: dict[str, str]
    cookies: list[CookieInfo]
    duration: timedelta
    ip_address: str
    hop_number: int
    warnings: list[str] = field(default_factory=list)

@dataclass
class DNSAnalysis:
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    name_servers: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    dnssec_enabled: bool = False
    cname: str | None = None
    ptr_record: str | None = None
    reverse_hostname: str | None = None
    ptr_validation: str | None = None
    propagation_status: str | None = None
    ttl_summary: str | None = None
    warnings: list[str] = field(default_factory=list)

@dataclass
class WhoisAnalysis:
    domain: str
    registrar: str
    created_date: str
    updated_date: str
    expiry_date: str
    domain_age: str
    name_servers: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    registrant: str | None = None
    raw_whois: str | None = None
    warnings: list[str] = field(default_factory=list)

@dataclass
class TLSAnalysis:
    certificate_valid: bool
    expires_in: timedelta
    issuer: str
    subject: str
    supported_protocols: list[str]
    encryption_grade: str
    has_weak_ciphers: bool
    ocsp_stapling: bool
    hsts_enabled: bool
    cipher_suites: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    compression_enabled: str | None = None
    server_type: str | None = None

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
    city: str | None = None
    region: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    threat_score: int | None = None
    reputation: str | None = None
    abuse_history: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

@dataclass
class HopDetail:
    number: int
    ip: str
    latency: timedelta
    host: str | None = None
    country: str | None = None

@dataclass
class NetworkAnalysis:
    target: str
    hop_count: int
    hops: list[HopDetail]
    average_latency: timedelta
    max_latency: timedelta
    min_latency: timedelta
    packet_loss: float
    geo_path: str | None = None
    warnings: list[str] = field(default_factory=list)

@dataclass
class ThreatAnalysis:
    analysis_id: str
    url: str
    threat_level: ThreatLevel
    threat_score: int
    redirect_chain: list[RedirectDetail]
    redirect_count: int
    analyzed_at: datetime
    analysis_duration: timedelta
    warnings: list[str] = field(default_factory=list)
    suspicious_features: list[str] = field(default_factory=list)
    phishing_indicators: list[str] = field(default_factory=list)
    safety_tips: list[str] = field(default_factory=list)
    security_headers: list[str] = field(default_factory=list)
    dns_info: DNSAnalysis | None = None
    whois_info: WhoisAnalysis | None = None
    tls_info: TLSAnalysis | None = None
    geo_analysis: GeoAnalysis | None = None
    network_analysis: NetworkAnalysis | None = None
    ai_result: Any | None = None
    ai_orchestration: Any | None = None
