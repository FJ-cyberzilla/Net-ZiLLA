from typing import List, Dict, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from urllib.parse import urlparse
from netzilla.models.threats import ThreatAnalysis
from netzilla.network.dns_client import DNSClient
from netzilla.network.whois_client import WhoisClient
# Assuming threatintel package exists
from netzilla.pkg.threatintel import Manager as ThreatIntelManager 

@dataclass
class IPReputation:
    score: int
    confidence: float
    abuse_reports: int
    country: str
    isp: str
    asn: str
    is_proxy: bool
    is_vpn: bool

@dataclass
class DomainHistory:
    created_date: datetime
    updated_date: datetime
    expires_date: datetime
    registrar: str
    name_servers: List[str]
    registrant: str

@dataclass
class ThreatFeed:
    source: str
    indicator: str
    score: int
    first_seen: datetime
    last_seen: datetime

@dataclass
class GeoData:
    country: str
    city: str
    region: str
    latitude: float
    longitude: float
    timezone: str

@dataclass
class SSLData:
    valid: bool
    expires: datetime
    issuer: str
    subject: str
    key_size: int
    signature_algo: str

@dataclass
class EnrichmentData:
    enriched_at: datetime
    ip_reputation: Optional[IPReputation] = None
    domain_history: Optional[DomainHistory] = None
    threat_feeds: List[ThreatFeed] = field(default_factory=list)
    geo_data: Optional[GeoData] = None
    ssl_data: Optional[SSLData] = None

class DataEnricher:
    def __init__(self):
        self.threat_intel = ThreatIntelManager()
        self.dns_client = DNSClient()
        self.whois_client = WhoisClient()
        self.cache: Dict[str, EnrichmentData] = {}

    def enrich_analysis(self, analysis: ThreatAnalysis) -> None:
        if analysis.ip_info:
            ip_data = self._enrich_ip_data(analysis.ip_info.ip)
            if ip_data:
                analysis.enrichment_data = ip_data

        domain = self._extract_domain(analysis.url)
        if domain:
            domain_data = self._enrich_domain_data(domain)
            if domain_data:
                analysis.domain_history = domain_data
            
            threat_data = self._enrich_threat_data(analysis.url, domain)
            if threat_data:
                analysis.threat_feeds = threat_data
            
            ssl_data = self._enrich_ssl_data(analysis.url)
            if ssl_data:
                analysis.ssl_data = ssl_data

    def _enrich_ip_data(self, ip: str) -> Optional[EnrichmentData]:
        if ip in self.cache:
            cached = self.cache[ip]
            if datetime.now() - cached.enriched_at < timedelta(hours=1):
                return cached

        enrichment = EnrichmentData(enriched_at=datetime.now())

        try:
            reputation = self.threat_intel.check_ip(ip)
            enrichment.ip_reputation = IPReputation(
                score=reputation.score,
                confidence=reputation.confidence,
                abuse_reports=reputation.abuse_count,
                country=reputation.country,
                isp=reputation.isp,
                asn=reputation.asn,
                is_proxy=reputation.is_proxy,
                is_vpn=reputation.is_vpn
            )
        except Exception:
            pass

        try:
            geo = self.threat_intel.geo_locate(ip)
            enrichment.geo_data = GeoData(
                country=geo.country,
                city=geo.city,
                region=geo.region,
                latitude=geo.latitude,
                longitude=geo.longitude,
                timezone=geo.timezone
            )
        except Exception:
            pass

        self.cache[ip] = enrichment
        return enrichment

    def _extract_domain(self, url: str) -> str:
        # Improved domain extraction using tldextract
        from tldextract import extract
        if "://" not in url:
            url = f"https://{url}"
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        extracted = extract(hostname)
        return extracted.registered_domain or hostname
    
    # Other methods (enrich_domain_data, enrich_threat_data, enrich_ssl_data) 
    # would follow a similar pattern as _enrich_ip_data.
