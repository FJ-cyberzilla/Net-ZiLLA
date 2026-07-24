from datetime import datetime, timedelta, UTC
from dataclasses import dataclass, field
from urllib.parse import urlparse
import structlog
from netzilla.models.threats import ThreatAnalysis
from netzilla.network.dns_client import DNSClient
from netzilla.network.whois_client import WhoisClient
from netzilla.network.cloudflare_intel import CloudflareIntelClient
# Assuming threatintel package exists
from netzilla.pkg.threatintel import Manager as ThreatIntelManager 

logger = structlog.get_logger(__name__)

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
    created_date: datetime | None = None
    updated_date: datetime | None = None
    expires_date: datetime | None = None
    registrar: str | None = None
    name_servers: list[str] = field(default_factory=list)
    registrant: str | None = None
    cloudflare_risk_score: int | None = None

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
    ip_reputation: IPReputation | None = None
    domain_history: DomainHistory | None = None
    threat_feeds: list[ThreatFeed] = field(default_factory=list)
    geo_data: GeoData | None = None
    ssl_data: SSLData | None = None

class DataEnricher:
    def __init__(self):
        self.threat_intel = ThreatIntelManager()
        self.dns_client = DNSClient()
        self.whois_client = WhoisClient()
        self.cf_intel = CloudflareIntelClient()
        self.cache: dict[str, EnrichmentData] = {}

    async def enrich_analysis(self, analysis: ThreatAnalysis) -> None:
        if analysis.ip_info:
            ip_data = await self._enrich_ip_data(analysis.ip_info.ip)
            if ip_data:
                analysis.enrichment_data = ip_data

        domain = self._extract_domain(analysis.url)
        if domain:
            domain_data = await self._enrich_domain_data(domain)
            if domain_data:
                analysis.domain_history = domain_data
            
            threat_data = await self._enrich_threat_data(analysis.url, domain)
            if threat_data:
                analysis.threat_feeds = threat_data
            
            ssl_data = await self._enrich_ssl_data(analysis.url)
            if ssl_data:
                analysis.ssl_data = ssl_data

    async def _enrich_ip_data(self, ip: str) -> EnrichmentData | None:
        if ip in self.cache:
            cached = self.cache[ip]
            if datetime.now(UTC) - cached.enriched_at < timedelta(hours=1):
                return cached

        enrichment = EnrichmentData(enriched_at=datetime.now(UTC))

        try:
            # Wrap synchronous threat intel calls
            import asyncio
            reputation = await asyncio.to_thread(self.threat_intel.check_ip, ip)
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
        except Exception as e:
            logger.error("Failed to check IP reputation", ip=ip, error=str(e))

        try:
            geo = await asyncio.to_thread(self.threat_intel.geo_locate, ip)
            enrichment.geo_data = GeoData(
                country=geo.country,
                city=geo.city,
                region=geo.region,
                latitude=geo.latitude,
                longitude=geo.longitude,
                timezone=geo.timezone
            )
        except Exception as e:
            logger.error("Failed to geo-locate IP", ip=ip, error=str(e))

        self.cache[ip] = enrichment
        return enrichment

    async def _enrich_domain_data(self, domain: str) -> DomainHistory | None:
        """Enrich domain data, including WHOIS and Cloudflare Threat Intel."""
        # Fetch data concurrently
        import asyncio
        whois_task = self.whois_client.lookup(domain)
        # Cloudflare is synchronous; wrapping to prevent blocking the event loop
        cf_task = asyncio.to_thread(self.cf_intel.query_domain_intel, domain)
        
        whois_data, cf_intel = await asyncio.gather(whois_task, cf_task, return_exceptions=True)
        
        # Handle potential errors in gather
        if isinstance(whois_data, Exception):
            return None
        
        cf_risk = cf_intel.get("risk_score") if not isinstance(cf_intel, Exception) else None
        
        return DomainHistory(
            created_date=whois_data.created_date,
            updated_date=whois_data.updated_date,
            expires_date=whois_data.expiry_date,
            registrar=whois_data.registrar,
            name_servers=whois_data.nameservers,
            registrant=None,
            cloudflare_risk_score=cf_risk
        )

    async def _enrich_threat_data(self, url: str, domain: str) -> list[ThreatFeed]:
        """Enrichment logic for threat feeds."""
        return []

    async def _enrich_ssl_data(self, url: str) -> SSLData | None:
        """Enrichment logic for SSL data."""
        return None

    def _extract_domain(self, url: str) -> str:
        # Improved domain extraction using tldextract
        from tldextract import extract
        if "://" not in url:
            url = f"https://{url}"
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        extracted = extract(hostname)
        return extracted.registered_domain or hostname
