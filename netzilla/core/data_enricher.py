import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Awaitable
from urllib.parse import urlparse

import structlog

from netzilla.network.cloudflare_intel import CloudflareIntelClient
from netzilla.network.dns_client import DNSClient
from netzilla.network.whois_client import WhoisClient

logger = structlog.get_logger(__name__)


@dataclass
class IPReputation:
    score: int
    confidence: float
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
    cloudflare_risk_score: int | None = None


@dataclass
class EnrichmentData:
    enriched_at: datetime
    ip_reputation: IPReputation | None = None
    domain_history: DomainHistory | None = None


class DataEnricher:
    def __init__(
        self,
        dns_client: DNSClient,
        whois_client: WhoisClient,
        cf_intel: CloudflareIntelClient,
    ):
        self.dns_client = dns_client
        self.whois_client = whois_client
        self.cf_intel = cf_intel
        self.cache: dict[str, EnrichmentData] = {}

    async def enrich_context(self, ctx: Any) -> None:
        """Enrich AnalysisContext with additional intelligence."""
        domain = self._extract_domain(ctx.url)

        tasks: list[Awaitable[DomainHistory | IPReputation | None]] = []
        if domain:
            tasks.append(self._enrich_domain_data(domain))

        # If we have IP info, enrich it
        if hasattr(ctx.network, "ip_info") and ctx.network.ip_info:
            tasks.append(self._enrich_ip_data(ctx.network.ip_info.ip))

        if not tasks:
            return

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, Exception):
                logger.error("Enrichment task failed", error=str(res))

    async def _enrich_ip_data(self, ip: str) -> IPReputation | None:
        try:
            # Placeholder for real IP intel integration
            return IPReputation(
                score=100,
                confidence=1.0,
                country="Unknown",
                isp="Unknown",
                asn="Unknown",
                is_proxy=False,
                is_vpn=False,
            )
        except Exception as e:
            logger.error("Failed to enrich IP data", ip=ip, error=str(e))
            return None

    async def _enrich_domain_data(self, domain: str) -> DomainHistory | None:
        try:
            whois_task = self.whois_client.lookup(domain)
            cf_task = asyncio.to_thread(self.cf_intel.query_domain_intel, domain)

            whois_data, cf_intel_res = await asyncio.gather(
                whois_task, cf_task, return_exceptions=True
            )

            cf_risk = (
                cf_intel_res.get("risk_score")
                if isinstance(cf_intel_res, dict) and "risk_score" in cf_intel_res
                else None
            )

            if isinstance(whois_data, Exception):
                logger.warning("WHOIS lookup failed", domain=domain, error=str(whois_data))
                return DomainHistory(cloudflare_risk_score=cf_risk)

            return DomainHistory(
                created_date=whois_data.created_date,
                expires_date=whois_data.expiry_date,
                registrar=whois_data.registrar,
                name_servers=whois_data.nameservers,
                cloudflare_risk_score=cf_risk,
            )
        except Exception as e:
            logger.error("Failed to enrich domain data", domain=domain, error=str(e))
            return None

    def _extract_domain(self, url: str) -> str:
        from tldextract import extract

        if "://" not in url:
            url = f"https://{url}"
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        extracted = extract(hostname)
        return extracted.registered_domain or hostname
