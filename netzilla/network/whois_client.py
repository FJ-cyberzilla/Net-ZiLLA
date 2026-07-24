import whois
from typing import Optional
from datetime import datetime
from netzilla.interfaces import WHOISClient, DomainInfo

class WhoisClient(WHOISClient):
    """Concrete implementation of WHOISClient using python-whois."""

    async def lookup(self, domain: str) -> DomainInfo:
        """Lookup WHOIS information for a domain."""
        w = whois.whois(domain)
        
        # Convert single items to lists if needed for DomainInfo
        def to_list(val) -> list[str]:
            if isinstance(val, list):
                return [str(v) for v in val]
            elif val:
                return [str(val)]
            return []

        # Handle dates
        def to_datetime(val) -> datetime | None:
            if isinstance(val, list):
                val = val[0]
            if isinstance(val, datetime):
                return val
            return None

        created = to_datetime(w.creation_date)
        
        return DomainInfo(
            domain=domain,
            registrar=str(w.registrar) if w.registrar else None,
            created_date=created,
            expiry_date=to_datetime(w.expiration_date),
            days_old=(datetime.now() - created).days if created else None,
            is_newly_registered=(datetime.now() - created).days < 30 if created else False,
            nameservers=to_list(w.name_servers),
            a_records=[], # WHOIS doesn't return A records
            mx_records=[],
            txt_records=[]
        )
