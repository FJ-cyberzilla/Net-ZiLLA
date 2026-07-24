"""DNS models for analysis."""
from dataclasses import dataclass, field


@dataclass
class DNSAnalysis:
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    name_servers: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    cname: str | None = None
    ptr_record: str | None = None
    reverse_hostname: str | None = None
    ptr_validation: str | None = None
    dnssec_enabled: bool = False
    propagation_status: str = "N/A"
    ttl_summary: str = "N/A"
    warnings: list[str] = field(default_factory=list)
