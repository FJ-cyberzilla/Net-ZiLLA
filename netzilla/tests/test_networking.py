
import pytest

from netzilla.network.dns_client import DNSClient
from netzilla.network.http_client import CloudflareHTTPClient


@pytest.mark.asyncio
async def test_dns_client_uses_cloudflare():
    client = DNSClient()
    assert client.resolver.nameservers == ["1.1.1.1"]
    # Perform a test lookup
    records = await client.resolve_a("example.com")
    assert len(records) > 0


@pytest.mark.asyncio
async def test_http_client_proxy_config():
    # Test that proxy is correctly passed to httpx client
    client = CloudflareHTTPClient(proxy_url="http://localhost:8888")
    assert client.proxy_url == "http://localhost:8888"

    # We can't easily test the actual proxy without a running proxy,
    # but we can verify the initialization logic.
