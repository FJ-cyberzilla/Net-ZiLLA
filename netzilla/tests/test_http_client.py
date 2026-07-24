import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from netzilla.network.http_client import CloudflareHTTPClient

@pytest.mark.asyncio
async def test_http_client_get_success():
    client = CloudflareHTTPClient()
    
    # Mock httpx.AsyncClient and its response
    with patch("httpx.AsyncClient", autospec=True) as MockClient:
        mock_client_instance = MockClient.return_value.__aenter__.return_value
        
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = "<html></html>"
        mock_response.url = "http://example.com"
        mock_response.headers = {}
        
        # Mock elapsed as a MagicMock, not AsyncMock
        mock_elapsed = MagicMock()
        mock_elapsed.total_seconds.return_value = 0.1
        mock_response.elapsed = mock_elapsed
        
        mock_client_instance.get.return_value = mock_response
        
        text, chain = await client.get("http://example.com", follow_redirects=False)
        
        assert text == "<html></html>"
        assert len(chain) == 1
        assert chain[0].url == "http://example.com"
        assert chain[0].status_code == 200
