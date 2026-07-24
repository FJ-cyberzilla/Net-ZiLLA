"""
Module for interacting with Cloudflare Threat Intelligence services.
"""
import os
from typing import Any

import requests
import structlog

logger = structlog.get_logger(__name__)


class CloudflareIntelClient:
    """Client for querying Cloudflare Threat Intelligence APIs."""

    def __init__(self) -> None:
        self.api_token = os.getenv("CLOUDFLARE_API_TOKEN")
        self.account_id = os.getenv("CLOUDFLARE_ACCOUNT_ID")
        self.base_url = (
            f"https://api.cloudflare.com/client/v4/accounts/{self.account_id}"
        )

        if not self.api_token or not self.account_id:
            logger.warning("Cloudflare API credentials not configured.")

    def query_domain_intel(self, domain_name: str) -> dict[str, Any]:
        """Query Cloudflare's domain intelligence endpoint."""
        if not self.api_token or not self.account_id:
            return {"error": "Credentials missing"}

        url = f"{self.base_url}/intel/domain"
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }
        params = {"domain": domain_name}

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            result: dict[str, Any] = response.json().get("result", {})
            return result
        except requests.exceptions.RequestException as e:
            logger.error("Cloudflare API request failed", error=str(e))
            return {"error": str(e)}
