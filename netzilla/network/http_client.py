"""
Module for making HTTP requests with redirect tracking.
"""
import httpx

from netzilla.interfaces import HTTPClient, RedirectHop


class CloudflareHTTPClient(HTTPClient):
    """
    HTTP Client implementation that supports proxying through Cloudflare/system proxy.
    """

    def __init__(self, proxy_url: str | None = None, timeout: float = 30.0):
        self.proxy_url = proxy_url
        self.timeout = timeout

    async def get(
        self, url: str, follow_redirects: bool = True
    ) -> tuple[str, list[RedirectHop]]:
        redirect_chain: list[RedirectHop] = []

        async with httpx.AsyncClient(
            proxy=self.proxy_url,
            follow_redirects=False,  # We handle it manually to capture the chain
            timeout=self.timeout,
        ) as client:

            current_url = url
            while True:
                response = await client.get(current_url)

                # Record hop
                redirect_chain.append(
                    RedirectHop(
                        url=str(response.url),
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        response_time_ms=response.elapsed.total_seconds() * 1000,
                    )
                )

                if follow_redirects and response.is_redirect:
                    current_url = response.headers.get("Location")
                    if not current_url:
                        break
                    # Handle relative URLs
                    if current_url.startswith("/"):
                        current_url = (
                            f"{response.url.scheme}://{response.url.host}{current_url}"
                        )
                else:
                    break

                if len(redirect_chain) > 20:  # Sanity limit
                    break

            return response.text, redirect_chain

    async def head(self, url: str) -> dict[str, str]:
        async with httpx.AsyncClient(
            proxy=self.proxy_url, timeout=self.timeout
        ) as client:
            response = await client.head(url)
            return dict(response.headers)
