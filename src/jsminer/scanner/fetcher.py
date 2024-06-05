"""Async JavaScript file fetcher."""

import asyncio
from urllib.parse import urljoin, urlparse

import aiohttp

from jsminer.core.config import Config
from jsminer.core.models import JSFile


class JSFetcher:
    """Async fetcher for JavaScript files."""

    def __init__(self, config: Config | None = None) -> None:
        """Initialize the fetcher.

        Args:
            config: Configuration options.
        """
        self.config = config or Config()
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp session."""
        if self._session is None or self._session.closed:
            headers = {
                "User-Agent": self.config.user_agent,
                **self.config.headers,
            }
            self._session = aiohttp.ClientSession(headers=headers)
        return self._session

    async def fetch(self, url: str) -> JSFile:
        """Fetch a single JavaScript file.

        Args:
            url: URL of the JavaScript file.

        Returns:
            JSFile with content or error.
        """
        session = await self._get_session()

        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                allow_redirects=self.config.follow_redirects,
            ) as response:
                if response.status != 200:
                    return JSFile(
                        url=url,
                        status_code=response.status,
                        error=f"HTTP {response.status}",
                    )

                # Check content length
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > self.config.max_js_size:
                    return JSFile(
                        url=url,
                        status_code=response.status,
                        error=f"File too large: {content_length} bytes",
                    )

                content = await response.text()
                return JSFile(
                    url=url,
                    content=content,
                    size=len(content),
                    status_code=response.status,
                )

        except asyncio.TimeoutError:
            return JSFile(url=url, error="Timeout")
        except aiohttp.ClientError as e:
            return JSFile(url=url, error=str(e))
        except Exception as e:
            return JSFile(url=url, error=f"Unexpected error: {e}")

    async def fetch_many(
        self,
        urls: list[str],
        limit: int | None = None,
    ) -> list[JSFile]:
        """Fetch multiple JavaScript files concurrently.

        Args:
            urls: List of URLs to fetch.
            limit: Maximum number of files to fetch.

        Returns:
            List of JSFile results.
        """
        if limit:
            urls = urls[:limit]

        semaphore = asyncio.Semaphore(self.config.max_concurrent)

        async def fetch_with_semaphore(url: str) -> JSFile:
            async with semaphore:
                result = await self.fetch(url)
                if self.config.delay > 0:
                    await asyncio.sleep(self.config.delay)
                return result

        tasks = [fetch_with_semaphore(url) for url in urls]
        return await asyncio.gather(*tasks)

    async def close(self) -> None:
        """Close the aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
