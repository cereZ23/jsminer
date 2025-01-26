"""Web crawler to find JavaScript files."""

import re
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from jsminer.core.config import Config


class JSCrawler:
    """Crawler to discover JavaScript files on a website."""

    # Patterns to find JS files
    JS_EXTENSIONS = {".js", ".mjs", ".jsx", ".ts", ".tsx"}

    def __init__(self, config: Config | None = None) -> None:
        """Initialize the crawler.

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

    async def crawl(self, url: str) -> list[str]:
        """Crawl a URL and extract JavaScript file URLs.

        Args:
            url: URL to crawl.

        Returns:
            List of discovered JavaScript file URLs.
        """
        session = await self._get_session()
        js_urls: set[str] = set()

        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                allow_redirects=self.config.follow_redirects,
            ) as response:
                if response.status != 200:
                    return []

                html = await response.text()

                # Parse HTML
                soup = BeautifulSoup(html, "html.parser")

                # Find script tags with src
                for script in soup.find_all("script", src=True):
                    src = script.get("src")
                    if src:
                        full_url = urljoin(url, src)
                        if self._is_js_url(full_url):
                            js_urls.add(full_url)

                # Find inline scripts
                for script in soup.find_all("script", src=False):
                    content = script.string
                    if content:
                        # Look for dynamically loaded JS
                        inline_urls = self._extract_js_urls_from_content(content, url)
                        js_urls.update(inline_urls)

                # Look for JS URLs in HTML attributes
                for attr in ["data-src", "data-script", "data-main"]:
                    for tag in soup.find_all(attrs={attr: True}):
                        src = tag.get(attr)
                        if src:
                            full_url = urljoin(url, src)
                            if self._is_js_url(full_url):
                                js_urls.add(full_url)

                # Look for JS URLs in href (some sites use this)
                for link in soup.find_all("link", rel="preload", href=True):
                    if link.get("as") == "script":
                        href = link.get("href")
                        if href:
                            full_url = urljoin(url, href)
                            js_urls.add(full_url)

        except Exception:
            pass

        return list(js_urls)

    def _is_js_url(self, url: str) -> bool:
        """Check if URL points to a JavaScript file."""
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()

            # Check extension
            for ext in self.JS_EXTENSIONS:
                if path.endswith(ext):
                    return True

            # Check for common JS patterns in path
            return bool("/js/" in path or "/javascript/" in path)
        except Exception:
            return False

    def _extract_js_urls_from_content(self, content: str, base_url: str) -> set[str]:
        """Extract JS URLs from inline script content."""
        urls: set[str] = set()

        # Pattern for dynamically loaded scripts
        patterns = [
            r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']',
            r'src\s*[=:]\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
            r'import\s+.*?\s+from\s+["\']([^"\']+)["\']',
            r'require\s*\(\s*["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                path = match.group(1)
                if path and not path.startswith("data:"):
                    full_url = urljoin(base_url, path)
                    if self._is_js_url(full_url) or not any(
                        c in path for c in ["(", ")", "{", "}"]
                    ):
                        urls.add(full_url)

        return urls

    async def close(self) -> None:
        """Close the aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
