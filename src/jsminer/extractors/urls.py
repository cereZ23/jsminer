"""URL extractor."""

from urllib.parse import urlparse

from jsminer.core.models import Finding, FindingType, Severity
from jsminer.extractors.base import BaseExtractor
from jsminer.patterns import URL_PATTERNS


class URLExtractor(BaseExtractor):
    """Extract URLs from JavaScript."""

    # High-value URL patterns
    INTERESTING_PATTERNS = {
        "internal",
        "staging",
        "dev",
        "test",
        "uat",
        "qa",
        "preprod",
        "admin",
        "api",
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "192.168",
        "10.",
        "172.16",
        ".local",
        ".corp",
        ".intranet",
        "debug",
    }

    # Skip these domains
    SKIP_DOMAINS = {
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "google-analytics.com",
        "facebook.com",
        "fbcdn.net",
        "twitter.com",
        "twimg.com",
        "cloudflare.com",
        "jsdelivr.net",
        "unpkg.com",
        "cdnjs.cloudflare.com",
        "jquery.com",
        "bootstrapcdn.com",
        "fontawesome.com",
        "w3.org",
        "schema.org",
        "mozilla.org",
        "github.com",
    }

    def __init__(self, target_domain: str | None = None) -> None:
        """Initialize the extractor.

        Args:
            target_domain: Target domain to focus on (optional).
        """
        self.target_domain = target_domain

    def extract(self, content: str, source_file: str) -> list[Finding]:
        """Extract URLs from JavaScript content."""
        findings: list[Finding] = []
        seen_urls: set[str] = set()

        for pattern in URL_PATTERNS:
            for match in pattern.finditer(content):
                url = match.group(0)

                # Normalize URL
                url = self._normalize_url(url)
                if not url:
                    continue

                # Skip duplicates
                if url in seen_urls:
                    continue

                # Skip common CDNs and third-party services
                if self._should_skip(url):
                    continue

                seen_urls.add(url)

                # Determine severity based on URL
                severity = self._get_severity(url)

                findings.append(
                    Finding(
                        type=FindingType.URL,
                        value=url,
                        severity=severity,
                        source_file=source_file,
                        line_number=self._get_line_number(content, match.start()),
                        context=self._get_context(content, match.start(), match.end()),
                        confidence=0.9,
                    )
                )

        return findings

    def _normalize_url(self, url: str) -> str | None:
        """Normalize and validate a URL."""
        # Strip quotes and whitespace
        url = url.strip("\"'`\n\r\t ,;")

        # Remove trailing punctuation
        while url and url[-1] in ".,;:!?)>]}'\"":
            url = url[:-1]

        # Validate URL structure
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return None
        except Exception:
            return None

        return url

    def _should_skip(self, url: str) -> bool:
        """Check if URL should be skipped."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Remove port
            if ":" in domain:
                domain = domain.split(":")[0]

            # Check against skip list
            for skip_domain in self.SKIP_DOMAINS:
                if domain == skip_domain or domain.endswith("." + skip_domain):
                    return True

            return False
        except Exception:
            return True

    def _get_severity(self, url: str) -> Severity:
        """Determine severity based on URL content."""
        url_lower = url.lower()

        # Critical: internal/private networks
        if any(
            p in url_lower
            for p in ["localhost", "127.0.0.1", "0.0.0.0", "192.168", "10.", "172.16"]
        ):
            return Severity.HIGH

        # High: staging/dev environments
        if any(
            p in url_lower
            for p in ["staging", "dev", "test", "uat", "qa", "preprod", ".local", ".internal"]
        ):
            return Severity.MEDIUM

        # Medium: admin/api endpoints
        if any(p in url_lower for p in ["admin", "api", "debug"]):
            return Severity.MEDIUM

        return Severity.LOW
