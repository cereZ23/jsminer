"""API endpoint extractor."""

from jsminer.core.models import Finding, FindingType, Severity
from jsminer.extractors.base import BaseExtractor
from jsminer.patterns import ENDPOINT_PATTERNS


class EndpointExtractor(BaseExtractor):
    """Extract API endpoints from JavaScript."""

    # High-value endpoint keywords
    HIGH_VALUE_KEYWORDS = {
        "admin",
        "auth",
        "login",
        "token",
        "oauth",
        "api/v",
        "graphql",
        "internal",
        "debug",
        "backup",
        "config",
        "upload",
        "download",
        "export",
        "user",
        "account",
        "password",
        "reset",
        "verify",
        "webhook",
        "callback",
    }

    # Common false positive patterns
    FALSE_POSITIVES = {
        "/static/",
        "/assets/",
        "/images/",
        "/img/",
        "/css/",
        "/js/",
        "/fonts/",
        "/favicon",
        ".png",
        ".jpg",
        ".gif",
        ".svg",
        ".css",
        ".js",
        ".map",
        ".woff",
        ".ttf",
        ".ico",
        "node_modules",
    }

    def extract(self, content: str, source_file: str) -> list[Finding]:
        """Extract endpoints from JavaScript content."""
        findings: list[Finding] = []
        seen_endpoints: set[str] = set()

        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.finditer(content):
                endpoint = match.group(1) if match.lastindex else match.group(0)

                # Normalize endpoint
                endpoint = self._normalize_endpoint(endpoint)
                if not endpoint:
                    continue

                # Skip duplicates
                if endpoint in seen_endpoints:
                    continue

                # Skip false positives
                if self._is_false_positive(endpoint):
                    continue

                seen_endpoints.add(endpoint)

                # Determine severity based on endpoint value
                severity = self._get_severity(endpoint)

                findings.append(
                    Finding(
                        type=FindingType.ENDPOINT,
                        value=endpoint,
                        severity=severity,
                        source_file=source_file,
                        line_number=self._get_line_number(content, match.start()),
                        context=self._get_context(content, match.start(), match.end()),
                        confidence=0.8,
                    )
                )

        return findings

    def _normalize_endpoint(self, endpoint: str) -> str | None:
        """Normalize and validate an endpoint."""
        # Strip quotes and whitespace
        endpoint = endpoint.strip("\"'`\n\r\t ")

        # Must start with /
        if not endpoint.startswith("/"):
            return None

        # Minimum length
        if len(endpoint) < 3:
            return None

        # Remove query strings for deduplication
        if "?" in endpoint:
            endpoint = endpoint.split("?")[0]

        # Remove trailing slashes
        endpoint = endpoint.rstrip("/")

        return endpoint if endpoint else None

    def _is_false_positive(self, endpoint: str) -> bool:
        """Check if an endpoint is likely a false positive."""
        endpoint_lower = endpoint.lower()
        return any(fp in endpoint_lower for fp in self.FALSE_POSITIVES)

    def _get_severity(self, endpoint: str) -> Severity:
        """Determine severity based on endpoint keywords."""
        endpoint_lower = endpoint.lower()

        # Critical endpoints
        if any(kw in endpoint_lower for kw in ["admin", "internal", "debug", "backup", "config"]):
            return Severity.HIGH

        # High-value endpoints
        if any(kw in endpoint_lower for kw in self.HIGH_VALUE_KEYWORDS):
            return Severity.MEDIUM

        return Severity.INFO
