"""Secret and API key extractor."""

from jsminer.core.models import Finding, FindingType
from jsminer.extractors.base import BaseExtractor
from jsminer.patterns import API_KEY_PATTERNS, SECRET_PATTERNS, CREDENTIAL_PATTERNS


class SecretExtractor(BaseExtractor):
    """Extract secrets, API keys, and credentials from JavaScript."""

    def __init__(self, min_confidence: float = 0.5) -> None:
        """Initialize the extractor.

        Args:
            min_confidence: Minimum confidence threshold for findings.
        """
        self.min_confidence = min_confidence

    def extract(self, content: str, source_file: str) -> list[Finding]:
        """Extract secrets from JavaScript content."""
        findings: list[Finding] = []
        seen_values: set[str] = set()

        # Extract API keys
        for pattern, secret_type, severity, confidence in API_KEY_PATTERNS:
            if confidence < self.min_confidence:
                continue

            for match in pattern.finditer(content):
                value = match.group(1) if match.lastindex else match.group(0)
                if value in seen_values:
                    continue
                seen_values.add(value)

                findings.append(
                    Finding(
                        type=FindingType.API_KEY,
                        value=value,
                        secret_type=secret_type,
                        severity=severity,
                        source_file=source_file,
                        line_number=self._get_line_number(content, match.start()),
                        context=self._get_context(content, match.start(), match.end()),
                        confidence=confidence,
                    )
                )

        # Extract other secrets
        for pattern, secret_type, severity, confidence in SECRET_PATTERNS:
            if confidence < self.min_confidence:
                continue

            for match in pattern.finditer(content):
                value = match.group(1) if match.lastindex else match.group(0)
                if value in seen_values:
                    continue
                seen_values.add(value)

                findings.append(
                    Finding(
                        type=FindingType.SECRET,
                        value=value,
                        secret_type=secret_type,
                        severity=severity,
                        source_file=source_file,
                        line_number=self._get_line_number(content, match.start()),
                        context=self._get_context(content, match.start(), match.end()),
                        confidence=confidence,
                    )
                )

        # Extract credentials
        for pattern, secret_type, severity, confidence in CREDENTIAL_PATTERNS:
            if confidence < self.min_confidence:
                continue

            for match in pattern.finditer(content):
                value = match.group(1) if match.lastindex else match.group(0)
                if value in seen_values:
                    continue

                # Skip common false positives
                if self._is_false_positive(value):
                    continue

                seen_values.add(value)

                findings.append(
                    Finding(
                        type=FindingType.CREDENTIAL,
                        value=value,
                        secret_type=secret_type,
                        severity=severity,
                        source_file=source_file,
                        line_number=self._get_line_number(content, match.start()),
                        context=self._get_context(content, match.start(), match.end()),
                        confidence=confidence,
                    )
                )

        return findings

    def _is_false_positive(self, value: str) -> bool:
        """Check if a value is likely a false positive."""
        false_positives = {
            "password", "secret", "token", "key", "test", "example",
            "placeholder", "your_", "xxx", "...", "null", "undefined",
            "true", "false", "none", "empty", "default", "sample",
        }
        value_lower = value.lower()
        return any(fp in value_lower for fp in false_positives) or len(value) < 6
