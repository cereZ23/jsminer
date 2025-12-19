"""Base extractor class."""

from abc import ABC, abstractmethod

from jsminer.core.models import Finding


class BaseExtractor(ABC):
    """Base class for all extractors."""

    @abstractmethod
    def extract(self, content: str, source_file: str) -> list[Finding]:
        """Extract findings from JavaScript content.

        Args:
            content: JavaScript file content.
            source_file: URL or path of the source file.

        Returns:
            List of findings.
        """
        pass

    def _get_line_number(self, content: str, match_start: int) -> int:
        """Get line number for a match position."""
        return content[:match_start].count("\n") + 1

    def _get_context(self, content: str, match_start: int, match_end: int, context_chars: int = 50) -> str:
        """Get surrounding context for a match."""
        start = max(0, match_start - context_chars)
        end = min(len(content), match_end + context_chars)
        context = content[start:end]
        # Clean up whitespace
        context = " ".join(context.split())
        if start > 0:
            context = "..." + context
        if end < len(content):
            context = context + "..."
        return context
