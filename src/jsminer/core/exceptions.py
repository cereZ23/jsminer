"""Custom exceptions for JSMiner."""


class JSMinerError(Exception):
    """Base exception for JSMiner."""

    pass


class FetchError(JSMinerError):
    """Error fetching a resource."""

    def __init__(self, message: str, url: str | None = None) -> None:
        super().__init__(message)
        self.url = url


class ParseError(JSMinerError):
    """Error parsing content."""

    def __init__(self, message: str, source: str | None = None) -> None:
        super().__init__(message)
        self.source = source


class ConfigError(JSMinerError):
    """Configuration error."""

    pass
