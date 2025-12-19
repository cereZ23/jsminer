"""Configuration for JSMiner."""

from dataclasses import dataclass, field


@dataclass
class Config:
    """JSMiner configuration."""

    # Network settings
    timeout: int = 30
    max_concurrent: int = 10
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    delay: float = 0.5

    # Crawling settings
    crawl_depth: int = 2
    follow_redirects: bool = True
    max_js_size: int = 10 * 1024 * 1024  # 10MB

    # Analysis settings
    extract_endpoints: bool = True
    extract_secrets: bool = True
    extract_urls: bool = True
    extract_comments: bool = True
    min_confidence: float = 0.5

    # Output settings
    verbose: bool = False
    output_format: str = "json"

    # Headers
    headers: dict[str, str] = field(
        default_factory=lambda: {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
    )
