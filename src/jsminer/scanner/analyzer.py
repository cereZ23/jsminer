"""JavaScript content analyzer."""

from jsminer.core.config import Config
from jsminer.core.models import Finding, JSFile, ScanResult
from jsminer.extractors.endpoints import EndpointExtractor
from jsminer.extractors.secrets import SecretExtractor
from jsminer.extractors.urls import URLExtractor
from jsminer.scanner.crawler import JSCrawler
from jsminer.scanner.fetcher import JSFetcher


class JSAnalyzer:
    """Main analyzer that coordinates crawling, fetching, and extraction."""

    def __init__(self, config: Config | None = None) -> None:
        """Initialize the analyzer.

        Args:
            config: Configuration options.
        """
        self.config = config or Config()
        self.fetcher = JSFetcher(self.config)
        self.crawler = JSCrawler(self.config)

        # Initialize extractors
        self.extractors = []
        if self.config.extract_secrets:
            self.extractors.append(SecretExtractor(self.config.min_confidence))
        if self.config.extract_endpoints:
            self.extractors.append(EndpointExtractor())
        if self.config.extract_urls:
            self.extractors.append(URLExtractor())

    async def analyze_url(self, url: str) -> ScanResult:
        """Analyze a single URL (crawl for JS files and analyze them).

        Args:
            url: Target URL to analyze.

        Returns:
            ScanResult with all findings.
        """
        result = ScanResult(target=url)

        try:
            # Crawl to find JS files
            js_urls = await self.crawler.crawl(url)

            if not js_urls:
                result.errors.append("No JavaScript files found")
                return result

            # Fetch all JS files
            js_files = await self.fetcher.fetch_many(js_urls)
            result.js_files = js_files

            # Analyze each successful file
            for js_file in js_files:
                if js_file.success and js_file.content:
                    findings = self._analyze_content(js_file.content, js_file.url)
                    result.findings.extend(findings)
                elif js_file.error:
                    result.errors.append(f"{js_file.url}: {js_file.error}")

            # Deduplicate findings
            result.findings = self._deduplicate_findings(result.findings)

        except Exception as e:
            result.errors.append(f"Analysis error: {e}")

        return result

    async def analyze_js_url(self, url: str) -> ScanResult:
        """Analyze a single JavaScript file URL directly.

        Args:
            url: URL of the JavaScript file.

        Returns:
            ScanResult with all findings.
        """
        result = ScanResult(target=url)

        try:
            # Fetch the JS file
            js_file = await self.fetcher.fetch(url)
            result.js_files = [js_file]

            if js_file.success and js_file.content:
                findings = self._analyze_content(js_file.content, js_file.url)
                result.findings = self._deduplicate_findings(findings)
            elif js_file.error:
                result.errors.append(f"{js_file.url}: {js_file.error}")

        except Exception as e:
            result.errors.append(f"Analysis error: {e}")

        return result

    async def analyze_urls(self, urls: list[str]) -> list[ScanResult]:
        """Analyze multiple URLs.

        Args:
            urls: List of URLs to analyze.

        Returns:
            List of ScanResults.
        """
        results = []
        for url in urls:
            if url.lower().endswith((".js", ".mjs", ".jsx")):
                result = await self.analyze_js_url(url)
            else:
                result = await self.analyze_url(url)
            results.append(result)
        return results

    def analyze_content(self, content: str, source: str = "local") -> ScanResult:
        """Analyze JavaScript content directly (for local files).

        Args:
            content: JavaScript content.
            source: Source identifier (filename or URL).

        Returns:
            ScanResult with all findings.
        """
        result = ScanResult(target=source)
        result.js_files = [JSFile(url=source, content=content, size=len(content), status_code=200)]

        findings = self._analyze_content(content, source)
        result.findings = self._deduplicate_findings(findings)

        return result

    def _analyze_content(self, content: str, source_file: str) -> list[Finding]:
        """Run all extractors on content."""
        findings: list[Finding] = []

        for extractor in self.extractors:
            try:
                extractor_findings = extractor.extract(content, source_file)
                findings.extend(extractor_findings)
            except Exception:
                pass  # Skip failed extractors

        return findings

    def _deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings."""
        seen: set[tuple[str, str]] = set()
        unique: list[Finding] = []

        for finding in findings:
            key = (finding.type.value, finding.value)
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    async def close(self) -> None:
        """Close all resources."""
        await self.fetcher.close()
        await self.crawler.close()
