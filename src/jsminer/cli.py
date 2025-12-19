"""Command-line interface for JSMiner."""

import asyncio
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from jsminer import __version__
from jsminer.core.config import Config
from jsminer.core.models import ScanResult, Severity
from jsminer.export.html import HTMLExporter
from jsminer.export.json import JSONExporter
from jsminer.scanner.analyzer import JSAnalyzer

console = Console()

BANNER = r"""
[bold cyan]
     ██╗███████╗███╗   ███╗██╗███╗   ██╗███████╗██████╗
     ██║██╔════╝████╗ ████║██║████╗  ██║██╔════╝██╔══██╗
     ██║███████╗██╔████╔██║██║██╔██╗ ██║█████╗  ██████╔╝
██   ██║╚════██║██║╚██╔╝██║██║██║╚██╗██║██╔══╝  ██╔══██╗
╚█████╔╝███████║██║ ╚═╝ ██║██║██║ ╚████║███████╗██║  ██║
 ╚════╝ ╚══════╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
[/bold cyan]
[dim]JavaScript Security Mining Tool - v{version}[/dim]
"""


@click.command()
@click.option(
    "-u",
    "--url",
    help="Single URL to analyze (webpage or .js file)",
)
@click.option(
    "-l",
    "--list",
    "url_list",
    type=click.Path(exists=True),
    help="File containing list of URLs (one per line)",
)
@click.option(
    "-f",
    "--file",
    "local_file",
    type=click.Path(exists=True),
    help="Local JavaScript file to analyze",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    help="Output file (JSON or HTML based on extension)",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Force JSON output format",
)
@click.option(
    "-c",
    "--concurrent",
    default=10,
    type=int,
    help="Maximum concurrent requests (default: 10)",
)
@click.option(
    "--delay",
    default=0.5,
    type=float,
    help="Delay between requests in seconds (default: 0.5)",
)
@click.option(
    "--timeout",
    default=30,
    type=int,
    help="Request timeout in seconds (default: 30)",
)
@click.option(
    "--no-endpoints",
    is_flag=True,
    help="Disable endpoint extraction",
)
@click.option(
    "--no-secrets",
    is_flag=True,
    help="Disable secret/API key extraction",
)
@click.option(
    "--no-urls",
    is_flag=True,
    help="Disable URL extraction",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    help="Verbose output",
)
@click.version_option(version=__version__)
def main(
    url: str | None,
    url_list: str | None,
    local_file: str | None,
    output: str | None,
    json_output: bool,
    concurrent: int,
    delay: float,
    timeout: int,
    no_endpoints: bool,
    no_secrets: bool,
    no_urls: bool,
    verbose: bool,
) -> None:
    """JSMiner - Extract endpoints, API keys, and secrets from JavaScript.

    Examples:

        # Analyze a website
        jsminer -u https://example.com -o report.html

        # Analyze a JavaScript file directly
        jsminer -u https://example.com/app.js -o report.json

        # Analyze multiple URLs from a file
        jsminer -l urls.txt -o report.html

        # Analyze a local JavaScript file
        jsminer -f app.js -o report.json
    """
    console.print(BANNER.format(version=__version__))

    # Validate input
    if not any([url, url_list, local_file]):
        console.print("[red]Error: Provide -u URL, -l URL_LIST, or -f FILE[/red]")
        raise click.Abort()

    # Create config
    config = Config(
        max_concurrent=concurrent,
        delay=delay,
        timeout=timeout,
        extract_endpoints=not no_endpoints,
        extract_secrets=not no_secrets,
        extract_urls=not no_urls,
        verbose=verbose,
    )

    # Run analysis
    if local_file:
        result = analyze_local_file(Path(local_file), config)
        results = [result]
    elif url_list:
        results = asyncio.run(analyze_url_list(Path(url_list), config))
    else:
        results = asyncio.run(analyze_single_url(url, config))

    # Display results
    for result in results:
        display_result(result, verbose)

    # Export if output specified
    if output:
        export_results(results, Path(output), json_output)


async def analyze_single_url(url: str, config: Config) -> list[ScanResult]:
    """Analyze a single URL."""
    analyzer = JSAnalyzer(config)

    try:
        with console.status(f"[bold green]Analyzing {url}..."):
            if url.lower().endswith((".js", ".mjs", ".jsx")):
                result = await analyzer.analyze_js_url(url)
            else:
                result = await analyzer.analyze_url(url)
        return [result]
    finally:
        await analyzer.close()


async def analyze_url_list(url_file: Path, config: Config) -> list[ScanResult]:
    """Analyze URLs from a file."""
    urls = [line.strip() for line in url_file.read_text().splitlines() if line.strip()]

    if not urls:
        console.print("[yellow]No URLs found in file[/yellow]")
        return []

    console.print(f"[cyan]Found {len(urls)} URLs to analyze[/cyan]\n")

    analyzer = JSAnalyzer(config)
    results: list[ScanResult] = []

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("Analyzing...", total=len(urls))

            for url in urls:
                progress.update(task, description=f"Analyzing {url[:50]}...")

                if url.lower().endswith((".js", ".mjs", ".jsx")):
                    result = await analyzer.analyze_js_url(url)
                else:
                    result = await analyzer.analyze_url(url)

                results.append(result)
                progress.advance(task)

    finally:
        await analyzer.close()

    return results


def analyze_local_file(file_path: Path, config: Config) -> ScanResult:
    """Analyze a local JavaScript file."""
    console.print(f"[cyan]Analyzing local file: {file_path}[/cyan]\n")

    content = file_path.read_text(encoding="utf-8", errors="ignore")
    analyzer = JSAnalyzer(config)

    return analyzer.analyze_content(content, str(file_path))


def display_result(result: ScanResult, verbose: bool) -> None:
    """Display scan result."""
    console.print()

    # Summary panel
    stats = result.stats
    severity_counts = {
        "critical": len(result.critical_findings),
        "high": len(result.high_findings),
    }

    summary = f"""
[bold]Target:[/bold] {result.target}
[bold]JS Files:[/bold] {stats["js_files"]} ({stats["js_files_success"]} successful)
[bold]Total Findings:[/bold] {stats["total_findings"]}
[bold]Critical:[/bold] [red]{severity_counts["critical"]}[/red]
[bold]High:[/bold] [yellow]{severity_counts["high"]}[/yellow]
[bold]Endpoints:[/bold] {stats["endpoints"]}
[bold]API Keys:[/bold] {stats["api_keys"]}
[bold]Secrets:[/bold] {stats["secrets"]}
[bold]URLs:[/bold] {stats["urls"]}
"""
    console.print(Panel(summary.strip(), title="[bold]Summary[/bold]", border_style="blue"))

    # Critical and high findings
    important_findings = [
        f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]

    if important_findings:
        table = Table(title="[bold red]Critical & High Findings[/bold red]")
        table.add_column("Severity", style="bold")
        table.add_column("Type")
        table.add_column("Value", max_width=60)
        table.add_column("Source")

        for finding in important_findings[:20]:
            severity_color = "red" if finding.severity == Severity.CRITICAL else "yellow"
            table.add_row(
                f"[{severity_color}]{finding.severity.value}[/{severity_color}]",
                finding.type.value,
                finding.value[:60] + "..." if len(finding.value) > 60 else finding.value,
                finding.source_file.split("/")[-1][:30],
            )

        console.print(table)
        console.print()

    # Verbose: show all findings
    if verbose and result.findings:
        table = Table(title="[bold cyan]All Findings[/bold cyan]")
        table.add_column("Type")
        table.add_column("Value", max_width=80)

        for finding in result.findings:
            table.add_row(
                finding.type.value,
                finding.value[:80] + "..." if len(finding.value) > 80 else finding.value,
            )

        console.print(table)

    # Errors
    if result.errors and verbose:
        console.print(f"\n[yellow]Errors ({len(result.errors)}):[/yellow]")
        for error in result.errors[:10]:
            console.print(f"  [dim]- {error}[/dim]")


def export_results(results: list[ScanResult], output_path: Path, force_json: bool) -> None:
    """Export results to file."""
    if force_json or output_path.suffix.lower() == ".json":
        exporter = JSONExporter()
    else:
        exporter = HTMLExporter()

    if len(results) == 1:
        exporter.export(results[0], output_path)
    else:
        exporter.export_many(results, output_path)

    console.print(f"\n[green]Report saved to: {output_path}[/green]")


if __name__ == "__main__":
    main()
