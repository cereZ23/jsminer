"""HTML export for JSMiner."""

from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from jsminer.core.models import ScanResult


class HTMLExporter:
    """Export scan results to HTML."""

    def __init__(self) -> None:
        """Initialize the HTML exporter."""
        self.env = Environment(
            loader=PackageLoader("jsminer.export", "templates"),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def export(self, result: ScanResult, output_path: Path) -> None:
        """Export a single scan result to HTML.

        Args:
            result: Scan result to export.
            output_path: Output file path.
        """
        template = self.env.get_template("report.html.j2")
        html = template.render(
            result=result,
            results=[result],
            is_single=True,
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

    def export_many(self, results: list[ScanResult], output_path: Path) -> None:
        """Export multiple scan results to HTML.

        Args:
            results: List of scan results.
            output_path: Output file path.
        """
        template = self.env.get_template("report.html.j2")

        # Aggregate stats
        total_stats = {
            "targets": len(results),
            "js_files": sum(len(r.js_files) for r in results),
            "findings": sum(len(r.findings) for r in results),
            "critical": sum(len(r.critical_findings) for r in results),
            "high": sum(len(r.high_findings) for r in results),
        }

        html = template.render(
            results=results,
            total_stats=total_stats,
            is_single=False,
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
