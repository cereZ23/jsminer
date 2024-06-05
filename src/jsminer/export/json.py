"""JSON export for JSMiner."""

import json
from pathlib import Path

from jsminer.core.models import ScanResult


class JSONExporter:
    """Export scan results to JSON."""

    def export(self, result: ScanResult, output_path: Path) -> None:
        """Export a single scan result to JSON.

        Args:
            result: Scan result to export.
            output_path: Output file path.
        """
        data = self._result_to_dict(result)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def export_many(self, results: list[ScanResult], output_path: Path) -> None:
        """Export multiple scan results to JSON.

        Args:
            results: List of scan results.
            output_path: Output file path.
        """
        data = {
            "scans": [self._result_to_dict(r) for r in results],
            "summary": self._create_summary(results),
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def _result_to_dict(self, result: ScanResult) -> dict:
        """Convert scan result to dictionary."""
        return {
            "target": result.target,
            "scan_time": result.scan_time.isoformat(),
            "stats": result.stats,
            "js_files": [
                {
                    "url": f.url,
                    "size": f.size,
                    "status": f.status_code,
                    "success": f.success,
                    "error": f.error,
                }
                for f in result.js_files
            ],
            "findings": [
                {
                    "type": f.type.value,
                    "value": f.value,
                    "secret_type": f.secret_type.value if f.secret_type else None,
                    "severity": f.severity.value,
                    "source_file": f.source_file,
                    "line_number": f.line_number,
                    "context": f.context,
                    "confidence": f.confidence,
                }
                for f in result.findings
            ],
            "errors": result.errors,
        }

    def _create_summary(self, results: list[ScanResult]) -> dict:
        """Create summary statistics for multiple results."""
        total_js = sum(len(r.js_files) for r in results)
        total_findings = sum(len(r.findings) for r in results)
        total_critical = sum(len(r.critical_findings) for r in results)
        total_high = sum(len(r.high_findings) for r in results)

        return {
            "total_targets": len(results),
            "total_js_files": total_js,
            "total_findings": total_findings,
            "critical_findings": total_critical,
            "high_findings": total_high,
        }
