"""
Human-readable text output formatter.
"""

from io import StringIO
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from fastapi_endpoint_detector.models.endpoint import Endpoint
from fastapi_endpoint_detector.models.report import AnalysisReport, ConfidenceLevel
from fastapi_endpoint_detector.output.formatters import BaseFormatter, register_formatter


@register_formatter("text")
class TextFormatter(BaseFormatter):
    """
    Format output as human-readable text using Rich.
    """

    def __init__(self, colorize: bool = True) -> None:
        """
        Initialize the text formatter.

        Args:
            colorize: Whether to use colors in output.
        """
        self.colorize = colorize

    def _confidence_style(self, confidence: ConfidenceLevel) -> str:
        """Get the style for a confidence level."""
        if not self.colorize:
            return ""

        styles = {
            ConfidenceLevel.HIGH: "bold red",
            ConfidenceLevel.MEDIUM: "yellow",
            ConfidenceLevel.LOW: "dim",
        }
        return styles.get(confidence, "")

    def _confidence_icon(self, confidence: ConfidenceLevel) -> str:
        """Get an icon for a confidence level."""
        icons = {
            ConfidenceLevel.HIGH: "🔴",
            ConfidenceLevel.MEDIUM: "🟡",
            ConfidenceLevel.LOW: "🟢",
        }
        return icons.get(confidence, "⚪")

    def format(self, report: AnalysisReport) -> str:
        """Format an analysis report as text."""
        output = StringIO()
        console = Console(file=output, force_terminal=self.colorize, width=120)

        # Header
        console.print()
        console.print(
            Panel.fit(
                "[bold]FastAPI Endpoint Change Detector[/bold]\nAnalysis Report",
                border_style="blue",
            )
        )
        console.print()

        # Summary
        console.print("[bold]Summary[/bold]")
        console.print(f"  App Path: {report.app_path}")
        console.print(f"  Diff Source: {report.diff_source}")
        console.print(f"  Total Endpoints: {report.total_endpoints}")
        console.print(
            f"  Files Changed: {report.total_files_changed} ({report.python_files_changed} Python)"
        )
        console.print(f"  Affected Endpoints: {report.affected_count}")
        if report.candidate_endpoints:
            console.print(f"  Reachable Candidates: {len(report.candidate_endpoints)}")
        if report.analysis_duration_ms:
            console.print(f"  Analysis Time: {report.analysis_duration_ms:.2f}ms")
        console.print()

        # Affected endpoints
        if report.affected_endpoints:
            console.print("[bold]Affected Endpoints[/bold]")
            console.print()

            # Group by confidence
            for confidence in [ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW]:
                endpoints = report.get_endpoints_by_confidence(confidence)
                if not endpoints:
                    continue

                icon = self._confidence_icon(confidence)
                style = self._confidence_style(confidence)
                console.print(
                    f"  {icon} [bold]{confidence.value.upper()} Confidence[/bold] ({len(endpoints)})"
                )

                for ae in endpoints:
                    ep = ae.endpoint
                    methods = ",".join(m.value for m in ep.methods)
                    console.print(f"    [{style}]{methods} {ep.path}[/{style}]")
                    console.print(
                        f"      Handler: {ep.handler.name} ({ep.handler.file_path}:{ep.handler.line_number})"
                    )
                    console.print(f"      Reason: {ae.reason}")
                    if ae.dependency_chain and len(ae.dependency_chain) > 1:
                        chain = " → ".join(ae.dependency_chain)
                        console.print(f"      Chain: {chain}")
                    for evidence in ae.effect_evidence:
                        console.print(
                            f"      Effect: [{evidence.status.value} / "
                            f"{evidence.disposition.value}] {evidence.summary}"
                        )

                    # Show traceback-style call stack if available
                    if ae.call_stacks:
                        console.print()
                        console.print("      [bold cyan]Call Stack (traceback style):[/bold cyan]")
                        traceback_lines = ae.format_traceback().strip().split("\n")
                        for line in traceback_lines:
                            console.print(f"      {line}")
                    console.print()
        else:
            console.print("[green]No endpoints selected by the confidence threshold.[/green]")
            console.print()

        additional = [
            candidate
            for candidate in report.candidate_endpoints
            if candidate not in report.affected_endpoints
        ]
        if additional:
            console.print("[bold]Additional Reachable Candidates[/bold]")
            console.print(
                "[dim]Retained for inspection; not selected by the legacy threshold.[/dim]"
            )
            for candidate in additional:
                methods = ",".join(method.value for method in candidate.endpoint.methods)
                console.print(
                    f"  {methods} {candidate.endpoint.path} ({candidate.confidence.value})"
                )
                for evidence in candidate.effect_evidence:
                    console.print(f"    {evidence.disposition.value}: {evidence.summary}")
            console.print()

        # Orphan changes
        if report.orphan_changes:
            console.print("[bold yellow]⚠️  Orphan Code Changes[/bold yellow]")
            console.print(
                f"[dim]Changes not related to any endpoint ({report.total_orphan_lines} lines in {report.orphan_count} files)[/dim]"
            )
            console.print()

            for oc in report.orphan_changes:
                file_name = Path(oc.file_path).name
                console.print(f"  📄 [cyan]{file_name}[/cyan] ({oc.file_path})")
                console.print(f"     {oc.format_lines()}")
                console.print(f"     [dim]Reason: {oc.reason}[/dim]")
                console.print()

            console.print("[dim]💡 Tip: Orphan changes may indicate:[/dim]")
            console.print("[dim]   • Unused or dead code[/dim]")
            console.print(
                "[dim]   • Code with incorrect types preventing dependency analysis[/dim]"
            )
            console.print("[dim]   • Utility code not called by any endpoint[/dim]")
            console.print("[dim]   • Code outside the analyzed application scope[/dim]")
            console.print()

        # Errors and warnings
        if report.errors:
            console.print("[bold red]Errors[/bold red]")
            for error in report.errors:
                console.print(f"  ❌ {error}")
            console.print()

        if report.warnings:
            console.print("[bold yellow]Warnings[/bold yellow]")
            for warning in report.warnings:
                console.print(f"  ⚠️  {warning}")
            console.print()

        return output.getvalue()

    def format_endpoints(self, endpoints: list[Endpoint]) -> str:
        """Format a list of endpoints as a table."""
        output = StringIO()
        console = Console(file=output, force_terminal=self.colorize, width=120)

        if not endpoints:
            console.print("[dim]No endpoints found.[/dim]")
            return output.getvalue()

        table = Table(title="FastAPI Endpoints", show_header=True, header_style="bold")
        table.add_column("Method(s)", style="cyan")
        table.add_column("Path", style="green")
        table.add_column("Handler", style="yellow")
        table.add_column("File", style="dim")
        table.add_column("Line", justify="right")

        for ep in endpoints:
            methods = ",".join(m.value for m in ep.methods)
            file_name = ep.handler.file_path.name
            table.add_row(
                methods,
                ep.path,
                ep.handler.name,
                file_name,
                str(ep.handler.line_number),
            )

        console.print(table)
        console.print(f"\nTotal: {len(endpoints)} endpoints")

        return output.getvalue()
