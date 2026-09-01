"""CLI for port-exposure-analyzer."""

from __future__ import annotations

from enum import IntEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from secintel_core import export_csv, export_json, export_sarif, render_report_html

from port_exposure_analyzer.core import TOOL_NAME, TOOL_VERSION, AnalysisConfig, analyze_scan

app = typer.Typer(
    name=TOOL_NAME,
    help="Policy-driven port exposure risk scoring from nmap/masscan scan data.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


class ExitCode(IntEnum):
    SUCCESS = 0
    INPUT_ERROR = 2


@app.command()
def analyze(
    scan_file: Path = typer.Argument(..., help="nmap XML or masscan list file"),
    policy: Path = typer.Option(..., "--policy", "-p", help="YAML exposure policy file"),
    json_output: bool = typer.Option(False, "--json"),
    html_output: Path | None = typer.Option(None, "--html"),
    csv_output: Path | None = typer.Option(None, "--csv"),
    sarif_output: Path | None = typer.Option(None, "--sarif"),
    trend: list[Path] | None = typer.Option(None, "--trend", help="Historical scans for trend"),
    trend_label: list[str] | None = typer.Option(None, "--trend-label", help="Labels for trend scans"),
    sample: bool = typer.Option(False, "--sample"),
    offline: bool = typer.Option(True, "--offline/--allow-network"),
    max_bytes: int = typer.Option(50 * 1024 * 1024, "--max-bytes"),
) -> None:
    """Analyze port exposure against a configurable policy."""
    if not offline:
        console.print("[yellow]Warning: this tool makes no network calls.[/yellow]")

    try:
        config = AnalysisConfig(
            base_dir=Path.cwd(), max_bytes=max_bytes,
            policy_path=policy,
            trend_scans=list(trend or []),
            trend_labels=list(trend_label or []),
        )
        result = analyze_scan(scan_file, config=config, is_sample=sample)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=ExitCode.INPUT_ERROR) from exc

    exp = result.exposure
    table = Table(title="Exposure Summary")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Aggregate Score", f"{exp.aggregate_score}/100")
    table.add_row("Policy Matches", str(exp.total_matches))
    for tier, count in exp.tier_counts.items():
        if count:
            table.add_row(f"Tier: {tier}", str(count))
    console.print(table)

    if json_output:
        typer.echo(export_json(result.report))
    if html_output:
        html_output.write_text(render_report_html(result.report, tool_title=TOOL_NAME), encoding="utf-8")
        console.print(f"HTML report: {html_output}")
    if csv_output:
        csv_output.write_text(export_csv(result.report), encoding="utf-8")
    if sarif_output:
        sarif_output.write_text(export_sarif(result.report), encoding="utf-8")
    if not any([json_output, html_output, csv_output, sarif_output]):
        typer.echo(export_json(result.report))
    raise typer.Exit(code=0)


@app.command()
def version() -> None:
    console.print(f"{TOOL_NAME} v{TOOL_VERSION}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
