"""
cli.py
------
netforec — AI-powered network attack forecasting from network traffic.

V1 command surface (per design doc):

    netforec analyze FILE [--json] [-o/--output PATH] [-v/--verbose]
    netforec --version
    netforec --help

This file is UI-only. It never computes anything itself — it calls
`pipeline.run_pipeline()` and formats/prints/saves the result.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from netforec.pipeline import AnalysisResult, PipelineError, run_pipeline

__version__ = "0.1.0"

app = typer.Typer(
    name="netforec",
    help="AI-powered network attack forecasting from network traffic.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)


def _version_callback(value: bool):
    if value:
        console.print(f"netforec version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the installed version.",
    ),
):
    """AI-powered network attack forecasting from network traffic."""
    return


# --------------------------------------------------------------------------
# Output formatting
# --------------------------------------------------------------------------

def _print_table(result: AnalysisResult) -> None:
    console.print()
    console.rule("[bold]NETFOREC — NETWORK ATTACK FORECAST[/bold]")
    console.print()

    console.print(
        f"History analyzed : previous {result.history_minutes} minutes "
        f"({result.window_start} -> {result.window_end})"
    )
    console.print(f"Forecast horizon : next {result.forecast_minutes} minutes")
    console.print(f"Flows processed  : {result.flows_processed:,}")
    console.print()

    console.print(f"Predicted threat : [bold]{result.predicted_class.upper()}[/bold]")
    console.print(f"Confidence       : [bold]{result.confidence * 100:.2f}%[/bold]")
    console.print()

    prob_table = Table(
        title="Probability distribution", show_header=True, header_style="bold"
    )
    prob_table.add_column("Class")
    prob_table.add_column("Probability", justify="right")
    max_bar = 30
    for name, prob in result.class_probabilities:
        bar = "█" * int(prob * max_bar)
        prob_table.add_row(name, f"{bar} {prob * 100:5.2f}%")
    console.print(prob_table)
    console.print()

    risk_styles = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "bold green"}
    style = risk_styles.get(result.risk_level, "bold")
    console.print(f"[{style}]⚠ RISK LEVEL: {result.risk_level}[/{style}]")
    console.print()

    if result.warnings:
        for w in result.warnings:
            console.print(f"[yellow]![/yellow] {w}")
        console.print()


def _write_output(result: AnalysisResult, output_path: Path, as_json: bool) -> None:
    if as_json or output_path.suffix.lower() == ".json":
        output_path.write_text(json.dumps(result.to_dict(), indent=2))
    else:
        # Plain text rendering for non-json output files.
        lines = [
            "NETFOREC — NETWORK ATTACK FORECAST",
            "-" * 34,
            f"History analyzed : previous {result.history_minutes} minutes "
            f"({result.window_start} -> {result.window_end})",
            f"Forecast horizon : next {result.forecast_minutes} minutes",
            f"Flows processed  : {result.flows_processed}",
            "",
            f"Predicted threat : {result.predicted_class}",
            f"Confidence       : {result.confidence * 100:.2f}%",
            "",
            "Probability distribution:",
        ]
        for name, prob in result.class_probabilities:
            lines.append(f"  {name}: {prob * 100:.2f}%")
        lines.append("")
        lines.append(f"Risk level: {result.risk_level}")
        output_path.write_text("\n".join(lines))


# --------------------------------------------------------------------------
# analyze command
# --------------------------------------------------------------------------

@app.command()
def analyze(
    file: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="Path to a PCAP, PCAPNG, or CSV file.",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output results as JSON to stdout."
    ),
    output: Optional[Path] = typer.Option(
        None,
        "-o",
        "--output",
        help="Save results to a file (.json for JSON, otherwise plain text).",
    ),
    verbose: bool = typer.Option(
        False, "-v", "--verbose", help="Show detailed processing information."
    ),
    quiet: bool = typer.Option(
        False,
        "-q",
        "--quiet",
        help="Suppress normal output (table/JSON on screen). "
        "Errors are still shown. Useful with --output when scripting "
        "or when you only want the saved file, not terminal noise.",
    ),
):
    """Analyze network traffic and forecast potential attack progression."""

    if quiet and verbose:
        err_console.print(
            "[bold red]✗[/bold red] --quiet and --verbose can't be used together."
        )
        raise typer.Exit(code=2)

    def log(msg: str) -> None:
        if verbose:
            err_console.print(f"[dim][INFO][/dim] {msg}")

    # --verbose already prints its own step-by-step [INFO] lines, which
    # would visually clash with a spinner sharing the same line. So the
    # spinner only runs in the non-verbose path; verbose users get the
    # log lines instead, which already indicate progress.
    try:
        if verbose:
            result = run_pipeline(str(file), log=log)
        else:
            with console.status(
                "[bold cyan]Analyzing traffic — extracting features, "
                "running model...[/bold cyan]",
                spinner="dots",
            ):
                result = run_pipeline(str(file), log=log)
    except PipelineError as exc:
        err_console.print(f"[bold red]✗ Analysis failed:[/bold red] {exc}")
        raise typer.Exit(code=1)
    except Exception as exc:  # noqa: BLE001 — last-resort guard for demo stability
        err_console.print(f"[bold red]✗ Analysis failed:[/bold red] {exc}")
        if verbose:
            err_console.print_exception()
        raise typer.Exit(code=1)

    if output is not None:
        _write_output(result, output, as_json=json_output)
        if quiet:
            return
        console.print(f"[green]✓[/green] Results saved to {output}")
        # Still show the result on screen by default — saving to a file
        # shouldn't silently mean the terminal stays empty. Pass --quiet
        # if you specifically don't want that (e.g. scripting).
        _print_table(result)
        return

    if quiet:
        # Quiet with no --output has nowhere for the result to go — it
        # would just be discarded, --json or not. Warn on stderr rather
        # than silently throwing away a completed analysis.
        err_console.print(
            "[yellow]![/yellow] --quiet with no --output discards the "
            "result. Did you mean to add -o/--output?"
        )
        return

    if json_output:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_table(result)


if __name__ == "__main__":
    app()