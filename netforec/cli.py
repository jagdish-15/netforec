"""
cli.py
------
netforec — AI-powered network attack forecasting from network traffic.
"""

from __future__ import annotations
import json
import sys
import subprocess
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from netforec.pipeline import AnalysisResult, PipelineError, run_pipeline
from netforec.validation import validate_input, ValidationResult

__version__ = "0.2.0"

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
        None, "--version", callback=_version_callback, is_eager=True, help="Show the installed version."
    ),
):
    return

def render_validation_result(result: ValidationResult, filename: str) -> None:
    """Consolidated rendering block for validation ✓/✗."""
    console.print()
    if result.is_valid:
        console.print(f"[bold green]✓[/bold green] {filename} is VALID")
    else:
        console.print(f"[bold red]✗[/bold red] {filename} is INVALID")
        for e in result.errors:
            console.print(f"  • {e}")
    for w in result.warnings:
        console.print(f"  [yellow]⚠[/yellow] {w}")
    console.print()

def _print_table(result: AnalysisResult, verbose: bool, investigate: bool, explain: bool) -> None:
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

    # -- Default Output Tiering --
    is_normal = (result.predicted_class == "Normal")
    
    console.print(f"Predicted threat : [bold]{result.predicted_class.upper()}[/bold]")
    console.print(f"Confidence       : [bold]{result.confidence * 100:.2f}%[/bold]")
    
    if is_normal and not verbose and not investigate and not explain:
        console.print()
        prob_table = Table(
            title="Probability distribution", show_header=True, header_style="bold"
        )
        prob_table.add_column("Class")
        prob_table.add_column("Probability", justify="right")
        for name, prob in result.class_probabilities:
            bar = "#" * int(prob * 30)
            prob_table.add_row(name, f"{bar} {prob * 100:5.2f}%")
        console.print(prob_table)
        console.print()
        console.print("[green]OK: No significant anomalies detected.[/green]")
        console.print("\n[bold green]⚠ RISK LEVEL: LOW[/bold green]")
        return
        
    # Extra data triggers
    if result.mitre_tactic and result.mitre_tactic != "—":
        console.print(f"MITRE Tactic     : {result.mitre_tactic}")
        console.print(f"MITRE Technique  : {result.mitre_technique} ({result.mitre_technique_id})")
        console.print(f"Description      : {result.mitre_description}")
    console.print()
    
    prob_table = Table(
        title="Probability distribution", show_header=True, header_style="bold"
    )
    prob_table.add_column("Class")
    prob_table.add_column("Probability", justify="right")
    for name, prob in result.class_probabilities:
        bar = "#" * int(prob * 30)
        prob_table.add_row(name, f"{bar} {prob * 100:5.2f}%")
    console.print(prob_table)
    console.print()

    raw = getattr(result, "raw_json", {})
    if raw:
        # K-Step Forecast - Only if verbose
        if verbose and "forecast" in raw and "predictions" in raw["forecast"]:
            console.print("[bold]K-Step Forward Forecast:[/bold]")
            f_table = Table(show_header=True, header_style="bold", box=None)
            f_table.add_column("Time Ahead")
            f_table.add_column("Infiltration Probability")
            for k in raw["forecast"]["predictions"]:
                f_table.add_row(f"+{k['time_ahead_minutes']} mins", f"{k['infiltration_probability'] * 100:.1f}%")
            console.print(f_table)
            console.print()

        # Evidence display logic
        if "evidence" in raw and len(raw["evidence"]) > 0:
            if explain:
                console.print("[bold]Explainability (Diagnostic Vectors):[/bold]")
                for e in raw["evidence"]:
                    console.print(f"  • [cyan]{e['feature']}[/cyan]: Z-Score: {e.get('value', 'N/A')} [{e['effect'].casefold()}] -> {e['description']}")
                console.print()
            elif verbose:
                console.print("[bold]Key Evidence (Feature Deviations):[/bold]")
                for e in raw["evidence"]:
                    console.print(f"  • [cyan]{e['feature']}[/cyan]: {e['description']}")
                console.print()
            elif not is_normal: # Compact indicators
                console.print("[bold]Top Indicators:[/bold]")
                indicators = raw["evidence"][:2]
                for e in indicators:
                    console.print(f"  • [cyan]{e['feature']}[/cyan] ({e['effect'].casefold()})")
                console.print()

        # Attack Progression - verbose only
        if verbose and "attack_progression" in raw:
            prog = raw["attack_progression"]
            console.print(f"Current Phase : {prog.get('current_stage', 'Unknown')}")
            console.print(f"Future Phase  : {prog.get('predicted_stage', 'Unknown')}")
            console.print()
            
        # Investigate IP logic
        if investigate and not is_normal:
            console.print("[bold]Investigation Target Detail:[/bold]")
            inv = raw.get("investigation", {})
            srcs = ", ".join(inv.get("source_ips", [])) or "None"
            dsts = ", ".join(str(p) for p in inv.get("destination_ports", [])) or "None"
            console.print(f"  Target Source IPs  : [red]{srcs}[/red]")
            console.print(f"  Target Dest Ports  : [yellow]{dsts}[/yellow]")
            console.print()
            if inv.get("source_ips") and len(inv.get("source_ips")) == 5:
                # Notify the team about lack of precise attribution in model capability
                console.print("  [dim]Note: Internal model does not currently assign attribution scores to individual IPs; logging active IPs in the affected flow window.[/dim]")
                console.print()

    # Compact risk summary line
    risk_styles = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "bold green"}
    style = risk_styles.get(result.risk_level, "bold")
    
    if not is_normal and not verbose and not explain and not investigate:
        indicators_str = "multi-dimensional analysis"
        if raw and "evidence" in raw and len(raw["evidence"]) > 0:
            indicators_str = " and ".join([e["feature"] for e in raw["evidence"][:2]])
        technique = raw.get("mitre_attack", {}).get("technique", {}).get("id", "Unknown") if raw else "Unknown"
        console.print(f"[{style}]⚠ RISK LEVEL: {result.risk_level}[/{style}] — {result.predicted_class} ({technique}) pattern detected, driven by {indicators_str}.")
    else:
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
        lines = [
            "NETFOREC — NETWORK ATTACK FORECAST",
            "-" * 34,
            f"History analyzed : previous {result.history_minutes} minutes "
            f"({result.window_start} -> {result.window_end})",
            f"Forecast horizon : next {result.forecast_minutes} minutes",
            f"Flows processed  : {result.flows_processed}",
            "",
            f"Predicted threat : {result.predicted_class}",
            f"Confidence       : {result.confidence * 100:.2f}%"
        ]
        if result.mitre_tactic and result.mitre_tactic != "—":
            lines.extend([
                f"MITRE Tactic     : {result.mitre_tactic}",
                f"MITRE Technique  : {result.mitre_technique} ({result.mitre_technique_id})",
                f"Description      : {result.mitre_description}"
            ])
        lines.extend([
            "",
            "Probability distribution:",
        ])
        for name, prob in result.class_probabilities:
            lines.append(f"  {name}: {prob * 100:.2f}%")
        lines.append("")
        lines.append(f"Risk level: {result.risk_level}")
        output_path.write_text("\n".join(lines))


@app.command()
def validate(
    file: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="Path to a CSV file to validate."
    )
):
    """Validate a CSV file against NETFOREC structure requirements."""
    val = validate_input(file)
    render_validation_result(val, file.name)
    if not val.is_valid:
        raise typer.Exit(code=1)


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
        None, "-o", "--output", help="Save results to a file (.json for JSON, otherwise plain text)."
    ),
    verbose: bool = typer.Option(
        False, "-v", "--verbose", help="Show full diagnostics and k-step forecast."
    ),
    investigate: bool = typer.Option(
        False, "-i", "--investigate", help="Render target source IPs and destination ports."
    ),
    explain: bool = typer.Option(
        False, "-e", "--explain", help="Show explicit SHAP/attribution Z-scores."
    ),
    quiet: bool = typer.Option(
        False, "-q", "--quiet",
        help="Suppress normal output (table/JSON on screen). Errors are still shown."
    ),
):
    """Analyze network traffic and forecast potential attack progression."""
    if quiet and (verbose or investigate or explain):
        err_console.print("[bold red]✗[/bold red] --quiet cannot be combined with visual detail flags.")
        raise typer.Exit(code=2)

    val = validate_input(file)
    if not val.is_valid:
        render_validation_result(val, file.name)
        raise typer.Exit(code=1)

    def log(msg: str) -> None:
        if verbose or investigate or explain:
            err_console.print(f"[dim][INFO][/dim] {msg}")

    try:
        if verbose or investigate or explain:
            result = run_pipeline(str(file), log=log)
        else:
            with console.status("[bold cyan]Analyzing traffic...[/bold cyan]", spinner="dots"):
                result = run_pipeline(str(file), log=log)
    except PipelineError as exc:
        err_console.print(f"[bold red]✗ Analysis failed:[/bold red] {exc}")
        raise typer.Exit(code=1)
    except Exception as exc:
        err_console.print(f"[bold red]✗ Analysis failed:[/bold red] {exc}")
        if verbose:
            err_console.print_exception()
        raise typer.Exit(code=1)

    if output is not None:
        _write_output(result, output, as_json=json_output)
        if quiet:
            return
        console.print(f"[green]OK:[/green] Results saved to {output}")
        _print_table(result, verbose, investigate, explain)
        return

    if quiet:
        err_console.print("[yellow]![/yellow] --quiet with no --output discards the result. Did you mean to add -o/--output?")
        return

    if json_output:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_table(result, verbose, investigate, explain)

@app.command()
def dashboard():
    """Launch the NETFOREC offline dashboard (Streamlit)."""
    webapp_path = Path(__file__).parent / "webapp.py"
    console.print("[bold green]Starting NETFOREC dashboard at http://localhost:8501[/bold green] (press Ctrl+C to stop)")
    try:
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", str(webapp_path), 
            "--server.headless=false", 
            "--theme.base=dark"
        ])
    except KeyboardInterrupt:
        pass

@app.command()
def batch(
    directory: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Directory containing CSV files.",
    ),
    json_path: Optional[Path] = typer.Option(
        None, "--json", help="Save full batch results to a JSON file."
    ),
    csv_path: Optional[Path] = typer.Option(
        None, "--csv", help="Save summarized batch results to a CSV file."
    ),
    fail_fast: bool = typer.Option(
        False, "--fail-fast", help="Stop processing at the first validation error."
    )
):
    """Batch analyze multiple CSV files in a directory."""
    files = sorted(directory.glob("*.csv"))
    if not files:
        err_console.print(f"[yellow]No .csv files found in {directory}[/yellow]")
        raise typer.Exit(code=1)

    console.print(f"\n[bold]Batch processing {len(files)} files found in {directory}...[/bold]\n")

    results_data = []
    
    summary_table = Table(show_header=True, header_style="bold", box=None)
    summary_table.add_column("File")
    summary_table.add_column("Predicted")
    summary_table.add_column("Confidence")
    summary_table.add_column("Risk")

    processed_count = 0
    skipped_count = 0
    classes = {}
    risks = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_conf = 0.0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Processing files...", total=len(files))
        for f in files:
            progress.update(task, description=f"[cyan]Validating {f.name}...")
            val = validate_input(f)
            if not val.is_valid:
                skipped_count += 1
                reason = val.errors[0] if val.errors else "Unknown"
                if fail_fast:
                    progress.stop()
                    render_validation_result(val, f.name)
                    raise typer.Exit(code=1)
                
                summary_table.add_row(f.name, f"[yellow]⚠ SKIPPED — {reason}[/yellow]", "", "")
                results_data.append({
                    "file": f.name,
                    "skipped": True,
                    "skip_reason": reason,
                    "predicted_class": "",
                    "confidence": "",
                    "risk_level": ""
                })
                progress.advance(task)
                continue
                
            progress.update(task, description=f"[cyan]Analyzing {f.name}...")
            try:
                res = run_pipeline(str(f), log=lambda x: None)
            except Exception as e:
                skipped_count += 1
                reason = f"Analysis Error: {str(e)}"
                if fail_fast:
                    progress.stop()
                    err_console.print(f"\n[bold red]Fail Fast triggered during analysis on {f.name}:[/bold red] {e}")
                    raise typer.Exit(code=1)
                summary_table.add_row(f.name, f"[red]✗ FAILED — {reason}[/red]", "", "")
                results_data.append({
                    "file": f.name,
                    "skipped": True,
                    "skip_reason": reason,
                    "predicted_class": "",
                    "confidence": "",
                    "risk_level": ""
                })
                progress.advance(task)
                continue

            processed_count += 1
            pred = res.predicted_class
            conf = res.confidence
            risk = res.risk_level
            
            classes[pred] = classes.get(pred, 0) + 1
            if risk in risks: risks[risk] += 1
            total_conf += conf
            
            summary_table.add_row(
                f.name, pred, f"{conf*100:.1f}%", f"[{'red' if risk=='HIGH' else 'yellow' if risk=='MEDIUM' else 'green'}]{risk}[/]"
            )
            
            raw = res.to_dict()
            raw.update({"skipped": False, "skip_reason": ""})
            results_data.append(raw)
            progress.advance(task)

    console.print(summary_table)
    console.print("\n[bold]Batch Summary:[/bold]")
    console.print(f"  {processed_count} files processed, {skipped_count} skipped")
    if processed_count > 0:
        dist_str = ", ".join([f"{k} ×{v}" for k, v in classes.items()])
        console.print(f"  Class distribution: {dist_str}")
        avg_conf = (total_conf / processed_count) * 100
        console.print(f"  Avg confidence: {avg_conf:.1f}%")
        console.print(f"  HIGH risk: {risks['HIGH']}   MEDIUM: {risks['MEDIUM']}   LOW: {risks['LOW']}")
    console.print()

    if json_path:
        with open(json_path, 'w') as f:
            json.dump({
                "summary": {
                    "processed": processed_count,
                    "skipped": skipped_count,
                    "classes": classes,
                    "avg_confidence": avg_conf if processed_count > 0 else 0,
                    "risks": risks
                },
                "results": results_data
            }, f, indent=2)
        console.print(f"[green]OK:[/green] JSON results saved to {json_path}")
        
    if csv_path:
        import csv
        with open(csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Filename", "Predicted_Class", "Confidence", "Risk_Level", "Skipped", "Skip_Reason"])
            for d in results_data:
                if d['skipped']:
                    fname = d['file']
                    pred = ""
                    conf = ""
                    risk = ""
                else:
                    fname = d.get('analysis', {}).get('input', {}).get('file', d.get('file', ''))
                    pred = d.get('forecast', {}).get('predicted_attack', {}).get('type', '')
                    conf = d.get('forecast', {}).get('predicted_attack', {}).get('confidence', '')
                    risk = d.get('risk', {}).get('level', '')
                writer.writerow([fname, pred, conf, risk, d['skipped'], d['skip_reason']])
        console.print(f"[green]OK:[/green] CSV results saved to {csv_path}")


if __name__ == "__main__":
    app()