"""
Capture netforec CLI output as beautiful SVG terminal screenshots.

This script imports the CLI internals and injects a recording Rich Console
to capture fully-formatted output with colors and box-drawing characters.

Run from project root:
    python docs/capture_screenshots.py
"""
import sys
import os
from pathlib import Path

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.text import Text
from io import StringIO

DOCS_DIR = Path(__file__).parent

# ─── Helpers ────────────────────────────────────────────────────────────────

def capture_help_output(argv: list[str], title: str) -> str:
    """Run a typer --help command and capture Rich-formatted output."""
    from unittest.mock import patch
    from typer.testing import CliRunner
    from netforec.cli import app

    runner = CliRunner()
    result = runner.invoke(app, argv)
    return result.output


def save_svg(text_content: str, filename: str, title: str, width: int = 88) -> None:
    """Render text through Rich Console recorder and export as SVG."""
    console = Console(record=True, width=width, force_terminal=True, color_system="truecolor")
    # Parse any ANSI in the output
    rich_text = Text.from_ansi(text_content)
    console.print(rich_text)
    svg_path = DOCS_DIR / filename
    console.save_svg(str(svg_path), title=title)
    size = svg_path.stat().st_size
    print(f"  ✓ {filename} ({size:,} bytes)")


def capture_analyze(csv_name: str, extra_args: list[str], filename: str, title: str) -> None:
    """Run netforec analyze against a test file, capturing Rich output."""
    from netforec import cli as cli_module
    from netforec.cli import app
    
    csv_path = str(PROJECT_ROOT / "test_data" / csv_name)
    
    # Replace the module's console with a recording one
    recording_console = Console(
        record=True, width=88, force_terminal=True,
        color_system="truecolor", file=StringIO()
    )
    original_console = cli_module.console
    original_err_console = cli_module.err_console
    cli_module.console = recording_console
    cli_module.err_console = recording_console
    
    try:
        from typer.testing import CliRunner
        runner = CliRunner()
        result = runner.invoke(app, ["analyze", csv_path] + extra_args)
    finally:
        cli_module.console = original_console
        cli_module.err_console = original_err_console
    
    svg_path = DOCS_DIR / filename  
    recording_console.save_svg(str(svg_path), title=title)
    size = svg_path.stat().st_size
    print(f"  ✓ {filename} ({size:,} bytes)")


def capture_batch(filename: str, title: str) -> None:
    """Run netforec batch against test_data/, capturing Rich output."""
    from netforec import cli as cli_module
    from netforec.cli import app
    
    test_dir = str(PROJECT_ROOT / "test_data")
    
    recording_console = Console(
        record=True, width=100, force_terminal=True,
        color_system="truecolor", file=StringIO()
    )
    original_console = cli_module.console
    original_err_console = cli_module.err_console
    cli_module.console = recording_console
    cli_module.err_console = recording_console
    
    try:
        from typer.testing import CliRunner
        runner = CliRunner()
        result = runner.invoke(app, ["batch", test_dir])
    finally:
        cli_module.console = original_console
        cli_module.err_console = original_err_console
    
    svg_path = DOCS_DIR / filename
    recording_console.save_svg(str(svg_path), title=title)
    size = svg_path.stat().st_size
    print(f"  ✓ {filename} ({size:,} bytes)")


# ─── Main ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"Capturing CLI screenshots to {DOCS_DIR}/\n")
    
    # 1. Help screens
    print("[Help Screens]")
    for args, fname, title in [
        (["--help"],            "help_main.svg",      "netforec --help"),
        (["analyze", "--help"], "help_analyze.svg",   "netforec analyze --help"),
        (["validate", "--help"],"help_validate.svg",  "netforec validate --help"),
        (["batch", "--help"],   "help_batch.svg",     "netforec batch --help"),
        (["dashboard", "--help"],"help_dashboard.svg","netforec dashboard --help"),
    ]:
        try:
            output = capture_help_output(args, title)
            save_svg(output, fname, title)
        except Exception as e:
            print(f"  ✗ {fname}: {e}")
    
    # 2. Sample outputs - analyze
    print("\n[Analysis Outputs]")
    try:
        capture_analyze("exfiltration_shaped.csv", [], "output_threat.svg",
                       "netforec analyze exfiltration_shaped.csv")
    except Exception as e:
        print(f"  ✗ output_threat.svg: {e}")
        import traceback; traceback.print_exc()
    
    try:
        capture_analyze("typical_baseline.csv", [], "output_normal.svg",
                       "netforec analyze typical_baseline.csv")
    except Exception as e:
        print(f"  ✗ output_normal.svg: {e}")
        import traceback; traceback.print_exc()
    
    try:
        capture_analyze("exfiltration_shaped.csv",
                       ["--verbose", "--investigate", "--explain"],
                       "output_forensic.svg",
                       "netforec analyze exfiltration_shaped.csv -v -i -e")
    except Exception as e:
        print(f"  ✗ output_forensic.svg: {e}")
        import traceback; traceback.print_exc()
    
    # 3. Batch output
    print("\n[Batch Output]")
    try:
        capture_batch("output_batch.svg", "netforec batch test_data/")
    except Exception as e:
        print(f"  ✗ output_batch.svg: {e}")
        import traceback; traceback.print_exc()
    
    print("\nDone!")
