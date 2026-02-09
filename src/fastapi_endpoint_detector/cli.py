"""
Command-line interface for FastAPI Endpoint Change Detector.

This module provides the CLI using Click framework for argument parsing
and orchestrates the analysis pipeline.
"""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn, TimeRemainingColumn

from fastapi_endpoint_detector import __version__
from fastapi_endpoint_detector.config import Config, load_config

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="fastapi-endpoint-detector")
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    help="Path to configuration file.",
)
@click.pass_context
def cli(ctx: click.Context, config: Optional[Path]) -> None:
    """FastAPI Endpoint Change Detector - Identify affected endpoints from code changes."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = load_config(config) if config else Config()


@cli.command()
@click.option(
    "--app",
    "-a",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to FastAPI application directory or entry point file.",
)
@click.option(
    "--diff",
    "-d",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to diff file or directory containing diff files.",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["text", "json", "yaml"]),
    default="text",
    help="Output format (default: text).",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path. If not specified, prints to stdout.",
)
@click.option(
    "--app-var",
    type=str,
    default="app",
    help="Name of the FastAPI app variable (default: app).",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output.",
)
@click.option(
    "--backend",
    "-b",
    type=click.Choice(["import", "coverage", "mypy"]),
    default="import",
    help="Dependency analysis backend: 'import' (grimp-based, fast), 'coverage' (AST tracing), or 'mypy' (type-based, precise). Default: import.",
)
@click.option(
    "--no-cache",
    is_flag=True,
    help="Disable caching of analysis results (coverage/mypy backends).",
)
@click.option(
    "--clear-cache",
    is_flag=True,
    help="Clear cached analysis data before running (coverage/mypy backends).",
)
@click.pass_context
def analyze(
    ctx: click.Context,
    app: Path,
    diff: Path,
    output_format: str,
    output: Optional[Path],
    app_var: str,
    verbose: bool,
    backend: str,
    no_cache: bool,
    clear_cache: bool,
) -> None:
    """Analyze code changes and identify affected FastAPI endpoints."""
    from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
    from fastapi_endpoint_detector.output.formatters import get_formatter
    
    config: Config = ctx.obj["config"]
    
    if verbose:
        console.print(f"[blue]Analyzing FastAPI application at:[/blue] {app}")
        console.print(f"[blue]Using diff file:[/blue] {diff}")
        console.print(f"[blue]App variable:[/blue] {app_var}")
        console.print(f"[blue]Dependency backend:[/blue] {backend}")
        if no_cache:
            console.print("[blue]Caching:[/blue] disabled")
        if clear_cache:
            console.print("[blue]Clearing cache before analysis[/blue]")
    
    try:
        # Run the analysis with selected backend
        mapper = ChangeMapper(
            app_path=app,
            config=config,
            app_variable=app_var,
            backend=backend,  # type: ignore[arg-type]
            use_cache=not no_cache,
        )
        
        # Clear cache if requested
        if clear_cache:
            mapper.clear_cache()
        
        # Track current line being analyzed
        current_line_info = {"text": ""}
        
        # Create progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            TextColumn("{task.fields[line_info]}", style="dim"),
            console=console,
            transient=True,  # Remove progress bar when done
        ) as progress:
            task = progress.add_task("Initializing...", total=100, line_info="")
            
            def update_progress(current: int, total: int, description: str) -> None:
                progress.update(
                    task, 
                    completed=current, 
                    description=description,
                    line_info=current_line_info["text"],
                )
            
            def line_progress(file_path: str, line_num: int, symbol: str) -> None:
                """Update the current line being analyzed."""
                from pathlib import Path
                filename = Path(file_path).name
                current_line_info["text"] = f"→ {filename}:{line_num} ({symbol})"
                progress.update(task, line_info=current_line_info["text"])
            
            # Set line progress callback on mypy analyzer if using that backend
            if backend == "mypy":
                mapper.mypy_analyzer.set_line_progress_callback(line_progress)
            
            report = mapper.analyze_diff(diff, progress_callback=update_progress)
        
        # Format and output results
        formatter = get_formatter(output_format)
        formatted_output = formatter.format(report)
        
        if output:
            output.write_text(formatted_output, encoding="utf-8")
            console.print(f"[green]Results written to:[/green] {output}")
        else:
            # Print directly to stdout to preserve ANSI codes from formatter
            sys.stdout.write(formatted_output)
            sys.stdout.flush()
            
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        raise click.Abort()


@cli.command("list")
@click.option(
    "--app",
    "-a",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to FastAPI application directory or entry point file.",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["text", "json", "yaml"]),
    default="text",
    help="Output format (default: text).",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path. If not specified, prints to stdout.",
)
@click.option(
    "--app-var",
    type=str,
    default="app",
    help="Name of the FastAPI app variable (default: app).",
)
@click.pass_context
def list_endpoints(
    ctx: click.Context,
    app: Path,
    output_format: str,
    output: Optional[Path],
    app_var: str,
) -> None:
    """List all FastAPI endpoints in the application."""
    from fastapi_endpoint_detector.parser.fastapi_extractor import FastAPIExtractor
    from fastapi_endpoint_detector.output.formatters import get_formatter
    
    try:
        extractor = FastAPIExtractor(app_path=app, app_variable=app_var)
        endpoints = extractor.extract_endpoints()
        
        formatter = get_formatter(output_format)
        formatted_output = formatter.format_endpoints(endpoints)
        
        if output:
            output.write_text(formatted_output, encoding="utf-8")
            console.print(f"[green]Results written to:[/green] {output}")
        else:
            # Print directly to stdout to preserve ANSI codes from formatter
            import sys
            sys.stdout.write(formatted_output)
            sys.stdout.flush()
            
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.Abort()


@cli.command()
@click.option(
    "--app",
    "-a",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to FastAPI application directory or entry point file.",
)
@click.option(
    "--module",
    "-m",
    type=str,
    help="Show dependencies for a specific module.",
)
@click.pass_context
def deps(
    ctx: click.Context,
    app: Path,
    module: Optional[str],
) -> None:
    """Show dependency information for the FastAPI application."""
    from fastapi_endpoint_detector.analyzer.dependency_graph import DependencyGraph
    
    try:
        # Determine package path
        if app.is_file():
            package_path = app.parent
        else:
            package_path = app
        
        dep_graph = DependencyGraph(package_path)
        dep_graph.build()
        
        if module:
            # Show info for specific module
            console.print(f"[bold]Module:[/bold] {module}")
            console.print()
            
            imports = dep_graph.get_modules_imported_by(module)
            console.print(f"[bold]Imports ({len(imports)}):[/bold]")
            for imp in sorted(imports):
                console.print(f"  • {imp}")
            console.print()
            
            imported_by = dep_graph.get_modules_that_import(module)
            console.print(f"[bold]Imported by ({len(imported_by)}):[/bold]")
            for imp in sorted(imported_by):
                console.print(f"  • {imp}")
        else:
            # Show overall stats
            all_modules = dep_graph.get_all_modules()
            console.print(f"[bold]Package:[/bold] {package_path.name}")
            console.print(f"[bold]Total modules:[/bold] {len(all_modules)}")
            console.print()
            console.print("[bold]Modules:[/bold]")
            for mod in sorted(all_modules):
                console.print(f"  • {mod}")
            
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.Abort()


def main() -> None:
    """Main entry point for the CLI."""
    cli(obj={})
