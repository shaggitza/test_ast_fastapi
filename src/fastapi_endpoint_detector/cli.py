"""
Command-line interface for FastAPI Endpoint Change Detector.

This module provides the CLI using Click framework for argument parsing
and orchestrates the analysis pipeline.
"""

import json
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
    type=click.Choice(["text", "json", "yaml", "markdown", "html"]),
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
    "--no-cache",
    is_flag=True,
    help="Disable caching of analysis results.",
)
@click.option(
    "--clear-cache",
    is_flag=True,
    help="Clear cached analysis data before running.",
)
@click.option(
    "--vm",
    is_flag=True,
    help="Execute analysis in isolated Docker container for untrusted code.",
)
@click.option(
    "--secure-ast",
    is_flag=True,
    help="Use pure AST analysis without importing code (secure mode).",
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
    no_cache: bool,
    clear_cache: bool,
    vm: bool,
    secure_ast: bool,
) -> None:
    """Analyze code changes and identify affected FastAPI endpoints."""
    from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
    from fastapi_endpoint_detector.output.formatters import get_formatter
    
    config: Config = ctx.obj["config"]
    
    # Validate mutually exclusive options
    if vm and secure_ast:
        console.print("[red]Error:[/red] --vm and --secure-ast cannot be used together")
        raise click.Abort()
    
    if verbose:
        console.print(f"[blue]Analyzing FastAPI application at:[/blue] {app}")
        console.print(f"[blue]Using diff file:[/blue] {diff}")
        console.print(f"[blue]App variable:[/blue] {app_var}")
        
        if vm:
            console.print("[blue]Execution mode:[/blue] VM (Docker container)")
        elif secure_ast:
            console.print("[blue]Execution mode:[/blue] Secure AST (no imports)")
        else:
            console.print("[blue]Using mypy for dependency analysis[/blue]")
            
        if no_cache:
            console.print("[blue]Caching:[/blue] disabled")
        if clear_cache:
            console.print("[blue]Clearing cache before analysis[/blue]")
    
    try:
        # Handle VM execution mode
        if vm:
            from fastapi_endpoint_detector.executor.vm_executor import VMExecutor, VMExecutorError
            
            executor = VMExecutor()
            
            # Check if Docker image exists, build if needed
            if not executor.check_image_exists():
                console.print("[yellow]Docker image not found. Building image...[/yellow]")
                executor.build_image()
                console.print("[green]Docker image built successfully[/green]")
            
            # Run analysis in VM
            result = executor.analyze_in_vm(
                app_path=app,
                diff_path=diff,
                app_variable=app_var,
                output_format=output_format,
            )
            
            # Output results
            if output_format == "json":
                import json
                formatted_output = json.dumps(result, indent=2)
            else:
                formatted_output = result
            
            if output:
                output.write_text(formatted_output, encoding="utf-8")
                console.print(f"[green]Results written to:[/green] {output}")
            else:
                sys.stdout.write(formatted_output)
                sys.stdout.flush()
            
            return
        
        # Handle secure AST mode
        if secure_ast:
            console.print("[yellow]Secure AST mode: Using pure static analysis without imports[/yellow]")
            console.print("[red]Error: Secure AST mode for analyze command is not yet implemented[/red]")
            console.print("[yellow]Use 'list --secure-ast' to list endpoints in secure mode[/yellow]")
            raise click.Abort()
        
        # Run the analysis with mypy (default mode)
        mapper = ChangeMapper(
            app_path=app,
            config=config,
            app_variable=app_var,
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
            
            # Set line progress callback on mypy analyzer
            # Note: This just initializes the analyzer without running analysis
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
    type=click.Choice(["text", "json", "yaml", "markdown", "html"]),
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
    "--vm",
    is_flag=True,
    help="Execute analysis in isolated Docker container for untrusted code.",
)
@click.option(
    "--secure-ast",
    is_flag=True,
    help="Use pure AST analysis without importing code (secure mode).",
)
@click.pass_context
def list_endpoints(
    ctx: click.Context,
    app: Path,
    output_format: str,
    output: Optional[Path],
    app_var: str,
    vm: bool,
    secure_ast: bool,
) -> None:
    """List all FastAPI endpoints in the application."""
    from fastapi_endpoint_detector.parser.fastapi_extractor import FastAPIExtractor
    from fastapi_endpoint_detector.output.formatters import get_formatter
    
    # Validate mutually exclusive options
    if vm and secure_ast:
        console.print("[red]Error:[/red] --vm and --secure-ast cannot be used together")
        raise click.Abort()
    
    try:
        # Handle VM execution mode
        if vm:
            from fastapi_endpoint_detector.executor.vm_executor import VMExecutor
            
            executor = VMExecutor()
            
            # Check if Docker image exists, build if needed
            if not executor.check_image_exists():
                console.print("[yellow]Docker image not found. Building image...[/yellow]")
                executor.build_image()
                console.print("[green]Docker image built successfully[/green]")
            
            # Run analysis in VM
            result = executor.analyze_in_vm(
                app_path=app,
                app_variable=app_var,
                output_format=output_format,
            )
            
            # Output results
            if output_format == "json":
                formatted_output = json.dumps(result, indent=2)
            else:
                formatted_output = result
            
            if output:
                output.write_text(formatted_output, encoding="utf-8")
                console.print(f"[green]Results written to:[/green] {output}")
            else:
                sys.stdout.write(formatted_output)
                sys.stdout.flush()
            
            return
        
        # Handle secure AST mode
        if secure_ast:
            from fastapi_endpoint_detector.parser.secure_ast_extractor import SecureASTExtractor
            
            console.print("[blue]Using secure AST mode (no code execution)[/blue]")
            extractor_obj = SecureASTExtractor(app_path=app, app_variable=app_var)
            endpoints = extractor_obj.extract_endpoints()
        else:
            # Use default runtime introspection
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


def main() -> None:
    """Main entry point for the CLI."""
    cli(obj={})
