"""
Command-line interface for FastAPI Endpoint Change Detector.

This module provides the CLI using Click framework for argument parsing
and orchestrates the analysis pipeline.
"""

import json
import sys
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from fastapi_endpoint_detector import __version__
from fastapi_endpoint_detector.config import Config, load_config
from fastapi_endpoint_detector.models.effect_contract import (
    BUNDLED_EFFECT_PRESETS,
    load_effect_contracts,
    load_effect_preset,
)
from fastapi_endpoint_detector.models.surface_contract import load_surface_contracts

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
def cli(ctx: click.Context, config: Path | None) -> None:
    """FastAPI Endpoint Change Detector - Identify affected endpoints from code changes."""
    ctx.ensure_object(dict)
    try:
        ctx.obj["config"] = load_config(config) if config else Config()
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc


@cli.command()
@click.option(
    "--app",
    "-a",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to FastAPI application directory or entry point file.",
)
@click.option(
    "--baseline-app",
    type=click.Path(exists=True, path_type=Path),
    help="Explicit baseline snapshot for SCIP analysis of removed Python lines.",
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
    "--app-entry",
    type=str,
    help="Exact secure-AST entry MODULE:SYMBOL (object or zero-argument factory).",
)
@click.option(
    "--bootstrap-entry",
    type=str,
    help="Exact secure-AST bootstrap MODULE:FUNCTION for registration effects.",
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
    help="Run the explicit gVisor/Kata-isolated runtime comparator.",
)
@click.option(
    "--secure-ast",
    is_flag=True,
    help="Use pure AST analysis without importing code (secure mode).",
)
@click.option(
    "--scip",
    is_flag=True,
    help="Use SCIP dependency analysis (requires scip-query and scip-python 0.6.6).",
)
@click.pass_context
def analyze(
    ctx: click.Context,
    app: Path,
    baseline_app: Path | None,
    diff: Path,
    output_format: str,
    output: Path | None,
    app_var: str,
    app_entry: str | None,
    bootstrap_entry: str | None,
    verbose: bool,
    no_cache: bool,
    clear_cache: bool,
    vm: bool,
    secure_ast: bool,
    scip: bool,
) -> None:
    """Analyze code changes and identify affected FastAPI endpoints."""
    from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
    from fastapi_endpoint_detector.output.formatters import get_formatter

    config: Config = ctx.obj["config"]

    # Validate mutually exclusive options
    has_surface_contracts = any((config.analysis.surface_contracts, config.analysis.surface_preset))
    has_effect_contracts = any((config.analysis.effect_contracts, config.analysis.effect_preset))
    if has_surface_contracts and not secure_ast:
        console.print("[red]Error:[/red] custom surface contracts require --secure-ast")
        raise click.Abort()
    if has_effect_contracts and vm:
        console.print("[red]Error:[/red] effect contract evidence is unavailable with --vm")
        raise click.Abort()
    if has_effect_contracts and scip:
        console.print("[red]Error:[/red] effect contract evidence requires the mypy backend")
        raise click.Abort()
    if has_effect_contracts and not secure_ast:
        console.print("[red]Error:[/red] effect contract evidence requires --secure-ast")
        raise click.Abort()
    if vm and secure_ast:
        console.print("[red]Error:[/red] --vm and --secure-ast cannot be used together")
        raise click.Abort()
    if vm and scip:
        console.print("[red]Error:[/red] --vm and --scip cannot be used together")
        raise click.Abort()
    if app_entry is not None and not secure_ast:
        console.print("[red]Error:[/red] --app-entry requires --secure-ast")
        raise click.Abort()
    if bootstrap_entry is not None and not secure_ast:
        console.print("[red]Error:[/red] --bootstrap-entry requires --secure-ast")
        raise click.Abort()
    if baseline_app is not None and not scip:
        console.print("[red]Error:[/red] --baseline-app requires --scip")
        raise click.Abort()

    if verbose:
        console.print(f"[blue]Analyzing FastAPI application at:[/blue] {app}")
        console.print(f"[blue]Using diff file:[/blue] {diff}")
        console.print(f"[blue]App variable:[/blue] {app_var}")
        if app_entry is not None:
            console.print(f"[blue]App entry:[/blue] {app_entry}")

        if vm:
            console.print("[blue]Execution mode:[/blue] isolated runtime comparator")
        elif secure_ast:
            console.print("[blue]Execution mode:[/blue] Secure AST (no imports)")
        console.print(f"[blue]Dependency analysis:[/blue] {'SCIP' if scip else 'mypy'}")

        if no_cache:
            console.print("[blue]Caching:[/blue] disabled")
        if clear_cache:
            console.print("[blue]Clearing cache before analysis[/blue]")

    try:
        # Handle VM execution mode
        if vm:
            from fastapi_endpoint_detector.executor.vm_executor import VMExecutor

            executor = VMExecutor()

            # Runtime execution requires a prebuilt immutable repository digest.
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

        if secure_ast and verbose:
            console.print("[yellow]Secure AST mode: discovering endpoints without imports[/yellow]")

        # Run dependency analysis with runtime or secure AST endpoint discovery.
        mapper = ChangeMapper(
            app_path=app,
            config=config,
            app_variable=app_var,
            app_entry=app_entry,
            bootstrap_entry=bootstrap_entry,
            use_cache=not no_cache,
            secure_ast=secure_ast,
            use_scip=scip,
            baseline_app_path=baseline_app,
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

            def update_progress(current: int, _total: int, description: str) -> None:
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
            if not scip:
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
        raise click.Abort() from e


@cli.command("validate-effect-contracts")
@click.option(
    "--contracts",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Strict YAML, JSON, or TOML effect-contract document.",
)
@click.option(
    "--preset",
    type=click.Choice(sorted(BUNDLED_EFFECT_PRESETS)),
    help="Versioned package-owned effect preset; conflicts with --contracts.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "yaml"]),
    default="text",
    help="Validation output format (default: text).",
)
def validate_effect_contracts(
    contracts: Path | None,
    preset: str | None,
    output_format: str,
) -> None:
    """Validate and hash data-only effect contracts without analyzing code."""
    if (contracts is None) == (preset is None):
        raise click.ClickException("exactly one of --contracts or --preset is required")
    try:
        loaded = (
            load_effect_contracts(contracts)
            if contracts is not None
            else load_effect_preset(preset or "")
        )
        data = {
            "schema_version": loaded.document.schema_version,
            "source_path": str(loaded.source_path),
            "raw_hash": loaded.raw_hash,
            "config_hash": loaded.config_hash,
            "preset_hash": loaded.preset_hash,
            "contract_hashes": loaded.contract_hashes,
            "preset": loaded.document.preset.model_dump(mode="json", exclude_none=True),
            "contracts": [
                contract.model_dump(mode="json", exclude_none=True)
                for contract in sorted(loaded.document.contracts, key=lambda item: item.id)
            ],
            "matching_status": "not_evaluated",
            "matching_limitation": (
                "This command validates semantics and provenance only; use "
                "audit-effect-contracts to evaluate endpoint-reachable typed calls."
            ),
        }
        if output_format == "json":
            rendered = json.dumps(data, indent=2)
        elif output_format == "yaml":
            rendered = yaml.safe_dump(data, sort_keys=False)
        else:
            rendered = (
                "Effect contracts valid\n"
                f"Schema: {data['schema_version']}\n"
                f"Preset: {loaded.document.preset.id}@{loaded.document.preset.version}\n"
                f"Contracts: {len(loaded.document.contracts)}\n"
                f"Config hash: {loaded.config_hash}\n"
                f"Preset hash: {loaded.preset_hash}\n"
                "Matching: not evaluated (use audit-effect-contracts)\n"
            )
        click.echo(rendered)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc


@cli.command("validate-surface-contracts")
@click.option(
    "--contracts",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Strict YAML, JSON, or TOML custom-surface contract document.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "yaml"]),
    default="text",
)
def validate_surface_contracts(contracts: Path, output_format: str) -> None:
    """Validate and hash custom-surface contracts without importing project code."""
    try:
        loaded = load_surface_contracts(contracts)
        data = {
            "schema_version": loaded.document.schema_version,
            "source_path": str(loaded.source_path),
            "raw_hash": loaded.raw_hash,
            "config_hash": loaded.config_hash,
            "preset_hash": loaded.preset_hash,
            "contract_hashes": loaded.contract_hashes,
            "preset": loaded.document.preset.model_dump(mode="json", exclude_none=True),
            "contracts": [
                item.model_dump(mode="json", exclude_none=True)
                for item in sorted(loaded.document.contracts, key=lambda item: item.id)
            ],
        }
        if output_format == "json":
            rendered = json.dumps(data, indent=2)
        elif output_format == "yaml":
            rendered = yaml.safe_dump(data, sort_keys=False)
        else:
            rendered = (
                "Surface contracts valid\n"
                f"Schema: {loaded.document.schema_version}\n"
                f"Preset: {loaded.document.preset.id}@{loaded.document.preset.version}\n"
                f"Contracts: {len(loaded.document.contracts)}\n"
                f"Config hash: {loaded.config_hash}\n"
                f"Preset hash: {loaded.preset_hash}\n"
            )
        click.echo(rendered)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc


@cli.command("audit-effect-contracts")
@click.option(
    "--app",
    "-a",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Application directory or entry point; endpoint discovery is execution-free.",
)
@click.option(
    "--contracts",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Contract document; conflicts with analysis.effect_contracts in --config.",
)
@click.option(
    "--preset",
    type=click.Choice(sorted(BUNDLED_EFFECT_PRESETS)),
    help="Versioned package-owned effect preset; conflicts with other contract sources.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "yaml"]),
    default="text",
    help="Audit output format (default: text).",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path. If omitted, print to stdout.",
)
@click.option(
    "--app-var",
    type=str,
    default="app",
    help="Name of the FastAPI app variable (default: app).",
)
@click.option(
    "--app-entry",
    type=str,
    help="Exact secure-AST entry MODULE:SYMBOL.",
)
@click.option(
    "--bootstrap-entry",
    type=str,
    help="Exact secure-AST bootstrap MODULE:FUNCTION.",
)
@click.option("--no-cache", is_flag=True, help="Disable mypy analysis caching.")
@click.option("--clear-cache", is_flag=True, help="Clear mypy analysis cache first.")
@click.pass_context
def audit_effect_contracts_command(
    ctx: click.Context,
    app: Path,
    contracts: Path | None,
    preset: str | None,
    output_format: str,
    output: Path | None,
    app_var: str,
    app_entry: str | None,
    bootstrap_entry: str | None,
    no_cache: bool,
    clear_cache: bool,
) -> None:
    """Dry-run exact contracts against endpoint-reachable typed calls."""
    from fastapi_endpoint_detector.analyzer.effect_contract_auditor import (
        audit_effect_contracts,
    )
    from fastapi_endpoint_detector.analyzer.mypy_analyzer import (
        MypyAnalyzer,
    )
    from fastapi_endpoint_detector.parser.secure_ast_extractor import (
        SecureASTExtractor,
    )

    config: Config = ctx.obj["config"]
    configured = any((config.analysis.effect_contracts, config.analysis.effect_preset))
    supplied = sum(item is not None for item in (contracts, preset))
    if supplied > 1:
        raise click.ClickException("--contracts conflicts with --preset")
    if supplied and configured:
        raise click.ClickException("CLI contract source conflicts with configured effect contracts")
    if not supplied and not configured:
        raise click.ClickException(
            "effect contracts are required via --contracts, --preset, or configuration"
        )

    try:
        if configured:
            loaded = config.load_effect_contract_snapshot()
        elif contracts is not None:
            loaded = load_effect_contracts(contracts.resolve())
        else:
            loaded = load_effect_preset(preset or "")
        if loaded is None:
            raise RuntimeError("configured effect contracts were not loaded")
        extractor = SecureASTExtractor(
            app_path=app.resolve(),
            app_variable=app_var,
            app_entry=app_entry,
            bootstrap_entry=bootstrap_entry,
        )
        inventory = extractor.extract_inventory()
        loaded_surfaces = config.load_surface_contract_snapshot()
        if loaded_surfaces is not None:
            from fastapi_endpoint_detector.parser.custom_surface_extractor import (
                CustomSurfaceExtractor,
                merge_surface_inventory,
            )

            custom = CustomSurfaceExtractor(
                app,
                loaded_surfaces,
                bootstrap_entry=bootstrap_entry,
            ).extract_inventory()
            inventory = merge_surface_inventory(inventory, custom)
        source_root = app.resolve().parent if app.is_file() else app.resolve()
        effective_depth = config.parser.max_depth if config.analysis.track_transitive else 1
        analyzer = MypyAnalyzer(source_root, max_depth=effective_depth)
        if clear_cache:
            analyzer.clear_cache()
        analyzer.analyze_endpoints(inventory.endpoints, use_cache=not no_cache)
        rows = []
        for endpoint in inventory.endpoints:
            dependencies = analyzer.get_endpoint_dependencies(endpoint)
            if dependencies is None:
                raise RuntimeError(
                    "typed call analysis did not produce a complete endpoint result for "
                    f"{endpoint.identifier} ({endpoint.handler.name})"
                )
            rows.append((endpoint, dependencies.get_resolved_call_sites()))
        audit = audit_effect_contracts(
            loaded,
            source_root=source_root,
            inventory=inventory,
            endpoint_call_sites=rows,
            track_transitive=config.analysis.track_transitive,
            max_depth=effective_depth,
            cache_enabled=not no_cache,
            resolver_versions=(f"mypy@{analyzer.resolver_version}",),
        )
        data = audit.model_dump(mode="json", exclude_none=True)
        if output_format == "json":
            rendered = json.dumps(data, indent=2)
        elif output_format == "yaml":
            rendered = yaml.safe_dump(data, sort_keys=False)
        else:
            summary = audit.summary
            lines = [
                "Effect contract audit complete",
                "Scope: endpoint-reachable calls (not whole-project usage)",
                f"Inventory: {audit.scope.inventory_status}",
                f"Endpoints: {audit.scope.endpoints}",
                f"Contracts: {summary.contracts} "
                f"({summary.matched_contracts} matched, "
                f"{summary.unmatched_contracts} unmatched)",
                f"Physical calls: {summary.physical_occurrences} "
                f"({summary.matched_calls} matched, "
                f"{summary.unmatched_calls} unmatched, "
                f"{summary.ambiguous_calls} ambiguous, "
                f"{summary.unresolved_calls} unresolved)",
                f"Config hash: {audit.provenance.config_hash}",
                f"Corpus hash: {audit.provenance.occurrence_corpus_hash}",
                "Package applicability: not evaluated",
                "Matches do not alter endpoint candidates or confidence.",
            ]
            for occurrence in audit.occurrences:
                target = occurrence.canonical_symbol or occurrence.reason_code or "unknown"
                lines.append(
                    f"[{occurrence.audit_status.value}] {occurrence.file_path}:"
                    f"{occurrence.line}:{occurrence.column} "
                    f"{occurrence.source_spelling} -> {target}"
                )
                for audit_endpoint in occurrence.endpoints:
                    lines.append(
                        "  endpoint "
                        f"{','.join(audit_endpoint.methods)} {audit_endpoint.path} "
                        f"({audit_endpoint.handler_module}.{audit_endpoint.handler_name})"
                    )
            rendered = "\n".join(lines) + "\n"
        if output is not None:
            output.write_text(rendered, encoding="utf-8")
            console.print(f"[green]Results written to:[/green] {output}")
        else:
            click.echo(rendered, nl=False)
    except click.ClickException:
        raise
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc


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
    "--app-entry",
    type=str,
    help="Exact secure-AST entry MODULE:SYMBOL (object or zero-argument factory).",
)
@click.option(
    "--bootstrap-entry",
    type=str,
    help="Exact secure-AST bootstrap MODULE:FUNCTION for registration effects.",
)
@click.option(
    "--vm",
    is_flag=True,
    help="Run the explicit gVisor/Kata-isolated runtime comparator.",
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
    output: Path | None,
    app_var: str,
    app_entry: str | None,
    bootstrap_entry: str | None,
    vm: bool,
    secure_ast: bool,
) -> None:
    """List all FastAPI endpoints in the application."""
    from fastapi_endpoint_detector.output.formatters import get_formatter
    from fastapi_endpoint_detector.parser.fastapi_extractor import FastAPIExtractor

    config: Config = ctx.obj["config"]

    # Validate mutually exclusive options
    if config.analysis.surface_contracts is not None and not secure_ast:
        console.print("[red]Error:[/red] custom surface contracts require --secure-ast")
        raise click.Abort()
    if vm and secure_ast:
        console.print("[red]Error:[/red] --vm and --secure-ast cannot be used together")
        raise click.Abort()
    if app_entry is not None and not secure_ast:
        console.print("[red]Error:[/red] --app-entry requires --secure-ast")
        raise click.Abort()
    if bootstrap_entry is not None and not secure_ast:
        console.print("[red]Error:[/red] --bootstrap-entry requires --secure-ast")
        raise click.Abort()

    try:
        # Handle VM execution mode
        if vm:
            from fastapi_endpoint_detector.executor.vm_executor import VMExecutor

            executor = VMExecutor()

            # Runtime execution requires a prebuilt immutable repository digest.
            result = executor.analyze_in_vm(
                app_path=app,
                app_variable=app_var,
                output_format=output_format,
            )

            # Output results
            formatted_output = json.dumps(result, indent=2) if output_format == "json" else result

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
            extractor_obj = SecureASTExtractor(
                app_path=app,
                app_variable=app_var,
                app_entry=app_entry,
                bootstrap_entry=bootstrap_entry,
            )
            inventory = extractor_obj.extract_inventory()
            loaded_surfaces = config.load_surface_contract_snapshot()
            if loaded_surfaces is not None:
                from fastapi_endpoint_detector.parser.custom_surface_extractor import (
                    CustomSurfaceExtractor,
                    merge_surface_inventory,
                )

                custom = CustomSurfaceExtractor(
                    app,
                    loaded_surfaces,
                    bootstrap_entry=bootstrap_entry,
                ).extract_inventory()
                inventory = merge_surface_inventory(inventory, custom)
            endpoints = inventory.endpoints
        else:
            # Use default runtime introspection
            extractor = FastAPIExtractor(app_path=app, app_variable=app_var)
            endpoints = extractor.extract_endpoints()

        formatter = get_formatter(output_format)
        formatted_output = (
            formatter.format_inventory(inventory)
            if secure_ast
            else formatter.format_endpoints(endpoints)
        )

        if output:
            output.write_text(formatted_output, encoding="utf-8")
            console.print(f"[green]Results written to:[/green] {output}")
        else:
            # Print directly to stdout to preserve ANSI codes from formatter
            sys.stdout.write(formatted_output)
            sys.stdout.flush()

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.Abort() from e


def main() -> None:
    """Main entry point for the CLI."""
    cli(obj={})
