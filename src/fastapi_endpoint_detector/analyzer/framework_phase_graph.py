"""Join phase evidence to the typed reverse graph without rebuilding its graph."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from pydantic import BaseModel, ConfigDict, Field

from fastapi_endpoint_detector.analyzer.framework_phase_bridge import FrameworkPhase  # noqa: TC001

if TYPE_CHECKING:
    from fastapi_endpoint_detector.analyzer.framework_phase_integration import (
        FrameworkPhaseIntegration,
    )


class _GraphSpan(Protocol):
    path: str
    source_sha256: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int


class _GraphSymbol(Protocol):
    module: str
    fullname: str
    span: _GraphSpan | None


class _TypedGraph(Protocol):
    root: str
    symbols: tuple[_GraphSymbol, ...]
    inventory_fingerprint: str
    config_fingerprint: str


class FrameworkPhaseGraphBinding(BaseModel):
    """One proven callback-to-graph symbol binding, retaining phase conditions."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    snapshot_side: str = Field(pattern="^(target|baseline)$")
    phase: FrameworkPhase
    callback_module: str
    callback_symbol: str
    callback_file: str
    callback_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    callback_start_line: int = Field(ge=1)
    callback_start_column: int = Field(ge=0)
    callback_end_line: int = Field(ge=1)
    callback_end_column: int = Field(ge=0)
    registration_file: str
    registration_line: int = Field(ge=1)
    registration_column: int = Field(ge=0)
    registration_end_line: int = Field(ge=1)
    registration_end_column: int = Field(ge=0)
    typed_framework_symbol: str
    contract_id: str
    conditions: tuple[str, ...]
    graph_inventory_fingerprint: str
    graph_config_fingerprint: str


class FrameworkPhaseGraphAdapterResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: int = 1
    bindings: tuple[FrameworkPhaseGraphBinding, ...]
    limitations: tuple[str, ...]


def _span_path(graph: _TypedGraph, path: str) -> Path:
    supplied = Path(path)
    return (supplied if supplied.is_absolute() else Path(graph.root) / supplied).resolve()


def adapt_framework_phases_to_graph(
    evidence: FrameworkPhaseIntegration,
    graph: _TypedGraph,
) -> FrameworkPhaseGraphAdapterResult:
    """Require exact callable span and full-file provenance equality with graph.

    This adapter does not synthesize graph nodes, edges, or callback reachability.
    It returns a phase-to-symbol binding only when the frontend evidence and
    typed graph agree on canonical symbol, complete source span, and file digest.
    """
    bindings: list[FrameworkPhaseGraphBinding] = []
    limitations: set[str] = set(evidence.limitations)
    graph_inventory = graph.inventory_fingerprint
    graph_config = graph.config_fingerprint
    if not graph_inventory or not graph_config:
        return FrameworkPhaseGraphAdapterResult(
            bindings=(),
            limitations=("typed graph lacks inventory/configuration provenance",),
        )
    for record in evidence.records:
        if (
            record.status == "unavailable"
            or record.registration is None
            or record.typed_framework_symbol is None
            or record.callback.end_line is None
            or record.callback.end_column is None
            or record.callback_file_sha256 is None
            or record.registration.end_line is None
            or record.registration.end_column is None
        ):
            limitations.add(
                f"{record.contract_id}: phase evidence lacks exact frontend spans or registration"
            )
            continue
        fullname = f"{record.callback.module}.{record.callback.symbol}"
        matching = [
            symbol
            for symbol in graph.symbols
            if symbol.module == record.callback.module
            and symbol.fullname == fullname
            and symbol.span is not None
            and _span_path(graph, symbol.span.path) == Path(record.callback.file).resolve()
            and symbol.span.source_sha256 == record.callback_file_sha256
            and (
                symbol.span.start_line,
                symbol.span.start_column,
                symbol.span.end_line,
                symbol.span.end_column,
            )
            == (
                record.callback.line,
                record.callback.column,
                record.callback.end_line,
                record.callback.end_column,
            )
        ]
        if len(matching) != 1:
            limitations.add(
                f"{record.contract_id}: callback graph symbol/span/provenance "
                f"match count={len(matching)}"
            )
            continue
        callback = record.callback
        registration = record.registration
        assert callback.end_line is not None and callback.end_column is not None
        assert registration.end_line is not None and registration.end_column is not None
        bindings.append(
            FrameworkPhaseGraphBinding(
                snapshot_side=record.snapshot_side,
                phase=record.phase,
                callback_module=callback.module,
                callback_symbol=callback.symbol,
                callback_file=callback.file,
                callback_source_sha256=record.callback_file_sha256,
                callback_start_line=callback.line,
                callback_start_column=callback.column,
                callback_end_line=callback.end_line,
                callback_end_column=callback.end_column,
                registration_file=registration.file,
                registration_line=registration.line,
                registration_column=registration.column,
                registration_end_line=registration.end_line,
                registration_end_column=registration.end_column,
                typed_framework_symbol=record.typed_framework_symbol,
                contract_id=record.contract_id,
                conditions=record.execution_conditions,
                graph_inventory_fingerprint=graph_inventory,
                graph_config_fingerprint=graph_config,
            )
        )
    return FrameworkPhaseGraphAdapterResult(
        bindings=tuple(bindings),
        limitations=tuple(sorted(limitations)),
    )
