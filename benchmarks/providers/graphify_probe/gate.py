"""Fail-closed status gate; deliberately contains no Graphify launcher."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path


class ProbeUnavailable(RuntimeError):
    """Raised when pinned upstream/runtime evidence does not permit extraction."""


@dataclass(frozen=True)
class GateStatus:
    eligible: bool
    reasons: tuple[str, ...]


def assess_gate(evidence_path: Path) -> GateStatus:
    """Return blockers from checked-in evidence without starting a process."""
    evidence: dict[str, Any] = json.loads(evidence_path.read_text(encoding="utf-8"))
    reasons = tuple(str(reason) for reason in evidence["extraction_blockers"])
    # This directory intentionally has no implementation capable of execution.
    reasons += ("no-execution-launcher-in-research-stage",)
    return GateStatus(eligible=not reasons, reasons=reasons)


def require_extraction_eligible(evidence_path: Path) -> None:
    """Always fail until blockers are removed by reviewed, trusted evidence."""
    status = assess_gate(evidence_path)
    if not status.eligible:
        raise ProbeUnavailable("Graphify extraction blocked: " + "; ".join(status.reasons))
