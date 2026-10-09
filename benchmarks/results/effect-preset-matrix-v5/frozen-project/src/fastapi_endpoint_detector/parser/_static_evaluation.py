"""Small execution-free evaluator for bounded static string data."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from collections.abc import Callable


MAX_STATIC_DEPTH = 32
MAX_STATIC_STEPS = 256
MAX_STATIC_VALUES = 32
MAX_STATIC_STRING_CHARS = 4096
MAX_STATIC_TOTAL_CHARS = 8192
MAX_CUSTOM_RESOURCE_CHARS = 256

StaticFailure = Literal["unsupported", "depth", "steps", "values", "string", "aggregate"]


@dataclass(frozen=True)
class StaticEvaluationResult:
    """An exact immutable value, or a deterministic fail-closed reason."""

    values: tuple[str, ...] | None
    failure: StaticFailure | None = None

    @property
    def string(self) -> str | None:
        if self.values is not None and len(self.values) == 1:
            return self.values[0]
        return None

    @property
    def reason(self) -> str:
        if self.failure in {"depth", "steps", "values", "string", "aggregate"}:
            return f"bounded static evaluation {self.failure} limit exceeded"
        return "static expression is unsupported or unresolved"


class StaticStringEvaluator:
    """Evaluate the deliberately narrow static string/container taxonomy."""

    def __init__(
        self,
        *,
        resolve_name: Callable[[str], str | None] | None = None,
        max_depth: int = MAX_STATIC_DEPTH,
        max_steps: int = MAX_STATIC_STEPS,
        max_values: int = MAX_STATIC_VALUES,
        max_string_chars: int = MAX_STATIC_STRING_CHARS,
        max_total_chars: int = MAX_STATIC_TOTAL_CHARS,
    ) -> None:
        self._resolve_name = resolve_name
        self._max_depth = max_depth
        self._max_steps = max_steps
        self._max_values = max_values
        self._max_string_chars = max_string_chars
        self._max_total_chars = max_total_chars
        self._steps = 0
        self._values = 0
        self._total_chars = 0
        self._failure: StaticFailure | None = None

    def evaluate_string(self, expression: ast.expr | None) -> StaticEvaluationResult:
        if self._failure is not None:
            return StaticEvaluationResult(None, self._failure)
        value = self._string(expression, 1)
        if value is None:
            self._fail("unsupported")
            return StaticEvaluationResult(None, self._failure)
        return StaticEvaluationResult((value,))

    def evaluate_values(self, expression: ast.expr | None) -> StaticEvaluationResult:
        if self._failure is not None:
            return StaticEvaluationResult(None, self._failure)
        values = self._values_from(expression, 1)
        if values is None:
            self._fail("unsupported")
            return StaticEvaluationResult(None, self._failure)
        return StaticEvaluationResult(tuple(values))

    def evaluate_flat_values(self, expression: ast.expr | None) -> StaticEvaluationResult:
        """Evaluate one direct container whose direct members are scalar strings."""
        if self._failure is not None:
            return StaticEvaluationResult(None, self._failure)
        if not isinstance(expression, (ast.List, ast.Tuple, ast.Set)) or not self._enter(1):
            self._fail("unsupported")
            return StaticEvaluationResult(None, self._failure)
        values: list[str] = []
        for item in expression.elts:
            if self._values >= self._max_values:
                self._fail("values")
                return StaticEvaluationResult(None, self._failure)
            value = self._string(item, 2)
            if value is None:
                self._fail("unsupported")
                return StaticEvaluationResult(None, self._failure)
            self._values += 1
            values.append(value)
        return StaticEvaluationResult(tuple(values))

    def evaluate_more_values(self, expression: ast.expr | None) -> StaticEvaluationResult:
        """Evaluate another aggregate argument with this same logical budget."""
        return self.evaluate_values(expression)

    def _fail(self, reason: StaticFailure) -> None:
        if self._failure is None:
            self._failure = reason

    def _enter(self, depth: int) -> bool:
        if depth > self._max_depth:
            self._fail("depth")
            return False
        if self._steps >= self._max_steps:
            self._fail("steps")
            return False
        self._steps += 1
        return True

    def _charge_name(self) -> bool:
        if self._steps >= self._max_steps:
            self._fail("steps")
            return False
        self._steps += 1
        return True

    def _charge_string(self, value: str) -> bool:
        length = len(value)
        if length > self._max_string_chars:
            self._fail("string")
            return False
        if length > self._max_total_chars - self._total_chars:
            self._fail("aggregate")
            return False
        self._total_chars += length
        return True

    def _string(  # noqa: PLR0911, PLR0912 - exact static taxonomy
        self, expression: ast.expr | None, depth: int
    ) -> str | None:
        if expression is None or not self._enter(depth):
            return None
        if isinstance(expression, ast.Constant) and isinstance(expression.value, str):
            return expression.value if self._charge_string(expression.value) else None
        if isinstance(expression, ast.Name):
            if self._resolve_name is None or not self._charge_name():
                return None
            value = self._resolve_name(expression.id)
            if value is None:
                return None
            return value if self._charge_string(value) else None
        if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Add):
            left = self._string(expression.left, depth + 1)
            if left is None:
                return None
            right = self._string(expression.right, depth + 1)
            if right is None:
                return None
            if len(left) > self._max_string_chars - len(right):
                self._fail("string")
                return None
            if len(left) + len(right) > self._max_total_chars - self._total_chars:
                self._fail("aggregate")
                return None
            value = left + right
            self._total_chars += len(value)
            return value
        if isinstance(expression, ast.JoinedStr):
            parts: list[str] = []
            length = 0
            for item in expression.values:
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    part = self._string(item, depth + 1)
                elif (
                    isinstance(item, ast.FormattedValue)
                    and item.conversion == -1
                    and item.format_spec is None
                ):
                    if not self._enter(depth + 1):
                        return None
                    part = self._string(item.value, depth + 2)
                else:
                    return None
                if part is None:
                    return None
                if length > self._max_string_chars - len(part):
                    self._fail("string")
                    return None
                length += len(part)
                parts.append(part)
            if length > self._max_total_chars - self._total_chars:
                self._fail("aggregate")
                return None
            value = "".join(parts)
            self._total_chars += length
            return value
        return None

    def _values_from(  # noqa: PLR0911 - fail closed before each allocation
        self, expression: ast.expr | None, depth: int
    ) -> list[str] | None:
        if expression is None:
            return None
        if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
            if not self._enter(depth):
                return None
            values: list[str] = []
            for item in expression.elts:
                resolved = self._values_from(item, depth + 1)
                if resolved is None:
                    return None
                if len(resolved) > self._max_values - len(values):
                    self._fail("values")
                    return None
                # Raw members (including duplicates) were charged by their leaves.
                values.extend(resolved)
            return values
        if self._values >= self._max_values:
            self._fail("values")
            return None
        value = self._string(expression, depth)
        if value is None:
            return None
        self._values += 1
        return [value]
