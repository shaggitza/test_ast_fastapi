"""Conservative source-level effect and post-call observation analysis."""

from __future__ import annotations

import ast
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

from fastapi_endpoint_detector.models.report import (
    ChangeEffectKind,
    CodeReference,
    ConfidenceLevel,
    DataObservationKind,
    EffectDisposition,
    EffectEvidence,
    EvidenceProducer,
    EvidenceStatus,
    ImpactChannel,
)


@dataclass(frozen=True)
class EffectAnalysis:
    """Structured evidence and the legacy confidence projection."""

    evidence: tuple[EffectEvidence, ...]
    confidence: ConfidenceLevel


@dataclass(frozen=True)
class _Observation:
    kind: DataObservationKind
    channel: ImpactChannel
    disposition: EffectDisposition
    location: CodeReference
    conditional: bool = False


_CONFIDENCE_RANK = {
    ConfidenceLevel.LOW: 0,
    ConfidenceLevel.MEDIUM: 1,
    ConfidenceLevel.HIGH: 2,
}


class EffectAnalyzer:
    """Recognize narrow effect deltas without executing application code."""

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root.resolve()
        self._trees: dict[Path, ast.Module | None] = {}

    def analyze(
        self,
        changed_file: str,
        changed_lines: set[int],
        call_stacks: Sequence[Sequence[object]],
    ) -> EffectAnalysis | None:
        """Classify defensive-copy changes and their caller observations."""
        path = self._resolve_path(changed_file)
        if path is None:
            return None
        tree = self._tree(path)
        if tree is None:
            return None
        changed = self._defensive_copy_change(path, tree, changed_lines)
        if changed is None:
            return None
        function, subject, copy_line = changed
        evidence: list[EffectEvidence] = []
        confidence = ConfidenceLevel.LOW
        for stack in call_stacks:
            result = self._analyze_stack(stack, subject)
            if result is None:
                continue
            observation, summary, limitations = result
            candidate_confidence = self._confidence_for(observation)
            if _CONFIDENCE_RANK[candidate_confidence] > _CONFIDENCE_RANK[confidence]:
                confidence = candidate_confidence
            status = (
                EvidenceStatus.ESTABLISHED
                if not observation.conditional
                and observation.kind
                in {
                    DataObservationKind.RETURNED,
                    DataObservationKind.LOGGED,
                }
                else EvidenceStatus.CONDITIONAL
            )
            evidence.append(
                EffectEvidence(
                    producer=EvidenceProducer.DATA_FLOW,
                    status=status,
                    effect=ChangeEffectKind.ARGUMENT_MUTATION_ISOLATED,
                    observations=[observation.kind],
                    channel=observation.channel,
                    disposition=observation.disposition,
                    summary=summary,
                    subject=subject,
                    changed_location=CodeReference(
                        file_path=str(path),
                        line_number=copy_line,
                        symbol=function.name,
                    ),
                    observation_location=observation.location,
                    conditions=["The path must select the changed callable at runtime."],
                    limitations=[
                        "The copy is shallow; nested mutable values remain aliased.",
                        *limitations,
                    ],
                )
            )
        if not evidence:
            evidence.append(
                EffectEvidence(
                    producer=EvidenceProducer.DATA_FLOW,
                    status=EvidenceStatus.UNRESOLVED,
                    effect=ChangeEffectKind.DEFENSIVE_COPY_ADDED,
                    observations=[DataObservationKind.UNKNOWN],
                    channel=ImpactChannel.DYNAMIC_EXTENSION,
                    disposition=EffectDisposition.DYNAMIC_OR_UNRESOLVED,
                    summary=(
                        "A defensive copy is added, but caller argument provenance is unresolved."
                    ),
                    subject=subject,
                    changed_location=CodeReference(
                        file_path=str(path), line_number=copy_line, symbol=function.name
                    ),
                    limitations=["Call-site argument identity could not be mapped conservatively."],
                )
            )
            confidence = ConfidenceLevel.MEDIUM
        return EffectAnalysis(tuple(evidence), confidence)

    def _resolve_path(self, value: str) -> Path | None:
        candidate = Path(value)
        if candidate.is_file():
            return candidate.resolve()
        relative = Path(str(value).replace("\\", "/"))
        direct = self.project_root / relative
        if direct.is_file():
            return direct.resolve()
        matches = [
            path
            for path in self.project_root.rglob(relative.name)
            if path.is_file() and str(path).replace("\\", "/").endswith(str(relative))
        ]
        return matches[0].resolve() if len(matches) == 1 else None

    def _tree(self, path: Path) -> ast.Module | None:
        if path not in self._trees:
            try:
                self._trees[path] = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (OSError, SyntaxError, UnicodeError):
                self._trees[path] = None
        return self._trees[path]

    @staticmethod
    def _function_nodes(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
        return [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]

    def _defensive_copy_change(
        self, path: Path, tree: ast.Module, changed_lines: set[int]
    ) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, str, int] | None:
        del path
        matches: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, str, int]] = []
        for function in self._function_nodes(tree):
            parameters = {
                argument.arg
                for argument in [
                    *function.args.posonlyargs,
                    *function.args.args,
                    *function.args.kwonlyargs,
                ]
            }
            if function.args.vararg:
                parameters.add(function.args.vararg.arg)
            if function.args.kwarg:
                parameters.add(function.args.kwarg.arg)
            for node in ast.walk(function):
                if not isinstance(node, ast.Assign) or node.lineno not in changed_lines:
                    continue
                if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                    continue
                subject = node.targets[0].id
                if subject not in parameters or not self._copies_name(node.value, subject):
                    continue
                if self._has_later_top_level_mutation(function, subject, node.lineno):
                    matches.append((function, subject, node.lineno))
        return matches[0] if len(matches) == 1 else None

    @staticmethod
    def _copies_name(value: ast.expr, subject: str) -> bool:
        if isinstance(value, ast.Dict):
            return any(
                key is None and isinstance(item, ast.Name) and item.id == subject
                for key, item in zip(value.keys, value.values, strict=True)
            )
        if isinstance(value, ast.Call):
            if (
                isinstance(value.func, ast.Attribute)
                and value.func.attr == "copy"
                and isinstance(value.func.value, ast.Name)
                and value.func.value.id == subject
                and not value.args
            ):
                return True
            if (
                isinstance(value.func, ast.Name)
                and value.func.id == "dict"
                and len(value.args) == 1
                and isinstance(value.args[0], ast.Name)
                and value.args[0].id == subject
            ):
                return True
        return False

    def _has_later_top_level_mutation(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        subject: str,
        copy_line: int,
    ) -> bool:
        mutators = {
            "add",
            "append",
            "clear",
            "discard",
            "extend",
            "insert",
            "pop",
            "remove",
            "reverse",
            "setdefault",
            "sort",
            "update",
        }
        for node in ast.walk(function):
            if getattr(node, "lineno", 0) <= copy_line:
                continue
            targets: list[ast.expr] = []
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                target = node.target if not isinstance(node, ast.Assign) else node.targets[0]
                targets.append(target)
            elif isinstance(node, ast.Delete):
                targets.extend(node.targets)
            if any(self._root_name(target) == subject for target in targets):
                return True
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in mutators
                and self._root_name(node.func.value) == subject
            ):
                return True
        return False

    @staticmethod
    def _root_name(node: ast.AST) -> str | None:
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        return node.id if isinstance(node, ast.Name) else None

    def _analyze_stack(  # noqa: PLR0911, PLR0912 - fail-closed provenance exits
        self, stack: Sequence[object], subject: str
    ) -> tuple[_Observation, str, list[str]] | None:
        current_subject = subject
        pending: list[_Observation] = []
        saw_edge = False
        outer_index = self._outer_frame_index(stack)
        for index in range(len(stack) - 1, 0, -1):
            callee = stack[index]
            caller_path_value = getattr(callee, "caller_file_path", None)
            call_line = getattr(callee, "caller_line_number", None)
            if caller_path_value is None or call_line is None:
                continue
            caller_path = self._resolve_path(str(caller_path_value))
            if caller_path is None:
                return None
            tree = self._tree(caller_path)
            if tree is None:
                return None
            function = self._function_at_line(tree, int(call_line))
            call = self._call_at_line(function, int(call_line)) if function else None
            if function is None or call is None:
                return None
            actual = self._actual_for_parameter(
                call,
                self._function_at_definition(
                    self._resolve_path(str(getattr(callee, "file_path", ""))),
                    int(getattr(callee, "line_number", 0)),
                ),
                current_subject,
            )
            if actual is None:
                return None
            saw_edge = True
            if not isinstance(actual, ast.Name):
                location = CodeReference(
                    file_path=str(caller_path),
                    line_number=int(call_line),
                    symbol=function.name,
                )
                return (
                    _Observation(
                        DataObservationKind.DYNAMIC_ESCAPE,
                        ImpactChannel.DYNAMIC_EXTENSION,
                        EffectDisposition.DYNAMIC_OR_UNRESOLVED,
                        location,
                    ),
                    "The changed argument is constructed or selected dynamically at the call site.",
                    ["Only simple local-name and parameter provenance is currently modeled."],
                )
            observation = self._post_call_observation(
                caller_path, function, call, actual.id, int(call_line)
            )
            parameters = {
                argument.arg
                for argument in [
                    *function.args.posonlyargs,
                    *function.args.args,
                    *function.args.kwonlyargs,
                ]
            }
            if observation.kind == DataObservationKind.RETURNED and index - 1 > outer_index:
                if self._nested_return_reaches_endpoint(function, stack[outer_index]):
                    return observation, self._summary(observation, actual.id), []
                returned = self._analyze_return_path(stack, index - 1, outer_index)
                if returned is not None:
                    pending.append(returned)
                if actual.id in parameters:
                    current_subject = actual.id
                    continue
                best = self._best_observation([observation, *pending])
                return best, self._summary(best, actual.id), []
            if observation.kind != DataObservationKind.NOT_OBSERVED_AFTER_CALL:
                best = self._best_observation([observation, *pending])
                return best, self._summary(best, actual.id), []
            if actual.id in parameters:
                current_subject = actual.id
                continue
            if pending:
                best = self._best_observation([observation, *pending])
                return best, self._summary(best, "call result"), []
            return (
                observation,
                f"The local argument '{actual.id}' is not observed by this caller after the call.",
                ["Dynamic callees may still observe object identity or retain the copied value."],
            )
        if saw_edge:
            location = CodeReference(
                file_path=str(getattr(stack[outer_index], "file_path", self.project_root)),
                line_number=max(int(getattr(stack[outer_index], "line_number", 1)), 1),
                symbol=str(getattr(stack[outer_index], "function_name", "")) or None,
            )
            not_observed = _Observation(
                DataObservationKind.NOT_OBSERVED_AFTER_CALL,
                ImpactChannel.IN_MEMORY_ALIASING,
                EffectDisposition.NOT_OBSERVED_BY_CALLER,
                location,
            )
            if pending:
                best = self._best_observation([not_observed, *pending])
                return best, self._summary(best, "call result"), []
            return (
                not_observed,
                (
                    "The caller-visible alias effect reaches the endpoint but no "
                    "post-call observation is established."
                ),
                ["Dynamic callees may still observe object identity or retain the copied value."],
            )
        return None

    @staticmethod
    def _outer_frame_index(stack: Sequence[object]) -> int:
        for index, frame in enumerate(stack):
            if not str(getattr(frame, "function_name", "")).startswith("[ENDPOINT]"):
                return index
        return 0

    def _analyze_return_path(
        self, stack: Sequence[object], start_index: int, outer_index: int
    ) -> _Observation | None:
        for index in range(start_index, 0, -1):
            callee = stack[index]
            caller_path_value = getattr(callee, "caller_file_path", None)
            call_line = getattr(callee, "caller_line_number", None)
            if caller_path_value is None or call_line is None:
                continue
            caller_path = self._resolve_path(str(caller_path_value))
            if caller_path is None:
                return None
            tree = self._tree(caller_path)
            if tree is None:
                return None
            function = self._function_at_line(tree, int(call_line))
            call = self._call_at_line(function, int(call_line)) if function else None
            if function is None or call is None:
                return None
            observation = self._call_result_observation(caller_path, function, call, int(call_line))
            if observation.kind == DataObservationKind.RETURNED and index - 1 > outer_index:
                continue
            return observation
        return None

    def _best_observation(self, observations: list[_Observation]) -> _Observation:
        return max(
            observations,
            key=lambda item: (
                _CONFIDENCE_RANK[self._confidence_for(item)],
                item.kind != DataObservationKind.NOT_OBSERVED_AFTER_CALL,
            ),
        )

    def _nested_return_reaches_endpoint(  # noqa: PLR0911 - fail-closed checks
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        endpoint_frame: object,
    ) -> bool:
        endpoint_path = self._resolve_path(str(getattr(endpoint_frame, "file_path", "")))
        if endpoint_path is None:
            return False
        tree = self._tree(endpoint_path)
        if tree is None:
            return False
        endpoint_line = int(getattr(endpoint_frame, "line_number", 0))
        outer = self._function_at_line(tree, endpoint_line)
        if outer is None or function is outer:
            return False
        if not (outer.lineno <= function.lineno <= (outer.end_lineno or outer.lineno)):
            return False
        nodes = self._same_scope_nodes(outer)
        parents: dict[ast.AST, ast.AST] = {}
        for parent in nodes:
            for child in ast.iter_child_nodes(parent):
                if child in nodes:
                    parents[child] = parent
        calls = [
            node
            for node in nodes
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == function.name
        ]
        if len(calls) != 1:
            return False
        ancestor = parents.get(calls[0])
        while ancestor is not None:
            if isinstance(ancestor, (ast.Return, ast.Yield, ast.YieldFrom)):
                return True
            ancestor = parents.get(ancestor)
        return False

    def _function_at_definition(
        self, path: Path | None, line: int
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        if path is None:
            return None
        tree = self._tree(path)
        if tree is None:
            return None
        matches = [
            function
            for function in self._function_nodes(tree)
            if function.lineno == line
            or any(decorator.lineno == line for decorator in function.decorator_list)
        ]
        return matches[0] if len(matches) == 1 else None

    def _function_at_line(
        self, tree: ast.Module, line: int
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        matches = [
            function
            for function in self._function_nodes(tree)
            if function.lineno <= line <= (function.end_lineno or function.lineno)
        ]
        return (
            min(matches, key=lambda item: (item.end_lineno or item.lineno) - item.lineno)
            if matches
            else None
        )

    @staticmethod
    def _same_scope_nodes(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.AST]:
        nodes: list[ast.AST] = []

        def visit(node: ast.AST) -> None:
            nodes.append(node)
            for child in ast.iter_child_nodes(node):
                if child is not function and isinstance(
                    child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
                ):
                    continue
                visit(child)

        visit(function)
        return nodes

    @classmethod
    def _call_at_line(
        cls, function: ast.FunctionDef | ast.AsyncFunctionDef, line: int
    ) -> ast.Call | None:
        matches = [
            node
            for node in cls._same_scope_nodes(function)
            if isinstance(node, ast.Call) and node.lineno == line
        ]
        return matches[0] if len(matches) == 1 else None

    @staticmethod
    def _actual_for_parameter(
        call: ast.Call,
        callee: ast.FunctionDef | ast.AsyncFunctionDef | None,
        parameter: str,
    ) -> ast.expr | None:
        if callee is None or any(keyword.arg is None for keyword in call.keywords):
            return None
        for keyword in call.keywords:
            if keyword.arg == parameter:
                return keyword.value
        positional = [*callee.args.posonlyargs, *callee.args.args]
        indexes = [index for index, argument in enumerate(positional) if argument.arg == parameter]
        if len(indexes) != 1 or indexes[0] >= len(call.args):
            return None
        return call.args[indexes[0]]

    def _call_result_observation(
        self,
        path: Path,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        call: ast.Call,
        call_line: int,
    ) -> _Observation:
        nodes = self._same_scope_nodes(function)
        parents: dict[ast.AST, ast.AST] = {}
        for parent in nodes:
            for child in ast.iter_child_nodes(parent):
                if child in nodes:
                    parents[child] = parent
        ancestor = parents.get(call)
        while ancestor is not None:
            if isinstance(ancestor, (ast.Return, ast.Yield, ast.YieldFrom)):
                return _Observation(
                    DataObservationKind.RETURNED,
                    ImpactChannel.HTTP_RESPONSE,
                    EffectDisposition.OBSERVABLE_BEHAVIOR,
                    CodeReference(file_path=str(path), line_number=call_line, symbol=function.name),
                )
            if isinstance(ancestor, (ast.Assign, ast.AnnAssign)):
                targets = (
                    ancestor.targets if isinstance(ancestor, ast.Assign) else [ancestor.target]
                )
                names = [target.id for target in targets if isinstance(target, ast.Name)]
                if len(names) == 1:
                    return self._post_call_observation(path, function, call, names[0], call_line)
                break
            ancestor = parents.get(ancestor)
        return _Observation(
            DataObservationKind.NOT_OBSERVED_AFTER_CALL,
            ImpactChannel.IN_MEMORY_ALIASING,
            EffectDisposition.NOT_OBSERVED_BY_CALLER,
            CodeReference(file_path=str(path), line_number=call_line, symbol=function.name),
        )

    def _post_call_observation(  # noqa: PLR0912 - explicit observation taxonomy
        self,
        path: Path,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        call: ast.Call,
        subject: str,
        call_line: int,
    ) -> _Observation:
        scope_nodes = self._same_scope_nodes(function)
        scope_set = set(scope_nodes)
        parents: dict[ast.AST, ast.AST] = {}
        for parent in scope_nodes:
            for child in ast.iter_child_nodes(parent):
                if child in scope_set:
                    parents[child] = parent
        ancestor = parents.get(call)
        while ancestor is not None:
            if isinstance(ancestor, (ast.Return, ast.Raise)):
                return _Observation(
                    DataObservationKind.NOT_OBSERVED_AFTER_CALL,
                    ImpactChannel.IN_MEMORY_ALIASING,
                    EffectDisposition.NOT_OBSERVED_BY_CALLER,
                    CodeReference(file_path=str(path), line_number=call_line, symbol=function.name),
                )
            ancestor = parents.get(ancestor)

        aliases = {subject}
        for node in scope_nodes:
            if getattr(node, "lineno", 0) >= call_line:
                continue
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Name)
                and node.value.id in aliases
            ):
                aliases.add(node.targets[0].id)
        changed = True
        while changed:
            changed = False
            for node in scope_nodes:
                if (
                    not isinstance(node, (ast.Assign, ast.AnnAssign))
                    or getattr(node, "lineno", 0) <= call_line
                ):
                    continue
                value = node.value
                if value is None:
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if not any(
                    isinstance(name, ast.Name)
                    and isinstance(name.ctx, ast.Load)
                    and name.id in aliases
                    for name in ast.walk(value)
                ):
                    continue
                for target in targets:
                    if isinstance(target, ast.Name) and target.id not in aliases:
                        aliases.add(target.id)
                        changed = True

        observations: list[_Observation] = []
        for node in scope_nodes:
            if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
                continue
            if node.id not in aliases or node.lineno <= call_line:
                continue
            exclusive, conditional = self._control_relationship(call, node, parents)
            if exclusive:
                continue
            observation = self._classify_use(path, function, node, parents)
            observations.append(
                replace(observation, conditional=True) if conditional else observation
            )
        if not observations:
            return _Observation(
                DataObservationKind.NOT_OBSERVED_AFTER_CALL,
                ImpactChannel.IN_MEMORY_ALIASING,
                EffectDisposition.NOT_OBSERVED_BY_CALLER,
                CodeReference(file_path=str(path), line_number=call_line, symbol=function.name),
            )
        order = {
            DataObservationKind.SENT_OUTBOUND: 8,
            DataObservationKind.PERSISTED: 8,
            DataObservationKind.EMITTED: 8,
            DataObservationKind.RETURNED: 7,
            DataObservationKind.BRANCH: 6,
            DataObservationKind.LOGGED: 5,
            DataObservationKind.FORWARDED: 4,
            DataObservationKind.READ: 3,
            DataObservationKind.DYNAMIC_ESCAPE: 2,
        }
        return max(observations, key=lambda item: order.get(item.kind, 0))

    @staticmethod
    def _control_relationship(
        call: ast.Call,
        use: ast.Name,
        parents: dict[ast.AST, ast.AST],
    ) -> tuple[bool, bool]:
        def signature(  # noqa: PLR0912 - explicit control-region taxonomy
            node: ast.AST,
        ) -> dict[ast.AST, str]:
            result: dict[ast.AST, str] = {}
            child = node
            parent = parents.get(child)
            while parent is not None:
                if isinstance(parent, ast.If):
                    if child in parent.body:
                        result[parent] = "body"
                    elif child in parent.orelse:
                        result[parent] = "orelse"
                    else:
                        result[parent] = "test"
                elif isinstance(parent, ast.Match):
                    arm = next(
                        (
                            f"case:{index}"
                            for index, case in enumerate(parent.cases)
                            if child is case
                        ),
                        "subject",
                    )
                    result[parent] = arm
                elif isinstance(parent, (ast.For, ast.AsyncFor, ast.While)):
                    if child in parent.body:
                        result[parent] = "body"
                    elif child in parent.orelse:
                        result[parent] = "orelse"
                    else:
                        result[parent] = "header"
                elif isinstance(parent, ast.Try):
                    if child in parent.body:
                        result[parent] = "body"
                    elif child in parent.orelse:
                        result[parent] = "orelse"
                    elif child in parent.finalbody:
                        result[parent] = "finally"
                    else:
                        handler = next(
                            (
                                f"handler:{index}"
                                for index, item in enumerate(parent.handlers)
                                if child is item
                            ),
                            "handler",
                        )
                        result[parent] = handler
                child = parent
                parent = parents.get(child)
            return result

        call_signature = signature(call)
        use_signature = signature(use)
        for branch, arm in call_signature.items():
            use_arm = use_signature.get(branch)
            if use_arm is not None and use_arm != arm and isinstance(branch, (ast.If, ast.Match)):
                return True, False
        controls = set(call_signature) | set(use_signature)
        conditional = set(call_signature) != set(use_signature) or any(
            isinstance(control, (ast.Match, ast.For, ast.AsyncFor, ast.While, ast.Try))
            for control in controls
        )
        return False, conditional

    def _classify_use(
        self,
        path: Path,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        node: ast.Name,
        parents: dict[ast.AST, ast.AST],
    ) -> _Observation:
        current: ast.AST = node
        while current in parents:
            current = parents[current]
            location = CodeReference(
                file_path=str(path), line_number=node.lineno, symbol=function.name
            )
            if isinstance(current, (ast.Return, ast.Yield, ast.YieldFrom)):
                return _Observation(
                    DataObservationKind.RETURNED,
                    ImpactChannel.HTTP_RESPONSE,
                    EffectDisposition.OBSERVABLE_BEHAVIOR,
                    location,
                )
            if isinstance(current, (ast.If, ast.While, ast.Assert, ast.Match)):
                return _Observation(
                    DataObservationKind.BRANCH,
                    ImpactChannel.CONTROL_FLOW,
                    EffectDisposition.INTERNAL_EFFECT,
                    location,
                )
            if isinstance(current, ast.Call):
                ancestor = parents.get(current)
                while ancestor is not None:
                    if isinstance(ancestor, (ast.Return, ast.Yield, ast.YieldFrom)):
                        return _Observation(
                            DataObservationKind.RETURNED,
                            ImpactChannel.HTTP_RESPONSE,
                            EffectDisposition.OBSERVABLE_BEHAVIOR,
                            location,
                        )
                    ancestor = parents.get(ancestor)
                name = self._call_name(current.func).lower()
                if (
                    name == "print"
                    or name.startswith(("logger.", "logging."))
                    or name == "warnings.warn"
                ):
                    return _Observation(
                        DataObservationKind.LOGGED,
                        ImpactChannel.LOG_OR_TELEMETRY,
                        EffectDisposition.OPERATIONAL_ONLY,
                        location,
                    )
                # Without a resolved receiver contract, method names such as
                # insert/send/publish are not proof of a persistence or I/O sink.
                return _Observation(
                    DataObservationKind.FORWARDED,
                    ImpactChannel.DYNAMIC_EXTENSION,
                    EffectDisposition.DYNAMIC_OR_UNRESOLVED,
                    location,
                )
        return _Observation(
            DataObservationKind.READ,
            ImpactChannel.UNKNOWN,
            EffectDisposition.INTERNAL_EFFECT,
            CodeReference(file_path=str(path), line_number=node.lineno, symbol=function.name),
        )

    @staticmethod
    def _call_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = EffectAnalyzer._call_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    @staticmethod
    def _confidence_for(observation: _Observation) -> ConfidenceLevel:
        if observation.conditional:
            return ConfidenceLevel.MEDIUM
        if observation.kind == DataObservationKind.RETURNED:
            return ConfidenceLevel.HIGH
        if observation.kind in {
            DataObservationKind.READ,
            DataObservationKind.BRANCH,
            DataObservationKind.LOGGED,
            DataObservationKind.FORWARDED,
            DataObservationKind.DYNAMIC_ESCAPE,
            DataObservationKind.UNKNOWN,
        }:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

    @staticmethod
    def _summary(observation: _Observation, subject: str) -> str:
        descriptions = {
            DataObservationKind.RETURNED: "is returned after the call",
            DataObservationKind.READ: "is read after the call",
            DataObservationKind.BRANCH: "controls a branch after the call",
            DataObservationKind.LOGGED: "is logged after the call",
            DataObservationKind.PERSISTED: "is persisted after the call",
            DataObservationKind.SENT_OUTBOUND: "is sent outbound after the call",
            DataObservationKind.EMITTED: "is emitted after the call",
            DataObservationKind.FORWARDED: "is forwarded to another callable after the call",
            DataObservationKind.DYNAMIC_ESCAPE: "escapes dynamically after the call",
        }
        description = descriptions.get(observation.kind, "has an unknown use")
        return f"The caller argument '{subject}' {description}."
