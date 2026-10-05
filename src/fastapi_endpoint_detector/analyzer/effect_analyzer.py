"""Conservative source-level effect and post-call observation analysis."""

from __future__ import annotations

import ast
from dataclasses import dataclass, replace
from itertools import product
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


@dataclass(frozen=True)
class _ExecutionNode:
    node: ast.AST
    conditional: bool
    path: tuple[tuple[ast.AST, int], ...]


_CONFIDENCE_RANK = {
    ConfidenceLevel.LOW: 0,
    ConfidenceLevel.MEDIUM: 1,
    ConfidenceLevel.HIGH: 2,
}


class EffectAnalyzer:
    """Recognize narrow effect deltas without executing application code."""

    _MAX_SCOPE_NODES = 2000
    _MAX_LOCAL_HELPERS = 8
    _MAX_BRANCH_WORLDS = 256

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
        function, subject, copy_line, conditional_mutation, unresolved_reason = changed
        if unresolved_reason is not None:
            return EffectAnalysis(
                (
                    EffectEvidence(
                        producer=EvidenceProducer.DATA_FLOW,
                        status=EvidenceStatus.UNRESOLVED,
                        effect=ChangeEffectKind.DEFENSIVE_COPY_ADDED,
                        observations=[DataObservationKind.UNKNOWN],
                        channel=ImpactChannel.DYNAMIC_EXTENSION,
                        disposition=EffectDisposition.DYNAMIC_OR_UNRESOLVED,
                        summary=unresolved_reason,
                        subject=subject,
                        changed_location=CodeReference(
                            file_path=str(path), line_number=copy_line, symbol=function.name
                        ),
                        limitations=[
                            "Effect qualification stops at its explicit AST and helper scan caps.",
                            "Caller argument identity could not be mapped conservatively.",
                        ],
                    ),
                ),
                ConfidenceLevel.MEDIUM,
            )
        evidence: list[EffectEvidence] = []
        confidence = ConfidenceLevel.LOW
        for stack in call_stacks:
            result = self._analyze_stack(stack, subject)
            if result is None:
                continue
            observation, summary, limitations = result
            candidate_confidence = self._confidence_for(observation)
            if conditional_mutation:
                candidate_confidence = min(
                    (candidate_confidence, ConfidenceLevel.MEDIUM),
                    key=lambda value: _CONFIDENCE_RANK[value],
                )
                observation = replace(observation, conditional=True)
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
                    conditions=[
                        "The path must select the changed callable at runtime.",
                        *(
                            ["The copy/mutation proof depends on a conditional path."]
                            if conditional_mutation
                            else []
                        ),
                    ],
                    limitations=[
                        "The copy is shallow; nested mutable values remain aliased.",
                        (
                            "Copy mutation qualification scans at most 2,000 scope nodes and "
                            "eight local helper definitions, eight branch tokens, and 256 "
                            "branch-state combinations; dynamic dispatch, recursive helper "
                            "effects, and helper aliases are unresolved."
                        ),
                        (
                            "Literal constant if conditions and while conditions are pruned; "
                            "other conditions are conservatively treated as reachable and "
                            "mark the mutation proof conditional."
                        ),
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
    ) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, str, int, bool, str | None] | None:
        del path
        matches: list[
            tuple[ast.FunctionDef | ast.AsyncFunctionDef, str, int, bool, str | None]
        ] = []
        for function in self._function_nodes(tree):
            execution = self._execution_nodes(function)
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
            for copy_index, item in enumerate(execution):
                node = item.node
                if not isinstance(node, ast.Assign) or node.lineno not in changed_lines:
                    continue
                if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                    continue
                subject = node.targets[0].id
                if subject not in parameters or not self._copies_name(node.value, subject):
                    continue
                if (
                    isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == "dict"
                    and not self._dict_is_unshadowed(tree)
                ):
                    continue
                local_helper_names = {
                    candidate.node.name
                    for candidate in execution
                    if isinstance(candidate.node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and candidate.node is not function
                }
                invoked_helper_names = {
                    candidate.node.func.id
                    for candidate in execution[copy_index + 1 :]
                    if isinstance(candidate.node, ast.Call)
                    and isinstance(candidate.node.func, ast.Name)
                    and candidate.node.func.id in local_helper_names
                }
                if len(execution) > self._MAX_SCOPE_NODES:
                    reason = (
                        "A candidate defensive copy is present, but the enclosing effect scan "
                        "exceeded the 2,000 node cap."
                    )
                    matches.append((function, subject, node.lineno, True, reason))
                    continue
                if len(invoked_helper_names) > self._MAX_LOCAL_HELPERS:
                    reason = (
                        "A candidate defensive copy is present, but the directly invoked local "
                        "helper scan exceeded the eight helper cap."
                    )
                    matches.append((function, subject, node.lineno, True, reason))
                    continue
                mutation_conditional = self._has_later_top_level_mutation(
                    function, subject, execution, copy_index
                )
                if mutation_conditional is not None:
                    matches.append(
                        (
                            function,
                            subject,
                            node.lineno,
                            mutation_conditional or item.conditional,
                            None,
                        )
                    )
        return matches[0] if len(matches) == 1 else None

    @staticmethod
    def _copies_name(value: ast.expr, subject: str) -> bool:
        if isinstance(value, ast.Dict):
            return any(
                key is None and isinstance(item, ast.Name) and item.id == subject
                for key, item in zip(value.keys, value.values, strict=True)
            )
        # A method named copy is not proof of built-in container semantics.
        # Keep only constructors whose target type is explicit below.
        return (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "dict"
            and len(value.args) == 1
            and isinstance(value.args[0], ast.Name)
            and value.args[0].id == subject
        )

    @staticmethod
    def _dict_is_unshadowed(tree: ast.Module) -> bool:  # noqa: PLR0911 - explicit binding kinds
        # Any module binding may shadow builtins for a nested function too.
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == "dict" and isinstance(node.ctx, ast.Store):
                return False
            if isinstance(node, ast.arg) and node.arg == "dict":
                return False
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and node.name == "dict"
            ):
                return False
            if isinstance(node, ast.alias) and (node.asname or node.name.split(".")[0]) == "dict":
                return False
            if isinstance(node, ast.ExceptHandler) and node.name == "dict":
                return False
            if isinstance(node, ast.MatchAs) and node.name == "dict":
                return False
            if isinstance(node, ast.MatchStar) and node.name == "dict":
                return False
            if isinstance(node, ast.MatchMapping) and node.rest == "dict":
                return False
            if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
                return False
        return True

    @staticmethod
    def _literal_truth(node: ast.expr) -> bool | None:
        if isinstance(node, ast.Constant) and type(node.value) in (
            bool,
            int,
            float,
            complex,
            str,
            bytes,
        ):
            return bool(node.value)
        if isinstance(node, ast.Constant) and node.value is None:
            return False
        return None

    def _execution_nodes(  # noqa: PLR0915 - bounded AST interpreter
        self, function: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> list[_ExecutionNode]:
        """Return scope nodes on possible execution paths with uncertainty attached."""
        result: list[_ExecutionNode] = []
        overflow = False

        def add_tree(  # noqa: PLR0911, PLR0912 - explicit AST execution cases
            node: ast.AST,
            conditional: bool,
            path: tuple[tuple[ast.AST, int], ...],
        ) -> None:
            nonlocal overflow
            if overflow:
                return
            result.append(_ExecutionNode(node, conditional, path))
            if len(result) > self._MAX_SCOPE_NODES:
                overflow = True
                return
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                return
            if isinstance(node, ast.GeneratorExp):
                return
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp)):
                for generator in node.generators:
                    add_tree(generator.iter, conditional, path)
                    for condition in generator.ifs:
                        add_tree(condition, True, path)
                if isinstance(node, ast.DictComp):
                    add_tree(node.key, True, path)
                    add_tree(node.value, True, path)
                else:
                    add_tree(node.elt, True, path)
                return
            if isinstance(node, ast.BoolOp):
                for index, value in enumerate(node.values):
                    add_tree(value, conditional or index > 0, path)
                    truth = self._literal_truth(value)
                    if isinstance(node.op, ast.And) and truth is False:
                        break
                    if isinstance(node.op, ast.Or) and truth is True:
                        break
                return
            if isinstance(node, ast.IfExp):
                add_tree(node.test, conditional, path)
                truth = self._literal_truth(node.test)
                if truth is True:
                    add_tree(node.body, conditional, path)
                elif truth is False:
                    add_tree(node.orelse, conditional, path)
                else:
                    add_tree(node.body, True, (*path, (node, 0)))
                    add_tree(node.orelse, True, (*path, (node, 1)))
                return
            for child in ast.iter_child_nodes(node):
                add_tree(child, conditional, path)

        def visit_block(  # noqa: PLR0912, PLR0915 - explicit control-flow cases
            statements: list[ast.stmt],
            conditional: bool,
            path: tuple[tuple[ast.AST, int], ...],
        ) -> bool:
            nonlocal overflow
            terminal = False
            path_conditional = conditional
            for statement in statements:
                if terminal or overflow:
                    break
                if isinstance(statement, ast.If):
                    add_tree(statement.test, path_conditional, path)
                    truth = self._literal_truth(statement.test)
                    if truth is True:
                        terminal = visit_block(statement.body, path_conditional, path)
                    elif truth is False:
                        terminal = visit_block(statement.orelse, path_conditional, path)
                    else:
                        body_path = (*path, (statement, 0))
                        else_path = (*path, (statement, 1))
                        body_terminal = visit_block(statement.body, True, body_path)
                        else_terminal = (
                            visit_block(statement.orelse, True, else_path)
                            if statement.orelse
                            else False
                        )
                        terminal = bool(statement.orelse) and body_terminal and else_terminal
                        if body_terminal != else_terminal:
                            path_conditional = True
                    continue
                if isinstance(statement, ast.While):
                    add_tree(statement.test, path_conditional, path)
                    truth = self._literal_truth(statement.test)
                    if truth is False:
                        terminal = visit_block(statement.orelse, path_conditional, path)
                    else:
                        visit_block(
                            statement.body,
                            path_conditional if truth is True else True,
                            (*path, (statement, 0)),
                        )
                        visit_block(statement.orelse, True, (*path, (statement, 1)))
                        terminal = truth is True and not self._loop_has_break(statement)
                    continue
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    result.append(_ExecutionNode(statement, path_conditional, path))
                    overflow = len(result) > self._MAX_SCOPE_NODES
                    # Decorators/defaults execute when the definition is reached.
                    for expr in [
                        *statement.decorator_list,
                        *statement.args.defaults,
                        *statement.args.kw_defaults,
                    ]:
                        if expr is not None:
                            add_tree(expr, path_conditional, path)
                elif isinstance(statement, (ast.For, ast.AsyncFor)):
                    result.append(_ExecutionNode(statement, path_conditional, path))
                    overflow = len(result) > self._MAX_SCOPE_NODES
                    add_tree(statement.iter, path_conditional, path)
                    body_path = (*path, (statement, 0))
                    add_tree(statement.target, True, body_path)
                    visit_block(statement.body, True, body_path)
                    visit_block(statement.orelse, True, (*path, (statement, 1)))
                elif isinstance(statement, (ast.With, ast.AsyncWith)):
                    for item in statement.items:
                        add_tree(item.context_expr, path_conditional, path)
                        if item.optional_vars is not None:
                            add_tree(item.optional_vars, path_conditional, path)
                    terminal = visit_block(statement.body, path_conditional, path)
                elif isinstance(statement, ast.Try):
                    body_terminal = visit_block(statement.body, path_conditional, path)
                    handler_terminals: list[bool] = []
                    for index, handler in enumerate(statement.handlers, start=1):
                        handler_path = (*path, (statement, index))
                        result.append(_ExecutionNode(handler, True, handler_path))
                        overflow = len(result) > self._MAX_SCOPE_NODES
                        if overflow:
                            break
                        if handler.type is not None:
                            add_tree(handler.type, True, handler_path)
                        handler_terminals.append(visit_block(handler.body, True, handler_path))
                    else_terminal = False
                    if statement.orelse and not body_terminal:
                        else_terminal = visit_block(statement.orelse, True, path)
                    finally_terminal = visit_block(statement.finalbody, path_conditional, path)
                    terminal = finally_terminal or (
                        body_terminal
                        and (not statement.handlers or all(handler_terminals))
                        and (not statement.orelse or else_terminal)
                    )
                elif isinstance(statement, ast.Match):
                    add_tree(statement.subject, path_conditional, path)
                    for index, case in enumerate(statement.cases):
                        case_path = (*path, (statement, index))
                        add_tree(case.pattern, True, case_path)
                        if case.guard is not None:
                            add_tree(case.guard, True, case_path)
                        visit_block(case.body, True, case_path)
                    terminal = False
                else:
                    add_tree(statement, path_conditional, path)
                    terminal = isinstance(statement, (ast.Return, ast.Raise))
            return terminal

        visit_block(function.body, False, ())
        return result

    @staticmethod
    def _loop_has_break(loop: ast.While) -> bool:
        pending: list[ast.AST] = list(loop.body)
        while pending:
            node = pending.pop()
            if isinstance(node, ast.Break):
                return True
            if isinstance(
                node,
                (
                    ast.For,
                    ast.AsyncFor,
                    ast.While,
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.Lambda,
                ),
            ):
                continue
            pending.extend(ast.iter_child_nodes(node))
        return False

    @staticmethod
    def _is_awaited(call: ast.Call, parents: dict[ast.AST, ast.AST]) -> bool:
        return isinstance(parents.get(call), ast.Await)

    @staticmethod
    def _paths_compatible(
        left: tuple[tuple[ast.AST, int], ...], right: tuple[tuple[ast.AST, int], ...]
    ) -> bool:
        left_values = dict(left)
        return all(
            token not in left_values or left_values[token] == value for token, value in right
        )

    @staticmethod
    def _path_contains(
        path: tuple[tuple[ast.AST, int], ...], required: tuple[tuple[ast.AST, int], ...]
    ) -> bool:
        values = dict(path)
        return all(values.get(token) == value for token, value in required)

    def _alias_status(
        self,
        name: str,
        path: tuple[tuple[ast.AST, int], ...],
        before: int,
        facts: dict[str, list[tuple[int, tuple[tuple[ast.AST, int], ...], bool | None]]],
    ) -> tuple[bool, bool]:
        records = [
            record
            for record in facts.get(name, [])
            if record[0] < before and self._paths_compatible(record[1], path)
        ]
        tokens = {token for token, _ in path}
        for _, record_path, _ in records:
            tokens.update(token for token, _ in record_path)
        if len(tokens) > 8:
            return any(state is not False for _, _, state in records), False
        ordered_tokens = sorted(tokens, key=id)
        domains = [
            tuple(range(len(token.cases) + 1)) if isinstance(token, ast.Match) else (0, 1)
            for token in ordered_tokens
        ]
        world_count = 1
        for domain in domains:
            world_count *= len(domain)
            if world_count > self._MAX_BRANCH_WORLDS:
                return any(state is not False for _, _, state in records), False
        outcomes: set[bool] = set()
        for values in product(*domains):
            world = dict(zip(ordered_tokens, values, strict=True))
            if any(world.get(token) != value for token, value in path):
                continue
            applicable = [
                record
                for record in records
                if all(world.get(token) == value for token, value in record[1])
            ]
            state = max(applicable, key=lambda record: record[0])[2] if applicable else False
            if state is None:
                outcomes.update((True, False))
            else:
                outcomes.add(state)
        if not outcomes:
            return False, False
        return True in outcomes, outcomes == {True}

    @staticmethod
    def _binding_names(node: ast.AST) -> set[str]:  # noqa: PLR0911 - explicit binding kinds
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            return {node.id}
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return {node.name}
        if isinstance(node, ast.ExceptHandler) and node.name:
            return {node.name}
        if isinstance(node, ast.alias):
            return {node.asname or node.name.split(".")[0]}
        if isinstance(node, ast.MatchAs) and node.name:
            return {node.name}
        if isinstance(node, ast.MatchStar) and node.name:
            return {node.name}
        if isinstance(node, ast.MatchMapping) and node.rest:
            return {node.rest}
        return set()

    @staticmethod
    def _helper_call_is_valid(  # noqa: PLR0911 - explicit signature validation exits
        call: ast.Call, helper: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> bool:
        if any(isinstance(argument, ast.Starred) for argument in call.args) or any(
            keyword.arg is None for keyword in call.keywords
        ):
            return False
        positional = [*helper.args.posonlyargs, *helper.args.args]
        keyword_only = helper.args.kwonlyargs
        if len(call.args) > len(positional) and helper.args.vararg is None:
            return False
        supplied = {argument.arg for argument in positional[: len(call.args)]}
        seen_keywords: set[str] = set()
        positional_only = {argument.arg for argument in helper.args.posonlyargs}
        accepted = {argument.arg for argument in [*positional, *keyword_only]}
        for keyword in call.keywords:
            assert keyword.arg is not None
            if keyword.arg in seen_keywords or keyword.arg in positional_only:
                return False
            if keyword.arg not in accepted and helper.args.kwarg is None:
                return False
            if keyword.arg in supplied:
                return False
            seen_keywords.add(keyword.arg)
        supplied.update(seen_keywords)
        default_start = len(positional) - len(helper.args.defaults)
        for index, argument in enumerate(positional):
            if (
                index not in range(len(call.args))
                and argument.arg not in supplied
                and index < default_start
            ):
                return False
        kw_defaults = dict(
            zip((arg.arg for arg in keyword_only), helper.args.kw_defaults, strict=True)
        )
        return all(
            argument.arg in supplied or kw_defaults[argument.arg] is not None
            for argument in keyword_only
        )

    @classmethod
    def _direct_mutation_names(cls, node: ast.AST, mutators: set[str]) -> set[str]:
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in mutators
            and isinstance(node.func.value, ast.Name)
        ):
            return {node.func.value.id}
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.Delete)):
            targets = node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
            return {
                target.value.id
                for target in targets
                if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
            }
        if (
            isinstance(node, ast.AugAssign)
            and isinstance(node.op, ast.BitOr)
            and isinstance(node.target, ast.Name)
        ):
            return {node.target.id}
        return set()

    def _has_later_top_level_mutation(  # noqa: PLR0915 - explicit bounded proof
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        subject: str,
        execution: list[_ExecutionNode],
        copy_index: int,
    ) -> bool | None:
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
        if copy_index >= len(execution):
            return None
        initial_path = execution[copy_index].path
        facts: dict[str, list[tuple[int, tuple[tuple[ast.AST, int], ...], bool | None]]] = {
            subject: [(-1, (), False), (copy_index, initial_path, True)]
        }
        scope_nodes = self._same_scope_nodes(function)
        scope_set = set(scope_nodes)
        parents = {
            child: parent
            for parent in scope_nodes
            for child in ast.iter_child_nodes(parent)
            if child in scope_set
        }
        invoked_helper_names = {
            item.node.func.id
            for item in execution[copy_index + 1 :]
            if isinstance(item.node, ast.Call) and isinstance(item.node.func, ast.Name)
        }
        helpers = [
            (index, item.node, item)
            for index, item in enumerate(execution)
            if isinstance(item.node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.node is not function
            and item.node.name in invoked_helper_names
        ]
        if len({helper.name for _, helper, _ in helpers}) > self._MAX_LOCAL_HELPERS:
            return None
        candidates: list[bool] = []

        def binding_state(
            value: ast.expr | None,
            path: tuple[tuple[ast.AST, int], ...],
            index: int,
            aliases: dict[str, list[tuple[int, tuple[tuple[ast.AST, int], ...], bool | None]]],
        ) -> bool | None:
            if not isinstance(value, ast.Name):
                return False
            may_alias, definite_alias = self._alias_status(value.id, path, index, aliases)
            return True if definite_alias else None if may_alias else False

        def update_bindings(  # noqa: PLR0912 - explicit binding forms
            node: ast.AST,
            path: tuple[tuple[ast.AST, int], ...],
            index: int,
            aliases: dict[str, list[tuple[int, tuple[tuple[ast.AST, int], ...], bool | None]]],
            binding_parents: dict[ast.AST, ast.AST],
        ) -> None:
            targets: list[ast.expr] = []
            value: ast.expr | None = None
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
                targets, value = [node.target], node.value
            elif isinstance(node, ast.AugAssign):
                targets = [node.target]
                if isinstance(node.op, ast.BitOr) and isinstance(node.target, ast.Name):
                    return
            elif isinstance(node, ast.Delete):
                targets = node.targets
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                return  # The target store is visited on the loop-body path.
            elif isinstance(node, ast.ExceptHandler) and node.name:
                targets = [ast.Name(id=node.name, ctx=ast.Store())]
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                parent = binding_parents.get(node)
                if isinstance(parent, (ast.For, ast.AsyncFor, ast.withitem)):
                    targets = [node]
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                targets = [ast.Name(id=node.name, ctx=ast.Store())]
            elif isinstance(node, ast.alias):
                targets = [ast.Name(id=node.asname or node.name.split(".")[0], ctx=ast.Store())]
            elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                targets = [ast.Name(id=node.name, ctx=ast.Store())]
            elif isinstance(node, ast.MatchMapping) and node.rest:
                targets = [ast.Name(id=node.rest, ctx=ast.Store())]
            state = binding_state(value, path, index, aliases)
            for target in targets:
                if isinstance(target, ast.Name):
                    aliases.setdefault(target.id, []).append((index, path, state))

        def helper_effect(  # noqa: PLR0911, PLR0912 - fail-closed helper proof
            call: ast.Call, call_index: int, call_item: _ExecutionNode
        ) -> bool | None:
            if not isinstance(call.func, ast.Name):
                return None
            matches = [(idx, fn, item) for idx, fn, item in helpers if fn.name == call.func.id]
            if len(matches) != 1:
                return None
            helper_index, helper, helper_item = matches[0]
            if helper_index >= call_index or not self._path_contains(
                call_item.path, helper_item.path
            ):
                return None
            if helper.decorator_list or not self._helper_call_is_valid(call, helper):
                return None
            if isinstance(helper, ast.AsyncFunctionDef) and not self._is_awaited(call, parents):
                return None
            helper_nodes = self._execution_nodes(helper)
            helper_scope = self._same_scope_nodes(helper)
            helper_scope_set = set(helper_scope)
            helper_parents = {
                child: parent
                for parent in helper_scope
                for child in ast.iter_child_nodes(parent)
                if child in helper_scope_set
            }
            if not helper_nodes or any(
                isinstance(node, (ast.Yield, ast.YieldFrom, ast.Global, ast.Nonlocal))
                for node in ast.walk(helper)
            ):
                return None
            for item in execution[helper_index + 1 : call_index]:
                if call.func.id in self._binding_names(item.node) and self._paths_compatible(
                    item.path, call_item.path
                ):
                    return None
                if isinstance(item.node, ast.ImportFrom) and any(
                    alias.name == "*" for alias in item.node.names
                ):
                    return None
            arguments = [*helper.args.posonlyargs, *helper.args.args, *helper.args.kwonlyargs]
            formal_names = {argument.arg for argument in arguments}
            locally_bound_names = {
                name for body_node in helper_scope for name in self._binding_names(body_node)
            }
            helper_facts: dict[
                str, list[tuple[int, tuple[tuple[ast.AST, int], ...], bool | None]]
            ] = {}
            for name in locally_bound_names - formal_names:
                helper_facts[name] = [(-1, (), False)]
            outer_names = set(facts) - formal_names - locally_bound_names
            for name in outer_names:
                may_alias, definite_alias = self._alias_status(
                    name, call_item.path, call_index, facts
                )
                if may_alias:
                    helper_facts[name] = [(-1, (), True if definite_alias else None)]
            for argument in arguments:
                actual = self._actual_for_parameter(call, helper, argument.arg)
                if isinstance(actual, ast.Name):
                    may_alias, definite_alias = self._alias_status(
                        actual.id, call_item.path, call_index, facts
                    )
                    helper_facts[argument.arg] = (
                        [(-1, (), True if definite_alias else None)]
                        if may_alias
                        else [(-1, (), False)]
                    )
                else:
                    helper_facts[argument.arg] = [(-1, (), False)]
            helper_candidates: list[bool] = []
            for body_index, body_item in enumerate(helper_nodes):
                node = body_item.node
                for root in self._direct_mutation_names(node, mutators):
                    may_alias, definite_alias = self._alias_status(
                        root, body_item.path, body_index, helper_facts
                    )
                    if may_alias:
                        helper_candidates.append(
                            call_item.conditional or body_item.conditional or not definite_alias
                        )
                update_bindings(node, body_item.path, body_index, helper_facts, helper_parents)
            return min(helper_candidates) if helper_candidates else None

        for index, item in enumerate(execution):
            if index <= copy_index:
                continue
            node = item.node
            for root in self._direct_mutation_names(node, mutators):
                may_alias, definite_alias = self._alias_status(root, item.path, index, facts)
                if may_alias:
                    candidates.append(item.conditional or not definite_alias)
            if isinstance(node, ast.Call):
                result = helper_effect(node, index, item)
                if result is not None:
                    candidates.append(item.conditional or result)
            update_bindings(node, item.path, index, facts, parents)
        return min(candidates) if candidates else None

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

    def _post_call_observation(  # noqa: PLR0912, PLR0915 - explicit observation taxonomy
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
        reachable_nodes = {item.node for item in self._execution_nodes(function)}
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
            if node not in reachable_nodes:
                continue
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Name)
                and node.value.id in aliases
            ):
                aliases.add(node.targets[0].id)
        # Follow straight-line assignments after the call. A write kills that
        # local's old identity; branch assignments are left conditional by the
        # control-region classifier rather than joined as definite aliases.
        killed_at: dict[str, int] = {}
        ordered_statements = sorted(
            (node for node in scope_nodes if isinstance(node, ast.stmt)),
            key=lambda node: (getattr(node, "lineno", 0), getattr(node, "col_offset", 0)),
        )
        for statement in ordered_statements:
            if getattr(statement, "lineno", 0) <= call_line:
                continue
            if statement not in reachable_nodes:
                continue
            control, _ = self._control_relationship(call, statement, parents)
            value = getattr(statement, "value", None)
            targets: list[ast.expr] = []
            if isinstance(statement, ast.Assign):
                targets.extend(statement.targets)
            elif isinstance(statement, ast.AnnAssign):
                if statement.value is None:
                    continue
                targets.append(statement.target)
            elif isinstance(statement, ast.AugAssign):
                targets.append(statement.target)
            if control:
                # An assignment in an opposite if arm cannot define a definite
                # alias on the call's path.
                for target in targets:
                    if isinstance(target, ast.Name) and target.id in aliases:
                        killed_at[target.id] = statement.lineno
                continue
            source_alias = value is not None and any(
                isinstance(name, ast.Name) and isinstance(name.ctx, ast.Load) and name.id in aliases
                for name in ast.walk(value)
            )
            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                if target.id in aliases:
                    killed_at[target.id] = statement.lineno
                if source_alias:
                    aliases.add(target.id)
                    killed_at.pop(target.id, None)

        observations: list[_Observation] = []
        for node in scope_nodes:
            if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
                continue
            if node not in reachable_nodes:
                continue
            if (
                node.id not in aliases
                or node.lineno <= call_line
                or node.lineno >= killed_at.get(node.id, 10**12)
            ):
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
        use: ast.AST,
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
