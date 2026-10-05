"""Bounded source ownership rules for FastAPI and Starlette route callbacks."""

from __future__ import annotations

import ast
from dataclasses import dataclass

_ROUTE_CALLBACKS: dict[str, tuple[str, ...]] = {
    "fastapi.FastAPI.get": ("decorator",),
    "fastapi.FastAPI.post": ("decorator",),
    "fastapi.FastAPI.put": ("decorator",),
    "fastapi.FastAPI.delete": ("decorator",),
    "fastapi.FastAPI.patch": ("decorator",),
    "fastapi.FastAPI.options": ("decorator",),
    "fastapi.FastAPI.head": ("decorator",),
    "fastapi.FastAPI.trace": ("decorator",),
    "fastapi.FastAPI.api_route": ("decorator",),
    "fastapi.FastAPI.websocket": ("decorator",),
    "fastapi.FastAPI.add_api_route": ("argument:1",),
    "fastapi.FastAPI.add_api_websocket_route": ("argument:1",),
    "starlette.applications.Starlette.route": ("decorator",),
    "starlette.applications.Starlette.websocket_route": ("decorator",),
    "starlette.applications.Starlette.add_route": ("argument:1",),
    "starlette.applications.Starlette.add_websocket_route": ("argument:1",),
    "fastapi.routing.APIRouter.get": ("decorator",),
    "fastapi.routing.APIRouter.post": ("decorator",),
    "fastapi.routing.APIRouter.put": ("decorator",),
    "fastapi.routing.APIRouter.delete": ("decorator",),
    "fastapi.routing.APIRouter.patch": ("decorator",),
    "fastapi.routing.APIRouter.options": ("decorator",),
    "fastapi.routing.APIRouter.head": ("decorator",),
    "fastapi.routing.APIRouter.trace": ("decorator",),
    "fastapi.routing.APIRouter.api_route": ("decorator",),
    "fastapi.routing.APIRouter.websocket": ("decorator",),
    "fastapi.routing.APIRouter.add_api_route": ("argument:1",),
    "fastapi.routing.APIRouter.add_api_websocket_route": ("argument:1",),
}


def route_callback_selector(symbol: str) -> str | None:
    """Return a documented callback selector for an exact framework route API."""
    selectors = _ROUTE_CALLBACKS.get(symbol)
    return selectors[0] if selectors and len(selectors) == 1 else None


def direct_route_callback(call: ast.Call, selector: str) -> ast.expr | None:
    """Select only the callback expression at a known positional or keyword slot."""
    if selector == "decorator":
        return None
    _, raw_index = selector.split(":", maxsplit=1)
    index = int(raw_index)
    if len(call.args) > index:
        return call.args[index]
    names = ("endpoint", "route", "view_func")
    return next((item.value for item in call.keywords if item.arg in names), None)


def eager_calls(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[ast.Call, ...]:
    """Return calls executed in a function body, excluding nested callables."""

    class Calls(ast.NodeVisitor):
        def __init__(self) -> None:
            self.result: list[ast.Call] = []

        def _visit_body(self, child: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            if child is node:
                for statement in child.body:
                    self.visit(statement)

        def visit_FunctionDef(self, child: ast.FunctionDef) -> None:
            self._visit_body(child)

        def visit_AsyncFunctionDef(self, child: ast.AsyncFunctionDef) -> None:
            self._visit_body(child)

        def visit_Lambda(self, _child: ast.Lambda) -> None:
            return

        def visit_ClassDef(self, _child: ast.ClassDef) -> None:
            return

        def visit_Call(self, child: ast.Call) -> None:
            self.result.append(child)
            self.generic_visit(child)

    visitor = Calls()
    visitor.visit(node)
    return tuple(visitor.result)


@dataclass(frozen=True)
class BackgroundTaskCall:
    """One add_task call and the preset contract proven by its receiver alias."""

    call: ast.Call
    contract_id: str | None


def background_task_calls(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    trusted_parameters: dict[str, str],
) -> tuple[BackgroundTaskCall, ...]:
    """Trace lexical aliases from trusted BackgroundTasks parameters, with bounded control flow."""
    return _BackgroundTaskAliasAnalysis(function, trusted_parameters).run()


class _BackgroundTaskAliasAnalysis:
    MAX_HELPER_DEPTH = 4

    def __init__(
        self,
        root: ast.FunctionDef | ast.AsyncFunctionDef,
        trusted_parameters: dict[str, str],
    ) -> None:
        self.root = root
        self.initial = dict(trusted_parameters)
        self.results: dict[int, BackgroundTaskCall] = {}
        self.helpers: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}

    def run(self) -> tuple[BackgroundTaskCall, ...]:
        aliases = dict(self.initial)
        suspect = {
            argument.arg
            for argument in _arguments(self.root)
            if argument.arg not in aliases and argument.arg in {"tasks", "background_tasks"}
        }
        self._statements(self.root.body, aliases, suspect, ())
        return tuple(
            sorted(
                self.results.values(),
                key=lambda item: (item.call.lineno, item.call.col_offset),
            )
        )

    def _expression(
        self,
        expression: ast.expr,
        aliases: dict[str, str],
        suspect: set[str],
        stack: tuple[str, ...],
    ) -> None:
        if isinstance(expression, ast.Call):
            if (
                isinstance(expression.func, ast.Attribute)
                and expression.func.attr == "add_task"
                and isinstance(expression.func.value, ast.Name)
            ):
                receiver = expression.func.value.id
                if receiver in aliases:
                    self.results[id(expression)] = BackgroundTaskCall(expression, aliases[receiver])
                elif receiver in suspect or receiver in {"tasks", "background_tasks"}:
                    self.results[id(expression)] = BackgroundTaskCall(expression, None)
            if (
                isinstance(expression.func, ast.Name)
                and expression.func.id in self.helpers
                and expression.func.id not in stack
                and len(stack) < self.MAX_HELPER_DEPTH
            ):
                helper_name = expression.func.id
                helper = self.helpers[helper_name]
                helper_aliases, helper_suspect = self._helper_environment(
                    helper, expression, aliases, suspect
                )
                self._statements(
                    helper.body,
                    helper_aliases,
                    helper_suspect,
                    (*stack, helper_name),
                )
            for argument in expression.args:
                self._expression(argument, aliases, suspect, stack)
            for keyword in expression.keywords:
                self._expression(keyword.value, aliases, suspect, stack)
            return
        for child in ast.iter_child_nodes(expression):
            if isinstance(child, ast.expr):
                self._expression(child, aliases, suspect, stack)

    def _statements(  # noqa: PLR0912, PLR0915
        self,
        statements: list[ast.stmt],
        aliases: dict[str, str],
        suspect: set[str],
        stack: tuple[str, ...],
    ) -> tuple[dict[str, str], set[str]]:
        for statement in statements:
            if isinstance(statement, ast.Import):
                for import_alias in statement.names:
                    local = import_alias.asname or import_alias.name.split(".")[0]
                    self._bind(ast.Name(id=local, ctx=ast.Store()), None, False, aliases, suspect)
                continue
            if isinstance(statement, ast.ImportFrom):
                for import_alias in statement.names:
                    if import_alias.name == "*":
                        continue
                    local = import_alias.asname or import_alias.name
                    self._bind(ast.Name(id=local, ctx=ast.Store()), None, False, aliases, suspect)
                continue
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.helpers[statement.name] = statement
                for decorator in statement.decorator_list:
                    self._expression(decorator, aliases, suspect, stack)
                for default in (*statement.args.defaults, *statement.args.kw_defaults):
                    if default is not None:
                        self._expression(default, aliases, suspect, stack)
                continue
            if isinstance(statement, ast.Assign):
                self._expression(statement.value, aliases, suspect, stack)
                rhs_alias = self._alias_value(statement.value, aliases)
                rhs_suspect = self._mentions_name(statement.value, suspect | set(aliases))
                for target in statement.targets:
                    self._bind(target, rhs_alias, rhs_suspect, aliases, suspect)
                continue
            if isinstance(statement, ast.AnnAssign):
                self._expression(statement.annotation, aliases, suspect, stack)
                if statement.value is not None:
                    self._expression(statement.value, aliases, suspect, stack)
                rhs_alias = self._alias_value(statement.value, aliases)
                rhs_suspect = statement.value is not None and self._mentions_name(
                    statement.value, suspect | set(aliases)
                )
                self._bind(statement.target, rhs_alias, rhs_suspect, aliases, suspect)
                continue
            if isinstance(statement, ast.If):
                self._expression(statement.test, aliases, suspect, stack)
                incoming_aliases = dict(aliases)
                incoming_suspect = set(suspect)
                left_aliases, left_suspect = self._statements(
                    statement.body, dict(incoming_aliases), set(incoming_suspect), stack
                )
                right_aliases, right_suspect = self._statements(
                    statement.orelse, dict(incoming_aliases), set(incoming_suspect), stack
                )
                names = (
                    set(incoming_aliases)
                    | incoming_suspect
                    | set(left_aliases)
                    | left_suspect
                    | set(right_aliases)
                    | right_suspect
                )
                joined_aliases = {
                    name: contract
                    for name, contract in left_aliases.items()
                    if right_aliases.get(name) == contract
                }
                joined_suspect = left_suspect | right_suspect
                joined_suspect.update(
                    name
                    for name in names
                    if left_aliases.get(name) != right_aliases.get(name)
                    and (
                        name in left_aliases
                        or name in right_aliases
                        or name in left_suspect
                        or name in right_suspect
                    )
                )
                aliases.clear()
                aliases.update(joined_aliases)
                suspect.clear()
                suspect.update(joined_suspect)
                continue
            if isinstance(statement, (ast.For, ast.AsyncFor)):
                self._expression(statement.iter, aliases, suspect, stack)
                iterable_aliases = self._literal_alias_values(statement.iter, aliases)
                if iterable_aliases is not None:
                    base_aliases = dict(aliases)
                    base_suspect = set(suspect)
                    for item_aliases in iterable_aliases:
                        loop_aliases = dict(aliases)
                        loop_suspect = set(suspect)
                        alias_value = item_aliases[0] if len(item_aliases) == 1 else None
                        self._bind(
                            statement.target,
                            alias_value,
                            bool(item_aliases) and alias_value is None,
                            loop_aliases,
                            loop_suspect,
                        )
                        loop_aliases, loop_suspect = self._statements(
                            statement.body, loop_aliases, loop_suspect, stack
                        )
                        base_aliases = {
                            name: contract
                            for name, contract in base_aliases.items()
                            if loop_aliases.get(name) == contract
                        }
                        base_suspect.update(loop_suspect)
                    else_aliases, else_suspect = self._statements(
                        statement.orelse, dict(base_aliases), set(base_suspect), stack
                    )
                    aliases.clear()
                    aliases.update(else_aliases)
                    suspect.clear()
                    suspect.update(else_suspect)
                else:
                    loop_aliases = dict(aliases)
                    loop_suspect = set(suspect)
                    self._bind(statement.target, None, True, loop_aliases, loop_suspect)
                    loop_aliases, loop_suspect = self._statements(
                        statement.body, loop_aliases, loop_suspect, stack
                    )
                    incoming_aliases = dict(aliases)
                    aliases.clear()
                    aliases.update(
                        {
                            name: contract
                            for name, contract in incoming_aliases.items()
                            if loop_aliases.get(name) == contract
                        }
                    )
                    suspect.update(loop_suspect)
                    aliases, suspect = self._statements(statement.orelse, aliases, suspect, stack)
                continue
            if isinstance(statement, ast.While):
                self._expression(statement.test, aliases, suspect, stack)
                body_aliases, body_suspect = self._statements(
                    statement.body, dict(aliases), set(suspect), stack
                )
                aliases_copy = dict(aliases)
                aliases.clear()
                aliases.update(
                    {
                        name: contract
                        for name, contract in aliases_copy.items()
                        if body_aliases.get(name) == contract
                    }
                )
                suspect.update(body_suspect)
                aliases, suspect = self._statements(statement.orelse, aliases, suspect, stack)
                continue
            if isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    self._expression(item.context_expr, aliases, suspect, stack)
                    if item.optional_vars is not None:
                        self._bind(item.optional_vars, None, True, aliases, suspect)
                aliases, suspect = self._statements(statement.body, aliases, suspect, stack)
                continue
            if isinstance(statement, ast.Try):
                branches = [statement.body, *[handler.body for handler in statement.handlers]]
                branch_states = [
                    self._statements(items, dict(aliases), set(suspect), stack)
                    for items in branches
                ]
                if statement.orelse:
                    branch_states.append(
                        self._statements(statement.orelse, dict(aliases), set(suspect), stack)
                    )
                aliases.clear()
                aliases.update(
                    {
                        name: contract
                        for name, contract in branch_states[0][0].items()
                        if all(state[0].get(name) == contract for state in branch_states[1:])
                    }
                )
                suspect.clear()
                for _, branch_suspect in branch_states:
                    suspect.update(branch_suspect)
                aliases, suspect = self._statements(statement.finalbody, aliases, suspect, stack)
                continue
            if isinstance(statement, (ast.Return, ast.Raise)):
                value = statement.value if isinstance(statement, ast.Return) else statement.exc
                if value is not None:
                    self._expression(value, aliases, suspect, stack)
                if isinstance(statement, ast.Raise) and statement.cause is not None:
                    self._expression(statement.cause, aliases, suspect, stack)
                continue
            if isinstance(statement, (ast.Global, ast.Nonlocal, ast.Pass, ast.Break, ast.Continue)):
                continue
            for child in ast.iter_child_nodes(statement):
                if isinstance(child, ast.expr):
                    self._expression(child, aliases, suspect, stack)
                elif isinstance(child, ast.stmt):
                    aliases, suspect = self._statements([child], aliases, suspect, stack)
        return aliases, suspect

    def _helper_environment(
        self,
        helper: ast.FunctionDef | ast.AsyncFunctionDef,
        call: ast.Call,
        closure_aliases: dict[str, str],
        closure_suspect: set[str],
    ) -> tuple[dict[str, str], set[str]]:
        local_names = _local_names(helper)
        aliases = {
            name: value for name, value in closure_aliases.items() if name not in local_names
        }
        suspect = {name for name in closure_suspect if name not in local_names}
        positional = list(call.args)
        named = {item.arg: item.value for item in call.keywords if item.arg is not None}
        positional_args = [*helper.args.posonlyargs, *helper.args.args]
        for index, argument in enumerate(positional_args):
            expression = positional[index] if index < len(positional) else named.get(argument.arg)
            if expression is None:
                continue
            alias = self._alias_value(expression, closure_aliases)
            is_suspect = self._mentions_name(expression, closure_suspect | set(closure_aliases))
            if alias is not None:
                aliases[argument.arg] = alias
            elif is_suspect:
                suspect.add(argument.arg)
        for argument in helper.args.kwonlyargs:
            expression = named.get(argument.arg)
            if expression is None:
                continue
            alias = self._alias_value(expression, closure_aliases)
            if alias is not None:
                aliases[argument.arg] = alias
            elif self._mentions_name(expression, closure_suspect | set(closure_aliases)):
                suspect.add(argument.arg)
        return aliases, suspect

    @staticmethod
    def _alias_value(expression: ast.expr | None, aliases: dict[str, str]) -> str | None:
        return aliases.get(expression.id) if isinstance(expression, ast.Name) else None

    @staticmethod
    def _mentions_name(expression: ast.expr, names: set[str]) -> bool:
        return any(isinstance(node, ast.Name) and node.id in names for node in ast.walk(expression))

    @classmethod
    def _literal_alias_values(
        cls,
        expression: ast.expr,
        aliases: dict[str, str],
    ) -> list[list[str]] | None:
        if isinstance(expression, (ast.Tuple, ast.List, ast.Set)):
            result: list[list[str]] = []
            for element in expression.elts:
                if not isinstance(element, ast.Name) or element.id not in aliases:
                    return None
                result.append([aliases[element.id]])
            return result
        return None

    @classmethod
    def _bind(
        cls,
        target: ast.expr,
        alias: str | None,
        rhs_suspect: bool,
        aliases: dict[str, str],
        suspect: set[str],
    ) -> None:
        if isinstance(target, ast.Name):
            was_suspect = target.id in suspect or target.id in aliases
            aliases.pop(target.id, None)
            suspect.discard(target.id)
            if alias is not None:
                aliases[target.id] = alias
            elif rhs_suspect or was_suspect:
                suspect.add(target.id)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                cls._bind(item, None, rhs_suspect, aliases, suspect)


def _arguments(function: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[ast.arg, ...]:
    return (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs)


def _local_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    class Locals(ast.NodeVisitor):
        def __init__(self) -> None:
            self.names = {argument.arg for argument in _arguments(function)}

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node is function:
                self.names.add(node.name)
                for statement in node.body:
                    self.visit(statement)
            else:
                self.names.add(node.name)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            if node is function:
                self.names.add(node.name)
                for statement in node.body:
                    self.visit(statement)
            else:
                self.names.add(node.name)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.names.add(node.name)

        def visit_Import(self, node: ast.Import) -> None:
            self.names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            self.names.update(
                alias.asname or alias.name for alias in node.names if alias.name != "*"
            )

        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, ast.Store):
                self.names.add(node.id)

    visitor = Locals()
    visitor.visit(function)
    return visitor.names
