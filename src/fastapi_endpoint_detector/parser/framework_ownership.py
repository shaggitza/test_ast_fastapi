"""Bounded source ownership rules for FastAPI and Starlette route callbacks."""

from __future__ import annotations

import ast

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
