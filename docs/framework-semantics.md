# Framework callback semantics

Framework contracts model callback execution explicitly instead of recursively
using FastAPI, Starlette, or AnyIO implementation internals as application
reachability evidence.

## Lifecycle and callback phases

Select execution-free lifecycle and middleware surfaces with:

```yaml
analysis:
  surface_preset: framework-v1
```

The versioned preset recognizes only exact source-proven receivers and handlers:

- `FastAPI.on_event` and `FastAPI.add_event_handler`;
- `Starlette.on_event` and `Starlette.add_event_handler`;
- `FastAPI.middleware("http")`;
- `FastAPI.add_middleware(LocalBaseHTTPMiddlewareSubclass)`;
- `Starlette.add_middleware(LocalBaseHTTPMiddlewareSubclass)`.

Startup and shutdown registrations have distinct `event:startup` and
`event:shutdown` IDs. Exact `FastAPI(lifespan=...)` async-generator callbacks
also produce distinct `lifespan:startup` and `lifespan:shutdown` surfaces. A
single unconditional top-level `yield` is required. The analyzer traces only
statements before that yield for startup and only statements after it for
shutdown, including transitive typed calls. Conditional, nested, absent, or
multiple yields fail closed with inventory limitations.

Startup lifecycle callbacks may also expose direct finite serving surfaces.
The schema-v5 preset recognizes exact `FastAPI`/`Starlette` receivers calling
`add_api_route`, `add_route`, `add_api_websocket_route`, or
`add_websocket_route` with one literal path, finite literal methods, and one
exact project-local handler. Lifespan activation is restricted to the
pre-yield range. Every activated route remains conditional on successful
startup lifecycle execution and cannot establish exhaustive route inventory.
Each route retains separate activation evidence for the lifecycle contract,
registration occurrence, route-call occurrence, phase, and provenance hashes.
Dynamic paths, unresolved handlers or receivers, receiver escape/rebinding,
control-flow registrations, router inclusion, mounts, factories, stars, and
unsupported methods fail closed with source limitations.

Middleware registrations retain every physical handler; multiple handlers for
the same protocol remain conditional rather than being collapsed. Class-based
HTTP middleware requires one exact project-local class, the exact
`starlette.middleware.base.BaseHTTPMiddleware` base, and a directly declared
async `dispatch` method. Class factories, instances, decorators, rebinding,
explicit metaclasses, dynamic class-scope calls/imports/nested classes,
inherited-only dispatch methods, additional/dynamic bases, and generic
`__call__` spelling fail closed. Same-named methods on other receiver types
never match.

Mypy execution summaries also model:

- exact `BackgroundTasks.add_task` callbacks after an endpoint response;
- exact `Depends` and `Security` provider execution.

Background task callbacks may be synchronous or asynchronous. Generator and
async-generator callbacks are rejected because invoking them only creates a
deferred iterator. Explicit finite callback arguments and exact bound receivers
cross the boundary, and the callback plus all descendants remain LOW. Call
stacks preserve `background_task_callback:<canonical-symbol>`.

Dependency providers keep standard confidence and preserve an explicit
`fastapi_dependency:<canonical-symbol>` boundary. Spelling alone is never
sufficient: user-defined `Depends`, `Security`, or `add_task` functions receive
no framework summary.

## Current limits

Starlette constructor lifespan callbacks, imported callback factories, aliases,
context-manager class implementations, and exception paths around `yield` remain
unresolved. Startup helper-mediated route mutation, router inclusion, mounts,
generic ASGI middleware, middleware ordering, arbitrary callback registries,
and runtime plugin loading also remain unresolved.

The static framework preset is optional because custom-surface configuration
currently has one provenance root. Composing several package presets without
losing per-contract raw provenance is deferred rather than silently merging
hashes.

Runtime import is not ground truth. Phase comparison against trusted fixtures
must run in the isolated runtime comparator; untrusted upstream applications are
never imported directly on the host.
