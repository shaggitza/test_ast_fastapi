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

The versioned preset recognizes exact source-proven receivers and handlers:

- FastAPI and Starlette `on_event` / `add_event_handler` registrations;
- FastAPI constructor `on_startup`, `on_shutdown`, and `lifespan` callbacks;
- APIRouter constructor and event registrations copied by `include_router`;
- mounted child application routes (child application lifecycle is not treated as
  parent lifecycle);
- FastAPI and Starlette exception handlers, keyed by exception class or literal
  status code;
- FastAPI HTTP middleware decorators and `add_middleware` registrations for
  bounded local `BaseHTTPMiddleware` subclasses or project-local ASGI callables;
- singular `Response(background=BackgroundTask(...))` callbacks and plural
  `BackgroundTasks.add_task(...)` callbacks associated with selected routes.

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

Middleware registrations retain every physical handler; contract multiplicity
is explicit (`all_execute` for lifecycle, middleware, and background tasks;
`last_wins` per exception key). Class middleware lookup follows a bounded local
single-base chain and preserves the source span of the resolved dispatch or
ASGI `__call__` method. Class factories, instances, decorators, rebinding,
explicit metaclasses, dynamic class-scope effects, ambiguous or external MRO
links, and unsupported callback signatures fail closed with inventory
limitations. Same-named methods on unrelated receiver types never match.

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

Dynamic callback factories, context-manager class implementations, and
exception paths around a lifespan `yield` remain unresolved. Lifespan phase
splitting requires the exact `contextlib.asynccontextmanager` binding and one
unconditional top-level yield; replacement or additional decorators produce an
explicit limitation. Startup helper-mediated route mutation, mount lifecycle
composition, middleware ordering, arbitrary callback registries, and runtime
plugin loading also remain unresolved. Dynamic selected registrations and
unresolved include or mount targets produce inventory limitations.

The static framework preset is optional because custom-surface configuration
currently has one provenance root. Composing several package presets without
losing per-contract raw provenance is deferred rather than silently merging
hashes.

Runtime import is not ground truth. Phase comparison against trusted fixtures
must run in the isolated runtime comparator; untrusted upstream applications are
never imported directly on the host.
