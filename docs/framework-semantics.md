# Framework callback semantics

Framework contracts model callback execution explicitly instead of recursively
using FastAPI, Starlette, or AnyIO implementation internals as application
reachability evidence.

## Phase 1

Select execution-free lifecycle and middleware surfaces with:

```yaml
analysis:
  surface_preset: framework-v1
```

The versioned preset recognizes only exact source-proven receivers and handlers:

- `FastAPI.on_event` and `FastAPI.add_event_handler`;
- `Starlette.on_event` and `Starlette.add_event_handler`;
- `FastAPI.middleware("http")`.

Startup and shutdown registrations have distinct `event:startup` and
`event:shutdown` IDs. Middleware registrations retain every physical handler;
multiple handlers for the same protocol remain conditional rather than being
collapsed. Same-named methods on other receiver types never match.

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

FastAPI/Starlette lifespan context managers require phase-sensitive ranges:
statements before `yield` execute at startup and statements after `yield` execute
at shutdown. They remain deferred until the analyzer can preserve those ranges
through both direct changes and transitive mypy traversal. Startup-time route
mutation, class-based middleware, arbitrary callback registries, and runtime
plugin loading also remain unresolved.

The static framework preset is optional because custom-surface configuration
currently has one provenance root. Composing several package presets without
losing per-contract raw provenance is deferred rather than silently merging
hashes.

Runtime import is not ground truth. Phase comparison against trusted fixtures
must run in the isolated runtime comparator; untrusted upstream applications are
never imported directly on the host.
