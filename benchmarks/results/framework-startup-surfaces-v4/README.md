# Framework startup surfaces v4

This phase freezes schema-v5 conditional serving surfaces installed by exact
FastAPI/Starlette startup callbacks.

## Supported

- exact `FastAPI` and `Starlette` startup lifecycle registrations;
- `FastAPI(lifespan=...)` statements before the single top-level yield;
- direct `add_api_route`, `add_route`, `add_api_websocket_route`, and
  `add_websocket_route` calls;
- one literal path, finite literal HTTP methods, and one exact project-local
  top-level handler;
- exact global app receivers or the framework-provided lifespan app parameter.

Activated routes retain their HTTP/WebSocket identity and physical handler but
are always `conditional`. Separate immutable activation evidence binds the
lifecycle contract, registration occurrence, route-call occurrence, startup
phase, and provenance hashes. They do not promote lifecycle evidence,
prove successful startup, or establish exhaustive inventory.

## Fail-closed cases

Dynamic paths or methods, unresolved/rebound receivers, receiver escape,
control flow, nested handlers, stars, duplicate arguments, router inclusion,
mounts, helper-mediated registration, factories, and post-yield route mutation
do not produce serving surfaces. Source limitations remain visible.

## Validation

Controlled unit fixtures cover decorator startup, pre/post-yield separation,
receiver rebinding, dynamic/control-flow registrations, router inclusion, and
receiver escape. An end-to-end diff fixture confirms that a changed activated
handler maps to a LOW conditional HTTP candidate. Focused strict mypy, Ruff,
and isolated pytest validation pass.

External isolated runtime phase comparison remains required before Issue #104
can close. Runtime inventory is a comparator and never automatic truth.
