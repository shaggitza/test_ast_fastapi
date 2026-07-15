# Exact framework callback summaries v1

Issue: [#104](https://github.com/shaggitza/test_ast_fastapi/issues/104)

This first phase adds execution-free, exact contracts for FastAPI/Starlette
startup, shutdown, HTTP middleware, background tasks, and dependency providers.

## Controlled fixtures

The frozen fixture matrix proves:

- decorator and imperative startup/shutdown registration;
- distinct lifecycle surface IDs and physical handlers;
- exact async HTTP middleware identity;
- duplicate middleware IDs retained conditionally;
- synchronous and asynchronous `BackgroundTasks` callbacks;
- finite background callback argument environments;
- generator callback rejection;
- exact Depends/Security boundary provenance;
- same-named user function and receiver negatives;
- LOW-only background descendants and cache round trips.

No framework method-name fallback or external implementation traversal is used.
The mypy cache schema is v13 and execution-summary semantics are version 4.

## Runtime comparison boundary

Trusted local fixtures can demonstrate that FastAPI executes dependency
providers before handlers and background callbacks after response construction.
That observation does not promote static confidence or establish behavior for
an arbitrary frozen upstream environment. A comparable isolated lifecycle
phase runner is deferred with lifespan pre/post-yield modeling.

## Deferred phase-sensitive scope

Lifespan async context managers, startup-added routes, class middleware,
arbitrary plugin callbacks, and isolated runtime phase comparison remain open in
#104. They are not approximated by traversing all FastAPI/Starlette/AnyIO code.
