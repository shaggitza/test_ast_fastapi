# Framework class middleware v3

This phase adds execution-free class-based HTTP middleware surfaces for Issue
#104.

## Frozen behavior

The schema-v4 `framework-v1` preset recognizes exact
`FastAPI.add_middleware(...)` and `Starlette.add_middleware(...)` registrations
only when the positional class is a unique project-local class with:

- the sole exact base `starlette.middleware.base.BaseHTTPMiddleware`;
- one directly declared async `dispatch` method;
- no class decorators, explicit metaclass, dynamic class-scope calls/imports,
  nested classes, factory construction, instance indirection, or rebinding.

The physical `dispatch` source range becomes
`FRAMEWORK.MIDDLEWARE protocol:http` with framework execution evidence. Imported
project-local aliases are followed exactly. Multiple physical middleware
handlers remain conditional instead of being collapsed. Generic ASGI
`__call__`, inherited-only dispatch, dynamic or additional bases, ordering, and
all-route fanout remain unresolved.

## Safety

The implementation parses source only. It does not import FastAPI, Starlette, or
the analyzed application and does not traverse framework implementation graphs.
Method spelling alone cannot match: registration receiver, local class identity,
base identity, method declaration, callback mode, and contract hashes must all
agree.

## Validation

Controlled FastAPI and Starlette fixtures cover direct and imported local
classes, wrong bases, rebinding, duplicate identities, and schema-version
rejection. The integration fixture proves a changed `dispatch` body maps only to
the explicit middleware surface and has no Starlette implementation frame.
Tests run through the resource-bounded per-file runner.

## Deferred

Startup-added serving surfaces, generic ASGI middleware, middleware ordering,
exception paths, and isolated runtime phase comparison remain open under Issue
#104.
