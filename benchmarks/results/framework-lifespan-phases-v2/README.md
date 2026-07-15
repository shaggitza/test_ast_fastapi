# Framework lifespan phases v2

This phase adds execution-free, phase-sensitive FastAPI lifespan surfaces.

## Frozen controlled behavior

For an exact `FastAPI(lifespan=lifespan)` registration where `lifespan` is a
project-local async generator with one unconditional top-level `yield`:

- pre-yield statements and their typed descendants reach only
  `FRAMEWORK.LIFECYCLE lifespan:startup`;
- post-yield statements and their typed descendants reach only
  `FRAMEWORK.LIFECYCLE lifespan:shutdown`;
- the yield boundary is preserved in handler-range evidence;
- conditional, nested, missing, and multiple yields produce no phase surface and
  retain an inventory limitation.

The implementation never imports application code and does not recurse through
FastAPI or contextlib internals. It uses strict schema-v3 constructor contracts,
exact callback identity, immutable contract/source hashes, and snapshot-local
mypy traversal.

## Validation

The controlled integration fixture changes a transitive startup descendant and
asserts that shutdown is absent. Existing decorator lifecycle, middleware,
background-task, surface-schema, and extraction tests remain unchanged. Full
validation uses the resource-bounded per-file runner.

## Deferred

Starlette constructor lifespans, callback aliases/factories, exception-path
feasibility, startup-added route mutation, class middleware, and isolated
runtime phase comparison remain open under Issue #104.
