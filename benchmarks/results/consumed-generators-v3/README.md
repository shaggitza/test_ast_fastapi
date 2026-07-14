# Consumed generator summaries v3

Issue: [#106](https://github.com/shaggitza/test_ast_fastapi/issues/106)

This third phase distinguishes generator creation from execution. Exact project
sync-generator and async-generator calls are captured as deferred values; merely
creating, assigning, returning, or passing one through unsupported code does not
trace its body.

A deferred body receives a LOW-only execution edge only at a proven consumer:

- protocol-matched `for` or `async for` over a direct call or exact local alias;
- exact built-in `next` or `anext` with a valid explicit positional call shape;
- synchronous `yield from`;
- exact Starlette `StreamingResponse` content, which accepts sync or async streams.

Simple local aliases are tracked separately from points-to objects. Reassignment,
unknown calls, member mutation, loops after iterable evaluation, `with`, and
`try` invalidate them. Branch joins retain only identical descriptors present in
every branch. Direct calls bind finite arguments and exact finite method
receivers into the generator body. Protocol mismatches, shadowed built-ins,
invalid consumer arity, expanded/variadic arguments, ambiguous receivers,
containers, globals, parameters, and unmodeled framework consumers fail closed.

Consumer edges and every descendant remain LOW. Call stacks identify
`consumed_generator` or `consumed_async_generator`; stronger independent paths
still dominate. Cache schema v12 and execution-summary version 3 fingerprint the
closed generator-consumer table.

## Frozen Khoj experiment

The execution-free corpus runner was rerun on the two frozen propagation
holdouts with root `src/khoj`, app `main:app`, and bootstrap `main:run`:

| PR | Analyzer time | Candidates | Identity change versus bootstrap v2 |
|---|---:|---:|---|
| Khoj #1212 | 12.937 s | 20 LOW | none |
| Khoj #1292 | 12.951 s | 1 LOW | none |

Khoj #1212 retains both chat surfaces. Its WebSocket handler consumes the exact
local async-generator alias with `async for`; its HTTP handler passes the same
alias to exact `starlette.responses.StreamingResponse`. Khoj #1292 retains only
`POST /api/content/convert`. No candidate was added or removed, and no generator
body is recovered by generic call tracing.

## Deferred scope

Other framework callback/lifecycle contracts remain in #104. Generator
expressions, arbitrary iterable containers, cross-function generator parameter
flow, globals, and dynamic consumer protocols remain intentionally unresolved.
