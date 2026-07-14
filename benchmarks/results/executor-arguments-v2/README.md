# Exact executor argument environments v2

Issue: [#106](https://github.com/shaggitza/test_ast_fastapi/issues/106)

This second phase extends the LOW-only, directly-awaited executor summaries from
v1 with finite callback argument environments. It retains the same exact wrapper
and callback requirements for:

- canonical `asyncio.threads.to_thread`;
- canonical `anyio.to_thread.run_sync`;
- canonical `starlette.concurrency.run_in_threadpool`.

Explicit positional and keyword payloads are normalized according to each
wrapper's real forwarding contract, then bound to one exact project callback.
AnyIO control keywords (`abandon_on_cancel`, `cancellable`, and `limiter`) are
never treated as callback arguments. Bound instance/class receivers and static
methods retain their descriptor semantics.

Binding fails closed for expanded actuals, callback variadic formals, duplicate
assignments, missing required arguments, excess arguments, positional values for
keyword-only formals, and keywords for positional-only formals. Unknown values
remain absent rather than being widened from annotations. Distinct finite
argument environments participate in traversal identity, so the same callback
can be analyzed for several source-proven receivers without method-name fanout.
The global depth and finite-edge caps still apply.

All callback and descendant references remain LOW. The execution boundary stays
visible as `executor_callback:<canonical-wrapper>` in call-stack evidence.
Cache schema v11 and execution-summary version 2 fingerprint the structured,
deterministically serialized forwarding contracts.

## Frozen Open WebUI experiment

The execution-free corpus runner was rerun for frozen Open WebUI #26911:

- parent: `0f8846b7fc8c210945366defbd1ed941b039a691`;
- merge: `f4a6ea9300f130dc2f755d82d935f18160b8f5d2`;
- root: `backend/open_webui`;
- analyzer time: 33.998 s;
- candidates: 0, unchanged.

The expected non-gain remains sound: runtime-selected vector backend identity is
not replaced by callback argument guessing, and no embedding-update false
positive was introduced.

## Deferred scope

Issue #106 remains open for creation-versus-consumption-correct async-generator
propagation and selected synchronous scheduling APIs with exact canonical
contracts.
