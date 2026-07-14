# Exact executor summaries v1

Issue: [#106](https://github.com/shaggitza/test_ast_fastapi/issues/106)

This first phase adds LOW-only execution contracts for directly awaited calls to:

- canonical `asyncio.threads.to_thread`;
- canonical `anyio.to_thread.run_sync`;
- canonical `starlette.concurrency.run_in_threadpool`.

The callback must be one exact project function or one exact method on a finite,
source-proven receiver. Formal `func` binding is distinguished from AnyIO control
keywords. Dynamic callbacks, callable annotations, registries, reflection,
starred callback slots, conflicting MRO targets, coroutine functions, generator
functions, and async-generator functions add no execution edge.

Only a directly awaited wrapper call executes these async wrappers. Merely creating,
storing, returning, or discarding the coroutine does not execute the callback.
The callback edge and descendants remain LOW, while an independent standard path
continues to dominate. Call stacks retain `executor_callback:<canonical-wrapper>`
at the physical boundary. Cache schema v10 fingerprints the summary table/version.

## Frozen Open WebUI experiment

The execution-free corpus runner was rerun for frozen Open WebUI #26911:

- parent: `0f8846b7fc8c210945366defbd1ed941b039a691`;
- merge: `f4a6ea9300f130dc2f755d82d935f18160b8f5d2`;
- root: `backend/open_webui`;
- analyzer time: 32.396 s;
- candidates: 0, unchanged.

This is the expected safe non-gain. The executor boundary can identify
`AsyncVectorDBClient` callbacks, but `_sync` ultimately comes from the
runtime-configured `Vector.get_vector` factory whose receiver set exceeds the
finite eight-target cap. The analyzer does not partially fan out to Milvus.
No embedding-update false positive was introduced.

## Deferred scope

Issue #106 remains open. Later phases must model:

- exact argument environments across callback boundaries;
- selected synchronous scheduling APIs only with source-backed canonical identity;
- async-generator creation separately from proven consumption;
- iteration/anext/async-for provenance and frozen Khoj experiments.
