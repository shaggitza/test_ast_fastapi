# Filesystem receiver origins v2

This phase adds source-proven finite resource identity for exact filesystem
instance methods without changing impact candidates.

## Supported

- direct `pathlib.Path(<finite string>).read_*` / `write_*` receivers;
- one unconditional local `Path(...)` assignment before an exact Path method;
- one unconditional local `builtins.open(...)` assignment before an exact
  `_io` read method;
- an exact active `with open(...) as handle` binding before `_io` read/write;
- exact and at-most-eight finite literal/`Final`/conditional/concatenated
  strings, emitted only as SHA-256 equality identities;
- exact `_io._TextIOBase` and buffered read/write contract symbols.

## Fail-closed boundaries

Reassignment, prior or containing control flow, escaped context handles,
captured handles, nested/multiple contexts, receiver aliases, arbitrary
factories, dynamic origin arguments, Path composition, selector paths,
`*args`, and `**kwargs` remain unavailable. No source spelling, suffix,
method-name, or receiver-candidate fallback is used. Append-mode writes are not
classified as a distinct append operation.

Receiver origin is preserved separately on the resolved call and audit
occurrence. The contract remains matched only by exact `(canonical symbol,
invocation)`. Resource identity is diagnostic evidence and does not create or
promote endpoint candidates.

## Validation

Controlled mypy fixtures cover finite Path receivers, sync text handles,
reassignment, control flow, hashing/no-literal output, audit integrity, preset
hashes, and cache round trips. Integration coverage confirms the packaged
filesystem preset attaches exact identities while preserving candidate
semantics. Validation uses per-file isolated pytest processes.
