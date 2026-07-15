# Finite resource evidence v1

This phase adds a versioned, content-addressed resource identity seam beneath
Issue #98. It does not yet create writer/reader coupling edges.

## Supported

- exact literal strings;
- bounded conditional literal sets and literal concatenation (maximum 8);
- positional and named keyword selectors;
- SHA-256 identities only—the source string is not emitted;
- deterministic audit, evidence, cache, and checkout-relocation behavior.

## Fail-closed cases

Dynamic values, overflowing sets, receiver origins, selector attribute paths,
star arguments, and unsupported expressions produce `unavailable` diagnostics.
They never fan out to other resources or endpoints. Unsalted hashes are stable
identities, not secrecy: they reveal equality and low-entropy values may be guessed.
Filesystem `Path` receivers,
Mongo collection receivers, and typed S3 composite bucket/key identities remain
unavailable until bounded receiver-origin and composite-resource phases land.

## Semantics

A finite identity decorates an already exact, endpoint-reachable contract call.
It does not establish changed-code causality, observation, persistence, or
cross-request impact, and cannot create or promote candidates. Cross-endpoint
writer/reader edges require a separate graph and evidence type in the next phase.
