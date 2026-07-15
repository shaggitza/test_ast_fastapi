# Resource coupling publish/consume v3

This phase closes the message-direction matrix and adds a reproducible 10,000
occurrence scale gate.

## Semantics

Finite resource groups now accept exactly two closed matrices:

- `write|update|delete|append -> read`;
- `publish -> consume`.

Mixed state/message directions, mixed channels, unknown resources, self-edges,
and dynamic identities still fail closed. Candidate mode retains the existing
exact-added-producer, independently reachable seed, LOW-only, nonrecursive, and
package-applicability gates.

## Controlled integration fixture

Two established FastAPI endpoints publish and consume one exact finite topic in
a user-qualified message space. The graph emits exactly one
`publish -> consume` edge. An exact added publish callsite adds only the consumer
as LOW while leaving default-threshold affected endpoints unchanged. A
`write -> consume` group is rejected before graph construction.

## 10,000-occurrence scale gate

Run:

```bash
.venv/bin/python benchmarks/resource_coupling_scale.py \
  --occurrences 10000 \
  --output benchmarks/results/resource-coupling-publish-consume-v3/scale.json
```

The synthetic seam fixture contains four equal roles across separate state and
message namespaces: 2,500 writes, reads, publishes, and consumes. Each producer
has exactly one matching consumer, yielding 5,000 expected edges and zero
diagnostics. The benchmark validates every graph model, checks both closed
operation directions, rebuilds the graph, and requires the same graph hash.

Frozen local result: 10,000 occurrences, 5,000 edges, 0 diagnostics, deterministic
hash, approximately 84 MiB peak RSS, 0.31 seconds for the measured first build
(0.93 seconds for the full process including fixture construction and repeated
build). This synthetic scale gate measures deterministic graph mechanics; it
does not claim real-world package applicability, receiver identity, or semantic
precision.
