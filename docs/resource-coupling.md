# Report-only finite resource coupling

Resource coupling is an explicit, execution-free diagnostic layered on an exact
effect-contract audit. Version 1 builds a potential cross-request graph and
**never changes endpoint candidates, confidence, reasons, dependency chains,
call stacks, thresholds, or orphan accounting**.

Configure an effect source and a separate namespace-qualified coupling document:

```yaml
analysis:
  effect_preset: redis-v1
  resource_coupling: .resource-coupling.yaml
```

```yaml
schema_version: 1
mode: report_only
groups:
  - id: orders-cache
    resource_space: production-orders-redis-db0
    producer_contract_ids: [redis-delete, redis-set]
    consumer_contract_ids: [redis-get]
limits:
  max_endpoint_links_per_resource: 32
  max_edges: 1000
```

Group IDs and contract IDs must be sorted and unique. A group must contain only
`write`, `update`, `delete`, or `append` producers and `read` consumers on one
channel. Unknown contract IDs, mixed channels, unsupported directions, malformed
limits, and incomplete effect audits fail closed.

`resource_space` qualifies otherwise identical keys across databases, clusters,
tenants, buckets, or environments. Its plaintext is never emitted; reports use a
full domain-separated SHA-256. Source resource values are likewise represented
only by the full hashes from finite resource evidence. These unsalted hashes
preserve equality and are not secrecy for low-entropy values.

## Matching

An edge requires:

- exact contract matches at both physical calls;
- established endpoint inventory and complete endpoint call corpus;
- available exact or bounded-finite resource identities;
- the same operator-qualified group, channel, and concrete resource hash;
- distinct producer and consumer endpoints.

Singleton-to-singleton equality is `exact`. Any bounded finite overlap is
`finite_overlap`. Unavailable or disjoint resources never act as wildcards.
Self-edges are omitted. The graph is deterministic and non-recursive.

If a resource component exceeds `max_endpoint_links_per_resource`, that entire
component is omitted with `resource_fanout_limit_exceeded`. If the global edge
limit is exceeded, all edges are omitted with `global_edge_limit_exceeded`.
There is no order-dependent “first N” behavior.

## Current boundary

Graph edges mean only that exact endpoint-reachable declared calls may access the
same qualified finite identity. They do not establish changed-code-to-writer
causality, runtime execution or ordering, persistence, transaction commit,
downstream observation, or impact. Candidate-producing coupling remains disabled
until changed-callsite causality, target package applicability, composite
resources, consume semantics, receiver origins, and scale/precision gates exist.
