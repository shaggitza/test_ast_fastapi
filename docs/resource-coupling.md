# Report-only finite resource coupling

Resource coupling is an explicit, execution-free layer over an exact
effect-contract audit. Version 1 defaults to `report_only`, which builds a
potential cross-request graph and **never changes endpoint candidates,
confidence, reasons, dependency chains, call stacks, thresholds, or orphan
accounting**. A separately explicit `changed_callsite_candidates` mode may add
bounded LOW-only targets under the stricter gates below.

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

Group IDs and contract IDs must be sorted and unique. Closed operation matrices
allow `write`/`update`/`delete`/`append -> read` state edges or
`publish -> consume` message edges on one channel. State/message directions may
not be mixed in one group. Unknown contract IDs, mixed channels, unsupported
directions, malformed limits, and incomplete effect audits fail closed.

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

## LOW-only changed-callsite candidates

Use `schema_version: 2` and set `mode: changed_callsite_candidates` only for
user/internal contracts without
package applicability metadata. Preset contracts remain ineligible until target
package versions can be attested. A reader is added only when:

- its graph edge is otherwise exact and eligible;
- the producer endpoint was independently present in the pre-coupling candidate set;
- an added target-side diff line overlaps the exact producer call occurrence;
- the bounded global candidate limit is not exceeded.

New readers are LOW, carry dedicated `potential_cross_request` evidence, and
usually remain outside `affected_endpoints` at the default threshold. Existing
candidates keep their stronger confidence and primary evidence. Expansion uses
the frozen pre-coupling seed set, so it cannot recursively cascade. Removed
writers, changes elsewhere in a writer implementation, package-constrained
contracts, and dynamic resources add nothing. Candidate overflow aborts the
whole expansion rather than returning an order-dependent prefix.

## Current boundary

Graph edges mean only that exact endpoint-reachable declared calls may access the
same qualified finite identity. Even candidate mode establishes only that the
producer call syntax changed; it does not establish runtime execution or
ordering, persistence, transaction commit, downstream observation, or impact.
Receiver origins, composite resources, removed producers, package applicability
attestation, and scale/precision gates remain deferred.
