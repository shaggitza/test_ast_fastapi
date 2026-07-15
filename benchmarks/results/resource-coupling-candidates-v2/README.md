# Changed-callsite resource coupling candidates v2

This phase adds an explicit candidate-producing mode above the immutable
report-only graph from v1.

## Candidate gate

`changed_callsite_candidates` uses only internal/user contracts without
unevaluated package metadata. A target reader is added only when:

- producer and consumer are already connected by a namespace-qualified finite edge;
- the producer endpoint is independently present in the pre-coupling candidate set;
- an added target-side diff line overlaps the exact producer call occurrence;
- producer and consumer endpoints differ;
- all graph and candidate limits pass atomically.

New readers are LOW and carry separate `potential_cross_request` evidence. The
normal dependency chain and call stack remain empty because this is not a
same-request call path. Existing candidates retain stronger confidence and their
primary reason. The frozen pre-coupling seed set prevents recursive propagation.

## Negative gates

Unrelated writer implementation changes, removed writers, disjoint/dynamic
resources, package-constrained contracts, mixed resource spaces/channels,
unsupported operation directions, and candidate overflow create no partial
fanout. Report-only mode remains candidate invariant.

## Validation

Controlled fixtures cover exact callsite addition, unrelated implementation
change, package-applicability rejection, report tampering, disjoint resources,
hot-resource atomic omission, and all output formats. The complete test corpus is
run one file per process to bound retained mypy heap rather than using one
monolithic pytest process.

## Deferred

Publish/consume, receiver origins, composite resources, package applicability
attestation, removed-writer baseline analysis, and the 10,000-occurrence
scale/precision gate remain open under Issue #98.
