# Resource coupling report-only graph v1

This phase freezes deterministic namespace-qualified writer/reader graph
construction over exact finite effect occurrences.

## Guarantees

- explicit data-only resource spaces prevent bare-key joins across deployments;
- closed `write/update/delete/append -> read` operation matrix;
- exact or bounded-finite hash intersection only;
- unknown resources never fan out;
- self-edges omitted and duplicate edges canonicalized;
- hot components and global overflow omitted atomically with diagnostics;
- graph, groups, edges, configuration, and source bytes are content-addressed;
- no candidate, confidence, threshold, chain, stack, or orphan changes.

## Validation fixture

The controlled fixture has separate writer and reader FastAPI endpoints using an
identical literal resource. It produces one exact report-only edge. Disjoint or
dynamic resources produce zero edges. A two-reader hot component with a limit of
one produces zero partial edges and one deterministic fanout diagnostic. Forged
endpoint evidence fails report validation.

## Resource-bounded validation

The complete 45-file test corpus was run one file per pytest process. This
prevents independent mypy semantic graphs from accumulating in one long-lived
Python heap. The five coupling/effect files peaked between 50 MiB and 1.69 GiB
per process; all passed. `ChangeMapper` also releases its heavy typed snapshot
after materializing the immutable report while retaining endpoint results.
Docker tests remain explicitly skipped, and validation does not build images.

## Deferred gates

Candidate-producing coupling, publish/consume, receiver origins, composite
resource dimensions, package applicability attestation, changed-writer callsite
causality, removed writers, and the 10,000-occurrence scale/precision benchmark
remain required before Issue #98 can close.
