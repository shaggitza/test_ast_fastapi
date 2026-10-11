# Pre-readiness recovery protocol v1

This is a separately versioned protocol proposal and profile. Its grant is a
single-use, expiring authorization to allocate one fresh attempt for the same
campaign lane and reviewer after one of the enumerated pre-readiness failures.
It never claims that the failed attempt was prepared, and it grants no model or
native launch by itself.

The profile is not wired into `ground_truth_run_v1.py`. Production v1's checksum
manifests, event schema, ledger validator, and prepare behavior remain frozen.
Before this protocol can be operational, a reviewed dispatcher must validate the
published profile, authenticate complete runtime custody, validate the existing
ledger head and failure evidence, archive evidence with no-clobber semantics,
and append the grant through the official ledger. The ordinary prepare path
must validate the grant and rerun full custody checks before allocating a fresh
run ID. Recovery never reuses the failed attempt ID as the new run ID.

The next prepare version must preflight exact canonical caller paths and hashes
for campaign, source, cache, ledger, and packet against authenticated runtime
custody before creating a durable slot or attempt claim. This prevents a
byte-identical campaign at the wrong path from consuming an authorized lane.
Failures after a valid preflight and durable claim remain append-only operational
failures. Runtime receipt validation and existing resource limits remain in
force; this protocol does not trigger corpus regeneration at each validation
stage or change any resolver checks.

The grant validator requires complete lane, reviewer, source, packet, runtime,
profile, authorization, failure event, and custody bindings; exact failure
phase/reason pairing; phase-specific evidence cardinality; authoritative proof
of no prepare, claim, launch, result, submission, or reviewer interaction; dead
broker and verified socket/registry/slot cleanup; a one-grant-per-attempt rule;
and expiry no later than the prior authorization. B's cause remains unknown.

The grant writer in the Python module is an isolated append-only primitive for
synthetic fixtures. It is not yet the official production writer or CLI, does
not inspect the production ledger, and must not be used for a live recovery.
A later integration change must connect it to authenticated production custody
and the official ledger/prepare dispatcher without changing v1 acceptance.
