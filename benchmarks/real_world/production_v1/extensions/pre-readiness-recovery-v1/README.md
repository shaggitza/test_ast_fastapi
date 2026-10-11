# Pre-readiness recovery protocol v1

This separately versioned extension adds an append-only grant for one exact
rank-1 lane whose only official event is an enumerated pre-readiness
`operational_failed` event. The grant binds campaign path and bytes, source,
packet publication, runtime attestation, the frozen production profile, the
prior authorization and expiry, the failed event, and archived evidence. It
never claims that the failed attempt was prepared and grants no model or native
launch.

`ground_truth_pre_readiness_recovery_official_v1.py` is the staged public
adapter and CLI. `issue-grant` authenticates complete production custody through
the frozen v1 validators, verifies this extension checksum manifest, checks the
exact campaign path before writes, validates the official ledger head and failed
history, derives no-launch and cleanup evidence, archives the evidence with
atomic no-clobber publication, and appends a grant in the extension ledger.
The old v1 ledger and event chain remain unchanged.

The frozen v1 prepare command cannot consume this grant: it accepts only its
original campaign attempt identifier and cannot retry its immutable failed
history. The sibling `prepare-retry` dispatcher therefore uses a separately
versioned run journal and a fresh UUID while retaining the original campaign
attempt ID in the new binding. It reauthenticates custody and the exact canonical
caller path before creating the journal, slot claim, binding, or run ID. No live
grant issuance or retry is part of this source change.

The extension checksum manifest binds the official adapter, grant validator,
policy, grant and retry schemas, documentation, and frozen v1 checksum manifest.
It is a public integrity chain, not an external signature. The standalone
protocol tests use synthetic fixtures only.

`prepare-retry` is the versioned dispatcher. After authenticating the official
custody again and confirming the official ledger head still matches the grant's
failure census, it appends a one-shot consumption row, allocates a fresh UUID run
identifier, records the retry ordinal, creates a separate retry run directory,
prepares a binding for the original campaign attempt/reviewer, and reaches broker
startup only after the broker-bundle lease gate succeeds. The original failed campaign
event and attempt directory are left intact. A failed retry stays consumed and
is recorded as a terminal `retry_failed` transition; the grant cannot be replayed.
The retry journal has its own strict schema and hash chain. No model or native
review launch is performed by this prepare command.

Operational broker startup remains fail-closed pending the separately versioned
receipt-bound broker bundle. The CLI requires a broker lease receipt and calls
the sibling `ground_truth_broker_bundle_v1.acquire_launch_lease` seam with the
runtime attestation, exact binding digest, and frozen launch-profile digest.
Before allocating any retry run, the adapter also requires the sibling
`launch_with_escrow_lease` operation; it never calls frozen v1 `posix_spawn`
directly. The lease must enforce exact runtime/bundle/binding/profile equality,
and the sibling launcher must transfer ownership of an exclusive code/profile
freeze through official escrow finalization. A JSON receipt path or public hash
chain alone is not proof of that lease. Until the sibling implementation
provides and wires this persistent lifecycle, the production seam rejects
startup before consuming the grant. Tests replace both seam operations with
explicit synthetic functions and mocked broker primitives; they do not
establish operational launch eligibility or create a real run.

The frozen production-v1 terminal ledger remains unchanged. The retry run journal
is a separately versioned overlay; its UUID identifies only an allocated retry
run and is never presented as a previously launched or native-result run.
