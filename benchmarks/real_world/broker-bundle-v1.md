# New-lineage immutable broker bundle prerequisite

Issue #272 adds a standalone, offline prerequisite for a future production
canary. It creates no launch authority, escrow, review, label, adjudication, or
canonical import, and it does not append to ledger-v7.

`broker_bundle_v1.py` copies an explicitly enumerated broker closure and the
exact runtime attestation, `SubmissionBindings` document, production checksum
profile, and launch profile. The builder validates only the existing supported
runtime-attestation, submission-binding, checksum-profile, and launch-profile
versions. Unknown versions and extra schema fields fail closed.

## Custody boundary

The output parent is a dedicated, owned mode-0700 new-lineage root. The first
builder creates a canonical `.broker-new-lineage-root-v1.json` marker under a
private `.broker-new-lineage-root-v1.lock`; later operations require that exact
lineage, root device/inode, path, and marker hash. Every ancestor is opened with
`O_NOFOLLOW`. Protected historical destination components (`production_v1`,
ledger-v7 aliases, escrow, reviews, and labels) are rejected.

A bundle directory is one atomic enclosing object: its manifest, copied bytes,
and `.bundle-receipt-v1.json` receipt are completed in staging and exposed by a
single no-replace rename. A failed rename exposes neither bundle nor receipt.
Verification holds the lineage lock, descriptor-walks the complete inventory,
retains every root/file descriptor, and revalidates descriptor and path
identities after the scan. Manifest, receipt, marker, control identities,
lineage, protocols, inventory, and all-false authority maps must agree exactly.

`prepare-freeze` writes the canonical freeze and consumes the `prepared` phase.
Each phase is a durable no-clobber receipt chained by hash and ordinal:
`prepared -> launch_claimed -> pre_escrow`. Replay, skipped order, concurrent
claims, malformed phase state, and orphan state all fail closed. These receipts
remain false-authority prerequisites; `pre_escrow` does not create escrow or
permit launch.

```console
python -m benchmarks.real_world.broker_bundle_v1 build-bundle \
  --runtime-attestation /private/new-lineage/runtime-attestation.json \
  --binding /private/new-lineage/binding.json \
  --production-profile /private/new-lineage/checksums-v1.json \
  --launch-profile /private/new-lineage/launch-profile.json \
  --source runner.py=/absolute/broker.py \
  --lineage-id production-v8 --output /private/new-lineage/broker-bundle
python -m benchmarks.real_world.broker_bundle_v1 prepare-freeze \
  --receipt /private/new-lineage/broker-bundle/.bundle-receipt-v1.json \
  --runtime-attestation /private/new-lineage/runtime-attestation.json \
  --binding /private/new-lineage/binding.json \
  --production-profile /private/new-lineage/checksums-v1.json \
  --launch-profile /private/new-lineage/launch-profile.json \
  --output /private/new-lineage/prepare-freeze.json
python -m benchmarks.real_world.broker_bundle_v1 verify-freeze \
  --freeze /private/new-lineage/prepare-freeze.json \
  --runtime-attestation /private/new-lineage/runtime-attestation.json \
  --binding /private/new-lineage/binding.json \
  --production-profile /private/new-lineage/checksums-v1.json \
  --launch-profile /private/new-lineage/launch-profile.json \
  --phase launch_claimed
```

## Residual governance gates

1. Independently review the actual complete broker closure and launch profile.
2. Define and approve a new campaign and separately versioned authority/ledger
   protocol; this tranche intentionally defines neither.
3. Prove immediately before authority work that terminal ledger-v7 and the
   checked-in historical production profile remain unchanged.
4. Require the eventual launcher to execute only the descriptor-verified bundle
   entrypoint and consume the phase chain.
5. Obtain independent governance approval before model launch or escrow.
