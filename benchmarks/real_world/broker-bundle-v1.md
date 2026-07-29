# New-lineage immutable broker bundle prerequisite

Issue #272 adds a standalone, offline prerequisite for any future production
canary. `broker_bundle_v1.py` copies an explicitly enumerated Python broker
closure together with the exact runtime attestation, lane binding, production
checksum profile, and launch profile into one immutable directory. A sibling
receipt binds the bundle manifest, full file inventory, directory device/inode,
and all four control identities. `prepare-freeze` then freezes those same bytes;
`verify-freeze` must succeed at preparation, launch claim, and immediately before
escrow. Mutation of the bundle or any control file fails closed.

This is deliberately a **new campaign/lineage prerequisite**, not another event
in the historical production ledger. It does not extend ledger-v7, does not
create or authorize a launch, and cannot write escrow, reviews, labels,
adjudication, or canonical imports. Historical profile compatibility remains
an audit-only property of the old lineage. A future canary still requires an
independent governance review and a separately versioned authority protocol.
The checksummed `production_v1` profile is unchanged.

The output parent must be an owned non-symlinked mode-0700 directory and every
input is an owned single-link regular file. Outputs are canonical, no-clobber,
and false-authority-only. The launch profile uses protocol
`ground-truth-broker-launch-profile-v1` and binds provider/model/client/decoding,
the exact tool list, agent hash, and one included broker entrypoint hash.

```console
python -m benchmarks.real_world.broker_bundle_v1 build-bundle \
  --runtime-attestation /private/new-lineage/runtime-attestation.json \
  --binding /private/new-lineage/binding.json \
  --production-profile /private/new-lineage/checksums-v1.json \
  --launch-profile /private/new-lineage/launch-profile.json \
  --source broker_bundle_v1.py=/absolute/broker_bundle_v1.py \
  --lineage-id production-v8 --output /private/new-lineage/broker-bundle
python -m benchmarks.real_world.broker_bundle_v1 prepare-freeze \
  --receipt /private/new-lineage/broker-bundle.receipt.json \
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
  --phase pre_escrow
```

## Governance review gates

Before any new live campaign:

1. Independently review the complete enumerated broker closure and launch profile.
2. Require exact runtime/binding/production-profile/launch-profile equality.
3. Verify the same receipt and freeze at `prepared`, `launch_claimed`, and
   `pre_escrow`; any byte, mode, path, device, inode, or inventory drift aborts.
4. Run mutation, alias, no-clobber, and boundary-escape tests.
5. Define a new campaign identifier and separately versioned ledger/authority
   protocol; these receipts themselves grant no authority.
6. Prove the terminal historical ledger and checksummed production profile were
   neither modified nor extended.
7. Obtain independent governance approval before creating escrow or launching a
   model. This tranche intentionally creates neither.
