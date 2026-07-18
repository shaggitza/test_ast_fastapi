# Ground-truth production v1: offline foundation

This separately versioned profile freezes the issue-to-repository assignments and
offline scheduler genesis for reviews #149–#198. It does not reuse pilot custody
as production authority.

`assignments-v1.json` maps issue 149 to the first authenticated lock project,
issue 150 to the second, and so on through issue 198. The campaign builder calls
the existing expansion-v2 authenticated loader and accepts only one complete,
rank-ordered 50-PR repository slice. Each manifest contains exactly 100 planned
lane identities, with distinct lane-qualified reviewer names and versions.

The current authorization gates are deliberately false:

- `live_launch_authorized: false`;
- `source_packet_materialization_authorized: false`;
- `canonical_import_authorized: false`.

Source trees and packets remain pending. No model, network, packet, adjudication,
or database-import operation exists in this milestone. Runtime policy records the
expected `pi-subagents` 0.35.1 profile but does not attest or launch it.

## Commands

All output and manifest paths must be absolute. Campaign and ledger state files
are published no-clobber as mode 0400 canonical JSON.

```console
python -m benchmarks.real_world.ground_truth_campaign_v1 build-manifest \
  --issue 149 --repository fastapi/full-stack-fastapi-template \
  --output /private/campaign-149.json
python -m benchmarks.real_world.ground_truth_campaign_v1 validate-manifest \
  --manifest /private/campaign-149.json
python -m benchmarks.real_world.ground_truth_campaign_v1 init-ledger \
  --manifest /private/campaign-149.json --ledger-root /private/ledger-149
python -m benchmarks.real_world.ground_truth_campaign_v1 validate-ledger \
  --ledger-root /private/ledger-149
```

The caller creates the ledger root in advance as an owned, non-symlinked,
absolute mode-0700 directory. Initialization serializes with `flock`, binds the
campaign file hash/device/inode, publishes exactly 100 `planned` states, and
creates a deterministic hash-chain genesis. It stores no capability or secret.
There are intentionally no state-transition or launch commands yet.
