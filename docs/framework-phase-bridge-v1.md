# Framework phase bridge v1

`fastapi_endpoint_detector.analyzer.framework_phase_bridge` is the typed
handoff point from mypy or a precise SCIP identity provider to framework
semantics. A record binds the source callback identity to a separate physical
registration occurrence, exact resolved framework symbol, selected versioned
surface contract, phase, callback range, reachability, and source/inventory/
engine/configuration hashes. Spelling and annotations cannot satisfy these
proof gates. SCIP records require an explicit capability statement.

Startup uses the pre-yield range; shutdown uses the post-yield range. A
conditional execution condition downgrades evidence to conditional. Callers
must mark surfaces installed by startup as lifecycle-conditional in their
surface evidence. The bridge does not analyze external framework bodies,
resolve uncertain aliases, or widen to arbitrary external call graphs.

`framework_phase_comparison` accepts already validated observations only. It
requires equal phase and snapshot, inventory, engine, and configuration hashes,
and preserves registration multiplicity. Missing isolated runtime evidence is
reported as unavailable. Runtime evidence is observation only and cannot
change secure classifications. This module does not execute applications or
create runtime attestations.

The bridge is intentionally not wired into the CLI/report/mapper yet. Parent
integration must adapt the existing typed callsite and report APIs and pass
their exact provenance; this PR does not claim the full GH104 integration.

## Synthetic phase comparison fixture protocol

The unit fixtures use synthetic identities with `validated=true` solely to
exercise comparator behavior. They are not secure or runtime attestations and
must not be included in corpus acceptance or benchmark denominators. An actual
phase comparison requires a trusted isolated runtime observation and its
validated provenance. GH101's freezer/canary authority is absent, so real
third-party apps and containers remain out of scope.
