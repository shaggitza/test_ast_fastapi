# Lifecycle observation comparison protocol

compare_phase_observation(manifest, observation) compares the existing static phase manifest with
positive-only lifecycle observation rows. It joins the full callback identity, registration identity,
phase, source hashes, source coordinates, and execution conditions under one matching manifest digest.

The returned PhaseComparison contains one row per static occurrence. Its statuses distinguish
observed_positive, self_reported_observation, callback_unavailable, and not_observed_positive_only.
The observation role is preserved. A self-reported observation is not promoted to a positive
observation. An absent row does not establish that a callback is unreachable or never executed.

Unavailable worker rows identify a callback rather than a particular registration. Identical reasons
are coalesced and applied only to unobserved occurrences of that callback; an exact observed sibling
is preserved. Unknown callbacks, duplicate observed occurrences, mismatched identities or conditions,
and observations attached to failed execution are rejected.

Input model updates are revalidated, with exact identity scalar types, paired and ordered coordinates,
bounded text and conditions, and explicit row budgets. Static entries and input rows together are
limited to 10,000; expanded unavailable-reason links are independently limited to 10,000. Callback
indexing avoids scanning the entire manifest for every unavailable row.

This API performs a protocol comparison. It does not authenticate an observation producer, execute an
application, establish sandbox isolation, or make canonical truth claims. GH104's isolated runtime
comparison gate and the GH100/GH101 isolation gates remain open.

Authoring validation used Ruff check/format and AST equivalence, strict type checking of 67 composed
production sources with cache disabled, independent exact-blob review, and 40 controls against the
actual production models/comparator with manually supplied data. No app, worker, or physical runtime
fixture was executed. Hosted unit regressions cover identity and digest matching, role separation,
callback-level unavailability, copied-model negatives, duplicates, failed executions, and bounds.
