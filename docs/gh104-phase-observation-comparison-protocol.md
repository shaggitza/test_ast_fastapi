# Lifecycle observation comparison protocol

compare_phase_observation(manifest, observation) compares the existing static phase manifest with
positive-only lifecycle observation rows. It joins the full callback identity, registration identity,
phase, source hashes, source coordinates, and execution conditions under one matching manifest digest.

FastAPI `lifespan` constructor registrations carry a separate optional `constructor_lifespan` record in
each manifest entry. It identifies the exact typed `FastAPI(...)` constructor span, installed FastAPI
source hash, and directly bound callback. Entries without this field retain their prior serialized
shape. A constructor entry is accepted only for the bundled `fastapi-lifespan-startup` or
`fastapi-lifespan-shutdown` contract; it does not masquerade as an ordinary method call site. The
runtime still matches the loaded app's actual lifespan callback to the manifest identity.

The constructor source hash comes from the bounded immutable source capture of the completed
provider build. The capture requires the installed module's retained graph state and verifies the
captured bytes against that state's source hash. A missing graph row, changed source, or capture
limit failure leaves constructor evidence unavailable. The capture identity also contributes to the
phase engine fingerprint, so changed imported framework source cannot reuse an earlier phase
identity.

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

The installed artifact comparator now consumes this API in its schema-v2 comparison output
(`secure-runtime-target-baseline-v2` for the four-artifact form). Input artifacts remain schema v1.
For each list/impact phase it emits exact callback and registration rows, execution conditions,
unavailability reasons, and counts derived from row statuses. An unobserved callback remains distinct
from an explicitly unavailable callback.

Artifact comparison retains the application-observation quarantine: every admitted phase observation
is compared as self_reported_nonpositive, including legacy positive-role claims. The original role is
reported as declared_observation_role; comparison observation_role remains nonpositive and
observed_count is zero. Producer quarantine, record validation and custody verification are unchanged.
Hosted controls retain the legacy-positive nonpromotion check and compare a signed two-callback
record with one unavailable callback and one unobserved callback. No isolated callback execution or
real-world paired measurement is established by this report shape.
