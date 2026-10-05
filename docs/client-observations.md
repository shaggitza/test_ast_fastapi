# Finite client observations

`fastapi_endpoint_detector.analyzer.client_observations` provides an opt-in,
source-only recognizer for a deliberately small TypeScript, JavaScript, and
Svelte-script subset. It tokenizes comments and quoted strings away before
recognition, consumes balanced calls, and accepts only literal URL arguments
and complete supported call forms. It handles `fetch`, common `axios` methods,
the literal `{url, method}` axios config form, and `new WebSocket(...)`.

Dynamic templates, concatenations, receiver calls such as `client.fetch`,
unknown request options, malformed calls, and unsupported config fields produce
no exact observation. Recognized calls with dynamic URLs or unsupported options
are kept in a separate uncertainty list with source spans and cannot be joined.
Svelte markup is masked; only script block contents are scanned. Each exact
result retains the exact source offsets, line, literal URL, and query. Repeated
identical calls remain separate observations.

Relative URLs have no origin and cannot be correlated. Absolute URLs retain a
normalized origin. A join requires the caller to provide an established server
surface ID, an explicit origin, and a `trusted=True` attestation; only exact
origin, method, and path matches are returned. Endpoint projection alone does
not imply trust or origin. No global URL fanout or inferred server candidate
is produced.

`analyzer.project_observations` applies client and deployment glob selection,
file-count and per-file byte budgets, records skipped-file issues, and emits
source evidence only. CLI/configuration wiring is being integrated in PR #310.
`analyzer.deployment_observations` separately records
simple `.env` and Dockerfile route settings, exposed ports, exec-form startup
argv, and direct Python `subprocess` calls with literal argv. Only allowlisted
route environment keys retain their values; unknown keys are redacted. URL
values containing credentials, query strings, or fragments are also redacted.
Variable expansion, shell-form Docker commands, shell subprocess calls, and
dynamic argv are recorded as uncertain. These observations are evidence only:
they do not execute commands, resolve environment expansion, or create route
joins. The isolated runtime comparator remains separate, with its Docker,
environment, and subprocess policy contracts.

## Exploratory source comparison

The source archive and evaluation atoms from PR #324 were checked against their
25 SHA-256/byte-count entries before scanning. That fixture contains six audited
PRs, eight client-route atoms, and one conditional deployment atom. Its stated
truth status is `reviewed_historical_atoms_provisional_not_canonical_truth`;
the available “nine” units are atoms across six PRs, not nine independent PR
cases.

The bounded project adapter scanned the selected TypeScript/Svelte and Docker
sources with no file-budget or read issues. It found one exact client call and
76 uncertain client calls. The exact call did not match any of the eight
provisional client-route atoms, and no origin-gated route join was possible
because the fixture supplies no explicit origin attestations. In the Langflow
case it found three exact Docker startup argv records and 33 uncertain
deployment records. Those static records do not establish the conditional
runtime-impact atom; no runtime behavior was executed or observed.

This is an exploratory extraction comparison against provisional reviewed
atoms, not canonical independent truth, and it does not support a precision or
recall claim.
