# Finite client observations

`fastapi_endpoint_detector.analyzer.client_observations` provides an opt-in,
source-only recognizer for a deliberately small TypeScript, JavaScript, and
Svelte-script subset. It tokenizes comments and quoted strings away before
recognition, consumes balanced calls, and accepts only literal URL arguments
and complete supported call forms. It handles `fetch`, common `axios` methods,
the literal `{url, method}` axios config form, and `new WebSocket(...)`.

Dynamic templates, concatenations, receiver calls such as `client.fetch`,
unknown fetch options, malformed calls, and unsupported config fields produce
no exact observation. Svelte markup is masked; only script block contents are
scanned. Each result retains the exact source offsets, line, literal URL, and
query. Repeated identical calls remain separate observations.

Relative URLs have no origin and cannot be correlated. Absolute URLs retain a
normalized origin. A join requires the caller to provide an established server
surface ID, an explicit origin, and a `trusted=True` attestation; only exact
origin, method, and path matches are returned. Endpoint projection alone does
not imply trust or origin. No global URL fanout or inferred server candidate
is produced.

This module is an extraction primitive, not yet a repository-wide client
inventory. CLI/configuration and analyzer integration must preserve the same
origin and trust gates. `analyzer.deployment_observations` separately records
simple `.env` and Dockerfile route settings, exposed ports, exec-form startup
argv, and direct Python `subprocess` calls with literal argv. Only allowlisted
route environment keys retain their values; unknown keys are redacted. URL
values containing credentials, query strings, or fragments are also redacted.
Variable expansion, shell-form Docker commands, shell subprocess calls, and
dynamic argv are recorded as uncertain. These observations are evidence only:
they do not execute commands, resolve environment expansion, or create route
joins. The isolated runtime comparator remains separate, with its Docker,
environment, and subprocess policy contracts.

The current checked-in benchmark corpus has no nine-case source-grounded,
audited TypeScript/Svelte evaluation set. Evaluation is therefore pending; no
precision/recall result is claimed from the general PR corpus.
