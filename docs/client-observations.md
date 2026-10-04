# Finite client observations

`fastapi_endpoint_detector.analyzer.client_observations` provides an opt-in,
source-only extraction primitive for literal JavaScript and TypeScript client
calls. It recognizes literal `fetch`, common `axios` methods/config objects, and
`WebSocket` construction. Dynamic templates, concatenation, computed methods,
and unsupported call shapes are omitted.

Each observation retains the source file, line, literal URL, and query string.
The route path excludes the query string. HTTP calls with no explicit method
are recorded as `GET`; WebSocket calls use `WEBSOCKET`.

`join_established_surfaces` performs exact method/path matching only against
surface identifiers supplied by the caller. `established_surfaces` projects
only established endpoints with secure native route provenance. The primitive
does not create endpoint candidates, infer server routes from client URLs,
expand dynamic base URLs, or fan out matches across languages.

Dockerfiles, environment-variable indirection, subprocess observations,
repository-level integration, and the audited non-Python case evaluation remain
outside this initial bounded extractor.
