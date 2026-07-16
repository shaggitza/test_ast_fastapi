# HTTP method and finite URL evidence v2

`http-clients-v1` 2.0 freezes exact method tables for requests `Session`, httpx
`Client`/`AsyncClient`, and aiohttp `ClientSession` across `GET`, `POST`, `PUT`,
`PATCH`, `DELETE`, `HEAD`, and `OPTIONS`.

The verb is structured `http_method` contract metadata and is valid only for an
`outbound_http` `request` contract. The URL uses the existing bounded argument
selector and is emitted only as exact/finite SHA-256 equality evidence. Dynamic
URLs, generic `request`/`send`, redirects, response observation, query
normalization, client construction, package applicability, and runtime network
behavior are not inferred.

Matching remains exact `(canonical symbol, invocation)`. The table does not use
source spelling, method suffixes, receiver candidates, or bare names, and it
cannot create or promote endpoint candidates.

Validation freezes all 28 symbol/method pairs, preset provenance and semantic
hashes, invalid-channel model rejection, and unchanged evidence-only behavior.
External package applicability and real-world recall remain explicit Issue #97
gates rather than assumptions.
