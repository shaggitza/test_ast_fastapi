# Effect presets v1

This artifact freezes the first independently versioned package-owned effect
contract tables. It is an infrastructure and controlled-fixture release, not a
claim of resource-coupling or real-world recall.

| Selector | Preset identity | Version | Initial exact families |
|---|---|---:|---|
| `redis-v1` | `redis-py-effects` | 1.0.0 | typed Redis get/set/delete/publish |
| `mongodb-v1` | `pymongo-effects` | 1.0.0 | synchronous Collection direct CRUD |
| `filesystem-v1` | `stdlib-filesystem-effects` | 1.0.0 | direct `Path` byte/text helpers |
| `http-clients-v1` | `python-http-client-effects` | 1.0.0 | explicit requests/httpx/aiohttp helpers |
| `object-storage-v1` | `typed-s3-effects` | 1.0.0 | `mypy-boto3-s3` typed client calls |

## Changelog

### 1.0.0

- added immutable named loading and per-contract semantic hashes;
- added exact class-qualified symbols, package support metadata, operation,
  channel, timing, and selector declarations;
- added CLI validation/audit selection and mutually exclusive config selection;
- added generic-name collision and package-content validation.

## Soundness boundaries

The exact symbol and invocation are the only match keys. Package ranges remain
`not_evaluated`; selectors remain declarations and do not establish resource
identity. A match remains `declared_reachable` and cannot create a candidate,
promote confidence, or establish changed-code causality or observation.

The tables deliberately omit generic HTTP dispatch, `open()`/handle calls,
Redis pipelines, Mongo cursors/transactions, dynamically typed boto3 clients,
and arbitrary `get`, `set`, `write`, `send`, or `publish` methods. Finite URL,
path, key, bucket, collection, and topic extraction belongs to the bounded
resource-evidence work before Issue #97 can close.
