# GH97 real-world evaluation protocol (r3)

Status: design/validator packet only. No real-world source has been acquired or analyzed. This packet fixes the scope and execution contract for a bounded, descriptive source-only pilot. The repair adds no user-permission gate; any future source acquisition or analyzer invocation remains subject to the source-completion order and bounds defined here.

## Objective and inference boundary

Evaluate the original GH97 acceptance criterion, “Controlled and real-world evaluation,” using an independently frozen physical-call inventory over a small, disjoint sample of public application diffs. The study reports finite descriptive counts for exact frozen contract scopes and exact versions. It does not estimate precision, recall, prevalence, population coverage, runtime behavior, causality, or production success. The existing controlled GH97 evidence remains separate.

The evaluator is the source-defined `fastapi-endpoint-detector audit-effect-contracts` CLI. It analyzes endpoint-reachable typed calls only. The independent inventory covers every physical call expression in selected files. Public JSON output schema v1 exposes line/column and source spelling, but no source byte offsets, source hash, or call AST hash. Therefore this protocol does not make exact observed-row or absence claims from that output: record `unsupported` with CLI status `unsupported` and preserve the output hash.

## Approved-source and artifact ledger

The starting code revision is approved `origin/main` commit `d4eec140bed84d3ff8cea8374f7f9e589b0e6def`. The guard and prior GH97 source-controlled records are context only; the protocol branch does not import or alter their artifacts. In particular, do not treat the abbreviation `342` as Motor or `358` as S3. Motor’s exact artifact is mapped below; typed S3 is mapped to its separate exact stub artifact and `typed-s3-effects` preset.

| Lane | Exact artifact and source evidence | Preset and frozen YAML | Boundary for this study |
|---|---|---|---|
| Redis | `redis==5.2.1`; wheel SHA-256 `ee7e1056b9aea0f04c6c2ed59452947f34c4940ee025f5dd83e6a6418b6989e4`; source `redis/commands/core.py`; matrix row in `benchmarks/results/effect-preset-matrix-v4/package-symbols.json` | `redis-v1`; `redis-py-effects@1.0.0/revision 1`; `src/fastapi_endpoint_detector/presets/effects_redis_v1.yaml` | Exact `BasicKeyCommands.get/set/delete`, `PubSubCommands.publish`; artifact version only, not declared range. |
| PyMongo | `pymongo==4.10.1`; wheel SHA-256 `cec237c305fcbeef75c0bcbe9d223d1e22a6e3ba1b53b2f0b79d3d29c742b45b`; `pymongo/synchronous/collection.py` | `mongodb-v1`; `pymongo-effects@1.0.0/revision 1`; `effects_mongodb_v1.yaml` | Exact `Collection.find_one/insert_one/update_one/delete_one`. |
| Motor | `motor==3.6.0`; wheel SHA-256 `9f07ed96f1754963d4386944e1b52d403a5350c687edc60da487d66f98dbf894`; `motor/core.py`, `motor/motor_asyncio.py` | No Motor-specific preset/resolved public method mapping in this matrix | Inventory source use; classify Motor public descriptor/delegation calls `unsupported` unless a frozen exact contract/resolver exists at selection freeze. Never transfer PyMongo matches to Motor. |
| Filesystem | CPython `3.11.16` source tar SHA-256 `6c0bd76ab0ec7d94ed400b1497f01ac6c7751c8822615ee0855a3eb2d893ea76`; `pathlib.py`, `_io` C sources | `filesystem-v1`; `stdlib-filesystem-effects@2.0.0/revision 2`; `effects_filesystem_v1.yaml` | Exact interpreter evidence required; path/open origin gaps stay incomplete. |
| HTTP | `requests==2.32.3`, wheel SHA-256 `70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6`; `httpx==0.28.1`, wheel SHA-256 `d909fcccc110f8c7faf814ca82a9a4d816bc5a6dbfea25d6591d6985b8ba59ad`; `aiohttp==3.11.11`, wheel SHA-256 `249cc6912405917344192b9f9ea5cd5b139d49e0d2f5c7f70bdfaf6b4dbf3a2e` | `http-clients-v1`; `python-http-client-effects@2.0.0/revision 2`; `effects_http_clients_v1.yaml` | Finite exact verbs only; URL from declared URL argument. Generic `.request(method, url)` remains unsupported. |
| Typed S3 | `mypy-boto3-s3==1.35.92`, wheel SHA-256 `ce302a635da78e1925d8ff4809184ba55618cd7e3707156bea405cde7fdcf67a`; `client.py`, `type_defs.py` | `object-storage-v1`; `typed-s3-effects@2.0.0/revision 2`; `effects_object_storage_v1.yaml` | Exact typed `S3Client.get_object/put_object/delete_object`; resource requires both `Bucket` and `Key`; put value requires `Body`. No generated boto3 inference. |
| Typed SQS publishing | `mypy-boto3-sqs==1.35.91`, wheel SHA-256 `346a87bc0a447bb4c005b04d3efa0008bfa0ddd498cadd97e0e53a58752f84e9`; `client.py`, `type_defs.py` | Approved PR #308 `e52d3f57f1848f61dc1700e03d39788ca7a02429` has source-controlled exact SQS declaration evidence. The approved d4e base also contains `src/fastapi_endpoint_detector/presets/effects_message_bus_v1.yaml` (Git blob `cedebc0e63d0a25d49d32304c8fde1157dd2e98c`, SHA-256 `7ce121f1c9225ecf29a54dfb0b450f4d58003547558dd75872b3f3ab124dea87`), the `message-bus-v1` typed SQS 1.35.91 preset. | Selectable exact lane: freeze this preset bytes/hash and the matching contract at the executed base, then assess only calls reachable through the actual app endpoint and matching the preset’s exact selector. PR #308 source approval is provenance, not an analyzer observation or a real-world result. Never substitute generated boto3 calls. |

Matrix authority is `docs/effect-preset-version-matrix.md` and `benchmarks/results/effect-preset-matrix-v4/{package-symbols.json,source-signature-observations.json,package-analyzer-cases.json,analyzer-source-snapshots.json}`. The matrix records the artifact hashes above and the source/signature evidence. Its historical `gh97-analyzer-source-snapshot-v1` identity is exactly: `benchmarks/providers/effect_preset_matrix.py` `18c4e70b78f841afd790b66e57994436161a93a2c77207a8a7abcd24991f6de9`; `src/fastapi_endpoint_detector/analyzer/effect_contract_auditor.py` `c6ecd7210e7c4fc054010c80e9df0961b1510fd9cb9599faa49a27e751258d57`; `analyzer/mypy_analyzer.py` `6f0d36417dc13c258a52da28d47d9a7c56b28662e55f55503dc42c26a4383fba`; `models/effect_contract.py` `392c7024633ea0d309447c1991f96d0f2293d52732371797538ca2f0637f92d8`; `models/endpoint.py` `d5a01763444a26da525f3320d7adab34df281407073b80a5b1a755c737c1ffa7`; and `strict_data.py` `ba4b87f249f2e54a5ce4b507a3cbd4871d00ee03f6ea2fc44ca5e1a60236ea81`. These are exact identities for the recorded controlled matrix, not the live `d4e` CLI implementation. At `d4e`, the CLI, auditor, effect-contract model, Mypy analyzer, endpoint model, and strict-data hashes are recorded in the companion durable memo. The working packet must freeze the exact executed source path/hash set, CLI package version, resolved executable hash, environment identity, and every selected preset/config before prediction; do not synthesize a new analyzer source identity from the matrix.

### Approval-status corrections retained in the protocol record

- Guard evidence: approved PR #369, `d2beb4fa43db119d0b6eae94bee6b333ae27dfb5` (full supplied PR head identifier); it is guard/control evidence, not real-world call labels.
- SQS source evidence: approved PR #308, `e52d3f57f1848f61dc1700e03d39788ca7a02429`; the d4e base independently contains selectable preset `effects_message_bus_v1.yaml`, SHA-256 `7ce121f1c9225ecf29a54dfb0b450f4d58003547558dd75872b3f3ab124dea87`. Neither source approval nor preset presence is an analyzer observation or real-world result.
- Motor source evidence: approved PR #342, `11d2c0aeae2b6771c8a92086ac65453e8a763c67`; this is Motor-related current composition, not S3.
- Typed S3 source evidence: approved PR #358, `3207161b12935885d8c4bd55d1b17072eabd03bc`; typed-stub evidence only, not generated boto3/runtime evidence.
- HTTP R7 observations `bf8` remain unapproved and excluded. The approved module-mutation guard is the only guard evidence usable as a separate negative control; it must be resolved to its full source-controlled commit and artifact hashes in the review packet before execution. Never cite unapproved `bf8` as a positive or accepted criterion result.

Full identifiers and statuses above are provenance references, not a claim that those PR commits are ancestors of this branch. Resolve the guard head against the source-controlled approval record during R4; do not silently substitute a similarly prefixed commit.

## Frozen populations and no-overlap rule

Before selecting candidates or fetching source, an exclusion manifest must be generated from the actual committed files and hashed. It must expand, rather than merely list, every protected identity from:

- `benchmarks/real_world/verification_sets/fastapi-verification-v1.json` and `open-webui-26642-stress-v1.json`;
- all v1 expansion project, longlist, PR-lock and checksum artifacts;
- all v2 50x50 project, 2500 PR-lock, checksum and preregistered checksum artifacts;
- pilot v1/v2 source bindings, policies, reports and checksums, plus pilot v3 checksums;
- current frozen corpora, verification/stress artifacts, and committed non-Python evaluation source.

For every protected identity retain repository/project, PR, base and target commit/tree, path, blob ID when available, and source SHA-256. A candidate is excluded on project/repository collision or any PR, commit/tree, path/blob/source-byte overlap. Protected sources are not opened to create candidate labels. Freeze/hash this exclusion manifest and candidate-selection rules before source acquisition and before any prediction. Any later overlap is `excluded_overlap`; never replace that case after labels or predictions.

No candidate project or PR has been named or acquired in this design step. At shortlist freeze, issue the public GitHub issue-search metadata query `is:merged is:pr language:Python`, sorted by `created` ascending, request page 1 at 100 rows, and freeze the raw response plus request URL, retrieval timestamp, and SHA-256. Exclude protected project/repository collisions using the already frozen exclusion manifest. From the remaining metadata rows, sort by `(repository full name, PR number)` and take no more than 2 PRs per repository and 6 PRs across at most 3 repositories. This creates a metadata-only shortlist, not a claim of eligibility. After shortlist freeze, source packets may be acquired only for those selected rows under the limits below; exact lock/version applicability and source limits are checked then. An ineligible selected row is retained as `unavailable` or typed exclusion; never backfill it. Do not expand the shortlist after any source, labels or analyzer output is seen. Fewer than six, including zero, is a valid result.

## Acquisition and packet limits

Only after the protocol source-completion prerequisites are fulfilled, perform bounded read-only public source acquisition:

- at most 3 repositories, 6 PRs total, and 2 PRs per repository;
- at most 20 changed/context text files and 2 MiB per PR; 12 MiB total;
- request timeout 30 seconds, at most 3 retries per request, total wall time 15 minutes;
- immutable base and target commits/trees; record parent-selection rule and diff URL;
- reject cross-host redirects; retain final URL, response status, content type, byte count and SHA-256;
- retain license evidence and only the minimal source context needed to review each call;
- failures, oversized packets, missing license/version/source, and unavailable commits remain typed ledger rows; no replacement cases.

Treat all bytes as inert data. No importing, executing, installing, building, project tests/hooks/tooling, external packages, network services, secrets, VM, generated corpus, model, broker, GitHub write action, or publication. No frozen manifest, labels, checksums or evaluation result is edited by this branch.

For each immutable case packet preserve repository/PR, base and target commit/tree, parent rule, diff identity, every included file path and blob ID/hash, byte lengths, source URL and response metadata, license evidence, packet SHA-256, and exclusion-manifest hash. Store an acquisition ledger even for failures. The source inventory file set is frozen before adjudication and prediction.

## Independent inventory, adjudication, and closed outcomes

Two reviewers independently enumerate every physical call expression in every frozen changed and context file, whether or not it appears relevant or is reachable from an endpoint. Review both base and target context; record changed-hunk state. Reviewers must not see CLI output. Each row binds packet hash, repo/PR/base/target IDs, exact path, start/end byte offsets, call AST hash, excerpt hash, callee syntax, import/rebinding evidence, receiver and origin evidence, positional and keyword bindings/spans, literal/dynamic status, enclosing function, and changed/context state. Record package or interpreter applicability evidence independently. A third reviewer adjudicates every disagreement. Hash both inventories and the adjudication packet before any CLI invocation.

Use only these inventory outcome values and CLI states. The inventory outcome and observation state are separate fields; the following closed table governs their combinations:

| Inventory outcome | Permitted CLI status | Additional requirement |
|---|---|---|
| `supported_match`, `supported_nonmatch` | None supported under public JSON schema v1 | The current report omits byte-level physical identity; exact support is unsupported. |
| `unsupported` | `unsupported` only | Completed invocation and authenticated output hash; row key null. |
| `incomplete`, `out_of_scope` | `not_run`, `unavailable` | No output mapping or row assertion. |
| `unobserved_by_cli` | Not accepted | Public output is endpoint-reachable and cannot prove physical inventory absence. |
| `not_run` | `not_run` only | Invocation, output hash and row key are null. |
| `unavailable` | `unavailable` only | Invocation ID, output hash and row key are null. |

`unsupported` requires non-empty invocation ID and output SHA-256 with a null row key. Unknown, missing, or contradictory states fail semantic validation. Exact support and absence are not inferred from line/column matching.

Use only these outcome values:

- `supported_match`: exact frozen contract and resolver plus all required receiver, argument, resource, and where applicable finite HTTP URL/method selectors are evidenced.
- `supported_nonmatch`: exact contract/resolver and applicability are supported, and adequate evidence shows the call fails a required selector.
- `unsupported`: relevant candidate call lacks an approved exact contract/resolver, including Motor public descriptors where unresolved, generic HTTP request, or generated boto3 operations.
- `incomplete`: potentially in scope but exact dependency/interpreter, import binding, receiver origin, required argument/resource part, or URL/method evidence is missing or dynamic.
- `out_of_scope`: physical call lies outside every frozen candidate contract universe.
- `unobserved_by_cli`: reserved legacy value; rejected for public CLI schema v1 because its endpoint-reachable collection cannot prove physical-inventory absence.
- `not_run`: eligible invocation was not performed or could not process its input; include a closed reason.
- `unavailable`: source, lock/version evidence, or immutable packet could not be acquired/verified.

The first six labels belong to the source inventory; CLI-observation status is separately `unsupported`, `not_run`, or `unavailable` for this public report version. Do not force one category into another. An incomplete or failed run never becomes an empty prediction set. No confusion matrix, precision/recall, provisional-atom score, pooled denominator, population estimate, or endpoint-truth substitution is allowed.

## CLI execution contract

After inventory and adjudication hashes are frozen, use the actual CLI at the frozen source revision and one preset per invocation:

```sh
fastapi-endpoint-detector audit-effect-contracts \
  --app /frozen/case/target/app \
  --preset http-clients-v1 \
  --format json \
  --no-cache
```

For a custom frozen contract file use `--contracts /frozen/contracts.yaml` instead of `--preset`; never pass both. `--app` is required. The command accepts a single preset and its JSON output is endpoint-reachable typed-call audit output. It does not expose `--secure-ast`, `--preset-set`, or a complete physical-call inventory. Do not invent `effects audit`, invoke `--secure-ast`, batch multiple presets into one invocation, or write a wrapper and call it the official CLI. Do not execute if the selected app entry would require unsafe prerequisites; record `not_run` and why.

For each case/preset invocation capture exact argv, resolved executable path/hash, CLI package version, frozen source revision and analyzer-source hashes, preset/config raw SHA-256 and IDs, packet SHA-256, environment identity, stdout/stderr hashes, exit status, and JSON output hash. Validate the JSON against the closed public report schema v1 and inspect only its authoritative `/occurrences` collection. Since report occurrences lack byte-level physical identity, record eligible inventory rows as `unsupported`/`unsupported`; do not create a mapping or infer absence.

## Required packet schema and reporting

`schemas/gh97-realworld-inventory-row-r3.schema.json` defines a closed JSON Schema for inventory row shape. `schemas/gh97-audit-effect-contracts-output-v1.schema.json` is generated from `EffectContractAudit` serialization fields, with nullable alternatives omitted to match the CLI's `model_dump(mode="json", exclude_none=True)`, and fixes the authoritative collection at `/occurrences`. The former caller-selected mapping schema is not valid evidence for public CLI rows. Before accepting/freezing a batch, validate both schemas, then run `python3 scripts/validate_gh97_inventory.py rows.json - output-dir sources-dir`; the mapping argument `-` means absent. The validator checks the report with the same `EffectContractAudit` model, enforces its cross-field invariants (including established inventory for a complete report, nested endpoint/limitation/resource identity validity, totals, and provenance hashes), and requires an exact exclude-none serializer round-trip. Authenticated JSON bytes are parsed with the product's strict decoder at all four inventory/mapping/output ingresses. Duplicate object members at every depth, non-finite constants and invalid byte encoding are rejected before model validation; an exact exclude-none serializer round-trip retains JSON scalar type distinctions. The schema includes the frozen CLI model's source-pin applicability state and optional package evidence hash. The output bytes must match each unsupported row's recorded hash. It also checks every referenced source file's exact byte length and SHA-256, hashes and parses exact output bytes, rejects non-v1/unexpected report shapes and any caller mapping, and permits only `unsupported` status for completed CLI reports. It does not fabricate offsets or claim a physical row mapping.

For each inventory source file, record its exact byte count and SHA-256. Every binding and resource-component evidence span records its own `source_path`, `source_sha256`, and `source_file_bytes`; validate `0 <= span_start < span_end <= source_file_bytes` for each span. Every binding span must use the call's exact source path/hash and lie within the physical call span. Same-file resource evidence must also lie within that span. A resource expression defined elsewhere may lie outside that call only when its exact source path and file SHA-256 are recorded; do not claim containment in another file. These checks validate bounds/references, not the truth of reviewer interpretation. `not_run` records carry no invocation/output/row key. Unresolved/incomplete inventory can validly have null bindings and no CLI run, and is not a negative result.

Publish one descriptive report per case and exact package/interpreter version: inventory totals by outcome/reason; CLI observations separately by status; disagreement and adjudication counts; negative-control results; incomplete/unsupported/out-of-scope/unobserved/not-run/unavailable counts; frozen paths, packet/exclusion/preset/analyzer/CLI hashes and exact command. If a supported-only descriptive fraction is presented, state its numerator and denominator explicitly and exclude every other outcome; do not name it precision, recall, accuracy, or coverage.

## Preserved review findings and unresolved objections

R1 was blocked because it invented an unavailable `effects audit --secure-ast --preset-set` CLI; treated analyzer omissions as negative predictions; underspecified complete v1/v2 identity exclusions; mixed SQLAlchemy into GH97; and misstated Motor/S3/SQS/HTTP evidence status. R2 correctly required the real CLI, full protected identity expansion, endpoint reachability limits, and closed outcome types, but its artifact shorthand swapped Motor and S3 and its SQS statement was stale. This r3 corrects those issues and omits SQLAlchemy entirely.

R4 required follow-up for a fresh decision: (1) this revision corrects the SQS base-tree claim and makes its exact lane selectable without converting source approval into an observation; (2) semantic validation is executable and required alongside the closed JSON Schema; (3) retain the full source pins for HTTP PR #374 (`5b084c8a61d04c7c12a756c4bd9baf671fff34b8`), guard PR #369 (`d2beb4fa43db119d0b6eae94bee6b333ae27dfb5`), and SQS PR #308 (`e52d3f57f1848f61dc1700e03d39788ca7a02429`) strictly as source/guard provenance. They are not real-world results. Before any later collection, freeze the complete exclusion ledger, metadata shortlist, exact CLI/environment/source hashes, and selected preset hashes under the preserved finite limits. This r5 packet itself performs no source collection or CLI audit.
