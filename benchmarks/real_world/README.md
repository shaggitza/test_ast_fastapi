# Real-world FastAPI PR benchmark

This benchmark tests whether an impact analyzer works on changes made by real
projects, rather than only on fixtures designed for the analyzer.

## Corpus

`repos.json` selects three popular but architecturally different FastAPI
applications. `collect_prs.py` records the latest 20 merged PRs from each
repository without filtering by size, author, or perceived relevance. This
produces 60 PRs and avoids cherry-picking easy examples.

The committed `corpus.json` freezes:

- repository and PR identity;
- base/head/merge commit identity;
- changed files and line counts;
- PR description and diff URL;
- ground-truth review state.

Third-party source and patches are fetched on demand and are not vendored.
Re-running the collector creates a new corpus; it must not silently replace the
frozen benchmark used in a published comparison.

## Execution-free route census

`build_route_census.py` inventories configured FastAPI routes in both the merge
snapshot and its resolved baseline parent. It always invokes `list
--secure-ast`; analyzed application code is never imported or executed, and
there is no runtime or VM fallback.

```bash
python benchmarks/real_world/build_route_census.py \
  --cache /tmp/current-corpus-cache \
  --app-root open-webui/open-webui=backend/open_webui \
  --app-root langflow-ai/langflow=src/backend/base/langflow \
  --app-root khoj-ai/khoj=src/khoj \
  --output /tmp/route-census.jsonl \
  --manifest /tmp/route-census-manifest.json
```

Pass the result to `evaluate.py --route-census` to partition primary FN after
HIGH/MEDIUM and LOW matching. The census is diagnostic only: it never changes
truth, predictions, confidence, TP/FP/FN, or candidate-ceiling metrics.

## Ground-truth protocol

Reviews may be committed incrementally. A review file is incomplete until it has one validated record for every corpus PR; partial files must never be passed off as a benchmark score.

An LLM opinion is not ground truth by itself. Each PR is reviewed independently
by two agents and adjudicated by a human or a third agent with access to both
reviews.

Reviewers must inspect the diff **and the base revision**, tracing changed
symbols in both directions. They must not see analyzer predictions.

Each review records:

```json
{
  "repository": "owner/repo",
  "pr": 123,
  "reviewer": {"kind": "agent|human", "name": "...", "version": "..."},
  "changed_symbols": ["module.symbol"],
  "affected_entrypoints": [
    {
      "id": "HTTP POST /api/items",
      "kind": "http|graphql|task|event|cli|cron|sdk|other",
      "confidence": "confirmed|probable|possible",
      "evidence": ["file.py:10 symbol_a -> file.py:30 handler"]
    }
  ],
  "affected_tests": ["tests/test_items.py::test_create"],
  "contract_changes": [],
  "cross_repository_consumers": [],
  "orphans": ["file.py:50-53"],
  "unknowns": ["dynamic registration cannot be resolved statically"],
  "notes": "..."
}
```

Rules:

1. `confirmed` requires a source-level path or direct entrypoint modification.
2. `probable` requires a dependency relation with unresolved dynamic behavior.
3. `possible` is reported separately and is not counted as positive ground
   truth until adjudication.
4. Missing evidence must be an `unknown`, never silently interpreted as no
   impact.
5. Docs-only and CI-only PRs remain in the corpus as negative controls.
6. Large or generated PRs may be marked `not_evaluable`, with a reason; they
   remain visible in coverage reporting.
7. Agent model, version, prompt hash, date, and token/tool constraints are
   recorded to make agent-assisted labeling auditable.

### Independence and leakage controls

- Review A and Review B run in separate contexts.
- Neither reviewer receives predictions from this project or a vendor.
- Repository popularity, PR title, and description may be used, but comments
  posted after merge are excluded from evidence.
- Adjudication sees both reviews and resolves disagreements entrypoint by
  entrypoint.
- Inter-reviewer agreement is reported before adjudication (exact-set Jaccard
  and per-entrypoint agreement).

## Running an analyzer

Every candidate emits the same prediction schema as the adjudicated labels,
plus runtime metadata:

```json
{
  "repository": "owner/repo",
  "pr": 123,
  "candidate": "name/version/config-hash",
  "affected_entrypoints": [{"id": "HTTP POST /api/items", "evidence": []}],
  "unresolved": [],
  "index_seconds": 0.0,
  "incremental_seconds": 0.0
}
```

Use `evaluate.py` to compare predictions. The product score is
`--scope fastapi`: finite HTTP method/path claims and explicit WebSocket routes
that the FastAPI adapter can emit. The default `--scope all` preserves the
broader cross-surface research score. Raw exact and normalized metrics are both
reported. Primary metrics are micro/macro recall, precision, F1, unresolved
rate, evaluable coverage, and latency. A candidate cannot improve its score by
omitting hard PRs. Versioned scope membership and source hashes live under
`scopes/`.

### Current candidate runner

`run_current.py` selects corpus PRs, fetches their immutable merge commits into
a bare cache, and writes one prediction per selected PR plus a reproduction
manifest. Repository-specific analyzer roots can be supplied without consulting
labels:

```bash
python benchmarks/real_world/run_current.py \
  --output /tmp/current.jsonl \
  --manifest /tmp/current-manifest.json \
  --app-root open-webui/open-webui=backend
```

By default the runner passes `--secure-ast`: endpoint discovery and dependency
analysis parse source without importing the upstream application. Running with
`--allow-upstream-execution` disables secure endpoint discovery and is an
explicit unsafe opt-in recorded in the manifest. Unsafe results are exploratory
only because imported code can access the host, network, and benchmark labels.
The secure mode is the official scoring path, with unsupported dynamic routing
reported through misses or unresolved evidence rather than hidden execution.

## Reproduction

```bash
python benchmarks/real_world/collect_prs.py
python benchmarks/real_world/evaluate.py \
  --scope fastapi \
  --ground-truth benchmarks/real_world/adjudicated.jsonl \
  --predictions path/to/predictions.jsonl
```

## Label status and limitations

The corpus has complete independent Review A and Review B files plus
`adjudicated.jsonl`. Two release-scale PRs remain `not_evaluable`; their empty
or partial endpoint lists must not be interpreted as negative labels.

Pre-adjudication agreement can be reproduced with:

```bash
python benchmarks/real_world/agreement.py \
  benchmarks/real_world/review-a.jsonl \
  benchmarks/real_world/review-b.jsonl
```

Agreement is intentionally computed from raw entrypoint IDs, before semantic
aliases are resolved during adjudication. This is conservative: spelling and
granularity differences count as disagreement even when both reviewers traced
the same behavior.
