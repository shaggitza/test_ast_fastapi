# Sourcegraph Enterprise + SCIP evaluation

**Evidence snapshot:** 2026-10-05. This is the protocol and current evidence boundary, not a completed product benchmark. No Enterprise credentials or indexed benchmark repositories were available, so live API, quality, cross-repository, setup, and latency measurements are **not evaluable**. Offline fixtures verify the evaluator only; they are not product output.

## Existing plan check

The repository has general candidate findings in `benchmarks/results/initial-findings.md`, including an older description of Sourcegraph Precise Impact Analysis and its dependency on indexed producer/consumer revisions. No dedicated Sourcegraph Enterprise evaluation plan or equivalent normalized evidence harness was present in `docs/` or `benchmarks/` at the start of this work. This document adds the missing protocol rather than duplicating a plan.

## Evaluation matrix

| Criterion | Evidence required | Current result |
|---|---|---|
| Changed-symbol detection | Before/after SCIP symbol identities tied to changed producer revision and source range | Not evaluable; no instance/index |
| Reverse references | Complete reference set with repository, revision, path and line ranges | Not evaluable; no instance/index |
| Call-chain evidence | Ordered, source-located hops at one revision; separately inspect edge semantics | Not evaluable; no live evidence |
| Cross-repository consumers | References in separately indexed consumer repositories and explicit coverage list | Not evaluable; no producer/consumer indexes |
| Language coverage | Run the frozen corpus per language; record index generation success and symbol/reference recall | Product docs advertise language-specific SCIP indexers and code navigation; no corpus run |
| Setup effort | Staff time from clean environment through repeatable indexed state, with blockers | Not measured; requires Enterprise instance and deployment decision |
| Incremental latency | Repeated paired cold/warm runs, index/update duration and query duration, host/load recorded | Not measured; no index or API access |
| API stability | Exercise only documented supported operations and pin API/schema version; distinguish debug GraphQL | New versioned API is documented as work in progress, with compatibility/migration commitment; debug GraphQL has no compatibility guarantees |
| Security/data residency | Review chosen deployment, subprocess/indexer isolation, data flow, region, retention, access and contractual controls | See official claims and deployment caveats below; customer-specific review remains open |
| Indicative 3-year TCO | Vendor quote + compute/storage + setup + ongoing operator labor | No quote; calculator is parametric and does not assign a license price |

## Evidence protocol

The offline provider module builds transport-neutral request descriptions and validates normalized response fixtures. It performs no HTTP, invokes no Sourcegraph endpoint, and accepts no credentials. Evidence is separated into `changed_symbol`, `reverse_reference`, `call_chain`, and `cross_repo_consumer`; one type cannot stand in for another. A response must include a receipt and bind its claims to the requested repository, exact revision and path, line range, index fingerprint, tool fingerprint, and configuration fingerprint. Reference and call-chain hops carry their own repository/revision/path/ranges. Cross-repository evidence must name a distinct consumer repository. A call chain requires at least two ordered hops.

The caller must independently attest authentication, required repository indexes, full coverage and provenance. Missing any gate yields `not_evaluable` with explicit reasons. Empty results are never inferred from missing credentials or indexes. The `sourcegraph-evaluation-evidence/` artifact records this state. The frozen tests are synthetic parser controls labelled non-authoritative; they do not fabricate index receipts or predictions.

When credentials and indexes are available through an approved evaluation setup, collect an immutable manifest for every producer and consumer repository: canonical repository ID, tested revision, index ID/fingerprint, SCIP tool name/version/fingerprint, build/config fingerprint, index timestamp, indexed-language coverage, and query/result fingerprints. Do not include authorization headers, tokens, or secret values in logs or artifacts. Use only the current documented API reference for production integrations; avoid the debug GraphQL API for a durable adapter.

## Official product claims and constraints

Sourcegraph documents Precise Code Navigation as an Enterprise feature based on SCIP indexes uploaded per repository. Its docs state that navigation is used when available and search-based navigation is a fallback. This advertises definition/reference navigation, not a complete change-impact graph or call-chain guarantee. The indexer matrix currently marks several SCIP indexers generally available and lists cross-repository support by language; verify the actual corpus and versions before making a coverage claim. Auto-indexing is documented as Enterprise, beta, and dependent on configured executors. The official setup guide recommends CI indexing for complex/authenticated builds. [Precise Code Navigation](https://sourcegraph.com/docs/code-navigation/precise-code-navigation) · [Indexers and language matrix](https://sourcegraph.com/docs/code-navigation/writing-an-indexer) · [Auto-indexing](https://sourcegraph.com/docs/code-navigation/auto-indexing) · [SCIP upload CLI](https://sourcegraph.com/docs/cli/references/code-intel/upload)

The API docs describe a new versioned external API introduced in Sourcegraph 7.0, with operations exposed at `/api-reference`; it is a work in progress, and Sourcegraph states backwards compatibility and migration assistance for integrations built on it. The same docs explicitly say debug GraphQL has no compatibility guarantees. Confirm the exact deployed version and supported operation for reference extraction before implementation. [Sourcegraph API](https://sourcegraph.com/docs/api)

Indexer releases are language/tool-specific and can affect coverage or index correctness. For example, the official `scip-python` changelog documents fixes in v0.6.3 for decorator-related inheritance crashes and zero-document macOS indexes, and marks v0.6.2 as problematic on macOS. Pin and record the actual indexer release used per language; do not treat “SCIP supported” as version-independent. [Sourcegraph scip-python changelog](https://github.com/sourcegraph/scip-python/blob/scip/packages/pyright-scip/CHANGELOG.md)

For language coverage, Sourcegraph separately advertises search-based navigation for 40 languages. That is distinct from precise SCIP support and cannot be counted as precise-symbol coverage. The current indexer page provides language-specific feature columns, including cross-repository navigation; that is vendor-published capability, not this benchmark's measured recall. [Code Navigation](https://sourcegraph.com/docs/code-navigation)

Security choices differ by deployment. The security page says self-hosted instances do not send customer code to other servers, subject to its stated exceptions. Sourcegraph Cloud docs list regions and describe encryption, isolated customer infrastructure, limited employee access with approval/audit controls, and management access that is enabled by default but can be disabled by request. Validate region availability, access model, retention, support access, and contractual terms for the purchased configuration; marketing statements are not a customer security assessment. [Sourcegraph security](https://sourcegraph.com/security) · [Cloud deployment/security details](https://sourcegraph.com/docs/cloud) · [Enterprise security overview](https://sourcegraph.com/security/enterprise)

The Enterprise pricing docs do not publish a list price: they say pricing is primarily based on active user accounts and sometimes indexed lines of code, and direct buyers to contact Sourcegraph. Therefore any numeric TCO requires an actual quote. Use `three_year_tco` with explicit annual license, compute, storage, setup hours, labor rate, and annual operations hours; preserve these inputs beside the result and run low/base/high scenarios. The code only calculates arithmetic and does not guess a quote. [Enterprise subscription pricing model](https://sourcegraph.com/docs/admin/subscriptions) · [Enterprise plans](https://sourcegraph.com/docs/pricing/plans/enterprise)

## Operational gates before scoring

1. Provide a user-authorized Enterprise target and credentials using a secret manager or environment injection. No credential was provided to this task; no outbound Enterprise calls were made.
2. Provision/index the benchmark producer and downstream consumer repositories at frozen revisions. Confirm language coverage and complete index provenance.
3. Approve the build/indexer execution boundary. This environment has host `runc` only; trusted gVisor/Kata execution is unavailable. Do not run untrusted indexer/build code here until an approved isolation boundary exists.
4. Establish API/version pinning and ensure secrets are redacted at source; export only normalized, fingerprinted evidence.
5. Execute common benchmark cases against all candidates, adjudicate expected symbols/references/chains/consumers, and record per-case precision/recall plus paired incremental latency distributions.
6. Obtain a vendor quote and approved deployment/security assumptions to complete three-year TCO and residency review.

This work is one part of openGitHub20. It does not claim the common benchmark criteria have been met and does not close the evaluation.
