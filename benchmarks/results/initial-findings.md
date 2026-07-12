# Initial candidate findings

**Date:** 2026-07-12  
**Scope:** early smoke tests and repository verification, not the final benchmark score.

## Current FastAPI endpoint detector

Case: `fastapi-transitive-service` from `benchmarks/fixtures/cases.json`.

Execution used a temporary Git repository containing the `before` tree, then
applied `after` and passed the resulting Git diff to the CLI.

Expected:

- `POST /quotes` affected;
- `POST /orders` affected;
- `GET /health` unaffected.

Observed:

- all three endpoints were discovered;
- zero affected endpoints were reported;
- the changed `services.calculate_total` line was reported as orphan;
- runtime was approximately 4.2 seconds.

Result for this positive case: **TP=0, FN=2**. This confirms that the current
implementation is a baseline, not evidence that the problem is solved.

Case: `orphan-negative-control`.

Observed:

- no affected endpoint;
- changed `helpers.unused` line reported as orphan;
- runtime approximately 0.1 seconds.

The negative control behaved as expected.

## CoDD 3.37.0

Installed and executed from PyPI using `uvx --from codd-dev`.

Commands tested:

```bash
codd init fixture --language python --project-type web --dest . --no-suggest-lexicons
codd extract --path . --language python --source-dirs . --init
codd scan --path .
codd impact --path . --diff HEAD
```

Findings:

- `extract` discovered both Python modules only when `--source-dirs .` was
  provided;
- extraction generated useful architecture Markdown;
- `scan` produced zero graph nodes and zero graph edges in this fresh project;
- `impact` resolved the changed file to zero graph nodes and reported no impact;
- therefore it also produced **TP=0, FN=2** on the FastAPI positive case in the
  tested out-of-box workflow.

Interpretation:

CoDD's impact graph appears to depend on promoted artifacts/frontmatter and a
CoDD-managed coherence map. It is not an immediate replacement for semantic
`diff → runtime entrypoint` analysis on an arbitrary existing repository. It
may remain useful for requirements/design/test traceability after onboarding,
but its README claims must not be translated into endpoint-impact claims
without benchmark evidence.

## Sourcegraph Precise Impact Analysis

Repository verified:
<https://github.com/sourcegraph-community/precise-impact-analysis>

As observed on 2026-07-12:

- Apache-2.0 example repository;
- created 2026-03-10;
- three commits, zero stars and zero forks at verification time;
- requires precise SCIP indexes for old and new producer revisions;
- requires indexes for downstream consumer repositories;
- compares old/new SCIP definition identities and queries precise cross-repo
  usages for removed or changed symbols;
- outputs JSON;
- uses Sourcegraph's debug GraphQL/code-intel API, explicitly documented as
  having no backwards-compatibility guarantee.

This is a credible mechanism for changed public symbols and cross-repository
consumers, but it is an example over commercial infrastructure, not a mature
standalone OSS product. It does not classify FastAPI/Spring/NestJS entrypoints,
map tests, or attach contract analysis. A real score requires a Sourcegraph
instance, access token, and SCIP indexes for the benchmark repositories.

## JCCI repository verification

Repository: <https://github.com/baikaishuipp/jcci>

As observed on 2026-07-12:

- Apache-2.0;
- approximately 348 stars and 60 forks;
- latest listed release `0.2` from 2024-05-27;
- last repository push observed in 2024-12;
- parses Java with `javalang`, parses diffs with `unidiff`, and recursively
  traverses impacted classes/methods toward controllers;
- supports dependent projects according to its documentation.

JCCI is a relevant Java/Spring comparison but not a polyglot foundation. Its
parser strategy is syntactic and should be tested specifically against
 overloads, inheritance, interfaces, annotations, generated code, and modern
Java syntax before relying on it.

## Consequence for the decision

No tested OSS candidate currently justifies dropping this repository. Equally,
the current implementation's failure on the first transitive fixture argues
against expanding it into hand-built analyzers for every language.

The leading hypothesis remains **HYBRID**:

1. buy/adopt compiler/LSP-backed symbols and references (Sourcegraph/SCIP or an
   equivalent);
2. maintain a smaller framework-entrypoint classification and evidence-report
   layer;
3. integrate dedicated test-impact and contract products;
4. keep the current tool only as a FastAPI benchmark/prototype until measured
   results justify retention.
