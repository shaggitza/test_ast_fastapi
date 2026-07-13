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

Initial result for this positive case: **TP=0, FN=2**. Investigation showed
that this was not an inherent mypy limitation: decorated handler bodies were
not traversed, top-level imported module names did not match the internal
source-root module names, and call-stack report validation rejected `Path`
objects. After targeted fixes and explicit handling of FastAPI `Depends`
callables, the same case reports both expected endpoints: **TP=2, FN=0**.

This demonstrates why candidates need documented onboarding and tuning before
being scored, while also showing that the benchmark finds real implementation
defects.

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

A fair tuning pass then followed the documented model:

1. extract with `--source-dirs .`;
2. promote extracted documents under the configured CoDD directory;
3. change `scan.source_dirs` from the default `src/` to `.` for this flat fixture;
4. point `scan.doc_dirs` at the promoted design documents;
5. scan again before applying the change.

After tuning, CoDD produced 7 nodes and 7 edges. The changed `services.py` file
resolved to `file:services.py`, propagated at depth 1 to the services design,
and at depth 2 to the main design with confidence 0.90. It therefore correctly
detected module-level transitive impact after onboarding.

It still did not emit the normalized `POST /quotes` and `POST /orders`
entrypoint identities, so its endpoint-level benchmark result remains
**TP=0, FN=2** under our output contract. This is a product-scope mismatch, not
a claim that its graph is incorrect.

Interpretation:

CoDD is a credible coherence/design impact layer after extraction, document
promotion, and scan configuration. It is not an immediate replacement for
semantic `diff → runtime entrypoint` analysis on an arbitrary repository. It
may be useful for requirements/design/test traceability, but requires a
framework-entrypoint adapter before it can satisfy our PR report.

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

JCCI was then executed from PyPI against the controlled
`spring-overloaded-service` fixture using a local Git repository with before
and after commits. The fixture changes only
`PricingService.calculate(String,int)` while leaving the one-argument overload
unchanged.

Observed output:

- detected the exact changed overload;
- produced a graph edge to `PricingController.quote(String,int)`;
- classified that controller method as an API;
- emitted `[Post]/quotes` in `impacted_api_list`;
- did not report `GET /prices/{sku}`, which calls the unchanged overload;
- completed in approximately 6.3 seconds including clone, parse, SQLite graph
  construction, and output generation.

Normalized result: **TP=1, FP=0, FN=0**. For this Java/Spring case, JCCI does
exactly the core traversal we want and is currently the strongest directly
executed alternative.

Caveats observed during execution:

- it is Java-only and uses `javalang` rather than compiler-derived semantics;
- configuration defaults write project clones and SQLite state inside the
  installed package directory unless overridden;
- the library clones through a shell command assembled from the Git URL, which
  requires security review before processing untrusted input;
- its `.cci` JSON schema and endpoint notation require normalization;
- inheritance, interfaces, generated code, modern Java syntax and scale still
  need benchmark coverage.

JCCI is therefore a useful reference implementation or Java adapter candidate,
not a polyglot foundation.

## oasdiff 1.23.0

Downloaded the official Linux ARM64 release and ran `oasdiff breaking` against
the controlled `openapi-breaking-contract` fixture.

Observed JSON:

- rule: `response-required-property-removed`;
- operation: `GET`;
- path: `/users/{id}`;
- message: removed required response property `email` from status `200`;
- severity level: 3;
- exact source location in the baseline OpenAPI document;
- stable fingerprint.

Normalized result: **TP=1, FP=0, FN=0** for both affected entrypoint and
contract change. No tuning beyond selecting the correct architecture binary was
required.

This strongly supports integration rather than reimplementation for OpenAPI
contract compatibility. oasdiff does not trace internal code impact; its JSON
should be attached to the shared evidence graph and PR report.

## GraphQL Inspector

Executed `@graphql-inspector/cli` through `npx` against a baseline schema where
`User.email: String!` exists and a changed schema where the field is removed.

Observed:

- detected exactly one change;
- identified `User.email` removal;
- classified it as breaking;
- exited non-zero, suitable for a CI quality gate.

Normalized contract result: **TP=1, FP=0, FN=0**. Its human-readable output is
sufficient for Markdown, while machine integration should use its programmatic
API or structured output rather than parse terminal text.

## Buf Breaking 1.71.0

Executed the official Linux ARM64 binary against two local Protobuf modules. A
baseline `PricingService.Quote` RPC was removed in the changed module under the
`FILE` breaking policy.

Observed JSON:

- rule: `RPC_NO_DELETE`;
- exact changed file and source range;
- message identifying `PricingService.Quote`;
- non-zero exit suitable for CI.

Normalized contract result: **TP=1, FP=0, FN=0**. As with oasdiff and GraphQL
Inspector, Buf should be integrated as authoritative contract evidence, not
reimplemented in the impact analyzer.

Pact `can-i-deploy` is different: it answers deploy compatibility from verified
consumer/provider interactions stored in a Pact Broker. A meaningful POC
requires a broker and version/environment matrix; a local schema fixture would
not test its actual value.

## SCIP TypeScript blast-radius POC

Executed `@sourcegraph/scip-typescript` 0.4.0, the SCIP CLI 0.9.0, and
`scip-query` 0.16.0 against the NestJS provider fixture. The fair tuned run
used multiline TypeScript, a `tsconfig.json`, decorator declarations, a
baseline Git commit, and a working-tree service change.

For `PricingService.total`, the index contained exact references at the two
controller call sites. `diff-impact` reported:

- changed file `pricing.service.ts`;
- changed class and exact `PricingService.total()` method symbols;
- fan-in of one consumer file;
- affected consumer `pricing.controller.ts`;
- no impact on `health.controller.ts`.

`refs` returned the exact lines inside `quote()` and `order()`. SCIP itself did
not classify their `@Post` decorators or concatenate the controller prefix, and
`scip-query call-graph` did not emit caller methods for these references.

Scoring depends on product boundary:

- raw SCIP/scip-query endpoint output: **TP=0, FN=2**, because it stops at
  symbols/files rather than HTTP identities;
- SCIP evidence plus a small NestJS adapter mapping reference lines to enclosing
  methods/decorators: **TP=2, FP=0, FN=0**.

This is actual blast-radius evidence, not interface compatibility. It validates
the proposed HYBRID architecture: compiler-backed, language-agnostic
references underneath; framework-specific entrypoint classification above.
It also shows why SCIP alone is not a finished PR impact product.

## SCIP Python blast-radius POC

Executed `@sourcegraph/scip-python` 0.6.6, `scip-query` 0.16.0, and the SCIP CLI
0.9.0 against the FastAPI transitive fixture. Indexing took 2.00 seconds for
the baseline and 1.81 seconds for the changed tree. SCIP reported
`quote_service()` and `order()` at depth 1 and the dependency-injected
`quote()` handler at depth 2. A 0.05-second AST adapter mapped the affected
functions' decorators to `POST /quotes` and `POST /orders`, while leaving
`GET /health` unaffected: **TP=2, FP=0, FN=0**.

Raw SCIP still emits symbols rather than HTTP identities, so its endpoint score
without the adapter is **TP=0, FN=2**. The adapter must eventually resolve
routers, prefixes, constants, mounted applications, and custom decorators.
One important implementation warning emerged: `scip-python-plus` 0.7.5, which
`scip-query` selected by default, omitted `quote()` and `health()` from its
outline and lost the dependency-injected endpoint. The successful run used
Sourcegraph's `scip-python` indexer explicitly.

## SCIP Java blast-radius POC

Attempted `scip-java` v0.13.1 with SCIP CLI 0.9.0, Temurin 21.0.11, and Maven
3.9.11 against the Spring overload fixture. The compact raw fixture could not
compile because its annotation types were intentionally undeclared. Adding
package-local Spring annotation stubs allowed indexing in 7.18 seconds, but
`scip lint` rejected the resulting index because referenced JDK symbols lacked
external `SymbolInformation` entries. The run stopped at that validation
failure, so overload precision was **not established** and no Java SCIP score
is claimed. This remains an integration blocker to resolve with a normal Maven
Spring project before comparing SCIP Java with JCCI's successful result.

## Role of contract analyzers

The oasdiff, GraphQL Inspector and Buf results above are **not blast-radius
scores** and must never be presented as alternatives to the symbol/reference
engine. They answer a separate question—whether an externally visible contract
changed—and contribute supplemental evidence only after affected entrypoints
have been found through code impact analysis.

## Consequence for the decision

No tested OSS candidate currently justifies dropping this repository. The
current implementation required framework-specific corrections to pass the
first transitive fixture; that success supports keeping the FastAPI layer, but
also illustrates the maintenance cost of expanding hand-built semantics to
every language and framework.

The leading hypothesis remains **HYBRID**:

1. buy/adopt compiler/LSP-backed symbols and references (Sourcegraph/SCIP or an
   equivalent);
2. maintain a smaller framework-entrypoint classification and evidence-report
   layer;
3. integrate dedicated test-impact and contract products;
4. keep the current tool only as a FastAPI benchmark/prototype until measured
   results justify retention.
