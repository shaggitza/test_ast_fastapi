# GH97 HTTP installed artifact source compatibility

`probe.py` verifies the raw SHA-256 of each of the three locally supplied
wheels before reading metadata, then extracts only bounded regular `.py`
members and gives those source trees to the product's `MypyAnalyzer`. It never
imports the HTTP packages, executes their code, or extracts native extensions.
The probe calls the actual analyzer and effect-contract auditor with the exact
`http-clients-v1` preset. It emits one observation per actual source call,
including resolver identity, receiver candidates, finite argument hashes,
resource selector status, and the auditor's contract decision. Counts are
calculated from these observations; controlled historical/synthetic records
are not inputs.

Run under Python 3.11.16 and mypy 1.19.1, with the candidate checkout on the
import path:

```sh
PYTHONPATH=src python -m benchmarks.gh97_http_compat.probe \
  --output benchmarks/gh97_http_compat/results/http-installed-artifact-source-v1.json
```

The fixture includes all seven supported HTTP methods, an invoked forwarding
wrapper, an unused wrapper, a deferred function, a foreign client, and a
dynamic URL control. Counts come from actual product call observations. The
report records relative product source paths and hashes, wheel and extracted
source hashes, runner hash, Git revision, preset/config hashes, and fixture
hash; it omits machine-specific absolute paths. Fixture-line diagnostics are
reported separately from the global mypy errors and missing dependencies.
`compatibility_complete` stays false when those global errors exist. Dynamic
selectors remain unavailable even when the URL call matches a contract. This
is source-level evidence for these exact three artifacts and this environment;
it does not establish version ranges, runtime behavior, or broad GH97
compatibility.

Evidence generation requires the runner and complete analyzer `src` tree to
match committed bytes. `runner_revision` identifies the last commit changing
the runner, and `git_revision` identifies the analyzer source revision; the
report also binds the complete analyzer source tree SHA. A later result-only
commit does not change these source identities. Commit runner changes before
regenerating the result. Diagnostics normalize temporary fixture, typeshed,
virtual environment, and checkout paths while preserving relative file names
and line numbers.
