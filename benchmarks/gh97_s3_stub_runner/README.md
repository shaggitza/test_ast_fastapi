# GH97 exact S3 stub probe

This opt-in probe checks one installed wheel artifact: `mypy-boto3-s3==1.35.92`,
SHA-256 `ce302a635da78e1925d8ff4809184ba55618cd7e3707156bea405cde7fdcf67a`.
It verifies the exact matrix manifest bytes from
`benchmarks/results/effect-preset-matrix-v4/package-symbols.json`, privately
extracts bounded regular ZIP files, and points mypy at that private stub tree.
The benchmark never installs the wheel, imports its modules, executes package
code, accesses an app or service, or invokes external commands based on wheel
contents.

Run it with the repository's Python environment containing the pinned mypy
version. The runner requires Python 3.11.16 and mypy 1.19.1:

```bash
/path/to/python benchmarks/gh97_s3_stub_runner/runner.py \
  --wheel /path/to/mypy_boto3_s3-1.35.92-py3-none-any.whl \
  --output /tmp/gh97-s3-stub-result.json
```

The JSON output uses schema version 1 and records the exact artifact/version,
matrix-manifest hash, inspected stub source hashes, fixture hashes, Python and
mypy versions, analyzer module hashes, and mypy settings. It contains three
separate result sections:

- `canonical_symbol_resolution` reports the resolved declaration from mypy's
  typed receiver and its method table. The complete, omitted-Body, and
  positional-misbound calls must resolve to
  `mypy_boto3_s3.client.S3Client.put_object`; the foreign same-name control
  must resolve to `__main__.Foreign.put_object`.
- `selector_binding_results` checks the contract-selected `Bucket`, `Key`, and
  `Body` bindings. The omitted-Body call intentionally has a matched canonical
  symbol and an incomplete value selector. Canonical-symbol audit status and
  selector-binding status are independent observations; a missing Body does
  not turn the canonical resolution into `unmatched`.
- `product_adapter` runs this checkout's `MypyAnalyzer` and effect contract
  auditor. It reports the checkout root, Git revision, source hashes, and
  resolved module paths; paths outside this checkout fail the probe. The
  adapter loads the bundled `object-storage-v1` preset and points the analyzer
  at the privately extracted, hash-verified stub package. Its call and audit
  outcomes are direct product evidence, including unresolved receivers or
  unavailable argument values.

Mypy may report diagnostics for transitively imported boto3/botocore types that
are absent from this deliberately isolated stub-only search path. The report
retains diagnostic counts per fixture; these do not change the independently
observed canonical-symbol or selector-binding results.

This probe is limited to this exact artifact and mypy environment. It does not
claim package-version-range compatibility, runtime behavior, Motor or SQS
coverage, or real-world application compatibility. The former generic
same-method-name matching is not a valid success criterion. Broader Motor,
SQS, version-range, and real-world validation remain open acceptance gates.
