# GH97 effect preset package and version matrix (v1)

This artifact records exact release artifacts inspected for the GH97 preset audit and one controlled analyzer observation. It does not claim that an entire declared compatibility range works. Each row names one package version and a SHA-256 pinned wheel or CPython source archive; adjacent releases remain unaudited until separately recorded.

The matrix is deliberately split into three kinds of evidence:

1. **Package source inspection** records wheel/source archive bytes, package metadata where present, inspected file hashes, callable declarations, and selectors seen in that source.
2. **Preset contract inventory** records the preset ID, its own version and revision, source YAML hash, and contract count. Package source evidence does not validate the preset’s package version range.
3. **Analyzer observations** are only the synthetic fixture run through `MypyAnalyzer` and `audit_effect_contracts`. No fixture program, package client, service, database, URL, bucket, or application was executed.

The machine-readable records and fail-closed verifier are [package-symbols.json](../benchmarks/results/effect-preset-matrix-v1/package-symbols.json), [controlled-results.json](../benchmarks/results/effect-preset-matrix-v1/controlled-results.json), and [effect_preset_matrix.py](../benchmarks/providers/effect_preset_matrix.py). The pre-existing [effect-presets-v1 evidence](../benchmarks/results/effect-presets-v1/README.md) remains historical and is not relabeled as package compatibility or real-world recall evidence.

## Exact package artifacts inspected

| Distribution | Exact version and artifact | Inspected source | Matrix status |
| --- | --- | --- | --- |
| [`redis`](https://github.com/redis/redis-py/tree/v5.2.1) | 5.2.1, `redis-5.2.1-py3-none-any.whl`, SHA-256 `ee7e1056b9aea0f04c6c2ed59452947f34c4940ee025f5dd83e6a6418b6989e4` | `redis/commands/core.py` | exact `BasicKeyCommands.get/set/delete`, `PubSubCommands.publish`; redis key/value and channel/message argument positions recorded |
| [`pymongo`](https://github.com/mongodb/mongo-python-driver/tree/4.10.1) | 4.10.1, CPython 3.11 Linux wheel, SHA-256 `cec237c305fcbeef75c0bcbe9d223d1e22a6e3ba1b53b2f0b79d3d29c742b45b` | `pymongo/synchronous/collection.py` | exact `Collection.find_one/insert_one/update_one/delete_one`; receiver is the collection; value/filter selectors recorded |
| [`motor`](https://github.com/mongodb/motor/tree/3.6.0) | 3.6.0, wheel, SHA-256 `9f07ed96f1754963d4386944e1b52d403a5350c687edc60da487d66f98dbf894` | `motor/core.py`, `motor/motor_asyncio.py` | partial: public methods are descriptor/delegation based; resolved public symbols and analyzer binding remain unsupported |
| [`python-stdlib`](https://github.com/python/cpython/tree/v3.11.16) | CPython 3.11.16 source tar, SHA-256 `6c0bd76ab0ec7d94ed400b1497f01ac6c7751c8822615ee0855a3eb2d893ea76` | `pathlib.py`, `_io` C sources including `_iomodule.c` | exact `Path` read/write/open declarations and built-in/open-handle origins recorded; analyzer fixture covers a limited subset |
| [`requests`](https://github.com/psf/requests/tree/v2.32.3) | 2.32.3, wheel, SHA-256 `70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6` | `requests/sessions.py` | exact `Session` wrapper signatures recorded; URL is the first explicit parameter and wrapper kwargs forward to `request` |
| [`httpx`](https://github.com/encode/httpx/tree/0.28.1) | 0.28.1, wheel, SHA-256 `d909fcccc110f8c7faf814ca82a9a4d816bc5a6dbfea25d6591d6985b8ba59ad` | `httpx/_client.py` | exact `Client` and `AsyncClient` method names and source signatures recorded; generic `request(method, url, ...)` is retained as an unsupported contract rather than generalized |
| [`aiohttp`](https://github.com/aio-libs/aiohttp/tree/v3.11.11) | 3.11.11, CPython 3.11 manylinux wheel, SHA-256 `249cc6912405917344192b9f9ea5cd5b139d49e0d2f5c7f70bdfaf6b4dbf3a2e` | `aiohttp/client.py` | exact finite `ClientSession` verbs recorded; runtime branch wrappers take URL, keyword-only redirect option and forwarded kwargs; call timing remains an analyzer/preset concern |
| [`boto3`](https://github.com/boto/boto3/tree/1.35.92) | 1.35.92, wheel, SHA-256 `786930d5f1cd13d03db59ff2abbb2b7ffc173fd66646d5d8bee07f316a5f16ca` | `boto3/session.py` | partial: `Session.client` factory signature inspected; generated operation members are not declared as ordinary source methods |
| [`botocore`](https://github.com/boto/botocore/tree/1.35.92) | 1.35.92, wheel, SHA-256 `f94ae1e056a675bd67c8af98a6858d06e3927d974d6c712ed6e27bb1d11bee1d` | client source plus pinned S3, SQS, SNS service model files | exact service operation model and request member evidence is hashed; `_make_api_call(operation_name, api_params)` is generic and is not treated as a concrete operation callable |
| [`mypy-boto3-s3`](https://github.com/youtype/mypy_boto3_builder/tree/1.35.92) | 1.35.92, wheel, SHA-256 `ce302a635da78e1925d8ff4809184ba55618cd7e3707156bea405cde7fdcf67a` | `client.py`, `type_defs.py` | exact typed `S3Client.get_object/put_object/delete_object`; request keys are keyword fields, `Bucket`+`Key` identify resource, `Body` is the put value |
| [`mypy-boto3-sqs`](https://pypi.org/project/mypy-boto3-sqs/1.35.91/) | 1.35.91, wheel, SHA-256 `346a87bc0a447bb4c005b04d3efa0008bfa0ddd498cadd97e0e53a58752f84e9` | `client.py`, `type_defs.py` | exact typed `SQSClient.send_message/send_message_batch`; `QueueUrl` and message fields are `Unpack[TypedDict]` keyword arguments |

Wheel and source hashes are verified against the locally supplied exact artifacts; the artifacts themselves are not vendored into this repository. The manifest stores the PyPI artifact URLs, release-source links, wheel metadata hashes, and every inspected source-file hash. Verification refuses missing artifacts, altered bytes, metadata mismatches, missing source files, or changed source hashes.

## Preset identities and version boundaries

The matrix freezes five independent preset contract sets by YAML hash: `redis-py-effects` 1.0.0/revision 1, `pymongo-effects` 1.0.0/revision 1, `stdlib-filesystem-effects` 2.0.0/revision 2, `python-http-client-effects` 2.0.0/revision 2, and `typed-s3-effects` 2.0.0/revision 2. The exact paths, hashes, and contract counts are in `versioned_contract_sets`. Their IDs and versions remain separate; no matrix version is used as a substitute for a preset version.

The audited release is compared with the current YAML range only as a cross-reference, not as compatibility proof. For example, `redis` 5.2.1 lies within the declared `>=5,<7` selector; only 5.2.1 source has been inspected. `pymongo` 4.10.1 lies within `>=4.9,<5`; this does not cover Motor. The filesystem artifact is Python 3.11.16, one interpreter release inside `>=3.10,<3.14`. `requests` 2.32.3, `httpx` 0.28.1, and `aiohttp` 3.11.11 are each one exact artifact. Typed S3 1.35.92 is one exact stub package inside the declared `>=1.34,<2` range. Range compatibility is therefore **not evaluated**.

The recent PR308 documentation commit `b612dc0` describes filesystem route/resource coverage. It does not add package-version observations and is not counted as matrix evidence. The v1 historical README describes controlled preset fixtures and infrastructure, not production package compatibility.

## Controlled analyzer observation

One synthetic pathlib fixture was analyzed with Python 3.11.16, mypy 2.4.0 and Ruff 0.16.10. The test invokes the repository’s `MypyAnalyzer` and `audit_effect_contracts` against the frozen `filesystem-v1` selector. The result file binds the exact test-source SHA-256, preset semantic/raw hashes, configuration hash, resolver version, and package manifest/artifact hashes.

Observed denominator: 11 calls; 4 matched, 7 unmatched, 0 ambiguous, 0 unresolved. Positive coverage was `Path.read_text`, `Path.write_text`, and two `_io._TextIOBase.read` occurrences. Five unrelated same-name calls (`read_text`, `get`, `set`, `write`, `send`) remained unmatched; two open constructors remained unmatched. The Path.open-derived handle read had unavailable receiver origin (`receiver_origin_unsupported`); the built-in `open` handle read had exact origin. This is one source-level controlled observation, not an estimate of package-wide precision or recall.

No package compatibility fixture currently executes the analyzer against Redis, MongoDB/Motor, HTTP clients, boto3/S3, or message publishing symbols. Those are source-audit-only or explicitly unsupported in this matrix. The existing analyzer did not establish that generated boto3 methods or Motor descriptors resolve to the audited symbols.

## Unsupported and missing evidence

- The exact request for `mypy-boto3-sqs==1.35.92` returned no matching distribution at the audited index. Version 1.35.91 is recorded as its own artifact; the unavailable version is not substituted or inferred.
- Motor 3.6.0 source inspection found descriptor delegation and generated framework-specific collection classes. Public-call resolution and analyzer binding are unresolved; no PyMongo result is transferred to Motor.
- `boto3` operation methods are generated from Botocore service models. S3/SQS/SNS models were hash-inspected, but this matrix does not declare generated runtime client methods as analyzer-resolved callable symbols.
- No licensed, frozen real-world source diff was added. Real-world evaluation status is `not_evaluated`; no truth labels, package recall, runtime receipts, or production claims are fabricated.

## Reproduction and validation

Use a Python 3.11 environment with pytest, Ruff 0.16.10 and mypy 2.4.0. From the repository root:

```sh
python -m pytest tests/benchmarks/test_effect_preset_matrix.py -q
ruff check benchmarks/providers/effect_preset_matrix.py tests/benchmarks/test_effect_preset_matrix.py
ruff format --check benchmarks/providers/effect_preset_matrix.py tests/benchmarks/test_effect_preset_matrix.py
python -c 'from pathlib import Path; from benchmarks.providers.effect_preset_matrix import verify_artifacts, verify_preset_contracts; print(len(verify_artifacts(Path("/path/to/frozen-artifacts")))); print(len(verify_preset_contracts()))'
```

The artifact directory must contain all eleven exact files named in the manifest. With any file missing, verification fails closed. The test suite does not download package files or contact external services.
