# FastAPI 0.139.0 source profile prerequisite

This profile authenticates a narrowly bounded source snapshot for the later GH107/109
analysis. It does not emit dependency bindings or establish that a dependency is invoked
successfully. The only supported version is FastAPI **0.139.0** because the project
declares `fastapi>=0.100.0`, while the current lock pins one precise wheel. Other versions
fail closed until a separately reviewed profile is added.

## Artifact and manifest

The profile is bound to the exact official wheel URL pinned in `uv.lock`:

`https://files.pythonhosted.org/packages/9e/7c/8e3c6ad324ea5cb36604fc3f968554887891c316d9dfde57761611d907ad/fastapi-0.139.0-py3-none-any.whl`

The wheel is 130,339 bytes with SHA-256
`cf15e1e9e667ddb0ad63811e60bd11390d1aac838ca4a7a23f421807b2308189`. Its source manifest
is [0.139.0.json](../src/fastapi_endpoint_detector/analyzer/data/fastapi_source_profiles/0.139.0.json),
whose trusted identity is SHA-256
`96808436ce00a7c25085a079342c480a9b1b48f94bb04fb65c67ffab7111ac92`. The verifier has
that identity pinned in its own code; callers cannot pass a custom manifest or choose a
different wheel hash/version.

The verifier reads at most the pinned wheel size plus one byte from one open file handle,
checks size and SHA-256 on those captured bytes, and opens the ZIP from that same in-memory
snapshot. A path replacement after capture cannot change the archive being inspected. It
reads at most 16 KiB plus one byte from the trusted manifest before checking its pinned
SHA-256. The verifier validates unique FastAPI name and version metadata, rejects duplicate,
unsafe, symlink, encrypted, oversized, or excessively compressed ZIP members, and checks the
exact six manifest paths and their per-file SHA-256 values. It parses only inert ZIP entries.
It does not install, import, or execute FastAPI or any application code.

| Exact wheel member | Role | SHA-256 |
| --- | --- | --- |
| `fastapi/__init__.py` | package public surface | `355dadc1d09da2db164be007769e1b07949ccce764c31bf0f4027a545485236c` |
| `fastapi/params.py` | dependency marker records | `d5f34d48ae49ecf339170f85e7ff6e3b2b00d8d802fbad666f72e5ac15a9a893` |
| `fastapi/param_functions.py` | dependency marker wrappers | `e1f4c2565bc40db010afb82f59890e5fc864b5d97623093e92fe05693cfb3fcc` |
| `fastapi/dependencies/utils.py` | graph construction and solver | `5c8a5130beedb71e44866721816cfa47908cb01b9ea71eca1dd9a2dfc17f7bfb` |
| `fastapi/dependencies/models.py` | dependency graph record | `5cf22411aba41da4da173f4ba1e23d7ff4fede8b4e015928382d75dd3a456d62` |
| `fastapi/routing.py` | routing solver entrypoint | `4fdf951bbf9ca943a5fc26f63ed83e8c424ff5d1debe10e8d1b73732bc8f2c7b` |

## Source-chain review notes

These sites were inspected from the verified wheel as source text. Line numbers refer to
FastAPI 0.139.0 source files inside that wheel.

1. `param_functions.py:2283–2369` implements `Depends` and returns
   `params.Depends(dependency=dependency, use_cache=use_cache, scope=scope)`. The
   corresponding `Security` wrapper at `param_functions.py:2372–2460` passes its
   dependency and scopes into `params.Security`.
2. `params.py:745–754` defines `Depends.dependency` and `Security(Depends)`, preserving
   the supplied callable on the marker record.
3. `dependencies/utils.py:286–359` implements `get_dependant`: it creates a `Dependant`
   with `call=call`, reads `param_details.depends.dependency`, recursively builds a child,
   and appends it to `dependant.dependencies`.
4. `dependencies/models.py:32–51` defines `Dependant.call` and the
   `dependencies: list[Dependant]` child records.
5. `routing.py:467–480` calls `solve_dependencies` with the request's `dependant`.
   The solver loops over `dependant.dependencies` at `dependencies/utils.py:628`, recurses
   at `649–659`, and executes the child call or generator branch at `667–680`.

This structural chain attests source roles and bytes only. It does not establish
runtime invocation, successful return, or application-level reachability. Security scopes
are carried through the graph (`dependencies/utils.py:330–343`); dependency overrides
can replace a callable and rebuild the child record (`632–647`); generator dependencies
select request/function exit stacks and need lifecycle handling (`667–676`, with routing
stack setup/cleanup in `routing.py:2185–2205`). These behaviors remain unsupported by
the downstream authentication prerequisite until separately reviewed. No positive
dependency binding is emitted from this profile.

## Analyzer source mapping

`verify_fastapi_wheel(path)` returns a `VerifiedFastAPISourceProfile`. Its
`source_root` identifies the authenticated wheel snapshot and `source_files` maps exact
logical wheel member names to the authenticated bytes. A later consumer may map a
retained Mypy node path to one logical member using its independently retained
environment/source-root information, then call `match_source_snapshot(member, bytes)`.
The method requires exact member path and exact snapshot bytes; it does not match by
basename or claim semantic execution. Direct construction validates the pinned profile
identity, all six exact content hashes, and hash map, then copies both maps into immutable
proxies. The source root is diagnostic text and grants no identity authority.

This prerequisite does not close GH107 or make a canonical corpus, parity, or performance
claim. The existing uncertainty collectors and selector behavior are unchanged.
