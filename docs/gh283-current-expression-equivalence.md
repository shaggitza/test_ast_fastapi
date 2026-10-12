# Current expression inference comparison for GH283

The generated retained-state DAG benchmark now requires three independent
agreements after each measured update phase:

1. The existing AST/call typed snapshot matches an independent cold build.
2. The source/config cache fingerprint matches that cold build.
3. A new bounded current-expression type projection matches that cold build.

The new projection has scope
`current-source-expression-types-and-owned-typevars-v1`. It walks explicit
source syntax edges in each current module tree, records expression positions,
presence or absence of a type-map entry, and hashes serialized type evidence.
Top-level TypeVar-like declarations are added only when the current module's
symbol-table key, declaration name and declaration fullname agree exactly.
Their bounds, defaults, value restrictions and variance are also compared.

This projection does not enumerate or modify retained type-map keys. The
`typed_expression_count` metric remains exactly `len(manager.all_types)`;
keys for replaced expressions can remain there after a fine-grained update.
That raw map size is separate from the new current-expression and mapped-type
counts. Neither count is an endpoint or truth denominator.

Source syntax traversal excludes symbol backreferences, analyzed replacements,
annotation/signature Type fields and PEP 695 TypeParam objects. This is not
full semantic-type equivalence. The legacy snapshot remains unchanged and is
still required alongside the new projection. Serialized TypeVar allocator IDs
are retained strictly; they are not normalized away to make builds agree.

Traversal is iterative and bounded for source nodes, containers, recursive
serializable type shapes and JSON evidence. Unsupported shapes, cycles,
serialization failures and exceeded limits abort comparison rather than
reporting a successful partial result. Instance extra attributes remain outside
the audited type shapes. The Mypy 2.4 callable instance-type child is preflighted
before serialization. Template-string interpolation projects only its value
and optional format-spec expressions, with shape validation.

The benchmark records the new scope, current/mapped/declaration counts and
per-module digests, and includes the helper in implementation source receipts.
Its phase gate requires the new flag to be literal true in addition to both
existing flags. Older checked-in result artifacts are unchanged; missing the
new flag does not satisfy the current gate.

Validation uses own manually constructed nodes and fake retained/cold stand-ins.
The same helper passed 29 controls with Mypy 1.19.1 (five Mypy 2.4-specific
controls skipped) and 34 with Mypy 2.4.0 (no skips). Four own gate controls cover
missing/non-boolean flags, mismatched live types despite matching legacy
evidence, count reporting and the unchanged raw map counter. These runs parse
no application sources and perform no real provider builds.

A hosted provider regression additionally changes two generic signatures from
Optional[T]/Optional[U] to T | None/U | None with unchanged imports, then compares
the retained result against a separate cold build. It is authored for CI and
was not run locally. It is a controlled fixture, not a corpus accuracy result.

GH283's medium-project latency, paired real-world runs, blind corpus accuracy
and publication acceptance remain open. This change generates no new latency
measurements and does not relabel historical performance evidence.
