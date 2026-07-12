# Controlled polyglot fixtures

These small cases complement the real-world corpus with exact, reviewable
ground truth. They cover:

- FastAPI transitive dependencies;
- Spring overloaded methods;
- NestJS provider injection;
- a cross-repository SDK consumer;
- an orphan negative control;
- an OpenAPI breaking contract change.

The source is stored compactly in `cases.json`. Materialize it when running a
candidate:

```bash
python benchmarks/fixtures/materialize.py --clean
```

Candidates must run from the `before` tree using the before→after diff. They
must not receive `expected.json`. Endpoint IDs are normalized as
`<KIND> <METHOD> <PATH>` so results from different engines can be compared.

These fixtures are intentionally not a substitute for historical PRs. A tool
can overfit six fixtures, while the frozen real-world corpus preserves unknown,
large, generated, documentation-only and architecture-specific changes.
