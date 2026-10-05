# Paired generated typed DAG CLI accuracy gate (v2)

This version runs every declared case through the installed public CLI with both `--app` and `--baseline-app`, in `--secure-ast --no-cache` mode. The independent call-edge oracle is derived from the deterministic generator and never uses analyzer output. Baseline and target source maps, unified diffs, configuration, raw CLI JSON, endpoint candidates, confidence rows, diagnostics, and timing are recorded per case. Synthetic fixture source is never imported or executed.

Run against a clean integration worktree that contains the actual analyzer and CLI revision under evaluation:

```sh
uv run python -m benchmarks.real_world.typed_dag_paired_cli_accuracy \
  --analyzer-project-root /path/to/clean/analyzer-worktree \
  --output benchmarks/results/typed-dag-paired-cli-accuracy-v2/current.json
```

The runner revision and harness hash are recorded separately from the analyzer git revision, installed module paths, package versions, and SHA-256 hashes of the committed analyzer source files and lock/config files. Validation rechecks those hashes against the analyzer worktree and rejects dirty analyzer trees. Each CLI run has an explicit timeout and records elapsed milliseconds.

The 15 established replacement and reachable-control cases are retained. Addition, deletion, and rename are separate capability probes with real baseline and target graphs: the new or removed function is called by `/one`, and both sides of the rename remain reachable. A probe is counted supported only after a real paired CLI run establishes the two-route inventory without errors or inventory limitations. A command failure is recorded as a failed case; an explicit analyzer limitation is recorded as unsupported. Neither can be guessed into a pass.

The gate requires 100% endpoint precision and recall across supported cases, zero HIGH/MEDIUM candidates for dead or unrelated controls, and complete recording of all 18 cases. LOW-only metrics remain explicit. An unsupported capability remains visible and does not satisfy the gate. The preserved run `paired-run-88365f0-analyzer-8ccd5d3.json` records analyzer `8ccd5d38483d89527f3ef651a1575e3a67bf0e2d` and runner `88365f0207e5c65dfcfc393bc12a9e87715db8cb`. It recorded 18/18 cases, 18 supported and zero unsupported; TP=14, FP=1, FN=0, precision=14/15 (0.9333), recall=1.0, and one HIGH/MEDIUM control candidate. The sole false positive is `deferred_lambda_control` at MEDIUM for `GET /one`. All three paired capability probes were supported and passed. Gate status is failed. The frozen v1 `current-main.json` and `historical-29a5d41.json` remain unchanged.

This generated gate does not establish canonical truth or close GH283's original corpus, blind-release, bootstrap, or incremental-performance milestones. Those gates remain open.
