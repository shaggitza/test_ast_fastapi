# Effect-aware impact evidence

Symbol reachability and externally observable behavior are different claims.
The analyzer therefore keeps every reachable candidate and reports structured
evidence describing what source establishes about the changed data.

## Independent dimensions

- **Legacy confidence** prioritizes candidates for existing consumers.
- **Evidence status** distinguishes established, conditional,
  reachability-only, and unresolved claims.
- **Change effect** describes the semantic shape of the change.
- **Observation** records how the relevant value is used after a call.
- **Impact channel** records response, persistence, outbound, event, logging,
  control-flow, in-memory aliasing, or dynamic-extension effects.
- **Disposition** distinguishes observable behavior, operational-only effects,
  internal effects, no established caller observation, and unresolved dynamic
  behavior.

A logging-only change can be established with high certainty while remaining
operational rather than an HTTP-contract change. Conversely, an exact call path
can remain reachability-only when no value flow to an observation is known.

## Defensive-copy analysis

The initial effect pass recognizes target-side defensive copies of a function
parameter:

```python
payload = {**payload}
payload = dict(payload)
payload = payload.copy()
```

It requires a later top-level mutation of the rebound parameter. It then walks
resolved mypy call edges backwards and classifies post-call uses of the original
argument as returned, read, branch-controlled, logged, persisted, emitted,
sent outbound, forwarded, dynamically escaped, or not observed by that caller.
Simple parameter forwarding is propagated across multiple project functions.

This pass does not remove reachability evidence. Candidates below the legacy
confidence threshold remain in `AnalysisReport.candidate_endpoints` and in the
JSON/YAML `candidate_endpoints` array.

## Safety limits

- Analysis is execution-free and uses Python AST plus mypy-resolved call edges.
- A shallow copy does not isolate nested mutable values.
- Unknown callbacks, reflection, plugins, `*args`, `**kwargs`, and ambiguous
  call sites remain unresolved.
- Sink recognition is deliberately narrow; an unknown call is forwarding or a
  dynamic boundary, not automatically persistence or outbound I/O.
- Target-only mypy analysis can recognize additions such as a defensive copy,
  but arbitrary before/after effect deltas require explicit baseline support.
- `NOT_OBSERVED_AFTER_CALL` means no caller observation was established by the
  modeled source path. It does not mean the changed code was not executed and
  must not be described as an absolute false positive.

## Output example

```json
{
  "confidence": "low",
  "effect_evidence": [
    {
      "producer": "data_flow",
      "status": "conditional",
      "effect": "argument_mutation_isolated",
      "observations": ["not_observed_after_call"],
      "channel": "in_memory_aliasing",
      "disposition": "not_observed_by_caller",
      "summary": "The local argument 'payload' is not observed by this caller after the call.",
      "limitations": [
        "The copy is shallow; nested mutable values remain aliased.",
        "Dynamic callees may still observe object identity or retain the copied value."
      ]
    }
  ]
}
```

The same route can have multiple evidence records when different paths have
different effects. Aggregation retains all distinct evidence and uses the
highest legacy confidence only for backward-compatible prioritization.
