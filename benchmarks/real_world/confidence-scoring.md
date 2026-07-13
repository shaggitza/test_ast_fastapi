# Ranked confidence scoring

The benchmark uses one primary operating point and one diagnostic candidate
pool. Confidence is assigned before evaluation by versioned analyzer rules.

## Primary score

`HIGH` and `MEDIUM` predictions participate in ordinary exact and normalized
TP/FP/FN, precision, recall, F1, macro, repository, kind, and negative-control
metrics. Predictions without confidence are treated as `MEDIUM` for legacy
artifact compatibility.

`LOW` never changes primary TP, FP, FN, precision, recall, or F1.

## LOW diagnostics

After primary one-to-one matching is frozen, LOW candidates are matched only
against truth atoms still counted as primary FN:

- `low_tp`: primary FN atoms covered by a LOW candidate;
- `low_fp`: LOW candidate atoms not in behavioral ground truth;
- `low_supported_reachability`: LOW atoms independently confirmed to execute the
  changed path without an established public/behavioral observation;
- `low_unmatched`: LOW atoms supported by neither behavioral nor supplemental
  reachability truth;
- `fn_with_low_candidate`: equal to `low_tp`;
- `fn_with_no_candidate`: primary FN atoms with no matching LOW candidate;
- `diagnostic_precision`: `low_tp / (low_tp + low_fp)`.

Required invariant:

```text
primary FN = fn_with_low_candidate + fn_with_no_candidate
```

The candidate ceiling reports the hypothetical union of selected and LOW
predictions, but it is never the headline score. This prevents emitting the
entire route inventory as LOW from improving primary results.

## Matching order

1. Collapse duplicate/canonical/explicit-alias candidate atoms, retaining the
   strongest tier (`HIGH > MEDIUM > LOW`).
2. Match selected atoms one-to-one using the frozen semantic rule priority.
3. Freeze primary TP/FP/FN.
4. Match LOW atoms against only the unmatched expected atoms.
5. Report selected and LOW match rules separately.

This guarantees a LOW exact alias cannot steal an atom from a MEDIUM/HIGH
prediction and composite method atoms cannot receive duplicate credit.

## Artifact schema

Prediction schema v2 preserves:

```json
{
  "affected_entrypoints": ["HIGH/MEDIUM compatibility projection"],
  "candidate_entrypoints": [
    {
      "id": "HTTP GET /items",
      "kind": "http",
      "confidence": "low",
      "effect_evidence": []
    }
  ]
}
```

The runner chooses the strongest confidence for duplicate IDs and preserves
versioned effect evidence. Legacy analyzer reports without candidates fall back
to affected endpoints at MEDIUM confidence.

## Interpretation

- LOW TP is a promotion opportunity, not primary credit.
- LOW FP is outside behavioral truth and is not a primary penalty; consult
  `low_supported_reachability` before calling it unrelated noise.
- Unresolved analysis is not LOW; it remains an abstention/failure.
- Raw exact and conservative normalized results remain co-reported.
- Per-repository results remain mandatory because aggregate micro scores can
  hide unsupported repositories.
