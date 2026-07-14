# Versioned verification sets

Verification sets select PR records after the entrypoint scope is applied. They
do not delete or rewrite canonical truth.

`fastapi-verification-v1` excludes Open WebUI #26642 from the primary score and
keeps it as a separately reported stress holdout. That PR contributes 106 of
177 normalized FastAPI atoms, so including it makes one release aggregation
control most recall and LOW-volume results.

Evaluate the primary verification set with:

```bash
python benchmarks/real_world/evaluate.py \
  --scope fastapi \
  --verification-set benchmarks/real_world/verification_sets/fastapi-verification-v1.json \
  --ground-truth benchmarks/real_world/adjudicated.jsonl \
  --predictions PREDICTIONS.jsonl
```

Report the stress holdout separately with
`open-webui-26642-stress-v1.json` using the same command. Exclusion from
verification is not a claim that the PR is invalid, out of product scope, or
solved. Evaluation artifacts include the selection mode, exact keys, matched
count, and manifest SHA-256.
