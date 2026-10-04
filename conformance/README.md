# roe-guard conformance vectors

Language-neutral decision vectors for roe-guard policy evaluation. Any
evaluator of the roe-guard policy schema — in any language — MUST pass
every case in this directory.

## Layout

```
conformance/
  schema/case-file.schema.json   JSON Schema (draft 2020-12) for case files
  cases/<suite>.json             the vectors
  tools/check_v1_baseline.py     v1 golden-case checker (Python)
```

Suites: `v1-golden` (v0.1 compatibility, rule a of SPEC §14.6), `ladder`
(the eight-step decision ladder), `agent` (identity step 0), `egress`
(`enforce_egress`, SPEC §14.5), `load` (policy parse failures).

## Case file format

`format` is `1`. An unknown `format` value is an error in the consumer.

Each case carries `id` (unique, `^[a-z0-9-]+$`), `description`,
`policy` (a full policy document as JSON), `input` and `expected`.

## Inputs

Two input kinds:

- `action`: `target` (string), `action_type` (string), `now`, `agent`.
- `egress`: `host`, `port`, `method` (string or null), `now`, `agent`.

`agent` is `null` or `{"id": str, "runtime": str | null}`. `now` is
RFC 3339 with a `Z` suffix; every case fixes the clock, so evaluation
has no time dependency. In negative port cases `port` may be a
non-integer; typed consumers treat a non-integer port as
`EGRESS_TARGET_INVALID`.

## Expected outcome

`expected` always carries `verdict` (`ALLOW`, `DENY`,
`REQUIRES_APPROVAL`) and `reason_code` (a SPEC §14.4/§14.5 code).
`ladder`, `agent` and `egress` cases also carry `matched_rule`;
`v1-golden` cases carry the v1 free-text `reason`.

A policy that fails to parse yields, for every input,
`{"verdict": "DENY", "reason_code": "POLICY_INVALID"}`. A policy that
is not a mapping (for example a JSON array) is also
`POLICY_INVALID`.

Matching semantics are defined in SPEC §14.4 (decision ladder) and
§14.5 (`enforce_egress`): deny-before-allow, first match wins,
case-sensitive globs where `*` also covers `/`, host globs never
matching IP literals, and the instance-metadata deny that no policy can
override.

## Running the Python runner

```
pytest tests/test_conformance.py
```

The runner validates every file against the case schema, evaluates each
case with the current roe-guard, and checks the meta guarantees (unique
ids, per-suite minimum sizes, all 20 reason codes covered, all three
verdicts seen, non-POLICY_INVALID policies schema-valid).

## Baseline check for the v1 golden suite

```
python conformance/tools/check_v1_baseline.py [--roe-guard-path DIR]
```

Uses only the v1 API (`load_policy`, `Engagement`, `enforce`), so it can
also verify a pre-v2 checkout.

## Stability

Consumers pin these vectors to a roe-guard commit SHA. Behavior changes
require updating the vectors and the changelog together.
