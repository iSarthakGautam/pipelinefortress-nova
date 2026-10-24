# ADR-001: Unified finding schema v1.0.0

**Status:** Proposed (R2) · **Needs sign-off:** R4 (consumer), R1, R5
**Schema:** `scanners/schema/finding.schema.json`

## Context
R4's `ai/` code was merged before a schema was agreed. This ADR freezes the contract and
lists where R4's current code and the plan's example differ, so one side adapts once.

## Decision
One JSON object per finding. Producers fill their own blocks and never touch others':

| Block | Written by |
|---|---|
| core fields, `location`, `package`, `evidence.snippet/raw_ref`, `severity_*` | normalizer (R2) |
| `baseline` | baseline diff (R2) |
| `dedupe` | `cluster.py` (R4) |
| `evidence.snippet_redacted` | redactor (R4) |
| `enrichment` | `enrich.py` (R4) |
| `triage` | LLM + validator (R4), the only model output |

## Mismatches with R4's current code (R4 to adapt unless noted)
1. **`rule_id`** is read by `cluster.py` but missing from the plan's schema. Added as required top-level.
2. **Snippet location.** `triage.py` reads top-level `snippet`; the plan has `evidence.snippet_redacted`.
   The normalizer emits `evidence.snippet` (raw, runner-local). R4 should read it from there.
3. **`severity`** in `triage_v1.txt` is not a field. Use `severity_raw` / `severity_norm`.
4. **`raw_cve`** in `validate.py` is not a field. `cve` holds scanner-reported IDs only and the model must not add any.
   The validator should check any model-claimed CVE against `cve` plus the offline DB.
5. **`finding_id`** must be 16 hex chars. `stub_triage.py` emits `sha256:example12345`.
6. **`cluster_id`** is an opaque string (R4 uses `tool::rule::file`), not necessarily `C-014`.
7. **`triage.priority`** allows `UNASSIGNED` (R4 emits it), added to the enum.
8. **`schema_version`** is new, so breaking changes are detectable.

## Consequences
- Breaking changes after week 1 need an ADR plus a channel heads-up.
- `scanners/normalize/` must validate its output against this schema in CI.
- Severity mapping lives in `scanners/normalize/severity_map.yaml` (to be written).
