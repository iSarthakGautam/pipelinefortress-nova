# ADR-002: Schema v1.1.0 and the R2 → R4 triage hand-off

**Status:** Proposed (R2) · **Needs sign-off:** R4 (consumer), R1 (runs the triage job)
**Supersedes:** parts of ADR-001 (snippet field, enrichment types)

## Context
R4's triage code on `main` (`ai/triage.py`, `ai/sarif_ref.py`, `ai/redaction/redactor.py`,
`ai/injection.py`) was built against `eval/stubs/r2_normalizer_stub.py`. Running it on the real
normalizer output (`tests/test_triage_handoff.py`) showed three breaks:

1. The normalizer wrote the raw snippet to `evidence.snippet`; R4 reads `evidence.snippet_raw`.
   Effects: R4's `_strip_raw` does not remove `evidence.snippet`, so **the raw snippet was copied into
   the triaged output**; the injection check never saw it; and for non-SARIF tools (Bandit) the model
   got no snippet at all, because `sarif_ref.hydrate` can only re-read SARIF.
2. R4 writes `enrichment.epss` / `enrichment.reachable` as `null` when unknown (offline, no data).
   v1.0.0 required a number / boolean, so R4's output failed R2's schema.
3. `raw_ref` was relative to whatever path the normalizer was given. R4 resolves it against
   `ARTIFACTS_BASE` (default: repo root) and refuses paths outside it.

## Decision
- **Schema v1.1.0** (breaking, hence the version bump):
  - `evidence.snippet` → **`evidence.snippet_raw`**, R4's existing name. "raw" says what it is,
    and R4's code already strips that key from everything it outputs.
  - `enrichment.epss` and `enrichment.reachable` accept `null` = not known. Never a guess.
- **`raw_ref`** is always relative to the repo root (`<path>#<JSON pointer>`), for example
  `artifacts/scans/semgrep.sarif#/runs/0/results/17`. The triage job sets
  `ARTIFACTS_BASE=$GITHUB_WORKSPACE`, or leaves it unset. (Answers `TODO(R2)` in `ai/sarif_ref.py`.)
- **What gets triaged:** `baseline.py check --triage-out artifacts/triage-input.json` writes the new
  findings, minus those covered by a valid `security-exception`. Known findings are accepted debt and
  excepted ones have a named owner, so neither needs a model verdict. A finding whose exception
  expired or is malformed still goes to triage. (Answers the `baseline.is_new` `TODO(R2)` in
  `ai/triage.py`: skipped findings are never sent, so no extra verdict value is needed.)
- **`severity_norm` is always present.** It is required by the schema. (Answers the `TODO(R2)` in
  `ai/triage.py`.)
- **`dedupe.cluster_id`:** the normalizer does not set it yet, so R4's fallback key
  `tool::rule_id::file` applies. Open item: clustering SCA findings across Trivy/Grype/OSV (same
  vuln, three tools) belongs to R2's dedupe keys and is a separate change.

## Enforcement
- `tests/test_triage_handoff.py` runs the real normalizer + gate output through R4's real
  `triage_findings` with only the model call mocked. It checks that every finding is triaged, the
  output is valid v1.1.0, snippets from SARIF and non-SARIF tools both reach the model, a secret
  in a snippet is redacted before the model, an injection in a snippet skips the model, and only
  `raw_ref` and `snippet_redacted` remain in `evidence`.
- CI (`10-security-scan.yml`) runs `ai/triage.py` on every PR's real `triage-input.json` with the
  model unreachable, then asserts the same output properties.

## Consequences
- R4: no code change needed. `eval/stubs/r2_normalizer_stub.py` and its `TODO(R2)` contract tests
  can now point at the real normalizer.
- R1: the `30-triage-ai` job reads `artifacts/triage-input.json` from the `security-scan`
  artifact and runs `ai/triage.py` with `ARTIFACTS_BASE` set to the workspace.
- Anything that stored v1.0.0 findings must rename `evidence.snippet`. Nothing on `main` does.
