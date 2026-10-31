# R5 review of the 49 Reviewer B UNRESOLVED findings

**Status:** Technical recommendations prepared; NOT human-adjudicated and NOT approved for freeze.

## Results

- Rows reviewed: 49
- Proposed TRUE_POSITIVE: 43
- Proposed FALSE_POSITIVE: 6
- Original Reviewer B labels changed: 0 (preserved as UNRESOLVED in the source columns)
- Required human confirmations: Reviewer A and Reviewer B for each proposed adjudicated label.

## Decision standard used

- For SCA rows, a TRUE_POSITIVE recommendation means the exact package version recorded by the source scan falls within an authoritative advisory's affected range. It does **not** assert that the vulnerable API is called or that exploitation is reachable.
- A FALSE_POSITIVE recommendation is used where the source code/rule location does not support the finding or where the advisory's platform/configuration condition is contradicted by the supplied repository (for example, Windows-only Werkzeug issues in the Linux Docker target).
- Transitive OSV-resolved packages (certifi and idna) are recommendations based on the resolved versions in the candidate finding record, not direct pins in the app requirements file.
- Where the project itself records security exceptions (asteval, ecdsa, mcp, opentelemetry), the recommendation remains a component/version TRUE_POSITIVE but records that the vulnerable operation is not reachable in the current CI workflow. A risk exception is not the same as a false-positive finding.

## Important corrections to prior rationales

- `CKV_K8S_23` maps to the run-as-root control, not CPU/memory limits.
- `KSV-0110` maps to default namespace, not AppArmor.
- `KSV-0118` maps to security context.
- `KSV-0014` maps to writable root filesystem, not dropped capabilities.
- `CVE-2024-43796` for Express is XSS via `response.redirect()`, not X-Forwarded-For spoofing.
- `CVE-2024-43799` for `send` and `CVE-2024-43800` for `serve-static` concern template injection/XSS in redirect handling, not directory traversal.
- `CVE-2022-29361` is a disputed Werkzeug request-smuggling issue; the repository has a Node HTTP proxy in front of Flask's Werkzeug development server. The proposed TP depends on that proxy meeting the advisory's external-server precondition; reviewers should explicitly verify this point.
- `NSWG-ECO-516` is a legacy Trivy identifier. Its exact database mapping should be checked against the source scan artifact before freezing.

## Files

- `reviewer_b_reassessment_recommendations.csv`: 49 proposed labels with rationale, evidence, caveats, and reviewer confirmation fields.
- `reviewer_ab_full_98_with_49_recommendations.csv`: all 98 original rows preserved, plus proposed adjudication columns for the 49 previously unresolved rows. Original A/B labels and metadata are unchanged.

## Human action required before using these as final adjudicated labels

1. Reviewer A and Reviewer B inspect each recommendation and its cited code/advisory evidence.
2. Confirm or change the proposed label and rationale.
3. Fill `reviewer_a_confirmation`, `reviewer_b_confirmation`, `adjudicated_by`, and `adjudication_date_utc`.
4. Only after confirmation should the proposal be copied to `adjudicated_label` in a new version of the dataset.
5. Re-run dataset validation, time-split/leakage checks, and generate the final SHA-256 manifest.

Do not replace the original independent `reviewer_b_label=UNRESOLVED` values in the source file. The proposed adjudicated labels are a separate audit layer.
