# R5 Final QA and Evidence Acceptance Checklist

**Release:** PipelineFortress R5  
**QA owner:** Rajdeep Kaur  
**Date:** 31 October 2026  
**Timezone:** IST (UTC+05:30)

---

## 1. Ground Truth

- [x] Population file and sampling manifest are present.
- [x] Original Reviewer A and Reviewer B label files are preserved separately.
- [x] All 49 reassessment outcomes have been reviewed and approved by the human reviewers.
- [x] Six initial reviewer disagreements have been reviewed and adjudicated.
- [x] Reviewer A and Reviewer B approvals are recorded separately for independent comparison.
- [x] Cohen's kappa report is present.
  - Paired cases: 49
  - Agreements: 43
  - Disagreements: 6
  - Raw agreement: 87.76%
  - Cohen's kappa: 0.4494
- [x] Merged 98-row ground-truth dataset exists.
- [x] Development and test split files have been generated.
- [x] Freeze manifest exists and its SHA-256 has been generated.
- [ ] Verify manifest source and output hashes.
- [ ] Verify duplicate-group and cluster-ID leakage checks against the generated split.
- [x] Human ground-truth approval is complete.

**Ground-truth artifacts:**

- Sampling manifest: `eval/ground_truth/data/sample-2026-10-29/sampling_manifest.json`
- Reviewer A labels: `eval/ground_truth/data/sample-2026-10-29/labels_reviewer_a.csv`
- Original Reviewer B labels: `eval/ground_truth/data/sample-2026-10-29/labels_reviewer_b.csv`
- Completed Reviewer B labels: `eval/ground_truth/data/sample-2026-10-29/labels_reviewer_b_completed.csv`
- Adjudication: `eval/ground_truth/data/adjudication.csv`
- Merged dataset: `eval/ground_truth/data/ground_truth_v1.jsonl`
- Development split: `eval/ground_truth/data/frozen-r5/development.jsonl`
- Test split: `eval/ground_truth/data/frozen-r5/test.jsonl`
- Freeze manifest: `eval/ground_truth/data/frozen-r5/freeze_manifest.json`
- Kappa report: `eval/ground_truth/cohen_kappa_report.md`
- Freeze approval: `eval/ground_truth/freeze_approval.md`

**Freeze manifest SHA-256:**

`F8D17E847160CD51439DF6D4E6FB4BDE165252EF7919563E10E338F573D6500B`

---

## 2. Metrics and Dashboard

- [ ] Metrics catalogue defines metric names, types, units, labels, sources and interpretation.
- [ ] Vanity metrics are excluded or explicitly justified.
- [ ] Real metrics output passes the appropriate validator.
- [ ] Prometheus targets screenshot records actual target status.
- [ ] Grafana screenshot shows the actual dashboard and selected time range.
- [ ] Prometheus query screenshot shows the actual expression and result.
- [ ] Evidence index references committed evidence files.

---

## 3. Report and Slides

- [ ] Report documents the ground-truth method, sample, kappa, adjudication, split and limitations.
- [ ] Numerical claims link to supporting source artifacts.
- [ ] Report is rebuilt from source Markdown at the release commit.
- [ ] Final HTML/PDF is opened and checked for missing sections, broken tables and page overflow.
- [ ] Slides match the final report and do not overstate evidence.
- [ ] Final slide PDF is exported and checked.

---

## 4. Reproducibility and Demo

- [ ] Clean checkout or machine is identified.
- [ ] Dependency and environment versions are recorded.
- [ ] Test suite is executed and raw output retained.
- [ ] Dashboard Compose stack is started and actual status retained.
- [ ] Report build is executed and output retained.
- [ ] Reproduction limitations and failures are disclosed.
- [ ] Demo script is reviewed against the current interface and artifacts.
- [ ] Rehearsal 1 is completed and issues recorded.
- [ ] Rehearsal 2 is completed and issues recorded.

---

## 5. Final Claim Audit

| Claim | Supporting artifact/path | Verified by | Status |
|---|---|---|---|
| Sample size and population | Sampling manifest and population CSV | Human reviewers | Human review complete; hash verification pending |
| Kappa and raw agreement | `cohen_kappa_report.md` | R5 owner | Report available; independent recalculation pending |
| Adjudication outcomes | Adjudication CSV and reassessment evidence | Both reviewers | Human approval complete |
| Time split and leakage | Development/test JSONL and freeze manifest | Pending | Leakage verification pending |
| Metric values | Metrics catalogue and validator output | Pending | Pending |
| Dashboard scrape status | Prometheus targets screenshot | Pending | Pending |
| Test/reproducibility result | Test logs and clean-checkout evidence | Pending | Pending |

---

## 6. Final Acceptance Decision

**Ground-truth human approval:** `APPROVED`

**Reviewer sign-off:** `COMPLETE`

**Adjudication status:** `APPROVED`

**Technical freeze status:** Generated artifacts and manifest SHA-256 recorded. Final technical verification remains pending.

**Overall R5 QA decision:** `PENDING FINAL EVIDENCE VERIFICATION`

**Outstanding items:**

1. Verify population and sampling-manifest hash agreement.
2. Verify freeze manifest source and output hashes.
3. Verify split counts and duplicate-group/cluster-ID leakage results.
4. Complete metrics validation and dashboard evidence capture.
5. Rebuild and inspect the final report and slides.
6. Complete clean-checkout testing and demo rehearsals.

**QA sign-off:** Pending completion of the overall release QA checks.

**Final acceptance date:** To be recorded after all applicable checks pass.

---

*Human approval of the ground-truth dataset is complete. Overall R5 release acceptance is a separate decision and remains pending until the outstanding technical, metrics, reporting and reproducibility evidence has been verified.*
