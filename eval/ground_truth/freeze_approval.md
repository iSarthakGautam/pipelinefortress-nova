Ground-Truth Freeze Approval

1. Approval status

Human approval status: APPROVED_FOR_FREEZE

Technical freeze status: Pending generation and verification of the merged dataset, frozen development/test split, and final freeze manifest.

Dataset version: R5 ground-truth dataset

2. Dataset identity and sampling

Source population: 264 real findings from the R2 candidate population.

Source commit: fbe9686af736240b2af673adc5e313e31351a7a0

Sampling method: All duplicate groups; one representative selected per group.

Sampling seed: 20261029

Rows selected: 98

Population exclusions: None recorded in the sampling manifest.

Sampling manifest: eval/ground_truth/data/sample-2026-10-29/sampling_manifest.json

3. Independent reviewer sign-off

Reviewer A: Signed off.

Reviewer B: Signed off.

Original independent reviewer labels are retained separately from reassessment recommendations and final adjudication outcomes.

4. Inter-rater agreement

The initial independent binary-label comparison included 49 paired cases:

Agreements: 43

Disagreements: 6

Raw agreement: 87.76%

Cohen's kappa: 0.4494

The 49 initially unresolved Reviewer B cases were excluded from the paired-binary calculation.

Calculation report: eval/ground_truth/cohen_kappa_report.md

Kappa describes initial independent binary labels and is not a post-adjudication agreement statistic.

5. Adjudication

Adjudication participants: Reviewer A and Reviewer B jointly.

Six initial disagreements were reviewed and adjudicated.

The review team accepted the 49 reassessment recommendations, as reported by the R5 owner.

Original independent labels remain preserved for auditability.

Reassessment and adjudication outcomes are maintained separately from original labels.

Disagreement evidence: eval/ground_truth/adjudication_evidence_review.md

The final merged dataset must contain the agreed outcomes and preserve the original reviewer labels.

6. Time-based split and leakage review

Approved cutoff (UTC): 2026-10-25T00:00:00Z

The recorded review covered:

98 sampled duplicate groups.

95 cluster IDs.

No cross-split duplicate-group leakage reported.

No cross-split cluster-ID leakage reported.

The final development and test split must be generated using the repository's split_and_freeze.py script. The generated split and manifest must be checked against these recorded results before technical freeze completion is declared.

7. Known limitations

Cohen's kappa applies only to the 49 initially paired binary labels.

The 49 initially unresolved Reviewer B labels were excluded from that calculation.

Original reviewer labels are preserved separately from reassessment and adjudication outcomes.

The final technical freeze remains conditional on successful generation and verification of the merged dataset, time-based split, and freeze manifest.

8. Approval decision

Human approval decision: APPROVED_FOR_FREEZE

Approved by: R5 owner — Rajdeep Kaur
Approval date: 30 October 2026

Reviewer A, Reviewer B, the adjudication participants, and the R5 owner have agreed to the ground-truth decisions and signed off, as recorded by the R5 owner.

This approval records the human decision. Technical freeze completion must be confirmed separately once all generated artifacts, split checks, and integrity hashes have been verified.




