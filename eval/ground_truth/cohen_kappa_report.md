
Cohen's Kappa Report — PipelineFortress R5
Scope
This report records the initial independent-label agreement between Reviewer A and Reviewer B. It does not measure agreement after adjudication.

Results
Metric	Result
Total sampled findings	98
Paired binary labels included	49
Reviewer B UNRESOLVED cases excluded	49
Agreements	43
Disagreements	6
Raw agreement	87.76%
Cohen's kappa	0.4494
Paired-label counts
Reviewer A	Reviewer B	Count
TRUE_POSITIVE	TRUE_POSITIVE	40
TRUE_POSITIVE	FALSE_POSITIVE	6
FALSE_POSITIVE	FALSE_POSITIVE	3
All six disagreements were cases where Reviewer A labelled TRUE_POSITIVE and Reviewer B labelled FALSE_POSITIVE.

Interpretation and limitations
The calculation uses only the 49 findings for which both reviewers supplied a binary label.
The 49 initial Reviewer B UNRESOLVED cases are excluded.
The six disagreements were subsequently jointly adjudicated by Reviewer A and Reviewer B; those adjudicated outcomes must not replace the original independent labels in this agreement calculation.
This report records the previously calculated result. It does not claim that cohen_kappa.py was executed to produce this report in this session.
The report does not establish dataset freeze readiness or replace the final freeze manifest.
Reproducibility
Use the repository's cohen_kappa.py with the original independent Reviewer A and Reviewer B labels, joined by finding_id, and exclude Reviewer B UNRESOLVED rows before calculating binary Cohen's kappa.

Report status: Initial agreement report; preserve alongside original reviewer labels.

⋮⋮⋮⋮
