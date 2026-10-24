# R5 Ground-truth protocol

## 1. Purpose and unit of analysis
The unit is one normalized security finding presented to the triage system. Preserve the source finding ID and source artefact. Do not relabel a model output as ground truth. Labels describe the finding's security validity, not whether the model agrees.

## 2. Sampling plan
1. Freeze the candidate population before selecting the evaluation sample. Include scanner/tool, rule family, severity/priority, repository path, and collection timestamp where available.
2. Sample across available tools and finding classes, including true positives and false positives where ground truth can be established. Document the population size, exclusions, sampling method, random seed if random sampling is used, and counts by stratum.
3. Avoid selecting only easy or model-familiar cases. Keep R3's planted vulnerabilities and any post-cutoff findings held out from prompt tuning where feasible.
4. If the real scanner population or R3 planted-vulnerability manifest is unavailable, explicitly state that the evaluation is synthetic/incomplete. Do not present the current 10-row smoke set as representative.

## 3. Two independent labellers
- Two reviewers label every sampled item independently before discussion.
- Each reviewer records label, rationale, evidence link, reviewer ID, and timestamp in separate columns/files.
- Reviewers must not see the other reviewer's label before submitting their own labels.
- Allowed primary labels: `TRUE_POSITIVE`, `FALSE_POSITIVE`, `NEEDS_HUMAN_REVIEW` (only if the project rubric defines this as a ground-truth class; otherwise use `UNRESOLVED` as an annotation state, not a model outcome).
- Reviewers must cite the underlying code/config, scanner output, CVE/advisory or policy evidence. Absence of evidence is not automatically a false positive.
- Keep a record of instructions and any label-definition changes. If definitions change, version the protocol and relabel affected records.

## 4. Agreement and adjudication
1. Calculate raw agreement and Cohen's κ on records independently labelled by both reviewers. Exclude blank/unresolved labels from the primary calculation and report the excluded count; do not silently drop disagreements.
2. κ = (observed agreement − expected agreement by chance) / (1 − expected agreement by chance). Report κ alongside raw agreement and the class distribution; κ alone can mislead with imbalanced classes.
3. After independent labels and agreement are frozen, review disagreements with a third reviewer or a documented joint adjudication. Record original labels, final label, rationale, adjudicator, date and evidence.
4. Do not replace the original independent labels with adjudicated labels in the agreement calculation.
5. If only one reviewer is available, report κ as **not calculable**. Do not manufacture a second label column.

## 5. Time-based split and leakage controls
- Use a trustworthy event/first-seen timestamp for each record. Define the cutoff before evaluating the model; older records form the development set and newer records form the held-out test set.
- Group related duplicate/cluster records together to prevent the same underlying issue leaking across both splits.
- Keep the held-out labels inaccessible to prompt/model tuning until the configuration is frozen.
- Record cutoff, timezone, source timestamp field, row counts, duplicate-group policy, exclusions and hashes in the freeze manifest.
- The supplied 10-row `eval/ground_truth.jsonl` has no timestamp field; it cannot support a defensible time split as currently supplied. Collect timestamped records first. Do not use file order or invent dates as a substitute.

## 6. Freeze and versioning
After two labels, adjudication and split decisions are complete:
1. Save the final dataset as a versioned immutable file (e.g. `r5/evaluation/data/ground_truth_v1.jsonl`).
2. Run `split_and_freeze.py` to produce split files and SHA-256 manifest.
3. Commit dataset, manifest, protocol version and reviewer instructions together. If any row changes, create a new version and hash; never silently update the frozen file.
4. Record who approved the freeze and when in `freeze_approval.md`.

## Current status for this repository
The supplied 10-row dataset is synthetic and single-labelled. `ground_truth/planted.yaml` is empty in the supplied ZIP. Therefore two-labeller agreement, adjudication, a real time-based split, and a final held-out set remain pending until real evidence/labels are provided.
