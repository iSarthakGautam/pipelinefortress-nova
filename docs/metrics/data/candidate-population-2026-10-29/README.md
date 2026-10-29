# Candidate population for the ground-truth sample (R2)

`GROUND_TRUTH_PROTOCOL.md` §2.1 asks for the candidate population to be frozen **before** the
sample is drawn. This is that population: every normalized finding from one real scan of main.
It has **no labels**. Sampling is R5's job and labelling belongs to the two reviewers (§3);
nothing here suggests what any label should be.

| | |
|---|---|
| Source | CI run 40762500169 (push to main, 2026-10-28T20:21:09Z), artifacts `findings` + `raw-scans` |
| Scanned commit | `fbe9686af736240b2af673adc5e313e31351a7a0` (committed 2026-10-28T20:21:06Z) |
| Rows | 264 findings in 98 duplicate groups (`dup_group`) and 257 triage clusters (`cluster_id`) |
| Exclusions | none; snippets and messages are left out (they are runner-local evidence) |
| File | `population.csv`, SHA-256 `f0a8f0cd5a9b42c1b027fb3bec3c112bb53796820db24d0f59b6b35fbbff0e7b` (LF line endings, as committed; check with `git show HEAD:<path> \| sha256sum`) |
| Rebuild | `build_population.py` (usage in its docstring) |

## Strata (§2.2)
| Family | Tool | CRITICAL | HIGH | MEDIUM | LOW | Findings | Distinct groups |
|---|---|---|---|---|---|---|---|
| iac | checkov | 0 | 2 | 25 | 0 | 27 | 3 |
| iac | trivy | 0 | 4 | 3 | 13 | 20 | 7 |
| sast | bandit | 0 | 1 | 4 | 5 | 10 | 10 |
| sast | semgrep | 0 | 15 | 9 | 1 | 25 | 18 |
| sca | grype | 1 | 20 | 33 | 8 | 62 | 61 |
| sca | osv | 2 | 26 | 33 | 4 | 65 | 65 |
| sca | trivy | 1 | 20 | 26 | 8 | 55 | 54 |

There are no gitleaks findings at this commit and no INFO findings. The 182 SCA findings are
**67 distinct vulnerabilities**: the same three tools mostly report the same CVE. Sampling
findings rather than `dup_group`s would oversample SCA about 3×.

## Columns
- **`cluster_id`**: R4's triage cluster (`ai/cluster.py`, `tool::rule::file`): what the model is shown once.
- **`dup_group`**: records that must stay on one side of a split (§5).
  - **SCA:** crosscheck's linking (same manifest, package and vulnerability ID).
  - **Everything else:** one group per `file:line`, which can join different rules on one line.
  - Until ADR-002 (#50) merges, asteval's `GHSA-9w56-46f6-3qhx` (Grype) and
    `CVE-2026-102734` (OSV) are two groups.
- **`first_seen`**, in UTC:
  - **Code finding:** the commit time of the flagged line (`git blame`).
  - **Dependency finding:** the later of the advisory's publish date and the manifest's first
    commit. This is a lower bound.
  - **Otherwise:** the file's first commit.

  The source is in `first_seen_source`. No row is unknown.
- **`advisory_published`**: the earliest publish date in OSV or Trivy for the finding's IDs.
  It's blank for the one vulnerability neither source dates, `NSWG-ECO-516`.

## What this means for §2.3 and §5 (for R5)
- **A time split on `first_seen` covers only 4 days.**
  - 181 findings date from 2026-10-25T10:07:36Z, when #17 (commit 231e991) added the target
    app, its manifests, Kubernetes specs and Dockerfile.
  - 65 findings date from 2026-10-28T17:45:35Z, when #42 (commit a775cac) added the
    vulnshop-api `package-lock.json`.

  A cutoff is possible, but it would split by "which PR added the code", not by age.
- **`advisory_published` is the better held-out signal for SCA.** Of the 67 distinct
  vulnerabilities, these many were published on or after each date:

  | Date | Vulnerabilities |
  |---|---|
  | 2024-01-01 | 53 |
  | 2025-01-01 | 34 |
  | 2026-01-01 | 27 |
  | 2026-07-01 | 16 |

  The "post-cutoff findings" of §2.3 are the ones published after the training cutoff of the
  models §9 ran (`llama3`, `gemma2`); R5 sets that date from the models' documentation.
- **The planted vulnerabilities** (`ground_truth/planted.yaml`) are matched by location, not by
  finding ID. `docs/metrics/data/gate-tuning-2026-10-27/threshold_sim.py` shows how. §2.3 asks
  to keep them out of prompt tuning.
