# Review: PR-003 (lodash bump in `package.json`)

| | |
|---|---|
| Patch | `artifacts/prs/pr-003.patch` (raw reply: `pr-003.model_output.txt`) |
| Drafted by | `llama3:latest@sha256:365c0bd3c000`, prompt `patch_draft_v1` (`b397fa91cdf1`) |
| Target | `eval/fixtures/pr_targets/package.json` (synthetic) |
| Ask | "Bump the dependency 'lodash' from 4.17.15 to 4.17.21. Change nothing else." |
| Reviewer | R2 (AmirdeshSU), 2026-10-27. Analysis drafted with Claude Code (see `docs/AI_DISCLOSURE.md`) |
| **Verdict** | **REJECT.** The patch does not apply, and the version it was asked for is no longer safe |

## 1. It does not apply

```
$ git apply --check pr-003.patch
error: corrupt patch at pr-003.patch:8
```

There are two independent defects:

- **Wrong hunk length.** The header `@@ -5,7 +5,7 @@` claims 7 lines on each side; the hunk has 3.
  The model copied the usual 3-lines-of-context shape and did not count its own lines.
- **Mangled indentation.** The file indents with 4 spaces. The context lines carry 3 and 1, and the
  `-`/`+` lines carry 1. With the counts recomputed (`git apply --recount`) it still fails
  (`patch failed: package.json:5`). It only applies with `--recount --ignore-whitespace`, and then it
  writes `lodash` with a 1-space indent. The result is valid JSON, but nobody would accept that diff.

## 2. The ask is stale, so even a perfect patch is not a fix

The version change itself is exactly what was asked: `4.17.15` → `4.17.21`, nothing else. The
problem is the ask. As of 2026-10-27, OSV (`api.osv.dev`, npm `lodash`) lists:

| Version | Open advisories |
|---|---|
| 4.17.15 | 6: CVE-2020-8203, CVE-2020-28500, CVE-2021-23337, CVE-2025-13465, CVE-2026-2950, CVE-2026-4800 |
| 4.17.21 | **3**: CVE-2025-13465 (prototype pollution in `_.unset`/`_.omit`, fixed 4.17.23); CVE-2026-2950 (same class, array-path bypass, fixed 4.18.0); CVE-2026-4800 (**code injection** via `_.template` imports, fixed 4.18.0) |

Merging this would close the advisory that was asked about and leave a code-injection advisory open.
The correct target today is **≥ 4.18.0**, which is a minor-version bump, so check the changelog
for breaking changes.

**Lesson for the triage design.** The model did what it was told. The fixed version was written
into the task by a human, from memory, and it went stale. A fix version should come from the
scanner's `fixed_version` at run time, checked against OSV, never from the prompt. R4's grounding
validator already checks a model-claimed version against the scanner record. This case shows the
*task* needs the same check.

## 3. Even a correct version bump is incomplete

- **No lockfile.** `apps/vulnshop-api/` has `package.json` only. `npm install` resolves the tree
  freshly each time, and none of our three SCA scanners can verify the fix, because they all read
  lockfiles (`docs/metrics/DETECTOR_OVERLAP.md`). A real fix PR must commit `package-lock.json`
  alongside the bump.
- **No test.** The app has no npm tests, so nothing shows the bump breaks nothing.

## 4. Do not re-target this at the real app

The fixture stands in for `apps/vulnshop-api/package.json`, which now exists. There, lodash 4.17.15
is **PLANT-005**, a planted vulnerability in `ground_truth/planted.yaml`. Fixing it in the real
app would delete a ground-truth item from the evaluation. If `ai/pr_bot.py` is re-run against R3's
real files, as the fixture README suggests, its PRs must stay drafts and never merge.

## What would make it acceptable

1. Generate the diff in code, not in the model. The model returns the new line (or the whole
   file), and `difflib` produces the hunk. That removes both defects in §1.
2. Take the target version from scanner data, not the prompt: `lodash` ≥ 4.18.0 today.
3. Ship it with the regenerated `package-lock.json`, and re-run the SCA scan to show the advisory
   count drop to zero.

## Reproduce

```
cp eval/fixtures/pr_targets/package.json . && git init -q .
git apply --check pr-003.patch                                    # corrupt patch at line 8
git apply --check --recount pr-003.patch                          # patch does not apply
git apply --check --recount --ignore-whitespace pr-003.patch      # applies, with mangled indentation
curl -s https://api.osv.dev/v1/query \
  -d '{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.21"}'   # 3 advisories
```
