# Review: PR-004 (SQL injection in `search.py`)

| | |
|---|---|
| Patch | `artifacts/prs/pr-004.patch` (raw reply: `pr-004.model_output.txt`) |
| Drafted by | `llama3:latest@sha256:365c0bd3c000`, prompt `patch_draft_v1` (`b397fa91cdf1`) |
| Target | `eval/fixtures/pr_targets/search.py` (synthetic) |
| Ask | "Rewrite it as a parameterised query using db.execute(sql, (q,)) with a ? placeholder." |
| Reviewer | R2 (AmirdeshSU). Analysis drafted with Claude Code (see `docs/AI_DISCLOSURE.md`); read and confirmed by R2 on 2026-10-27 |
| **Verdict** | **REJECT.** The patch does not apply, and its diff hides half of the fix in a context line |

## 1. It does not apply

```
$ git apply --check pr-004.patch
error: corrupt patch at pr-004.patch:8
$ git apply --check --recount pr-004.patch
error: patch failed: search.py:1
```

- **Wrong hunk length:** `@@ -1,7 +1,7 @@` for a 3-line hunk, the same defect as PR-001 to PR-003.
- **Context does not match the file**, so it fails even with the counts recomputed and whitespace
  ignored. The patch shows line 3 as unchanged context:

  ```
       return db.execute(query, (q,)).fetchall()
  ```

  But the file says `return db.execute(query).fetchall()`. The model wrote the second half of the
  fix into a line it marked as unchanged.

## 2. Why that matters more than the apply failure

A reviewer who reads only the `-`/`+` lines sees a complete-looking fix: the f-string becomes a
`?` placeholder. If they re-type that change by hand, which is the normal reaction to a patch that
"almost applies", the query gets a placeholder and no parameter. I ran all three versions against
an in-memory SQLite table with two rows:

| Version | `q = "apple"` | `q = "x' OR '1'='1"` |
|---|---|---|
| Original | 1 row | **2 rows: injection works** |
| Model's `-`/`+` lines only | `ProgrammingError: Incorrect number of bindings` | `ProgrammingError` |
| Correct two-line fix | 1 row | 0 rows |

The half-fix fails safe, because the search breaks rather than leaking data. But it would ship
a broken endpoint, and the diff gives no hint of it. **The intended change is correct**: the
placeholder plus the parameter tuple, which is the exact fix that was asked for. Only the diff
misrepresents it.

## 3. If this is re-targeted at the real app

The fixture stands in for `apps/vulnshop-api/routes/search.py`, which now exists:

- **The same helper is there** (lines 34–35), so this fix would carry over.
- **There is a second injection** in the route itself (line 42): `f"SELECT ... '{user_input}'"`,
  passed to `cursor.execute(q)`. Fixing the helper alone would leave the endpoint injectable. A scanner
  -driven patch should target each reported location, not "the file".
- **An error leak.** On error, line 48 returns the raw query and the database error message to the
  client. That's an information leak that makes the injection easier to exploit.
- **A side bug for R3, not part of this review.** The route's `finally: conn.close()` names a
  `conn` that the function never defines. It uses `get_db().cursor()` directly. The `NameError`
  raised in `finally` replaces the return value, so every request to `/api/search/` should end in a
  500. Static scanners don't care, but DAST and the demo would never reach the injection.
- **Planted vulnerability.** This is **PLANT-001**, so as with PR-003, it must not merge into the real
  app, or it removes a ground-truth item.

## What would make it acceptable

1. Generate the diff in code from the model's replacement lines (`difflib`). Then a change can
   never sit in a context line, and the hunk counts are always right.
2. Add a regression test with an injection payload, like the table above, and require it to pass
   before a draft is registered. "Applies cleanly" is not evidence that a patch is correct.
3. Re-run Semgrep (`pf-python-sqli-formatted-query`) and Bandit (B608) on the patched file, and show the finding
   is gone.

## Reproduce

```
cp eval/fixtures/pr_targets/search.py . && git init -q .
git apply --check pr-004.patch                                    # corrupt patch at line 8
git apply --check --recount --ignore-whitespace pr-004.patch      # still does not apply
```
