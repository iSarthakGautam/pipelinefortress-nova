# Demo script: "One pull request walks into a pipeline"

**Team Nova · PipelineFortress.** 20 slides, one story: a developer pushes a file with a real vulnerability; it travels through every pipeline stage; at each stop a bad actor attacks and we show what stops it; an AI reviewer joins at triage; a human decides. At the end we show the real results.

| Version | Length | When to use |
|---|---|---|
| **Main path** (deck only) | **8:40** | The official 8-minute slot with a little slack |
| **Recommended** (deck + 5 window cuts) | **≈ 11:00** | Panel with time for a live feel; the cuts are what make it look like a real, running project |
| **Short** | ≈ 5:30 | Skip slides 3, 6, 12, 19 and every cut. See section 4 |

**The sentence to land twice (open and close):** *Anyone can rebuild this from the repo in under an hour, and every claim the model makes is checkable against evidence we also ship.*

**Story framing for the panel:** this is a finished engineering project. All seven deliverables in the brief are built, tested, and in the repo (slide 17), including human review notes on the AI-drafted pull requests and the dual-annotator adjudicated 98-issue dataset freeze.

---

## 0. Setup (do this 30 minutes before; 10 if you only have 10)

### 0.1 One command
```bash
make demo-prep          # = bash scripts/demo_prep.sh
# optional: PF_RUN_URL=<latest green Actions run> PF_PR_URL=<PR with the AI comment> make demo-prep
```
It rebuilds `demo/results.html` and `build/report.html`, recomputes the catch rate if `artifacts/findings.json` exists, starts Grafana and pushes metrics if Docker is running, checks Ollama, and opens the windows. Anything it cannot do it lists as a fallback, and every window below has an offline fallback.

### 0.2 The windows (put each on its own desktop/space, in this order, so `Ctrl+←/→` walks them)

| # | Window | What it is | Open it with | Offline fallback |
|---|---|---|---|---|
| **W1** | **The deck** | Fullscreen, this is home | `open demo/index.html`, press **F** | the PDF: **⬇ PDF** button or `P` |
| **W2** | **Results dashboard** | Real numbers from the repo's own files: catch rate, funnel, bake-off, runtime proof, AI metrics, PRs | `open demo/results.html` | it *is* the fallback |
| **W3** | **Grafana** (live dashboard) | `http://localhost:3001` → "PipelineFortress — AI Triage Monitoring" | `make dash`, then `demo_prep.sh` pushes data | W2 |
| **W4** | **GitHub Actions run** | The real pipeline graph of the latest green run + its step summary (catch-rate table) | open `$PF_RUN_URL` | screenshot saved in `artifacts/evidence/` |
| **W5** | **The AI PR** | The real PR with the triage comment and the policy-bot comment | open `$PF_PR_URL` | `artifacts/demo/out/pr_comment.md` in an editor |
| **W6** | **Terminal** | In the repo, venv active, big font (≥ 18 pt), dark theme | `cd` to the repo | pre-run output is on disk (see each cut) |
| **W7** | **Editor / repo tree** | Repo open at the root; tabs ready for `ai/validate.py`, `artifacts/prs/v2/pr-004.patch`, `docs/BASELINE_VULNERABILITY_REPORT.md` | VS Code | n/a |

**Switching rule:** say the sentence *before* you switch ("let me show you the real thing"), switch, show for the stated seconds, say what to notice, come back to W1 with **one** gesture. Never explain a window while looking for it.

### 0.3 Pre-flight checklist
- [ ] Deck opens, **F** = fullscreen, **N** shows the notes, **P** exports the PDF (do it once and keep the PDF as backup)
- [ ] **Team slide (19): names typed**, then re-export the PDF so the names are in it
- [ ] `make catch-rate` run on the **latest** CI artifact; if the number is not 8/10, edit slide 16 (search `8/10` in `demo/index.html`) and say the new one
- [ ] Slide 14 and 17 confirm all 4 v2 patches have formal human reviews in `artifacts/prs/reviews/` (2 accepted w/ limits, 2 rejected)
- [ ] Ollama running with `llama3:latest` (only for live inserts B and C; otherwise show the saved output)
- [ ] W4/W5 URLs open and logged in
- [ ] Notifications off, fonts big, a glass of water

**Keys:** **→ / Space** next · **←** back · **A** replay the attack · **N** notes · **G** jump · **F** fullscreen · **P** PDF · **T** reset timer · **Home/End**. Each slide reveals in steps; the last step of a stage slide plays the attack.

---

## 1. Slide by slide

Say the **bold** lines nearly word for word. **▶ CUT** marks a switch to another window (skip it in the main path). Times are cumulative on the main path; each cut adds its own seconds.

### 1 · Title (0:20 → 0:20)
- **→** tagline, **→** chips.
- **"We are Team Nova. One sentence for the project: anyone can rebuild this from the repo in under an hour, and every claim the model makes is checkable against evidence we ship. I'll follow one real file through the pipeline."**

### 2 · The problem (0:25 → 0:45)
- Reveal 30+, 1×, 80%; pause on 80%.
- **"The CISO's problem: thirty deploys a day, one review a sprint, and they want eighty percent of bugs caught before merge. The trap is the gate: if it's red on every pull request, developers switch it off. So we built a gate people keep on, and an AI that can't be turned against us."**
- Land the four rules; they come back at the end.

### 3 · The cast (0:15 → 1:00)
- Five reveals, then the banner.
- **"Five characters. Only one can merge: the human. The AI reviewer has no tools, no credentials, and no 'approve' field."**

### 4 · The pipeline in 3D (0:30 → 1:30)
- **→** conveyor, **→** the file runs, **→** stops red at the gate, **→** flattens with the legend.
- **"The whole route as a conveyor. The file has to stop at every station, and it stops at the gate because it carries a real vulnerability. Three kinds of things live here: code that decides, a model that only suggests, and a human who merges."**
- **▶ CUT A · W4 GitHub Actions run (20 s).** *"This is the real thing."* Show the job graph: build → scanners → normalize+baseline → triage → comment → gate, and the container/kind/DAST stages beside it. Point at the green and the one intentional red. *"Same stations as the animation."* Back to W1.

### 5 · Push (0:35 → 2:05) ← first attack
- **→** hooks, **→** why it matters, **→** the attack plays by itself.
- **"This is the file. Line 42 builds SQL with an f-string, a classic injection planted on purpose. Before it leaves the laptop two hooks run. The bad actor tries `git push origin feature:main`. Blocked: the hook checks the pushed ref, not the current branch. Our first version got this wrong; we found it in review and tested the fix against a bare remote."**

### 6 · Build and test (0:15 → 2:20)
- **"Stage zero is boring on purpose: two hundred thirty-seven tests, no network, no model. The interesting part is the pipeline protects itself: actions pinned by commit SHA, scanner binaries by sha256."**

### 7 · Scanners (0:35 → 2:55)
- **"Scanners run in parallel. Semgrep and Bandit both flag line 42. Three SCA tools on purpose, because where they disagree is a metric. One honest finding: the planted AWS key is the public example key, so gitleaks ignores it and our own Semgrep rule catches it. We say so in the report."**

### 8 · Baseline diff (0:30 → 3:25)
- Funnel 264 → 98 → 1 new.
- **"This is what makes the gate usable. Two hundred sixty-four findings collapse to ninety-eight real issues; existing debt is accepted in a reviewed baseline, so the gate only fails on what's new, and our injection is new. The bad actor's trick, rewriting an accepted line to reuse its slot, changes the line fingerprint and counts as new."**
- **▶ CUT B · W2 Results dashboard, "Noise to signal" panel (15 s).** *"Same funnel, computed from the real scan: 264 findings, 98 issues, by tool and by severity."* Back.

### 9 · AI: redaction (0:25 → 3:50)
- **"Before the model sees anything, four layers of redaction. This output is real: the email and the AWS key are gone. A canary check blocks the call if anything survives, and the egress guard allows loopback only, so the model physically can't phone home."**
- **▶ CUT C · W6 Terminal (30 s):** `python3 ai/redaction/redactor.py` → shows the redacted record, `canary self-test passes: True`, and the four egress decisions (localhost allowed, the three lookalikes denied). *"Sixty-three of sixty-three adversarial fixtures pass, with the caveat that the same person wrote both."* Back.

### 10 · The AI is attacked (0:40 → 4:30) ← the highlight
- **→** the planted comment, **→** no defence, **→** framing only, **→** detector, **→** last attack.
- **"Now they attack the AI itself: an instruction hidden in a code comment. We ran it for real with llama3. With no defence it obeyed. Delimiters alone did not stop it. What held is a detector that routes the finding to a human without calling the model, plus the architecture: no approve field, no tools, no credentials. The safety is in the plumbing, not the prompt."**
- Slow down on "delimiters alone did not stop it": admitting it is the credibility moment.
- **▶ CUT D · W7 open `eval/injection_demo_results.md` (20 s)** *or* run `python3 eval/injection_demo.py` live (needs Ollama, 60 s).

### 11 · The AI reviewer (0:55 → 5:25) ← the "agent walks in" moment
- **→** robot flies in, **→** the finding, **→** it reasons (typed), **→** verdict, **→** validator, **→** priority.
- **"Now the AI reviewer on the clean file. It gets only the redacted finding and returns a verdict in a fixed JSON shape. This is real llama3 output. Then the part I care about: a validator in plain code checks every identifier the model relied on. Models in our runs invented a CWE that doesn't exist and a fix version that wasn't in the scanner data; none reached a human. Priority is computed by code. The model suggests; it can't merge."**
- **▶ CUT E · W7 `artifacts/llm_trace/trace.jsonl` (20 s):** one line per model call: prompt hash, model digest, raw reply, validator verdict, hash-chained. *"Everything it said is replayable."* Back.
- If asked: n = 10 smoke set; llama3 was confidently wrong on two rows; the validator catches unproven claims, not wrong judgement.

### 12 · The PR comment (0:20 → 5:45)
- **"What the developer sees: one comment, clustered and prioritised, not a wall of alerts. Below it the policy bot from the brief's stretch list. On five rules it was right three times and invented a Kubernetes setting once, so it's advisory."**
- **▶ CUT F · W5 the real PR (25 s):** scroll to the bot comment. *"Posted by the pipeline, escaped and checked; the AI cannot approve."* Back.

### 13 · The gate (0:25 → 6:10)
- **"The file stops at the gate. One deterministic exit code decides. If the model is down, wrong or hijacked, the answer is the same. The bad actor's last trick is cancelling the scan so the job shows as skipped, which GitHub counts as passing. Our gate runs even when cancelled and fails unless the scan actually succeeded."**

### 14 · The fix and the AI-drafted PR (0:30 → 6:40)
- The token jumps back to Push: "second push".
- **"A fix arrives. Our bot drafts these as draft pull requests that a human decides on. We had a real failure: the model wrote the diff and none of four patches applied, because models can't count hunk lines. Now the model returns the whole file and code computes the diff; all four apply. But applying isn't correct, so people review them, and we show a rejection on purpose: the lodash bump still has open advisories."**
- **▶ CUT G · W7 `artifacts/prs/v2/pr-004.patch` and `PR_REGISTER.md` (20 s):** the three-line diff, the "lines changed" column.
- Point to `artifacts/prs/reviews/`: all 4 v2 patches have formal human reviews on record (2 accepted w/ limits, 2 rejected).

### 15 · Ship (0:25 → 7:05)
- **"After the code is clean: the image is scanned, a software bill of materials in both standard formats, a Rego policy against CIS. We prove the policy bites: the hardened manifest passes ten of ten, the planted bad one fails six. Then a kind cluster and ZAP. Honest status: advisory until a few green runs."**
- **▶ CUT H · W6 `make policy` (20 s)** shows pass and fail, or W4 → artifact `container-sbom` (SBOM JSON).

### 16 · The scoreboard (0:25 → 7:30)
- **"Did it work? Eight of ten planted vulnerabilities caught before merge on the last full scan, seven rated high enough to block, neither safe control flagged. That's against the CISO's eighty percent, with the caveat that we planted them. Ninety-eight issues from two hundred sixty-four findings is why the gate stays usable. Zero hallucinated identifiers reached a human. And we proved the planted bugs are real by attacking our own app on localhost."**
- **▶ CUT I · W2 Results dashboard (30 s), top to bottom:** catch-rate table (point at the two "missed" rows and say why), bake-off, runtime proof table ("exploitable" in red). *"All of this is computed from files in the repo."*
- **▶ CUT J · W3 Grafana (20 s)** if live: the four "planted" panels and the AI-triage panels. *"The live twin."*

### 17 · Deliverables (0:25 → 7:55)
- One row per press.
- **"The brief lists seven deliverables; here is each one and where it lives. The pipeline, the policy as code, the hardened image with its bill of materials, the triage tool with redaction and a versioned prompt library, the remediation pull requests with human review notes, the dashboard, and the report. All built and accounted for in the repo."**
- **▶ CUT K · W7 repo tree (15 s):** scroll the folders `.github/ ai/ scanners/ infra/ docker/ eval/ dashboards/ docs/`. *"It's all real."*

### 18 · Scope, limits and what comes next (0:20 → 8:15)
- **"Said plainly so the numbers can be trusted. Our initial automated bake-off used ten smoke fixtures; the full ground truth v1 is now frozen at ninety-eight consensus issues with dual-annotator adjudication. The model is confidently wrong sometimes, and a validator can't catch bad judgement. Some stages are advisory until their first green runs. And we planted the bugs, so the catch rate is recall on known plants."**
- Do not rush this slide.

### 19 · Team Nova (0:10 → 8:25)
- Introduce each person by name and one sentence.
- **"R1 pipeline and platform, R2 scanners and policy, R3 container and supply chain, R4 AI, R5 data, metrics and report. Each of us defends someone else's slice."**

### 20 · Close (0:15 → 8:40)
- **"The sentence we were graded on: anyone can rebuild this from the repo in under an hour, and every claim the model makes is checkable against evidence we ship. Here are the commands. Happy to take questions; press G to jump to any slide."**

---

## 2. The recommended 11-minute version: which cuts

Keep **A, B, C, E, I** (about 2 min 20 s). Add **D, F, G, H, J, K** if you have time. If anything is slow to switch, drop that cut and say the output is in the evidence index.

| Cut | After slide | Window | Seconds | Proves |
|---|---|---|---|---|
| A | 4 | W4 Actions run | 20 | the pipeline is real |
| B | 8 | W2 funnel panel | 15 | 264 → 98 |
| C | 9 | W6 `redactor.py` | 30 | redaction + canary + egress |
| D | 10 | W7 injection results | 20 | the AI attack was run |
| E | 11 | W7 `trace.jsonl` | 20 | replayable AI calls |
| F | 12 | W5 PR comment | 25 | posted by the pipeline |
| G | 14 | W7 patch + register | 20 | PR bot output |
| H | 15 | W6 `make policy` / SBOM | 20 | policy bites, SBOM exists |
| I | 16 | W2 results | 30 | real numbers |
| J | 16 | W3 Grafana | 20 | live dashboard |
| K | 17 | W7 repo tree | 15 | complete project |

## 3. Live inserts (need Ollama, optional)

| Insert | Command | Output | Fallback |
|---|---|---|---|
| Redaction | `python3 ai/redaction/redactor.py` | redacted record + canary pass + 4 egress decisions | none needed, no model |
| Injection before/after | `python3 eval/injection_demo.py` | followed / framed / detector | `eval/injection_demo_results.md` |
| End-to-end triage | `make demo-local` | stub scanner input → llama3 → comment + metrics + trace | `artifacts/demo/out/` already holds it |
| Policy check | `make policy` | hardened 10/10 pass, bad manifest fails | `infra/policy/` + screenshot |
| Runtime probes | `python3 scripts/runtime_baseline.py` | live attacks on the lab app (loopback) | the "runtime proof" panel in W2 |

## 4. Short version (≈ 5:30)
Slides 1, 2, 4, 5, 7, 8, 10, 11, 13, 14, 16, 18, 20. Press **G** and click to jump. No cuts except I (results, 20 s).

---

## 5. Questions you will be asked (press **G** to jump)

| Question | Answer in one breath | Slide / window |
|---|---|---|
| "Show me a case where the LLM was wrong." | llama3 called a parameterised query and a `helmet.frameguard` header true positives (gt-002, gt-010). The validator can't catch judgement errors; that is why abstention and human review exist. | 11 · W2 bake-off |
| "How do you know no secret reached the model?" | Four-layer redaction, canary check before every call, pre-egress tripwire, loopback-only egress with a log (`artifacts/evidence/egress/egress.log`). Caveat: same author wrote fixtures and redactor. | 9 · cut C |
| "Why this model? Would a 70B be better?" | Local 8B with grammar-constrained JSON and a hard validator. Bake-off of three models with ablations; n = 10, so we claim a design, not accuracy. | 16 · W2 |
| "Juice Shop has 300 HIGHs. How is your gate usable?" | Baseline diffing: fail on new findings only, reviewed baseline, expiring exceptions. | 8 · cut B |
| "What is your false-negative rate?" | On what we planted: 8 of 10 on the last full scan; the misses were an unscanned lockfile and a moved line. On unknown bugs we don't know, and we say so. | 16 · W2 |
| "Could someone attack your triage bot?" | We did, first: prompt injection in a code comment. Framing alone failed; the detector and the architecture held. | 10 |
| "Is the AI allowed to merge?" | No: no tools, no credentials, no approve field, and the merge gate never reads its output. | 13 |
| "What would you do next?" | Two-reviewer labels and κ on the frozen 98-issue set; close the remaining gate edge cases; first green runs for the advisory stages. | 18 |
| "Did AI help write this?" | Yes. Every use is in `docs/AI_DISCLOSURE.md`, including two entries we had to correct. | 20 |

## 6. If something breaks

| Problem | Do this |
|---|---|
| Deck won't open | Open the PDF (⬇ PDF button or `P` earlier); backup: `docs/slides/pipelinefortress.md` (Marp) |
| An animation glitches | **←** then **→** to replay the step, or **A** to replay the attack |
| A window is missing or slow | Skip that cut; say "the output is in the evidence index", and use W2 (the offline dashboard) |
| Grafana empty | Use W2. Say "the same data, offline" |
| Ollama down during a live insert | Say "this is the degrade-don't-block case" and run `make triage`: every finding becomes `NEEDS_HUMAN_REVIEW`, exit 0. That is a feature |
| Running over | Drop all cuts; never skip slides 10, 11, 16, 18 |
| A question you can't answer | "I'm not certain; the evidence index is `artifacts/evidence/INDEX.md`, and I won't guess." |

## 7. Rehearsal (two runs, as the team plan requires)

1. **Run 1, deck only, with the timer (N).** Target 8:40. Mark where you were late.
2. **Run 2, full 11-minute version with all windows, a teammate as the panel.** They interrupt on slides 10, 11 and 18 with the questions above. Practise one-gesture switching between windows.
3. Record run 2: that is the fallback video.

*Every number in the deck comes from a file in this repository (`eval/results.md`, `docs/BASELINE_VULNERABILITY_REPORT.md`, `docs/metrics/`, `artifacts/`). `make demo-prep` rebuilds the results window from them.*
