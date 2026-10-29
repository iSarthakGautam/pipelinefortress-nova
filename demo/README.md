# PipelineFortress demo (Team Nova)

A 20-slide, animated, keyboard-driven presentation plus an offline results dashboard. A code file is pushed and travels through every pipeline stage; at each stop a bad actor attacks and we show what stops it; an AI reviewer joins at triage; a human decides; the real results close the story.

No build step, no dependencies, no network: plain HTML, CSS and JavaScript.

```bash
make demo-prep                       # builds the results page + report, starts Grafana if Docker is up, opens every window
open demo/index.html                 # just the deck (press F for fullscreen)
make demo-slides                     # or serve it at http://localhost:8080
```

| Key / button | Action |
|---|---|
| `→` / `Space` / **Next** | Next step (each slide reveals in steps; the last step of a stage slide plays the attack) |
| `←` / **Back** | Back one step |
| `A` | Replay the attack on this slide |
| `N` / **Notes** | Speaker notes + timer (target time per slide, ahead/behind) |
| `G` / **Slides** | Jump to any slide |
| `P` / **⬇ PDF** | Export all 20 slides to PDF (1280x720 pages, every step shown) |
| `F` | Fullscreen |
| `T` | Reset the timer |

**PDF export:** click **⬇ PDF**, choose *Save as PDF*, margins *None*, tick *Background graphics*. Headless: `chrome --headless --no-pdf-header-footer --print-to-pdf=deck.pdf "file:///.../demo/index.html?print=1"`.

**Team names:** slide 19 has five empty name fields (R1 to R5). Type them in; they are remembered in this browser. To fix them in the file, set `value="..."` on each `input.name` in `index.html`, then export the PDF again.

URL options: `index.html#11` opens slide 11; `?step=3` sets the step; `?static=1` turns animations off (screenshots); `?notes=1` opens the notes; `?print=1` prepares the print layout.

## Files
- `index.html`: the 20 slides and their speaker notes (`<aside class="notes">`)
- `css/style.css`, `js/app.js`: the look, navigation, pipeline rail, attack animation, notes/timer, PDF export
- `results.html`: the offline results dashboard (generated: `python3 scripts/build_demo_results.py`, or `make demo-prep`)
- `DEMO_SCRIPT.md`: word-for-word script for the 8:40 main path and the ~11 minute version with the cuts to other windows, live inserts, Q&A, fallbacks, rehearsal plan

## What is real and what is illustration
Every number and every output on the slides and in `results.html` comes from this repository (`eval/`, `docs/`, `artifacts/`); the redaction result and the llama3 verdict were captured on 2026-10-29. The characters, the conveyor and the attack animations are illustration: they depict what each control does and point to the tests or runs that exercise it. The only live attacks in the repo are the loopback probes in `scripts/runtime_baseline.py` against our own lab app. Re-check the numbers against the latest CI run before presenting (`DEMO_SCRIPT.md`, section 0).
