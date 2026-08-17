# SDLC validators v1 — `validate_zros` and `claim_sweep`

Two instruments, zero dependencies, Python standard library only.

They exist because both operating documents name their own absence as the thing
that makes everything else a ritual:

> "Known weakness: the ledger has no validator yet — rules R1–R5 are prose; the
> machine check … is specified but unbuilt. Until built, the ledger is exactly
> the kind of ritual M9 warns about."
> `[QUOTED: claude/APEX-v6.0.md §SELF-AUDIT finding 5]`

> "STANDING PRIORITY: until validate_zros and the claim-ledger sweep exist as
> runnable code, every rule above is a ritual and M9 says rituals fail"
> `[QUOTED: claude/PROJECT-INSTRUCTIONS.md]`

| file | what it enforces |
|---|---|
| `validate_zros.py` | ZROS-FORGE v1.1 `<validator_spec id="V">`, checks V1–V12 |
| `claim_sweep.py` | APEX v6.0 §C2 Reality Ladder + §C4 rules R1–R5, checks CS1–CS8 |
| `claim_ledger-titan-v1.json` | the CL-1…CL-7 rows of APEX Part V, machine-readable |
| `fixtures/` | every known-bad and known-good case both instruments must catch or pass |

---

## Run them

Both blocks are paste-safe: absolute `cd` first, an existence check before any
consume step, every dependent step `&&`-chained, no placeholders, nothing
interactive.

The destination path below is `[QUOTED: claude/START-HERE-titan-gate.md "repo:
~/01-Projects/titan-gate"]` and is **not** `[MEASURED:]` — the session that wrote
these files could not reach that machine. If the path is wrong, the first
command fails loudly rather than doing something in the wrong directory.

```bash
cd ~/01-Projects/titan-gate && test -d sdlc && echo SDLC_DIR_OK
```

```bash
cd ~/01-Projects/titan-gate/sdlc && test -f validate_zros.py && python validate_zros.py --selftest && python validate_zros.py --selftest-meta && python claim_sweep.py --selftest && python claim_sweep.py --selftest-meta
```

Run those four before trusting a single verdict either tool produces. They are
the answer to "presence of a check is not truth of a check" (L6).

Sweeping the real ledger:

```bash
cd ~/01-Projects/titan-gate/sdlc && test -f claim_ledger-titan-v1.json && python claim_sweep.py claim_ledger-titan-v1.json --all
```

Add `--artifact` once per shipped surface so R1 can actually sweep them:

```bash
cd ~/01-Projects/titan-gate/sdlc && test -f claim_ledger-titan-v1.json && python claim_sweep.py claim_ledger-titan-v1.json --artifact ../../titan-gate-public/README.md --artifact ../../titan-gate-public/SPEC.md --all
```

## Exit codes

`validate_zros`: `0` clean · `1` FAIL · `2` CRITICAL (V7 tag-truth mismatch,
strictly above FAIL) · `3` usage or parse error.
`claim_sweep`: `0` no BLOCK · `1` BLOCK · `3` usage or parse error.

## The checks

| id | name | descends from |
|---|---|---|
| V1 | parentage; ANTICIPATED needs EXISTENTIAL + a complete consequence model | P1, gate schema |
| V2 | coverage — every usable incident is a parent, ACCEPTED or CALIBRATION | Stage 5 |
| V3 | fixture proof — known_bad must BLOCK, known_good must PASS | G4 |
| V4 | untagged numeral sweep, exemptions derived from the fixtures | provenance law |
| V5 | placeholder ban, runnable destinations only | M5 |
| V6 | block safety: absolute cd, `&&`-chained destructives, nothing interactive | M5 |
| V7 | tag-truth sampling — re-executes `[MEASURED:]` commands | the tag-truth rule |
| V8 | no hardcoded counts | M3 |
| V9 | selftest before ship, asserted on ids | APPENDIX-V warning 2 |
| V10 | exemption tamper guard, runs against a diff | G7, M4 |
| V11 | runbook projection, including subtotal arithmetic | Stage 4b |
| V12 | law cache coherence — a law citing no gate is a slogan | Stage 4b |

| id | name | descends from |
|---|---|---|
| CS1 | a row below its required rung may not ship | APEX R2 |
| CS2 | security/compliance rows require SHIPPED-PROBED | APEX L2 |
| CS3 | a rung past its re-verify interval decays one rung | APEX §C2 |
| CS4 | a live contradicting defect pins the rung at ASSERTED | APEX R5 |
| CS5 | evidence must be one of the six tags, well formed; EST is never load-bearing | APEX §C3 |
| CS6 | claim-shaped sentences in shipped artifacts that match no row | APEX R1 |
| CS7 | a SHIPPED-PROBED row must name the artifact the consumer receives | G-SHIP-PROBE |
| CS8 | a retracted row needs a note; a deleted row is a second incident | APEX R3 |

## NOT_RUN is a FAIL

Both tools print a per-check `RAN / NOT_RUN / SKIPPED` line and exit non-zero if
a check did not execute. This is deliberate and it is aimed at a defect this
project already has:

> "Pre-commit hook reports green when a test file fails to import."
> `[QUOTED: claude/session-2026-08-17-state.md]`

`--skip V7,V10` is the only way to silence a check, and the skip is printed.

## The validator's own failure modes

Required by §V. Read this before treating a green run as evidence.

1. **It proves tags exist, not that they are true.** Only V7 touches truth, only
   with `--tag-audit`, and only for tags written in the `[MEASURED: cmd → frag]`
   shape. A fabricated `[QUOTED:]` passes everything.
2. **It proves gates fire on their fixtures, not on reality.** V3 is only as
   good as the known-bad case someone wrote.
3. **V3 cannot prove a `check.kind: "human"` gate at all.** It reports those as
   FAIL for CORE/STANDARD tiers rather than pretending.
4. **V3 does not execute `check.kind: "command"` gates unless you pass
   `--run-commands`.** Without it they are reported NOT-EXECUTED, which is a
   FAIL, not a pass.
5. **V2 cannot invent the incident universe.** Without `--register` it reports
   NOT_RUN. It will not infer coverage from the gate file it is auditing.
6. **V4/V8 are text sweeps with a false-positive profile.** They stand down on
   any line carrying a provenance tag, on `§R`/`§7` table rows (whose numerals
   V11 re-computes arithmetically), and on ordinal identifiers. Everything else
   is reported. `--explain V4` prints why a token was not exempt.
7. **`claim_sweep`'s CS6 matches sentences to rows by content-word overlap.** A
   claim reworded past 40% divergence reads as unrowed. That direction is the
   safe one; the unsafe direction — a genuinely new claim matching an old row —
   is possible and is why CS6 is a sweep, not a proof.
8. **Neither tool has been run against a real ZROS**, because no project ZROS
   exists yet — only the FORGE that derives one. Pre-mortem failure mode 1 (the
   sweeps firing so heavily on real material that someone widens the exemption
   list instead of tagging) is therefore **untested**. First real run, check the
   V4 count before you change a regex.

## Governed widenings — the log V10 exists to keep honest

Every relaxation of a check in this codebase, with the fixture that proves the
check still fires. If you add a row here without a fixture, you have done the
thing G-TAMPER-GUARD is watching for.

| # | what was widened | why | fixture that proves the check still fires |
|---|---|---|---|
| 1 | V4/V8 stand down on ordinal identifiers (`LAW 4`, `WARNING 1`, `STAGE 2`) | the numeral names the thing, it does not measure it — same class as `G-04` / `M2`, which the closed exemption list already covered | `fixtures/selftest_known_bad_zros-v1.md` still yields `V4@L44:0.7` (a real threshold) and `V8@L88:38` (a real count) |
| 2 | V4/V8 stand down on `§R` and `§7` markdown table rows | those numerals are re-computed by V11's subtotal arithmetic, so they are not unsourced assertions | the same fixture's `§R` subtotals are checked by `V11`, and a deliberate mismatch there fails |
| 3 | a version-string token now needs a leading `v` or three components | so that `0.7` reads as a threshold rather than a version — the original regex swallowed every decimal, including load-bearing ones | `V4@L44:0.7` exists only because of this tightening; it is a widening of the check, not of the exemption |

## Pre-commit placement

Cheap enough for a hook: V1, V2, V5, V6, V10, V11, V12 and all of CS1–CS8.
Scheduled runs only: V3 with `--run-commands`, V7 with `--tag-audit`.

Do not put mutation runs in the hook `[QUOTED: claude/session-2026-08-17-state.md
"Do NOT put mutation runs in pre-commit; CI only."]`. Fix the hook's
green-on-import-error defect before adding anything to it.

## Self-audit of this delivery

Not clean. Per doctrine a clean audit would mean the instruments were pointed
away from their author.

1. **`claim_ledger-titan-v1.json` contains no `[MEASURED:]` field, and that is
   correct.** Every row was transcribed from project documents by a session that
   could not reach the repository. The rungs are `[QUOTED:]` readings of APEX
   Part V, and APEX's own self-audit says those rungs were assigned single-pass
   and are provisional until you confirm them. Confirm before relying.
2. **CL-4 carries an unresolved ambiguity and was not resolved by picking.**
   `session-2026-08-17-state.md` reports "W4 RESOLVED — FAIL is reachable, the
   premise was wrong" with a verdict table; `START-HERE-titan-gate.md` and
   `APEX-v6.0.md` Part V both restate "FAIL unreachable". The row states both
   readings and stays at ASSERTED. The resolving evidence is a run of
   `classify()` on the shipped path — read it, do not choose.
3. **V9 has no seeded document-level case**, because it is an entry point rather
   than a document check. `--selftest-meta` covers it instead, by pointing the
   selftest at a deliberately wrong expectation and asserting it fails.
4. **The friction cost of these tools is unmeasured.** No `cost_per_fire_s` here
   is `[MEASURED:]`; the first real runs should be timed.
5. **`claim_sweep`'s CLAIM_SHAPED regex is `[UNVERIFIED]` as a detector.** It was
   written from the claim vocabulary in the project documents, not calibrated
   against a corpus of real README sentences. Expect to tune it on first
   contact — and per the log above, tune it with a fixture.

## What this does not do

It does not derive a ZROS, it does not decide what to build, and it does not
make a claim true. It makes the gap between a claim and its evidence
mechanically visible, which is the only thing that was missing.
