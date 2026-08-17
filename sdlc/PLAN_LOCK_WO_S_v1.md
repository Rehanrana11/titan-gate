# PLAN LOCK — WO-S SKILLS WORKSTREAM — v1 (locked 2026-08-17)

STATUS: **LOCKED**. This plan does not drift, grow, reorder, or partially
complete silently. It ends in exactly one of two ways: every item below shows
a filled EVIDENCE line, or the operator writes an explicit UNLOCK line (§5).

Mechanical completion check (the lock's own runnable check, per the standing
meta-prompting rule — a plan with no check is a document):

    cd ~/01-Projects/titan-gate/sdlc && grep -c "\[UNFILLED\]" PLAN_LOCK_WO_S_v1.md

    5 = locked and untouched · 0 = plan complete · anything else = in progress
    (the count is per EVIDENCE line; this header's mentions are not counted
    because they carry no brackets — only the five EVIDENCE lines do)

## §1 PRECEDENCE — what this lock does and does not outrank

1. Evidence outranks this lock (charter rule).
2. **The Aug 23 release stream (W1–W9 under FIX_TITAN_GATE_v1.1) outranks this
   lock.** If time contends, W-items win and WO-S items wait WITHOUT being
   dropped — the lock holds them, it does not compete with the release.
3. This lock outranks convenience, new ideas, and anything not written here.

## §2 THE LOCKED ITEMS — in order, no reordering, each with its done-test

Done = VERIFIED AT DESTINATION (L7): the test runs on Rehan's machine, in the
repo, output pasted. "Done except X" = not done.

**WO-S1 — semantic_judge abstention token** (order: 1)
- Task: bare `except → 0.5` becomes explicit `INSUFFICIENT_CONTEXT`; no
  exception path may yield a numeric score.
- Done-test: a test that raises inside the judge and asserts the token, plus
  the full suite green with the pytest summary line visible.
- Probe state: semantic_judge.py READ (19 lines, one bare except → 0.5,
  `[MEASURED: operator's probe paste]`). Patch is blocked on ONE more read:
  the engine/composite consumer of `semantic_score`, so the abstention shape
  cannot break an unread caller (M2: the costliest register incidents came
  from deriving before reading the deciding artifact). Also read
  policy_judge.py for the W1 tri-state shape precedent.
- EVIDENCE: [MEASURED: abstention tests 2 passed; defect-pin test flipped to token guard; full suite '899 passed, 1 skipped, 10 xfailed'; 2026-08-17]

**WO-S3a — PROVE the hook fails on unexpected collection error** (order: 2)
- AMENDED AT LOCK TIME (evidence > docs): the probe shows the hook already
  handles collection errors via `--continue-on-collection-errors` + a
  `test_collection_health.py` KNOWN_RED guard (TG-11). The register/state-doc
  claim "green on import error" is STALE. The task is therefore the proof,
  not the fix: a deliberately broken import must turn the hook RED, output
  pasted. If it does NOT, the item reverts to a fix task at the same slot.
- Known brittleness noted, not in scope unless the proof fails: the guard
  grep matches the hardcoded string "2 passed" ("12 passed" would substring-
  match it).
- EVIDENCE: [MEASURED: seeded broken import -> '1 failed, 896 passed, 1 skipped, 10 xfailed, 1 error in 48.49s'; 'SUITE RED - commit blocked'; HOOK_EXIT=1; 2026-08-17]

**WO-S3b — wire selftests into the fixed hook** (order: 3, hard-gated on S3a)
- Task: `validate_zros --selftest` + `claim_sweep --selftest` + 10-probe
  battery subset in pre-commit.
- Done-test: a commit's hook output showing all three ran; then a seeded
  selftest failure shown to block a commit.
- EVIDENCE: [MEASURED: amend 368e620 -- hook output 'validator selftests green' + suite '899 passed, 1 skipped, 10 xfailed'; negative proof: fixture aside -> 'VALIDATOR SELFTEST RED -- commit blocked', NEGATIVE_EXIT=1, blocked commit absent from git log; 2026-08-17]

**WO-S4 — contrastive negatives per rubric level** (order: 4)
- Task: one annotated known-bad per judge rubric level, extending the
  D5-xfail discipline. NOT a golden set (see §3).
- Done-test: each negative provably scores below its level's positive, in a
  committed test.
- EVIDENCE: [MEASURED: tests/test_judge_rubric_contrastive.py -> '4 passed, 2 xfailed'; full suite '903 passed, 1 skipped, 12 xfailed'; commit 431f8f6; H2/H3/P3 negatives below their positives; P1-dead and correctness-blind pinned as strict xfails; 2026-08-17]

**WO-S2 — cost per receipt** (order: 5)
- Task: tokens + $ logged per receipt; one published number.
- Done-test: a `[MEASURED:]` log line from a real run; new ledger row born at
  PROBED. (PROVISIONAL-IMPORT parentage, per the analysis.)
- Blocked on: a second probe to locate receipt emission — not yet run.
- EVIDENCE: [MEASURED: bench_receipt_cost.py, N=200 chained GENESIS-rooted -> median 0.095 ms/receipt, p99 0.139 ms, 1900 bytes/receipt, ~10526 receipts/second; zero LLM call sites (RECON_MATCH_LINES=0); 2026-08-17]

**WO-S5 — evidence_quote in judge/report layer** (folded into S1/S4 commits
where natural; H1 GUARD ABSOLUTE: the receipt body and schema_version are
untouched. A citation field in the receipt during this lock = drift incident.)
- Done-test: a fired rule's finding carries the matched line verbatim; a
  finding with no citable line emits `[UNVERIFIED]`, never silently drops.
- EVIDENCE: counted under S1/S4's lines — no separate blank.

## §3 FROZEN WHILE LOCKED — naming them so silence isn't drift

- Golden set, LLM-judge validation, κ/CI (#4→#2→#13): **banned** until the
  `classify()` run resolves CL-4. Unlock is that run's pasted output, nothing
  else. Any golden-set work during this lock is an anti-scope incident.
- Few-shot / prompt-chaining / prefill (#3/#10/#14): parked with aivis or
  `[UNVERIFIED]` applicability. No work.
- AgentRepEngine (#15), MCP (#17): post-Aug-23. No work.
- HITL spec (#16): week after 1.0.3.
- **No new framework/prompt versions during this lock** except where a locked
  item's own evidence obligation requires a runnable check in the same change.

## §4 VERIFICATION AT LOCK-CLOSE — the exit ritual, not optional

1. All five EVIDENCE lines filled with `[MEASURED:]` entries (grep returns 0).
2. Full sweep re-run: `claim_sweep claim_ledger-titan-v2.json --previous
   claim_ledger-titan-v1.json --artifact <README> --artifact <SPEC> --all` —
   BLOCK delta recorded against today's 12.
3. Ledger updated (v3 if rows moved) with the R4 diff pasted.
4. All commits show the pytest summary line (hook now trustworthy per S3a).
5. Session-state doc refreshed; register appended in place.

## §5 AMENDMENT — the only door

Only the operator amends this lock, by writing in this file:

    UNLOCK <item-id> | <date> | <one-line reason>

An unlock without that line, work on frozen items, reordering, or a new item
appearing mid-lock is logged as a drift incident in the register with this
document as the evidence quote. The assistant may PROPOSE an unlock in one
line; it may not act on one.

## §6 CURRENT STATE AT LOCK TIME

Repo: `w1-soc2-honesty` at `7918a8b` `[MEASURED: operator's git log]`.
Suite: 897/1/10 `[MEASURED: pre-commit output, twice]`. Ledger v2: 12 BLOCKs,
CS6 unrowed 0 `[MEASURED: v2 sweep]`. Probe RETURNED at lock time: judges live
in `judge_engine/v1/`; semantic_judge 19 lines with the bare except; hook
already TG-11-fixed (S3a amended above accordingly); structural_judge's P1
rubric entry is defined but fired by no rule (WO-S4 input). Calibration:
behaviour prediction right, hook prediction wrong — the register is stale on
the hook, and the state docs need that correction at next refresh. Lock
starts at 5 UNFILLED.
