# ZROS-EXAMPLE v1 — KNOWN-GOOD FIXTURE

Derived from `selftest_register-v1.md`, three usable incidents
[DERIVED: counted rows matching the incident-id form in the register, minus the
row marked UNUSABLE, gives three]. Mission: prove the validator passes material
it must pass. Deadline: none. Retire when: the register stops resembling it.

This file is the answer to APPENDIX-V warning 1 — a validator whose regexes are
written from imagination rejects its own author's known-good input on first run.
If a change to `validate_zros.py` makes this file fail, the change is wrong until
proven otherwise.

## §L THE LAWS

LAW 1 — Probe before you assert; the machine answers faster than the rework.
        (caches G-M1-01; ranked first because M1 is the largest and only
        recurrence-flagged mechanism in this register)

LAW 2 — Read the deciding document before deriving anything from it.
        (caches G-M2-01)

LAW 3 — Never paste what you have not made safe to paste.
        (caches G-M5-01)

## §R SESSION RUNBOOK

#### SESSION START

| gate | check | command | cost |
|---|---|---|---|
| G-M1-01 | environment truth row exists for every machine claim | `python validate_zros.py --version` | 5 |
| **SUBTOTAL** | | | 5 |

#### BEFORE PLAN

| gate | check | command | cost |
|---|---|---|---|
| G-M2-01 | the deciding document has been read this session | none | 10 |
| **SUBTOTAL** | | | 10 |

#### BEFORE PASTE

| gate | check | command | cost |
|---|---|---|---|
| G-M5-01 | block starts with an absolute cd and carries no placeholder | `python validate_zros.py --selftest` | 5 |
| **SUBTOTAL** | | | 5 |

## §0 SCOPE, KILL CONDITIONS, AND WHAT THIS DOES NOT COVER

Covers execution hygiene for one project. Does not cover what to build or what
may be claimed — that is the companion strategy document's jurisdiction.

## §1 ENVIRONMENT TRUTH

| fact | command | output fragment |
|---|---|---|
| the shell returns a sentinel | `echo probe-ok` | [MEASURED: echo probe-ok → probe-ok] |

## §2 PROVENANCE LAW

Six tags, inherited unchanged: MEASURED, QUOTED, DERIVED, EST, REPORTED,
UNVERIFIED. The exemption list is closed and widening it is a governed act.

## §3 GATES

CORE gates live in `known_good_gates-v1.json`. Each carries a trigger, a check,
a fail-closed disposition, both fixtures, its parents, a placement, and a tamper
signature.

## §4 MANDATORY RITUALS

Pre-mortem before any component with no incident history: name three specific
failure modes, a detection signal inside half a minute, and a one-command
recovery. Log them as predictions and score them at the next register.

## §5 STOP CONDITIONS

A required input is missing; the probe has not been run; a deciding document is
unreachable; the operator signals close; the work was not requested; a tag's
source cannot be named.

## §6 COVERAGE MATRIX

| incident | disposition |
|---|---|
| I-1 | G-M1-01 |
| I-2 | G-M2-01, G-M5-01 |
| I-3 | CALIBRATION — predicting and being wrong was correct behaviour |

Uncovered: none. A matrix with no gaps is the suspicious one, and this fixture
is small enough that the absence of gaps is a property of its size.

## §7 FRICTION LEDGER + CUT LIST + THE BILL

| gate | cost per fire | fires per turn |
|---|---|---|
| G-M1-01 | 5 | 2 |
| G-M2-01 | 10 | 1 |
| G-M5-01 | 5 | 3 |

Cut list: none.

## §8 VALIDATOR SPEC

`validate_zros.py`, run as the pasteable block in the appendix.

## §9 CALIBRATION PROTOCOL

Predict before measuring; a blank prediction is refused; a placeholder recorded
as an actual corrupts the log.

## §10 SELF-AUDIT

Not clean by construction: this fixture's §6 has no uncovered rows, which the
document itself flags as a property of its size rather than of its rigour.

## §11 DIAGNOSTIC PROTOCOL

Never patch forward from a broken state. Three failed patches on one file in one
session means guessing: revert and return to capture.

## §12 REWORK TELEMETRY

Rework share, zoned against the register's own measured baseline. Gaming it
looks like relabelling fix commits as features.

## §13 DONE LADDER

Done is verified at the destination. "Done except for X" means not done.

## §14 SESSION DELTA

Captured at session end and fed to the next register.

## §A MECHANISM CATALOG

| id | mechanism | members |
|---|---|---|
| M1 | asserted a property of the environment without querying it | I-1 |
| M2 | formed a claim before reading the artifact that decides it | I-2 |
| M5 | emitted text for verbatim execution that was not safe to execute | I-2 |

## §B TECHNIQUE MAP

Role conditioning, decomposition, step-back, self-consistency, verification,
schema-constrained output, adversarial self-prompting.

## §C AMENDMENT RULE + CHANGE LOG

Adding a gate needs a parent. Loosening one needs a new known-bad fixture in the
same change. Retiring one needs two clean registers.

## §D APPENDIX — THE CONSUME BLOCK

```bash
cd /home/claude/sdlc-validators
test -f validate_zros.py && python3 validate_zros.py --selftest
```
