# ZROS-SELFTEST v1 — KNOWN-BAD FIXTURE, NOT A REAL OPERATING DOCUMENT

This document exists to be wrong. Every defect below is seeded deliberately, one
per validator check, so that `--selftest` can assert the exact set of violation
ids it produces. Do not copy anything here into a real ZROS.

Mission: prove each check fires. Deadline: none. Retire when: a check is added
without a seeded case here.

## §L THE LAWS

LAW 1 — Probe before you assert; the machine answers faster than the rework.
        (caches G-M1-01)

LAW 2 — Read the deciding document before deriving anything from it.
        (caches G-M2-01)

LAW 3 — Encode the lesson as structure, and never paste what you have not made
        safe to paste. (caches G-M9-01, G-M5-01)

LAW 4 — Excellence is a habit.

## §R SESSION RUNBOOK

#### SESSION START

| gate | check | command | cost |
|---|---|---|---|
| G-M1-01 | environment truth row exists | `python validate_zros.py --selftest` | 5 |
| G-M9-01 | recurrence sweep | `git log --oneline` | 5 |
| **SUBTOTAL** | | | 10 |

#### BEFORE CLAIM

| gate | check | command | cost |
|---|---|---|---|
| G-M2-01 | deciding document read | `git status` | 5 |
| G-A1 | no unverified claim escapes | `git diff --name-only` | 10 |
| G-M6-01 | delivered name equals consumed name | `ls -l` | 5 |
| **SUBTOTAL** | | | 20 |

## §0 SCOPE

This fixture covers nothing real. SCORE_PASS is set to 0.7 for the default
profile, which is the seeded untagged threshold.

## §1 ENVIRONMENT TRUTH

Sentinel row: [MEASURED: echo hello → goodbye]

## §2 PROVENANCE LAW

The six tags are inherited from ZROS-FORGE v1.1 and are not restated here.

## §3 GATES

Gates live in `selftest_known_bad_gates-v1.json`. G-M5-01 is deliberately
absent from §R above.

## §4 MANDATORY RITUALS

Pre-mortem before any novel component.

## §5 STOP CONDITIONS

Stop when an input is missing.

## §6 COVERAGE MATRIX

I-4 — ACCEPTED — the register row carries no evidence quote.

## §7 FRICTION LEDGER

| gate | cost per fire | fires per turn |
|---|---|---|
| G-M1-01 | 5 | 2 |

## §8 VALIDATOR

See `validate_zros.py`.

## §9 CALIBRATION PROTOCOL

Predict before measuring.

## §10 SELF-AUDIT

The register contains 38 incidents, which is the seeded untagged count.

## §11 DIAGNOSTIC PROTOCOL

Never patch forward from a broken state.

## §12 REWORK TELEMETRY

Rework share, zoned against the register baseline.

## §13 DONE LADDER

Done means verified at the destination.

## §14 SESSION DELTA

Captured at session end.

## §A APPENDIX — SEEDED BLOCKS

The block below seeds the V5 placeholder violation:

```bash
cd /home/claude/sdlc-validators
curl -H "Authorization: Bearer YOUR_TOKEN_HERE" https://example.invalid/api
```

The block below seeds the V6 block-safety violation:

```bash
cd /home/claude/sdlc-validators
rm -rf build
```
