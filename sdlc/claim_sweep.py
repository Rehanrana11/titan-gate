#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""claim_sweep v1 -- the machine check for an APEX Claim Ledger.

Implements the operating rules of APEX v6.0 §C4 (R1-R5) and the Reality Ladder
of §C2 against a JSON ledger and the artifacts a consumer actually receives.

APEX v6.0 §SELF-AUDIT finding 5 names this file's absence:

    "Known weakness: the ledger has no validator yet -- rules R1-R5 are prose;
     the machine check (sweep shipped artifacts for unrowed claims; diff rows
     per release) is specified but unbuilt. Until built, the ledger is exactly
     the kind of ritual M9 warns about."

Checks (each fails closed, each names the rule it descends from):

  CS1  REQUIRED RUNG        R2   a row below its required rung may not ship
  CS2  SECURITY RUNG        L2   security/compliance rows require SHIPPED-PROBED
  CS3  DECAY                §C2  a rung past its re-verify interval decays one
  CS4  PINNED BY DEFECT     R5   a live contradicting defect caps the rung
  CS5  TAG FORM             §C3  evidence tags must be one of the six, well formed
  CS6  UNROWED CLAIM SWEEP  R1   claim-shaped sentences in shipped artifacts
                                 that match no ledger row
  CS7  PROOF SURFACE        G-SHIP-PROBE  a SHIPPED-PROBED row must name the
                                 artifact the consumer receives, and that
                                 artifact must be one it actually appears in
  CS8  RETRACTION LOG       R3   a row retracted since the previous ledger must
                                 carry a retraction note (silent deletion of a
                                 false claim is a second incident, not a fix)

Exit codes:
    0  no BLOCK
    1  at least one BLOCK
    3  usage / parse error (fail closed)
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys

__version__ = "2"

RUNGS = ["ASSERTED", "SOURCED", "PROBED", "SHIPPED-PROBED"]
RUNG_INDEX = {r: i for i, r in enumerate(RUNGS)}

BLOCK = "BLOCK"
WARN = "WARN"

SECURITY_WORDS = re.compile(
    r"\b(secur\w*|crypt\w*|sign\w*|tamper\w*|forge\w*|non-repudiation|"
    r"compliance|complian\w*|attest\w*|SOC\s*2|audit\w*|verif\w*|immutab\w*|"
    r"integrity|provenance)\b",
    re.IGNORECASE,
)

# Sentences that assert capability, security, performance or compliance.
# R1: every one of these in a shipped artifact IS a ledger row.
CLAIM_SHAPED = re.compile(
    r"\b("
    r"prove[sd]?|proof|guarantee[sd]?|ensure[sd]?|verifiable|verifies|"
    r"tamper-(?:proof|evident)|immutable|cryptographically|"
    r"independently\s+verif\w+|attest\w*|certified|compliant|compliance|"
    r"SOC\s*2|ISO\s*27001|non-repudiation|unforgeable|cannot\s+be\s+forged|"
    r"detects?\s+\w+|blocks?\s+\w+|prevents?\s+\w+|fails?\s+\w+\s+code|"
    r"faster\s+than|reduces?\s+\w+\s+by"
    r")\b",
    re.IGNORECASE,
)

TAG_FORM = re.compile(
    r"^\[(MEASURED|QUOTED|DERIVED|EST|REPORTED):\s*\S.*\]$|^\[UNVERIFIED\]$"
)

REQUIRED_FIELDS = [
    "id", "claim", "appears_in", "rung", "required_rung", "category",
    "evidence", "advancing_probe", "shipping_artifact", "last_verified",
    "reverify_days", "owner",
]


# ------------------------------------------------------------------ io

def read_text(path):
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return fh.read()


def read_lines(path):
    return [ln[:-1] if ln.endswith("\r") else ln
            for ln in read_text(path).split("\n")]


# ------------------------------------------------------------------ model

class Finding(object):
    __slots__ = ("check", "fid", "severity", "where", "message")

    def __init__(self, check, locator, severity, where, message):
        self.check = check
        self.fid = "%s@%s" % (check, locator)
        self.severity = severity
        self.where = where
        self.message = message

    def as_dict(self):
        return {"id": self.fid, "check": self.check, "severity": self.severity,
                "where": self.where, "message": self.message}


def load_ledger(path):
    errors = []
    try:
        raw = json.loads(read_text(path))
    except Exception as exc:                        # noqa: BLE001
        return None, ["ledger is not readable JSON: %s" % exc]
    rows = raw.get("rows") if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        return None, ["ledger must be a JSON array of rows, or an object with "
                      "a 'rows' array"]
    seen = set()
    for pos, r in enumerate(rows):
        tag = r.get("id") if isinstance(r, dict) and r.get("id") else "row[%d]" % pos
        if not isinstance(r, dict):
            errors.append("%s is not an object" % tag)
            continue
        for f in REQUIRED_FIELDS:
            if f not in r:
                errors.append("%s: missing required field '%s'" % (tag, f))
        if r.get("id") in seen:
            errors.append("%s: duplicate row id" % tag)
        seen.add(r.get("id"))
        for f in ("rung", "required_rung"):
            if r.get(f) not in RUNG_INDEX:
                errors.append("%s: %s %r is not a Reality Ladder rung %s"
                              % (tag, f, r.get(f), RUNGS))
        if not isinstance(r.get("appears_in"), list):
            errors.append("%s: appears_in must be an array of surfaces" % tag)
        if not isinstance(r.get("reverify_days"), int):
            errors.append("%s: reverify_days must be an integer" % tag)
    return rows, errors


def parse_date(s):
    try:
        return datetime.date(*[int(p) for p in str(s).split("-")[:3]])
    except Exception:                               # noqa: BLE001
        return None


# ------------------------------------------------------------------ checks

def cs1_required_rung(rows, ctx):
    out = []
    for r in rows:
        have = RUNG_INDEX.get(r.get("rung"), -1)
        need = RUNG_INDEX.get(r.get("required_rung"), 99)
        if have < 0 or need > 90:
            continue
        if r.get("retracted"):
            continue
        if have < need and r.get("appears_in"):
            out.append(Finding(
                "CS1", r["id"], BLOCK, ", ".join(r["appears_in"]),
                "row is at %s but ships on %d external surface(s) requiring %s "
                "-- R2 blocks the release, and S2 says the CLAIM is rewritten "
                "down to its rung, never shipped up"
                % (r["rung"], len(r["appears_in"]), r["required_rung"])))
    return out


def cs2_security_rung(rows, ctx):
    out = []
    for r in rows:
        cat = str(r.get("category", "")).lower()
        is_sec = cat in ("security", "compliance") or bool(
            SECURITY_WORDS.search(str(r.get("claim", ""))))
        if not is_sec or r.get("retracted"):
            continue
        if r.get("required_rung") != "SHIPPED-PROBED":
            out.append(Finding(
                "CS2", r["id"], BLOCK, r.get("shipping_artifact") or "?",
                "security/compliance claim declares required_rung=%s; L2 allows "
                "only SHIPPED-PROBED to face a customer"
                % r.get("required_rung")))
    return out


def cs3_decay(rows, ctx):
    out = []
    today = ctx["today"]
    for r in rows:
        if r.get("retracted"):
            continue
        lv = parse_date(r.get("last_verified"))
        if lv is None:
            out.append(Finding(
                "CS3", r["id"], BLOCK, r.get("shipping_artifact") or "?",
                "last_verified is not a readable date (%r); an unre-verifiable "
                "rung cannot be trusted to be current" % r.get("last_verified")))
            continue
        days = int(r.get("reverify_days") or 0)
        if days <= 0:
            continue
        age = (today - lv).days
        if age > days:
            have = RUNG_INDEX.get(r.get("rung"), 0)
            decayed = RUNGS[max(0, have - 1)]
            out.append(Finding(
                "CS3", r["id"], BLOCK, r.get("shipping_artifact") or "?",
                "last verified %d days ago against a %d-day interval -- rung "
                "decays %s -> %s until re-probed by: %s"
                % (age, days, r.get("rung"), decayed,
                   r.get("advancing_probe") or "(no probe recorded)")))
    return out


def cs4_pinned(rows, ctx):
    out = []
    for r in rows:
        pins = r.get("pinned_by") or []
        if not pins or r.get("retracted"):
            continue
        if RUNG_INDEX.get(r.get("rung"), 0) > RUNG_INDEX["ASSERTED"]:
            out.append(Finding(
                "CS4", r["id"], BLOCK, r.get("shipping_artifact") or "?",
                "row sits at %s while these live defects contradict it: %s -- "
                "R5 pins a contradicted claim at ASSERTED until they are fixed"
                % (r["rung"], ", ".join(str(p) for p in pins))))
    return out


def cs5_tag_form(rows, ctx):
    out = []
    for r in rows:
        ev = str(r.get("evidence", "")).strip()
        if not TAG_FORM.match(ev):
            out.append(Finding(
                "CS5", r["id"], BLOCK, "ledger",
                "evidence %r is not one of the six provenance tags in "
                "well-formed shape; [UNVERIFIED] is always available and is "
                "never a violation" % ev))
        elif ev.startswith("[EST:") and RUNG_INDEX.get(r.get("rung"), 0) >= \
                RUNG_INDEX["PROBED"]:
            out.append(Finding(
                "CS5", r["id"] + ":est-load-bearing", BLOCK, "ledger",
                "row is at %s on [EST:] evidence; an EST value may never be "
                "load-bearing" % r["rung"]))
    return out


def cs6_unrowed(rows, ctx):
    out = []
    if not ctx["artifacts"]:
        return None
    claim_texts = [_norm(r.get("claim", "")) for r in rows]
    # GOVERNED WIDENING v2 (see the governed-widening log in the README):
    # two accept channels, both visible, neither a regex loosening.
    #   1. Markdown heading lines are skipped -- a heading names a section, it
    #      does not assert a capability.  Fixture: the known-bad shipped README
    #      fixture ends with a heading full of claim words that must produce
    #      no finding while line 8's real claim still fires.
    #   2. accepted_non_claims -- an explicit, per-sentence allowlist carried
    #      IN THE LEDGER with a reason and an acceptance basis per entry.
    #      Matching is exact / prefix / 0.8-overlap on normalized text, so an
    #      entry accepts one sentence shape, not a category.  Skipped hits are
    #      surfaced as a WARN finding, never silently (no silent caps).
    accepted_norm = []
    for a in ctx.get("accepted_non_claims") or []:
        t = _norm(a.get("text", "")) if isinstance(a, dict) else _norm(a)
        if t:
            accepted_norm.append(t)
    accepted_hits = 0
    for path in ctx["artifacts"]:
        try:
            lines = read_lines(path)
        except Exception as exc:                    # noqa: BLE001
            out.append(Finding("CS6", os.path.basename(path), BLOCK, path,
                               "shipped artifact unreadable: %s" % exc))
            continue
        in_fence = False
        for i, line in enumerate(lines):
            if line.lstrip().startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            if line.lstrip().startswith("#"):
                continue                        # heading, not an assertion
            for sentence in _sentences(line):
                if not CLAIM_SHAPED.search(sentence):
                    continue
                n = _norm(sentence)
                if any(_overlaps(n, c) for c in claim_texts):
                    continue
                if any(n == a or n.startswith(a) or _overlaps(n, a, 0.8)
                       for a in accepted_norm):
                    accepted_hits += 1
                    continue
                out.append(Finding(
                    "CS6", "%s:%d" % (os.path.basename(path), i + 1), BLOCK,
                    "%s:%d" % (path, i + 1),
                    "claim-shaped sentence in a shipped artifact matches no "
                    "ledger row (R1): %s" % sentence.strip()[:120]))
    if accepted_hits:
        out.append(Finding(
            "CS6", "accepted-non-claims", WARN, "ledger:accepted_non_claims",
            "%d claim-shaped sentence(s) skipped via the ledger's "
            "accepted_non_claims list -- review that list when reviewing the "
            "ledger; an acceptance is a decision, not an absence" % accepted_hits))
    return out


def cs7_proof_surface(rows, ctx):
    out = []
    for r in rows:
        if r.get("rung") != "SHIPPED-PROBED" or r.get("retracted"):
            continue
        art = str(r.get("shipping_artifact") or "").strip()
        if not art:
            out.append(Finding(
                "CS7", r["id"], BLOCK, "ledger",
                "row claims SHIPPED-PROBED but names no shipping artifact; "
                "G-SHIP-PROBE asks 'proven on WHAT?' and this row cannot answer"))
            continue
        surfaces = [str(s) for s in (r.get("appears_in") or [])]
        if surfaces and not any(
                _overlaps(_norm(art), _norm(s)) for s in surfaces):
            out.append(Finding(
                "CS7", r["id"] + ":surface", BLOCK, art,
                "proof was taken on %r but the claim appears on %s -- the "
                "intermediate is never the proof (L7)"
                % (art, ", ".join(surfaces))))
    return out


def cs8_retraction_log(rows, ctx):
    prev = ctx["previous_rows"]
    if prev is None:
        return None
    out = []
    now_by_id = {r.get("id"): r for r in rows}
    for old in prev:
        oid = old.get("id")
        if oid in now_by_id:
            new = now_by_id[oid]
            if new.get("retracted") and not str(new.get("retraction_note", "")).strip():
                out.append(Finding(
                    "CS8", oid, BLOCK, "ledger",
                    "row is retracted with no retraction_note; R3 says silent "
                    "deletion of a false claim is a second incident, not a fix"))
            continue
        out.append(Finding(
            "CS8", oid or "?", BLOCK, "ledger",
            "row %s existed in the previous ledger and is simply gone -- "
            "retract it explicitly with a note, do not delete it" % oid))
    return out


CHECKS = [
    ("CS1", cs1_required_rung, None),
    ("CS2", cs2_security_rung, None),
    ("CS3", cs3_decay, None),
    ("CS4", cs4_pinned, None),
    ("CS5", cs5_tag_form, None),
    ("CS6", cs6_unrowed,
     "no shipped artifacts supplied; pass --artifact <path> (repeatable) so "
     "R1 can sweep the surfaces a consumer actually receives"),
    ("CS7", cs7_proof_surface, None),
    ("CS8", cs8_retraction_log,
     "no previous ledger supplied; pass --previous <path> so R3/R4 can see "
     "what was retracted between releases"),
]


# ------------------------------------------------------------------ helpers

_WORD = re.compile(r"[a-z0-9]+")


def _norm(text):
    return " ".join(_WORD.findall(str(text).lower()))


def _sentences(line):
    stripped = re.sub(r"^[#>\-*\s|]+", "", line)
    if not stripped.strip():
        return []
    return [s for s in re.split(r"(?<=[.!?])\s+", stripped) if s.strip()]


_STOP = set("a an the of to in on for and or is are be that this it with as by "
            "you your we our can will not no".split())


def _overlaps(a, b, threshold=0.6):
    """Content-word overlap, used to match a sentence to a ledger row."""
    aw = {w for w in a.split() if w not in _STOP}
    bw = {w for w in b.split() if w not in _STOP}
    if not aw or not bw:
        return False
    small, large = (aw, bw) if len(aw) <= len(bw) else (bw, aw)
    return len(small & large) / float(len(small)) >= threshold


# ------------------------------------------------------------------ diff

def ledger_diff(old_rows, new_rows):
    """R4: the honest changelog of what the product actually is."""
    old = {r.get("id"): r for r in old_rows}
    new = {r.get("id"): r for r in new_rows}
    added, advanced, decayed, retracted, removed, unchanged = [], [], [], [], [], []
    for rid, r in new.items():
        if rid not in old:
            added.append((rid, r.get("rung"), r.get("claim")))
            continue
        o, n = RUNG_INDEX.get(old[rid].get("rung"), 0), RUNG_INDEX.get(r.get("rung"), 0)
        if r.get("retracted") and not old[rid].get("retracted"):
            retracted.append((rid, r.get("retraction_note", ""), r.get("claim")))
        elif n > o:
            advanced.append((rid, old[rid].get("rung"), r.get("rung"), r.get("claim")))
        elif n < o:
            decayed.append((rid, old[rid].get("rung"), r.get("rung"), r.get("claim")))
        else:
            unchanged.append(rid)
    for rid in old:
        if rid not in new:
            removed.append((rid, old[rid].get("claim")))
    return {"added": added, "advanced": advanced, "decayed": decayed,
            "retracted": retracted, "silently_removed": removed,
            "unchanged": unchanged}


def render_diff(d):
    out = ["CLAIM DIFF (APEX R4 -- the honest changelog)"]
    for label, key in (("ADDED", "added"), ("ADVANCED", "advanced"),
                       ("DECAYED", "decayed"), ("RETRACTED", "retracted"),
                       ("SILENTLY REMOVED", "silently_removed")):
        rowset = d[key]
        out.append("  %s (%d)" % (label, len(rowset)))
        for item in rowset:
            out.append("    %s" % " | ".join(str(x)[:70] for x in item))
    out.append("  UNCHANGED (%d): %s" % (len(d["unchanged"]),
                                         ", ".join(d["unchanged"])))
    if d["silently_removed"]:
        out.append("")
        out.append("  A silently removed row is an R3 incident. Retract with a "
                   "note instead.")
    return "\n".join(out)


# ------------------------------------------------------------------ runner

def run(ledger_path, opts):
    rows, errors = load_ledger(ledger_path)
    if rows is None:
        return None, errors
    previous_rows = None
    if opts.previous:
        previous_rows, prev_errors = load_ledger(opts.previous)
        if previous_rows is None:
            errors.extend("previous ledger: %s" % e for e in prev_errors)
    today = parse_date(opts.today) if opts.today else datetime.date.today()
    if today is None:
        return None, ["--today is not an ISO date: %r" % opts.today]
    accepted = []
    try:
        raw_all = json.loads(read_text(ledger_path))
        if isinstance(raw_all, dict):
            accepted = raw_all.get("accepted_non_claims", []) or []
    except Exception:                               # noqa: BLE001
        pass                                        # load_ledger already reported
    ctx = {"artifacts": opts.artifact or [], "previous_rows": previous_rows,
           "today": today, "accepted_non_claims": accepted}
    results = []
    for cid, fn, missing_reason in CHECKS:
        try:
            found = fn(rows, ctx)
        except Exception as exc:                    # noqa: BLE001 -- fail closed
            results.append((cid, False, "check raised %s: %s"
                            % (type(exc).__name__, exc), []))
            continue
        if found is None:
            results.append((cid, False, missing_reason or "not run", []))
        else:
            results.append((cid, True, "", found))
    return (rows, results), errors


def render(rows, results, errors, ledger_path, opts):
    out = ["claim_sweep v%s" % __version__,
           "  ledger : %s" % ledger_path,
           "  rows   : %d  (computed, not typed)" % len(rows),
           "  today  : %s" % (opts.today or datetime.date.today().isoformat()),
           ""]
    for e in errors:
        out.append("  LEDGER SCHEMA ERROR: %s" % e)
    if errors:
        out.append("")
    out.append("  RUNG CENSUS")
    for rung in RUNGS:
        n = sum(1 for r in rows if r.get("rung") == rung)
        ships = sum(1 for r in rows if r.get("rung") == rung and r.get("appears_in"))
        out.append("    %-15s %2d row(s), %d of them on an external surface"
                   % (rung, n, ships))
    out.append("")
    out.append("  CHECK  STATUS   COUNT  NOTE")
    for cid, ran, reason, found in results:
        status = "RAN" if ran else ("SKIPPED" if cid in opts.skip else "NOT_RUN")
        out.append("  %-5s  %-8s %5d  %s" % (cid, status, len(found), reason))
    out.append("")
    for cid, ran, _reason, found in results:
        if not found:
            continue
        out.append("  %s -- %d finding(s)" % (cid, len(found)))
        for f in found[:opts.max_per_check] if not opts.all else found:
            out.append("    [%s] %s" % (f.severity, f.fid))
            out.append("        %s" % f.message)
            out.append("        at %s" % f.where)
        hidden = len(found) - (len(found) if opts.all else min(len(found), opts.max_per_check))
        if hidden > 0:
            out.append("    ... %d more (use --all)" % hidden)
        out.append("")
    return "\n".join(out)


def exit_code(results, errors, opts):
    if errors:
        return 3
    for cid, ran, _reason, found in results:
        if not ran and cid not in opts.skip:
            return 1
        if any(f.severity == BLOCK for f in found):
            return 1
    return 0


def selftest(expected_name="cs_expected-v1.json", quiet=False):
    """Prove every check fires on a case it must catch (L6: an instrument is
    only as honest as its known-bad fixtures)."""
    here = os.path.dirname(os.path.abspath(__file__))
    fx = os.path.join(here, "fixtures")

    class O(object):
        artifact = [os.path.join(fx, "shipped_readme_known_bad-v1.md")]
        previous = os.path.join(fx, "cs_ledger_previous-v1.json")
        today = "2026-08-17"
        skip = set()
        all = True
        max_per_check = 200

    expect_path = os.path.join(fx, expected_name)
    ledger_path = os.path.join(fx, "cs_ledger_known_bad-v1.json")
    for p in (expect_path, ledger_path):
        if not os.path.isfile(p):
            print("SELFTEST FAIL: missing fixture %s" % p)
            return 3
    expected = json.loads(read_text(expect_path))
    payload, errors = run(ledger_path, O())
    if payload is None:
        print("SELFTEST FAIL: known-bad ledger did not parse")
        for e in errors:
            print("   %s" % e)
        return 3
    _rows, results = payload
    got = sorted(f.fid for (_c, _r, _n, fs) in results for f in fs)
    want = sorted(expected["finding_ids"])
    ran = sorted(c for (c, r, _n, _f) in results if r)
    want_ran = sorted(expected["checks_that_must_run"])

    out = []
    ok = True
    for i in want:
        if i not in got:
            ok = False
            out.append("   MISSING  %s" % i)
    for i in got:
        if i not in want:
            ok = False
            out.append("   EXTRA    %s" % i)
    for c in want_ran:
        if c not in ran:
            ok = False
            out.append("   NOT_RUN  %s" % c)
    if sorted(errors) != sorted(expected.get("schema_errors", [])):
        ok = False
        out.append("   SCHEMA ERROR SET DIFFERS: %s" % errors)
    if quiet:
        return 0 if ok else 1
    if ok:
        print("SELFTEST PASS")
        print("  finding ids matched exactly : %d" % len(got))
        print("  checks proven to have run   : %s" % ", ".join(ran))
        print("  (asserted on ids, never on a count)")
        return 0
    print("SELFTEST FAIL")
    for line in out:
        print(line)
    return 1


def selftest_meta():
    here = os.path.dirname(os.path.abspath(__file__))
    wrong = os.path.join(here, "fixtures", "cs_expected_WRONG-v1.json")
    if not os.path.isfile(wrong):
        print("META FAIL: missing fixture %s" % wrong)
        return 3
    rc_good = selftest("cs_expected-v1.json", quiet=True)
    rc_bad = selftest("cs_expected_WRONG-v1.json", quiet=True)
    print("META: selftest vs correct expectation -> %d (want 0)" % rc_good)
    print("META: selftest vs wrong   expectation -> %d (want 1)" % rc_bad)
    if rc_good == 0 and rc_bad == 1:
        print("META PASS: the selftest is provably able to fail")
        return 0
    print("META FAIL: the selftest cannot tell a wrong expectation from a right one")
    return 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="claim_sweep",
        description="Enforce an APEX v6.0 Claim Ledger (§C2 Reality Ladder, "
                    "§C4 rules R1-R5).")
    ap.add_argument("ledger", nargs="?", help="path to the claim ledger JSON")
    ap.add_argument("--artifact", action="append",
                    help="a shipped artifact to sweep for unrowed claims "
                         "(repeatable): README, SPEC, PyPI description, deck")
    ap.add_argument("--previous", help="the previous release's ledger, for R3/R4")
    ap.add_argument("--diff", action="store_true",
                    help="print the claim diff against --previous and exit")
    ap.add_argument("--today", help="ISO date to evaluate decay against")
    ap.add_argument("--skip", default="", help="comma-separated check ids to skip")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--max-per-check", type=int, default=10)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--version", action="store_true")
    ap.add_argument("--selftest", action="store_true",
                    help="run against the bundled known-bad ledger and assert "
                         "the exact finding-id set")
    ap.add_argument("--selftest-meta", action="store_true",
                    help="prove the selftest itself can fail")
    opts = ap.parse_args(argv)

    if opts.version:
        print("claim_sweep v%s" % __version__)
        return 0
    if opts.selftest_meta:
        return selftest_meta()
    if opts.selftest:
        return selftest()
    if not opts.ledger:
        ap.print_usage()
        print("error: <ledger> is required")
        return 3
    if not os.path.isfile(opts.ledger):
        print("error: no such file: %s" % opts.ledger)
        return 3
    opts.skip = {s.strip().upper() for s in opts.skip.split(",") if s.strip()}

    if opts.diff:
        if not opts.previous:
            print("error: --diff needs --previous <path>")
            return 3
        new_rows, e1 = load_ledger(opts.ledger)
        old_rows, e2 = load_ledger(opts.previous)
        if new_rows is None or old_rows is None:
            for e in (e1 or []) + (e2 or []):
                print("LEDGER ERROR: %s" % e)
            return 3
        print(render_diff(ledger_diff(old_rows, new_rows)))
        return 0

    payload, errors = run(opts.ledger, opts)
    if payload is None:
        for e in errors:
            print("LEDGER ERROR: %s" % e)
        return 3
    rows, results = payload
    results = [(c, r, n, f) for (c, r, n, f) in results if c not in opts.skip] + \
              [(c, False, "SKIPPED by --skip %s" % c, [])
               for (c, _fn, _m) in CHECKS if c in opts.skip]
    results.sort(key=lambda t: t[0])
    if opts.json:
        print(json.dumps({
            "ledger": opts.ledger, "row_count": len(rows),
            "schema_errors": errors,
            "checks": [{"check": c, "ran": r, "reason": n,
                        "findings": [f.as_dict() for f in fs]}
                       for (c, r, n, fs) in results],
        }, indent=2, ensure_ascii=False))
    else:
        print(render(rows, results, errors, opts.ledger, opts))
    return exit_code(results, errors, opts)


if __name__ == "__main__":
    sys.exit(main())
