#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""invariant_sweep v1 -- one truth, one source, every copy checked.

The third leg of the titan-gate instrument set:

    claim_sweep      guards what is SAID against its evidence rung
    validate_zros    guards the PROCESS documents against their own rules
    invariant_sweep  guards the product's FACTS against their own copies

Parent incident classes (titan-incident-register + session states): stale-copy
extraction (#13), inherited stale figures (#3), five inconsistent SOC2 tables,
SPEC field table 32 vs 33 wire fields, SPEC silent on canonical encoding.
Every one is the same mechanism: one truth living in several places,
diverging silently. This tool makes that divergence a red exit code.

Registry: invariants-titan-v1.json. Each row names ONE authoritative source
(file + pattern), zero or more mirrors (places the truth is restated), a
change trigger, a violation response, and a provenance tag. Rows a machine
cannot check are kind "declaration" and are COUNTED AND PRINTED as
UNENFORCED -- never silently mixed in with the checked ones (no silent caps).

Verdicts per row:
    OK             source and every mirror agree
    DRIFT          a copy disagrees with its source, or a source lost its
                   value -- and NO ledger row tracks it. Exit 1.
    DRIFT-TRACKED  drift that a live claim-ledger row already tracks
                   (tracked_by). Printed loudly, exit 0 -- the ledger owns it.
                   A tracked_by naming a MISSING or RETRACTED ledger row is
                   itself DRIFT: tracking that points nowhere is theatre.
    UNENFORCED     declaration rows -- counted, printed, honest.
    NOT_RUN        file unreadable / check impossible. Exit 1. A check that
                   did not run is a FAIL, not an absence of failure.

Exit codes: 0 clean-or-tracked | 1 new drift or NOT_RUN | 3 usage/parse error.
Zero dependencies. UTF-8, newline="" I/O throughout (mutate.py harness lesson).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

__version__ = "1"

OK = "OK"
DRIFT = "DRIFT"
TRACKED = "DRIFT-TRACKED"
UNENFORCED = "UNENFORCED"
NOT_RUN = "NOT_RUN"

REQUIRED_ROW_FIELDS = ["id", "invariant", "value", "change_trigger",
                       "violation_response", "provenance", "check"]


def read_text(path):
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return fh.read()


class Finding(object):
    __slots__ = ("row", "fid", "verdict", "where", "message")

    def __init__(self, row, locator, verdict, where, message):
        self.row = row
        self.fid = "%s@%s" % (row, locator)
        self.verdict = verdict
        self.where = where
        self.message = message

    def as_dict(self):
        return {"id": self.fid, "row": self.row, "verdict": self.verdict,
                "where": self.where, "message": self.message}


def load_registry(path):
    errors = []
    try:
        raw = json.loads(read_text(path))
    except Exception as exc:                        # noqa: BLE001
        return None, ["registry is not readable JSON: %s" % exc]
    rows = raw.get("rows") if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        return None, ["registry must be a JSON array of rows or an object "
                      "with a 'rows' array"]
    seen = set()
    for pos, r in enumerate(rows):
        tag = r.get("id") if isinstance(r, dict) and r.get("id") else "row[%d]" % pos
        if not isinstance(r, dict):
            errors.append("%s is not an object" % tag)
            continue
        for f in REQUIRED_ROW_FIELDS:
            if f not in r:
                errors.append("%s: missing required field '%s'" % (tag, f))
        if r.get("id") in seen:
            errors.append("%s: duplicate row id" % tag)
        seen.add(r.get("id"))
        chk = r.get("check")
        if not isinstance(chk, dict) or chk.get("kind") not in (
                "constant", "grep", "declaration"):
            errors.append("%s: check.kind must be constant|grep|declaration" % tag)
    return rows, errors


def load_ledger_rows(path):
    """Return {id: row} for live (non-retracted) claim-ledger rows."""
    raw = json.loads(read_text(path))
    rows = raw.get("rows") if isinstance(raw, dict) else raw
    out = {}
    for r in rows or []:
        if isinstance(r, dict) and r.get("id"):
            out[r["id"]] = r
    return out


def check_constant(root, spec):
    """spec: {file, name, expected}. Regex NAME = value, quotes stripped."""
    path = os.path.join(root, spec["file"])
    try:
        text = read_text(path)
    except Exception as exc:                        # noqa: BLE001
        return None, "source unreadable: %s" % exc
    pat = re.compile(r"^\s*%s\s*=\s*(.+?)\s*(?:#.*)?$"
                     % re.escape(spec["name"]), re.MULTILINE)
    m = pat.search(text)
    if not m:
        return False, "constant %s not found in %s" % (spec["name"], spec["file"])
    got = m.group(1).strip().strip("\"'")
    want = str(spec["expected"]).strip()
    if got == want:
        return True, "%s = %s" % (spec["name"], got)
    return False, "%s is %r in %s but the registry says %r -- one of them is " \
                  "stale, and the registry must never silently win" \
                  % (spec["name"], got, spec["file"], want)


def check_grep(root, spec):
    """spec: {file, pattern, expect: present|absent}."""
    path = os.path.join(root, spec["file"])
    try:
        text = read_text(path)
    except Exception as exc:                        # noqa: BLE001
        return None, "file unreadable: %s" % exc
    try:
        found = re.search(spec["pattern"], text, re.MULTILINE) is not None
    except re.error as exc:
        return None, "bad pattern: %s" % exc
    expect_present = spec.get("expect", "present") == "present"
    if found == expect_present:
        return True, "%s %s in %s" % (
            spec["pattern"], "present" if found else "absent", spec["file"])
    return False, "expected %r to be %s in %s, it is %s" % (
        spec["pattern"], "present" if expect_present else "absent",
        spec["file"], "present" if found else "absent")


def run_row(row, root, ledger):
    rid = row.get("id", "?")
    chk = row["check"]
    findings = []
    tracked_by = row.get("tracked_by")
    tracking_ok = None
    if tracked_by:
        if ledger is None:
            findings.append(Finding(rid, "tracking", NOT_RUN, "ledger",
                                    "row carries tracked_by=%s but no ledger "
                                    "was supplied (--ledger); tracking cannot "
                                    "be verified" % tracked_by))
            tracking_ok = False
        elif tracked_by not in ledger:
            findings.append(Finding(rid, "tracking", DRIFT, "ledger",
                                    "tracked_by names %s which is not in the "
                                    "ledger -- tracking that points nowhere is "
                                    "theatre" % tracked_by))
            tracking_ok = False
        elif ledger[tracked_by].get("retracted"):
            findings.append(Finding(rid, "tracking", DRIFT, "ledger",
                                    "tracked_by names %s which is RETRACTED -- "
                                    "the drift lost its owner" % tracked_by))
            tracking_ok = False
        else:
            tracking_ok = True

    def drift_verdict():
        return TRACKED if tracking_ok else DRIFT

    if chk["kind"] == "declaration":
        findings.append(Finding(rid, "declaration", UNENFORCED,
                                row.get("provenance", ""),
                                "%s -- no machine check yet; suggested probe: %s"
                                % (row["invariant"],
                                   chk.get("suggested_probe", "none recorded"))))
        return findings

    fn = check_constant if chk["kind"] == "constant" else check_grep
    ok, msg = fn(root, chk)
    if ok is None:
        findings.append(Finding(rid, "source", NOT_RUN, chk.get("file", "?"), msg))
    elif not ok:
        findings.append(Finding(rid, "source", drift_verdict(),
                                chk.get("file", "?"), msg))

    for i, mspec in enumerate(row.get("mirrors") or []):
        mok, mmsg = check_grep(root, mspec)
        loc = "mirror%d:%s" % (i + 1, mspec.get("file", "?"))
        if mok is None:
            findings.append(Finding(rid, loc, NOT_RUN, mspec.get("file", "?"), mmsg))
        elif not mok:
            findings.append(Finding(rid, loc, drift_verdict(),
                                    mspec.get("file", "?"),
                                    mmsg + (" [tracked by %s]" % tracked_by
                                            if tracking_ok else "")))
    if not findings:
        findings.append(Finding(rid, "ok", OK, chk.get("file", "?"),
                                row["invariant"]))
    return findings


def run(registry_path, opts):
    rows, errors = load_registry(registry_path)
    if rows is None:
        return None, errors
    ledger = None
    if opts.ledger:
        try:
            ledger = load_ledger_rows(opts.ledger)
        except Exception as exc:                    # noqa: BLE001
            errors.append("ledger unreadable: %s" % exc)
    all_findings = []
    for row in rows:
        if not isinstance(row, dict) or "check" not in row:
            continue
        try:
            all_findings.extend(run_row(row, opts.root, ledger))
        except Exception as exc:                    # noqa: BLE001 -- fail closed
            all_findings.append(Finding(row.get("id", "?"), "crash", NOT_RUN,
                                        "sweep", "row check raised %s: %s"
                                        % (type(exc).__name__, exc)))
    return (rows, all_findings), errors


def exit_code(findings, errors):
    if errors:
        return 3
    for f in findings:
        if f.verdict in (DRIFT, NOT_RUN):
            return 1
    return 0


def render(rows, findings, errors, registry_path, opts):
    out = ["invariant_sweep v%s" % __version__,
           "  registry : %s" % registry_path,
           "  root     : %s" % os.path.abspath(opts.root),
           "  ledger   : %s" % (opts.ledger or "(none -- tracked_by unverifiable)"),
           "  rows     : %d  (computed, not typed)" % len(rows),
           ""]
    for e in errors:
        out.append("  REGISTRY ERROR: %s" % e)
    if errors:
        out.append("")
    counts = {}
    for f in findings:
        counts[f.verdict] = counts.get(f.verdict, 0) + 1
    out.append("  VERDICT CENSUS")
    for v in (OK, TRACKED, DRIFT, UNENFORCED, NOT_RUN):
        out.append("    %-14s %d" % (v, counts.get(v, 0)))
    out.append("")
    order = {DRIFT: 0, NOT_RUN: 1, TRACKED: 2, UNENFORCED: 3, OK: 4}
    for f in sorted(findings, key=lambda x: (order[x.verdict], x.fid)):
        if f.verdict == OK and not opts.all:
            continue
        out.append("  [%s] %s" % (f.verdict, f.fid))
        out.append("      %s" % f.message)
        out.append("      at %s" % f.where)
    out.append("")
    if counts.get(UNENFORCED):
        out.append("  %d declaration row(s) are UNENFORCED -- they are honesty, "
                   "not coverage." % counts[UNENFORCED])
    if counts.get(TRACKED):
        out.append("  %d drift(s) are tracked by live ledger rows -- the ledger "
                   "owns them; fixing the code or the copy closes them."
                   % counts[TRACKED])
    return "\n".join(out)


# ------------------------------------------------------------------ selftest

def selftest(expected_name="inv_expected-v1.json", quiet=False):
    here = os.path.dirname(os.path.abspath(__file__))
    fx = os.path.join(here, "fixtures")

    class O(object):
        root = os.path.join(fx, "inv_mockrepo")
        ledger = os.path.join(fx, "inv_mock_ledger-v1.json")
        all = True

    reg = os.path.join(fx, "inv_registry_known_bad-v1.json")
    exp = os.path.join(fx, expected_name)
    for p in (reg, exp, O.root, O.ledger):
        if not os.path.exists(p):
            print("SELFTEST FAIL: missing fixture %s" % p)
            return 3
    expected = json.loads(read_text(exp))
    payload, errors = run(reg, O())
    if payload is None:
        print("SELFTEST FAIL: fixture registry did not parse")
        for e in errors:
            print("   %s" % e)
        return 3
    _rows, findings = payload
    got = sorted("%s|%s" % (f.fid, f.verdict) for f in findings)
    want = sorted(expected["finding_ids"])
    ok = True
    lines = []
    for i in want:
        if i not in got:
            ok = False
            lines.append("   MISSING  %s" % i)
    for i in got:
        if i not in want:
            ok = False
            lines.append("   EXTRA    %s" % i)
    if quiet:
        return 0 if ok else 1
    if ok:
        print("SELFTEST PASS")
        print("  finding id+verdict pairs matched exactly : %d" % len(got))
        print("  (asserted on ids, never on a count)")
        return 0
    print("SELFTEST FAIL")
    for ln in lines:
        print(ln)
    return 1


def selftest_meta():
    here = os.path.dirname(os.path.abspath(__file__))
    wrong = os.path.join(here, "fixtures", "inv_expected_WRONG-v1.json")
    if not os.path.isfile(wrong):
        print("META FAIL: missing fixture %s" % wrong)
        return 3
    rc_good = selftest(quiet=True)
    rc_bad = selftest("inv_expected_WRONG-v1.json", quiet=True)
    print("META: selftest vs correct expectation -> %d (want 0)" % rc_good)
    print("META: selftest vs wrong   expectation -> %d (want 1)" % rc_bad)
    if rc_good == 0 and rc_bad == 1:
        print("META PASS: the selftest is provably able to fail")
        return 0
    print("META FAIL: the selftest cannot tell a wrong expectation from a right one")
    return 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="invariant_sweep",
        description="Check every copy of a product truth against its one "
                    "authoritative source.")
    ap.add_argument("registry", nargs="?", help="invariants JSON registry")
    ap.add_argument("--root", default=".", help="repo root the paths resolve against")
    ap.add_argument("--ledger", help="claim ledger JSON, to verify tracked_by rows")
    ap.add_argument("--all", action="store_true", help="print OK rows too")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--selftest-meta", action="store_true")
    ap.add_argument("--version", action="store_true")
    opts = ap.parse_args(argv)

    if opts.version:
        print("invariant_sweep v%s" % __version__)
        return 0
    if opts.selftest_meta:
        return selftest_meta()
    if opts.selftest:
        return selftest()
    if not opts.registry:
        ap.print_usage()
        print("error: <registry> is required (or --selftest)")
        return 3
    if not os.path.isfile(opts.registry):
        print("error: no such file: %s" % opts.registry)
        return 3
    payload, errors = run(opts.registry, opts)
    if payload is None:
        for e in errors:
            print("REGISTRY ERROR: %s" % e)
        return 3
    rows, findings = payload
    if opts.json:
        print(json.dumps({"registry": opts.registry,
                          "findings": [f.as_dict() for f in findings],
                          "errors": errors}, indent=2, ensure_ascii=False))
    else:
        print(render(rows, findings, errors, opts.registry, opts))
    return exit_code(findings, errors)


if __name__ == "__main__":
    sys.exit(main())
