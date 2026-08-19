#!/usr/bin/env python3
"""install_gate v0.1 — the INSTALL LADDER made runnable (OMEGA-INSTALLFORGE v1.0).

Companion to validate_zros.py (execution gates) and index_gate.py (index claims).
This one gates ARTIFACT PLACEMENT: not "is the claim true" but "is the thing
where a consumer can meet it, and can we prove that today".

Parented by claude/value-dilution-register-2026-08-19-v1.md: 40 dilution events,
zero deletions. The mechanism is non-compounding, not destruction.

Read-only. Never writes, never deletes. Exit 0 = clean, 1 = findings, 2 = usage.
Stdlib only. Git Bash / MINGW64 compatible. Never reads a wall clock: the two
date-dependent rules run ONLY with --as-of, and say so when they do not run.

  python install_gate_v0_1.py check install_ledger.json --as-of 2026-08-19
  python install_gate_v0_1.py debt --register REG.md --report R1.md --report R2.md
  python install_gate_v0_1.py selftest
  python install_gate_v0_1.py selftest-meta
  python install_gate_v0_1.py schema
"""
import sys, os, json, re, hashlib, tempfile, argparse
from datetime import date

VERSION = "install_gate v0.1"

RUNGS = ["CREATED", "STORED", "WIRED", "INSTALLED", "COMPOUNDING"]
CLAIM_RUNGS = ["ASSERTED", "SOURCED", "PROBED", "SHIPPED-PROBED"]

ORPHAN_MAX_DAYS = 1     # an artifact at CREATED past one day is an orphan (A1: 177)
DECAY_MAX_DAYS = 30     # a verification older than this has decayed (CL-6 pattern)

ALL_IDS = {
    "IG-01-ORPHAN",
    "IG-02-NO-DESTINATION",
    "IG-03-NO-VERIFY",
    "IG-04-DECAYED",
    "IG-05-DUP-JOB",
    "IG-06-MISSING",
    "IG-06-DRIFT",
    "IG-07-BELOW-REQUIRED",
    "IG-08-CLAIM-ABOVE-INSTALL",
    "IG-08-BELOW-CLAIM-RUNG",
    "IG-09-INCIDENT-DEBT",
}

DISABLED = set()   # selftest-meta switches rules off here


# ---------------------------------------------------------------- helpers

def rung_idx(v, table=RUNGS):
    try:
        return table.index((v or "").strip().upper())
    except ValueError:
        return -1


def parse_date(s):
    if not s:
        return None
    try:
        y, m, d = str(s).strip().split("-")
        return date(int(y), int(m), int(d))
    except Exception:
        return None


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def V(rid, row_id, msg):
    return {"id": rid, "row": row_id, "msg": msg}


# ---------------------------------------------------------------- rules

def rule_IG01(rows, ctx):
    out = []
    if ctx["as_of"] is None:
        ctx["not_run"].append("IG-01-ORPHAN (needs --as-of)")
        return out
    for r in rows:
        if rung_idx(r.get("rung")) == 0:
            created = parse_date(r.get("created"))
            if created is None:
                out.append(V("IG-01-ORPHAN", r["id"], "at CREATED with no created date"))
            else:
                age = (ctx["as_of"] - created).days
                if age > ORPHAN_MAX_DAYS:
                    out.append(V("IG-01-ORPHAN", r["id"],
                                 "at CREATED for %d days (max %d)" % (age, ORPHAN_MAX_DAYS)))
    return out


def rule_IG02(rows, ctx):
    return [V("IG-02-NO-DESTINATION", r["id"], "no destination named")
            for r in rows if not str(r.get("destination", "")).strip()]


def rule_IG03(rows, ctx):
    out = []
    for r in rows:
        if rung_idx(r.get("rung")) >= rung_idx("WIRED") and not str(r.get("verify", "")).strip():
            out.append(V("IG-03-NO-VERIFY", r["id"], "at %s with no verify command" % r.get("rung")))
    return out


def rule_IG04(rows, ctx):
    out = []
    if ctx["as_of"] is None:
        ctx["not_run"].append("IG-04-DECAYED (needs --as-of)")
        return out
    for r in rows:
        if rung_idx(r.get("rung")) < rung_idx("WIRED"):
            continue
        lv = parse_date(r.get("last_verified"))
        if lv is None:
            out.append(V("IG-04-DECAYED", r["id"], "at %s with no last_verified" % r.get("rung")))
        else:
            age = (ctx["as_of"] - lv).days
            if age > DECAY_MAX_DAYS:
                out.append(V("IG-04-DECAYED", r["id"],
                             "last verified %d days ago (max %d)" % (age, DECAY_MAX_DAYS)))
    return out


def rule_IG05(rows, ctx):
    counts = {}
    for r in rows:
        j = str(r.get("job", "")).strip().lower()
        if j:
            counts.setdefault(j, []).append(r["id"])
    out = []
    for j, ids in counts.items():
        if len(ids) > 1:
            for rid in ids:
                out.append(V("IG-05-DUP-JOB", rid,
                             "job '%s' also claimed by %s" % (j, ",".join(x for x in ids if x != rid))))
    return out


def rule_IG06(rows, ctx):
    out = []
    for r in rows:
        p = str(r.get("destination_file", "")).strip()
        if not p:
            continue
        ctx["files_checked"] += 1
        if not os.path.isfile(p):
            out.append(V("IG-06-MISSING", r["id"], "destination_file absent: %s" % p))
            continue
        want = str(r.get("sha256", "")).strip().lower()
        if want:
            got = sha256_of(p)
            if got != want:
                out.append(V("IG-06-DRIFT", r["id"],
                             "sha256 %s != recorded %s" % (got[:12], want[:12])))
    return out


def rule_IG07(rows, ctx):
    out = []
    for r in rows:
        have, need = rung_idx(r.get("rung")), rung_idx(r.get("required_rung"))
        if need >= 0 and have < need:
            out.append(V("IG-07-BELOW-REQUIRED", r["id"],
                         "at %s, required %s" % (r.get("rung"), r.get("required_rung"))))
    return out


def rule_IG08(rows, ctx):
    out = []
    for r in rows:
        cr = (r.get("claim_rung") or "").strip().upper()
        if not cr:
            continue
        ci = rung_idx(cr, CLAIM_RUNGS)
        if cr == "SHIPPED-PROBED" and rung_idx(r.get("rung")) < rung_idx("INSTALLED"):
            out.append(V("IG-08-CLAIM-ABOVE-INSTALL", r["id"],
                         "claim SHIPPED-PROBED while artifact is only %s" % r.get("rung")))
        need = (r.get("required_claim_rung") or "").strip().upper()
        if need:
            ni = rung_idx(need, CLAIM_RUNGS)
            if ni >= 0 and ci < ni:
                out.append(V("IG-08-BELOW-CLAIM-RUNG", r["id"],
                             "claim at %s, required %s" % (cr, need)))
    return out


RULES = {
    "IG-01": rule_IG01, "IG-02": rule_IG02, "IG-03": rule_IG03,
    "IG-04": rule_IG04, "IG-05": rule_IG05, "IG-06": rule_IG06,
    "IG-07": rule_IG07, "IG-08": rule_IG08,
}


def run_rules(rows, as_of=None):
    ctx = {"as_of": as_of, "not_run": [], "files_checked": 0}
    found = []
    for rid, fn in sorted(RULES.items()):
        if rid in DISABLED:
            continue
        found.extend(fn(rows, ctx))
    return found, ctx


# ---------------------------------------------------------------- IG-09 debt

INCIDENT_HEADING = re.compile(r"INCIDENT", re.I)
SEP_ROW = re.compile(r"^\|[\s:\-\|]+\|$")


def count_incident_rows(text):
    """Rows under a heading containing INCIDENT, >=8 cells, first cell a real id.
    Mirrors how titan-incident-register.md counts itself."""
    n, under = 0, False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            under = bool(INCIDENT_HEADING.search(s))
            continue
        if not under or not s.startswith("|") or SEP_ROW.match(s):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if len(cells) < 8:
            continue
        first = cells[0].replace("\\", "")
        if not first or first == "#":
            continue
        if re.match(r"^[A-Za-z]*\d+[a-z]?$|^[A-Za-z0-9]+-\d+$", first):
            n += 1
    return n


def cmd_debt(args):
    if "IG-09" in DISABLED:
        print("IG-09 disabled"); return 0
    reg = count_incident_rows(open(args.register, encoding="utf-8").read())
    per, total = [], 0
    for p in args.report or []:
        c = count_incident_rows(open(p, encoding="utf-8").read())
        per.append((os.path.basename(p), c)); total += c
    unmerged = total
    print("%s  mode=debt" % VERSION)
    print("REGISTER_ROWS=%d  REPORTS_SCANNED=%d  REPORT_ROWS=%d" % (reg, len(per), total))
    for name, c in per:
        print("  %-52s %d" % (name[:52], c))
    if unmerged > 0:
        print("IG-09-INCIDENT-DEBT: %d incident rows live in session reports and "
              "not in the register" % unmerged)
        print("FINDINGS=1  EXIT=1")
        return 1
    print("FINDINGS=0  CLEAN  EXIT=0")
    return 0


# ---------------------------------------------------------------- check

def cmd_check(args):
    data = json.load(open(args.ledger, encoding="utf-8"))
    rows = data.get("rows", [])
    for i, r in enumerate(rows):
        r.setdefault("id", "row%d" % i)
    as_of = parse_date(args.as_of)
    if args.as_of and as_of is None:
        print("bad --as-of (want YYYY-MM-DD)"); return 2
    found, ctx = run_rules(rows, as_of)

    print("%s  mode=check" % VERSION)
    # G1-05 / session-8 lesson 2: absence always carries its scope
    print("ROWS_SCANNED=%d  FILES_CHECKED=%d  RULES_RUN=%d  LEDGER=%s"
          % (len(rows), ctx["files_checked"], len(RULES) - len(DISABLED),
             os.path.basename(args.ledger)))
    for nr in ctx["not_run"]:
        print("DETECTOR_NOT_RUN: %s" % nr)
    if not found:
        print("FINDINGS=0  CLEAN  EXIT=0")
        return 0
    for v in sorted(found, key=lambda x: (x["id"], x["row"])):
        print("  %-26s %-8s %s" % (v["id"], v["row"], v["msg"]))
    ids = sorted({v["id"] for v in found})
    print("FINDINGS=%d  DISTINCT_IDS=%d  ids: %s" % (len(found), len(ids), " ".join(ids)))
    print("BLOCK  EXIT=1")
    return 1


# ---------------------------------------------------------------- fixtures

def _tmp(content):
    fd, p = tempfile.mkstemp(suffix=".txt", prefix="ig_fx_")
    os.write(fd, content); os.close(fd)
    return p


def build_fixtures():
    """Every fixture is a MEASURED event from the value-dilution register.
    CLEAN must produce the empty set: if the base fires, nothing below proves
    anything."""
    good = _tmp(b"installed artifact\n")
    good_hash = sha256_of(good)
    drift = _tmp(b"the file changed under us\n")

    F = []
    base = dict(id="CLEAN", artifact="index_gate.py", job="caai-index-gate",
                kind="code", created="2026-08-19", rung="INSTALLED",
                required_rung="INSTALLED", destination="index_gate2/",
                verify="python index_gate.py selftest", last_verified="2026-08-19",
                destination_file=good, sha256=good_hash,
                claim_rung="SHIPPED-PROBED", required_claim_rung="SHIPPED-PROBED")
    F.append(("CLEAN", [base], set()))

    F.append(("A1_caai_orphan", [dict(base, id="A1", job="caai-scoring",
              artifact="caai_v1_scorer.py", created="2026-02-23", rung="CREATED",
              required_rung="INSTALLED", last_verified="2026-02-23",
              destination_file="", sha256="", claim_rung="", required_claim_rung="")],
              {"IG-01-ORPHAN", "IG-04-DECAYED"} - {"IG-04-DECAYED"} | {"IG-07-BELOW-REQUIRED"}))

    F.append(("A2_spec2_unpublished", [dict(base, id="A2", job="signing-spec",
              artifact="docs/SPEC-2.md", rung="STORED", required_rung="INSTALLED",
              destination_file="", sha256="", claim_rung="", required_claim_rung="")],
              {"IG-07-BELOW-REQUIRED"}))

    F.append(("A5_no_destination", [dict(base, id="A5", job="evidence-trail",
              destination="", destination_file="", sha256="",
              claim_rung="", required_claim_rung="")],
              {"IG-02-NO-DESTINATION"}))

    F.append(("E4_no_verify", [dict(base, id="E4", job="register-merge",
              verify="", destination_file="", sha256="",
              claim_rung="", required_claim_rung="")],
              {"IG-03-NO-VERIFY"}))

    F.append(("CL6_decayed", [dict(base, id="CL6", job="suite-count",
              last_verified="2026-06-01", destination_file="", sha256="",
              claim_rung="", required_claim_rung="")],
              {"IG-04-DECAYED"}))

    F.append(("C1_dup_job", [
        dict(base, id="C1a", job="ai-visibility-audit", destination_file="", sha256="",
             claim_rung="", required_claim_rung=""),
        dict(base, id="C1b", job="ai-visibility-audit", destination_file="", sha256="",
             claim_rung="", required_claim_rung="")],
        {"IG-05-DUP-JOB"}))

    F.append(("B4_identity_drift", [dict(base, id="B4", job="index-gate-binary",
              destination_file=drift, sha256=good_hash,
              claim_rung="", required_claim_rung="")],
              {"IG-06-DRIFT"}))

    F.append(("C3_missing_file", [dict(base, id="C3", job="zros-validator",
              destination_file=os.path.join(tempfile.gettempdir(), "ig_absent_xyz.txt"),
              sha256="", claim_rung="", required_claim_rung="")],
              {"IG-06-MISSING"}))

    F.append(("D1_claim_above_install", [dict(base, id="D1", job="soc2-attestation",
              rung="WIRED", required_rung="WIRED", destination_file="", sha256="",
              claim_rung="SHIPPED-PROBED", required_claim_rung="")],
              {"IG-08-CLAIM-ABOVE-INSTALL"}))

    F.append(("D2_below_claim_rung", [dict(base, id="D2", job="receipt-verifiability",
              destination_file="", sha256="",
              claim_rung="ASSERTED", required_claim_rung="SHIPPED-PROBED")],
              {"IG-08-BELOW-CLAIM-RUNG"}))

    return F, [good, drift]


SELFTEST_AS_OF = date(2026, 8, 19)


def cmd_selftest(args=None, quiet=False):
    fixtures, tmps = build_fixtures()
    ok, produced = True, set()
    for name, rows, expected in fixtures:
        found, _ = run_rules([dict(r) for r in rows], SELFTEST_AS_OF)
        got = {v["id"] for v in found}
        produced |= got
        if got != expected:
            ok = False
            if not quiet:
                print("  FAIL %-24s expected %s got %s"
                      % (name, sorted(expected) or "{}", sorted(got) or "{}"))
        elif not quiet:
            print("  ok   %-24s %s" % (name, sorted(got) or "{}"))

    # debt fixture (IG-09) — a report row that never reached the register
    reg = _tmp(b"## INCIDENTS\n| # | Class | I | E | R | D | C | G |\n"
               b"|---|---|---|---|---|---|---|---|\n"
               b"| 1 | D | x | y | z | a | b | c |\n")
    rep = _tmp(b"## INCIDENTS\n| # | Class | I | E | R | D | C | G |\n"
               b"|---|---|---|---|---|---|---|---|\n"
               b"| S4-1 | D | x | y | z | a | b | c |\n"
               b"| S4-2 | B | x | y | z | a | b | c |\n")
    tmps += [reg, rep]
    debt = count_incident_rows(open(rep, encoding="utf-8").read())
    regn = count_incident_rows(open(reg, encoding="utf-8").read())
    if debt == 2 and regn == 1:
        produced.add("IG-09-INCIDENT-DEBT")
        if not quiet:
            print("  ok   %-24s ['IG-09-INCIDENT-DEBT'] (report=2 register=1)" % "IG09_debt")
    else:
        ok = False
        if not quiet:
            print("  FAIL IG09_debt  report=%d register=%d (want 2/1)" % (debt, regn))

    missing = ALL_IDS - produced
    if missing and not DISABLED:
        ok = False
        if not quiet:
            print("  FAIL coverage: ids never produced by any fixture: %s" % sorted(missing))

    for p in tmps:
        try:
            os.unlink(p)   # created by this process inside tempdir; never a pre-existing path
        except OSError:
            pass

    if not quiet:
        print("selftest: %d fixtures + coverage assertion" % (len(fixtures) + 1))
        print("PASS" if ok else "FAIL")
        print("SELFTEST_EXIT=%d" % (0 if ok else 1))
    return 0 if ok else 1


def cmd_selftest_meta(args=None):
    """APEX L6 on the checker itself: a selftest that still passes with a rule
    switched off proves that rule has no fixture."""
    allok = True
    for rid in sorted(RULES):
        DISABLED.add(rid)
        rc = cmd_selftest(quiet=True)
        DISABLED.discard(rid)
        good = (rc != 0)
        allok &= good
        print("  %-4s disabling it %s the selftest" % (rid, "breaks" if good else "DOES NOT BREAK"))
    print("PASS" if allok else "FAIL")
    print("META_EXIT=%d" % (0 if allok else 1))
    return 0 if allok else 1


SCHEMA = {
    "version": "1",
    "as_of": "YYYY-MM-DD",
    "rows": [{
        "id": "IL-1",
        "artifact": "what the thing is",
        "job": "the job it claims — two rows with one job is IG-05",
        "kind": "code|doc|claim|incident|capability|data",
        "created": "YYYY-MM-DD",
        "rung": "|".join(RUNGS),
        "required_rung": "|".join(RUNGS),
        "destination": "the surface a consumer actually meets",
        "destination_file": "optional local path for hash identity (IG-06)",
        "sha256": "optional recorded hash",
        "verify": "the command that proves it is installed",
        "last_verified": "YYYY-MM-DD",
        "claim_rung": "|".join(CLAIM_RUNGS) + " (optional)",
        "required_claim_rung": "|".join(CLAIM_RUNGS) + " (optional)",
    }],
}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="install_gate_v0_1.py", add_help=True)
    sub = ap.add_subparsers(dest="cmd")
    c = sub.add_parser("check"); c.add_argument("ledger"); c.add_argument("--as-of", default=None)
    d = sub.add_parser("debt"); d.add_argument("--register", required=True)
    d.add_argument("--report", action="append")
    sub.add_parser("selftest"); sub.add_parser("selftest-meta"); sub.add_parser("schema")
    a = ap.parse_args(argv)
    if a.cmd == "check":
        return cmd_check(a)
    if a.cmd == "debt":
        return cmd_debt(a)
    if a.cmd == "selftest":
        return cmd_selftest(a)
    if a.cmd == "selftest-meta":
        return cmd_selftest_meta(a)
    if a.cmd == "schema":
        print(json.dumps(SCHEMA, indent=2)); return 0
    ap.print_help(); return 2


if __name__ == "__main__":
    sys.exit(main())
