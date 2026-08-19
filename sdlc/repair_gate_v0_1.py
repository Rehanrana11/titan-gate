#!/usr/bin/env python3
"""repair_gate v0.1 — the repair queue made runnable (OMEGA-REPAIRFORGE v1.0).

Third in the family: validate_zros (execution) / index_gate (index claims) /
install_gate (artifact placement) / repair_gate (FIX ORDER).

Subject: not "is the fix correct" but "is it scheduled where it cannot bake a
known bug into a downstream artifact". The register's most expensive failures
were ordering failures, not coding failures:
  - a golden set labelled on a broken parser bakes the bug into the labels
  - export before cleaning ships a manufactured citation as tamper-evident
  - depth on an unvalidated extractor buys precision, not accuracy
  - re-weighting before SS is redesigned tunes against a degenerate basis

Read-only. Never writes, never deletes. Exit 0 clean / 1 findings / 2 usage.
Stdlib only. MINGW64 compatible. Reads no wall clock.

  python repair_gate_v0_1.py check repair_queue_v1.json [--issues ISSUES.txt]
  python repair_gate_v0_1.py plan  repair_queue_v1.json
  python repair_gate_v0_1.py selftest
  python repair_gate_v0_1.py selftest-meta
  python repair_gate_v0_1.py schema
"""
import sys, os, json, argparse

VERSION = "repair_gate v0.1"
STATUSES = ["blocked", "ready", "done"]

ALL_IDS = {
    "RQ-01-NO-ACCEPT",
    "RQ-02-CLOSES-NOTHING",
    "RQ-03-CYCLE",
    "RQ-04-ORDER-VIOLATION",
    "RQ-05-NO-DESTINATION",
    "RQ-06-ANTI-SCOPE",
    "RQ-07-UNCLOSED-ISSUE",
    "RQ-08-READY-BUT-BLOCKED",
    "RQ-09-UNKNOWN-DEP",
}
DISABLED = set()


def V(rid, fid, msg):
    return {"id": rid, "fix": fid, "msg": msg}


# ------------------------------------------------------------------ rules

def rule_RQ01(fx, ctx):
    return [V("RQ-01-NO-ACCEPT", f["id"], "no acceptance test")
            for f in fx if not str(f.get("accept", "")).strip()]


def rule_RQ02(fx, ctx):
    return [V("RQ-02-CLOSES-NOTHING", f["id"], "closes no issue id")
            for f in fx if not f.get("closes")]


def rule_RQ03(fx, ctx):
    """Cycle detection. A cycle means the queue can never start."""
    byid = {f["id"]: f for f in fx}
    WHITE, GREY, BLACK = 0, 1, 2
    color = {i: WHITE for i in byid}
    out, seen = [], set()

    def visit(n, stack):
        if color.get(n, BLACK) == GREY:
            cyc = " -> ".join(stack[stack.index(n):] + [n])
            if cyc not in seen:
                seen.add(cyc)
                out.append(V("RQ-03-CYCLE", n, "dependency cycle: %s" % cyc))
            return
        if color.get(n, BLACK) == BLACK:
            return
        color[n] = GREY
        for d in byid[n].get("depends_on", []):
            if d in byid:
                visit(d, stack + [n])
        color[n] = BLACK

    for i in list(byid):
        if color[i] == WHITE:
            visit(i, [])
    return out


def rule_RQ04(fx, ctx):
    """A fix may not be scheduled in an earlier phase than something it needs."""
    byid = {f["id"]: f for f in fx}
    out = []
    for f in fx:
        for d in f.get("depends_on", []):
            dep = byid.get(d)
            if dep is None:
                continue
            if int(f.get("phase", 0)) < int(dep.get("phase", 0)):
                out.append(V("RQ-04-ORDER-VIOLATION", f["id"],
                             "phase %s but depends on %s in phase %s"
                             % (f.get("phase"), d, dep.get("phase"))))
    return out


def rule_RQ05(fx, ctx):
    return [V("RQ-05-NO-DESTINATION", f["id"], "no destination named")
            for f in fx if not str(f.get("destination", "")).strip()]


def rule_RQ06(fx, ctx):
    """A fix carrying a declared anti-scope tag is banned until its unlock
    condition is satisfied by a dependency being present."""
    banned = {a["tag"]: a for a in ctx.get("anti_scope", [])}
    out = []
    for f in fx:
        for t in f.get("anti_scope_tags", []):
            a = banned.get(t)
            if a is None:
                continue
            unlock = a.get("unlocked_by")
            if unlock and unlock in f.get("depends_on", []):
                continue
            out.append(V("RQ-06-ANTI-SCOPE", f["id"],
                         "anti-scope '%s' — unlock requires depends_on %s"
                         % (t, unlock)))
    return out


def rule_RQ07(fx, ctx):
    closed = set()
    for f in fx:
        closed |= set(f.get("closes", []))
    out = []
    for i in sorted(ctx.get("issues", [])):
        if i not in closed:
            out.append(V("RQ-07-UNCLOSED-ISSUE", "-", "issue %s has no fix" % i))
    return out


def rule_RQ08(fx, ctx):
    byid = {f["id"]: f for f in fx}
    out = []
    for f in fx:
        if f.get("status") != "ready":
            continue
        for d in f.get("depends_on", []):
            dep = byid.get(d)
            if dep is not None and dep.get("status") != "done":
                out.append(V("RQ-08-READY-BUT-BLOCKED", f["id"],
                             "ready while %s is %s" % (d, dep.get("status"))))
    return out


def rule_RQ09(fx, ctx):
    ids = {f["id"] for f in fx}
    return [V("RQ-09-UNKNOWN-DEP", f["id"], "depends on unknown fix %s" % d)
            for f in fx for d in f.get("depends_on", []) if d not in ids]


RULES = {"RQ-01": rule_RQ01, "RQ-02": rule_RQ02, "RQ-03": rule_RQ03,
         "RQ-04": rule_RQ04, "RQ-05": rule_RQ05, "RQ-06": rule_RQ06,
         "RQ-07": rule_RQ07, "RQ-08": rule_RQ08, "RQ-09": rule_RQ09}


def run_rules(fx, ctx):
    found = []
    for rid, fn in sorted(RULES.items()):
        if rid in DISABLED:
            continue
        found.extend(fn(fx, ctx))
    return found


# ------------------------------------------------------------------ plan

def topo(fx):
    """Kahn, tie-broken by (phase, id) so the order is deterministic."""
    byid = {f["id"]: f for f in fx}
    indeg = {i: 0 for i in byid}
    for f in fx:
        for d in f.get("depends_on", []):
            if d in byid:
                indeg[f["id"]] += 1
    order, ready = [], sorted([i for i in byid if indeg[i] == 0],
                              key=lambda i: (int(byid[i].get("phase", 0)), i))
    while ready:
        n = ready.pop(0)
        order.append(n)
        for f in fx:
            if n in f.get("depends_on", []) and f["id"] in indeg:
                indeg[f["id"]] -= 1
                if indeg[f["id"]] == 0:
                    ready.append(f["id"])
        ready.sort(key=lambda i: (int(byid[i].get("phase", 0)), i))
    return order, [i for i in byid if i not in order]


def cmd_plan(args):
    q = json.load(open(args.queue, encoding="utf-8"))
    fx = q.get("fixes", [])
    byid = {f["id"]: f for f in fx}
    order, stuck = topo(fx)
    print("%s  mode=plan" % VERSION)
    print("FIXES=%d  ORDERED=%d  UNORDERABLE=%d" % (len(fx), len(order), len(stuck)))
    cur = None
    for i in order:
        f = byid[i]
        p = int(f.get("phase", 0))
        if p != cur:
            cur = p
            print("-- PHASE %d --" % p)
        print("  %-5s %-46s closes=%s" %
              (i, str(f.get("title", ""))[:46], ",".join(f.get("closes", [])) or "-"))
    if stuck:
        print("UNORDERABLE (cycle): %s" % " ".join(stuck))
        return 1
    return 0


# ------------------------------------------------------------------ check

def cmd_check(args):
    q = json.load(open(args.queue, encoding="utf-8"))
    fx = q.get("fixes", [])
    issues = []
    if getattr(args, "issues", None):
        issues = [l.strip() for l in open(args.issues, encoding="utf-8")
                  if l.strip() and not l.startswith("#")]
    ctx = {"anti_scope": q.get("anti_scope", []), "issues": issues}
    found = run_rules(fx, ctx)
    print("%s  mode=check" % VERSION)
    print("FIXES_SCANNED=%d  ISSUES_SCANNED=%d  ANTI_SCOPE_RULES=%d  RULES_RUN=%d"
          % (len(fx), len(issues), len(ctx["anti_scope"]), len(RULES) - len(DISABLED)))
    if not issues:
        print("DETECTOR_NOT_RUN: RQ-07-UNCLOSED-ISSUE (no --issues supplied)")
    if not found:
        print("FINDINGS=0  CLEAN  EXIT=0")
        return 0
    for v in sorted(found, key=lambda x: (x["id"], x["fix"])):
        print("  %-24s %-5s %s" % (v["id"], v["fix"], v["msg"]))
    ids = sorted({v["id"] for v in found})
    print("FINDINGS=%d  DISTINCT_IDS=%d  ids: %s" % (len(found), len(ids), " ".join(ids)))
    print("BLOCK  EXIT=1")
    return 1


# ------------------------------------------------------------------ fixtures

def build_fixtures():
    base = dict(id="F0", title="clean fix", closes=["X1"], depends_on=[],
                phase=0, destination="somewhere", accept="run this",
                anti_scope_tags=[], status="ready")
    AS = [{"tag": "golden-set-before-parser", "unlocked_by": "PARSER"}]
    F = []
    F.append(("CLEAN", [dict(base)], [], AS, set()))
    F.append(("no_accept", [dict(base, accept="")], [], AS, {"RQ-01-NO-ACCEPT"}))
    F.append(("closes_nothing", [dict(base, closes=[])], [], AS, {"RQ-02-CLOSES-NOTHING"}))
    F.append(("cycle", [dict(base, id="A", depends_on=["B"]),
                        dict(base, id="B", depends_on=["A"])], [], AS,
              {"RQ-03-CYCLE", "RQ-08-READY-BUT-BLOCKED"}))
    F.append(("order_violation", [dict(base, id="P", phase=2, status="done"),
                                  dict(base, id="Q", phase=1, depends_on=["P"])],
              [], AS, {"RQ-04-ORDER-VIOLATION"}))
    F.append(("no_destination", [dict(base, destination="")], [], AS,
              {"RQ-05-NO-DESTINATION"}))
    F.append(("anti_scope", [dict(base, anti_scope_tags=["golden-set-before-parser"])],
              [], AS, {"RQ-06-ANTI-SCOPE"}))
    F.append(("anti_scope_unlocked",
              [dict(base, id="PARSER", closes=["X0"], status="done"),
               dict(base, id="G", depends_on=["PARSER"],
                    anti_scope_tags=["golden-set-before-parser"])], [], AS, set()))
    F.append(("unclosed_issue", [dict(base)], ["X1", "X9"], AS,
              {"RQ-07-UNCLOSED-ISSUE"}))
    F.append(("ready_but_blocked",
              [dict(base, id="D1", status="blocked"),
               dict(base, id="D2", depends_on=["D1"], status="ready")], [], AS,
              {"RQ-08-READY-BUT-BLOCKED"}))
    F.append(("unknown_dep", [dict(base, depends_on=["NOPE"])], [], AS,
              {"RQ-09-UNKNOWN-DEP"}))
    return F


def cmd_selftest(args=None, quiet=False):
    ok, produced = True, set()
    fixtures = build_fixtures()
    for name, fx, issues, anti, expected in fixtures:
        ctx = {"anti_scope": anti, "issues": issues}
        got = {v["id"] for v in run_rules([dict(f) for f in fx], ctx)}
        produced |= got
        if got != expected:
            ok = False
            if not quiet:
                print("  FAIL %-22s expected %s got %s"
                      % (name, sorted(expected) or "{}", sorted(got) or "{}"))
        elif not quiet:
            print("  ok   %-22s %s" % (name, sorted(got) or "{}"))
    # topological order must be deterministic and complete on an acyclic graph
    fx = [dict(id="A", phase=0, depends_on=[]), dict(id="B", phase=1, depends_on=["A"]),
          dict(id="C", phase=1, depends_on=["A"])]
    order, stuck = topo(fx)
    if order == ["A", "B", "C"] and not stuck:
        if not quiet:
            print("  ok   %-22s topo A,B,C deterministic" % "topo_order")
    else:
        ok = False
        if not quiet:
            print("  FAIL topo_order got %s stuck=%s" % (order, stuck))
    missing = ALL_IDS - produced
    if missing and not DISABLED:
        ok = False
        if not quiet:
            print("  FAIL coverage: ids never produced: %s" % sorted(missing))
    if not quiet:
        print("selftest: %d fixtures + topo + coverage assertion" % len(fixtures))
        print("PASS" if ok else "FAIL")
        print("SELFTEST_EXIT=%d" % (0 if ok else 1))
    return 0 if ok else 1


def cmd_selftest_meta(args=None):
    allok = True
    for rid in sorted(RULES):
        DISABLED.add(rid)
        rc = cmd_selftest(quiet=True)
        DISABLED.discard(rid)
        good = rc != 0
        allok &= good
        print("  %-5s disabling it %s the selftest"
              % (rid, "breaks" if good else "DOES NOT BREAK"))
    print("PASS" if allok else "FAIL")
    print("META_EXIT=%d" % (0 if allok else 1))
    return 0 if allok else 1


SCHEMA = {
    "version": "1",
    "anti_scope": [{"tag": "short-name", "rule": "why it is banned",
                    "unlocked_by": "the fix id that must be a dependency"}],
    "fixes": [{
        "id": "R01", "title": "one line",
        "closes": ["register/dilution issue ids this retires"],
        "depends_on": ["fix ids that must land first"],
        "phase": "0 now | 1 release | 2 post-release | 3 compound",
        "destination": "the surface a consumer meets after this lands",
        "accept": "the command or observation that proves it landed",
        "anti_scope_tags": ["tags from anti_scope this fix would trip"],
        "status": "blocked | ready | done",
    }],
}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="repair_gate_v0_1.py")
    sub = ap.add_subparsers(dest="cmd")
    c = sub.add_parser("check"); c.add_argument("queue"); c.add_argument("--issues")
    p = sub.add_parser("plan"); p.add_argument("queue")
    sub.add_parser("selftest"); sub.add_parser("selftest-meta"); sub.add_parser("schema")
    a = ap.parse_args(argv)
    if a.cmd == "check": return cmd_check(a)
    if a.cmd == "plan": return cmd_plan(a)
    if a.cmd == "selftest": return cmd_selftest(a)
    if a.cmd == "selftest-meta": return cmd_selftest_meta(a)
    if a.cmd == "schema": print(json.dumps(SCHEMA, indent=2)); return 0
    ap.print_help(); return 2


if __name__ == "__main__":
    sys.exit(main())
