#!/usr/bin/env python3
"""fillsafe v1.0 — section-bounded, idempotent fills for evidence-bearing files.

Parent: register #43 — an unbounded lazy fill-regex cross-filled a plan lock,
stamping one item's evidence onto the next: a fabricated evidence line on an
unfinished item. This module is that incident encoded as the gate.

Contract (all four proven by --selftest):
  1. BOUNDED  — the fill can only touch text between its section header and
                the next header of the same level; other sections are
                byte-identical afterward, asserted, not assumed.
  2. IDEMPOTENT — re-running the same fill is a no-op (terminals re-execute
                pasted blocks; design for double-execution, never hope).
  3. CONFLICT-LOUD — a section already filled with DIFFERENT content raises;
                it is never silently overwritten.
  4. COUNTED  — the caller gets (new_text, changed); a wrapper that wants a
                sentinel prints the measured remaining-placeholder count,
                never absence (#47).

Usage: fill(text, section_header, placeholder, replacement) -> (text, changed)
       python fillsafe.py --selftest | --selftest-meta
"""
import re, sys, io

class FillConflict(Exception): pass
class FillTargetMissing(Exception): pass

def _section_span(text, header):
    lines = text.split('\n')
    start = next((i for i, l in enumerate(lines) if l.strip() == header.strip()), None)
    if start is None:
        raise FillTargetMissing("section header not found: %r" % header)
    level = len(header) - len(header.lstrip('#')) if header.lstrip().startswith('#') else None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        s = lines[j]
        if s.startswith('#') and (level is None or (len(s) - len(s.lstrip('#'))) <= level):
            end = j; break
        if level is None and s.startswith('**WO-'):  # plan-lock item boundary
            end = j; break
    return lines, start, end

def fill(text, section_header, placeholder, replacement):
    lines, start, end = _section_span(text, section_header)
    before, section, after = lines[:start], lines[start:end], lines[end:]
    body = '\n'.join(section)
    if placeholder not in body:
        if replacement in body:
            return text, False                       # idempotent no-op
        raise FillConflict(
            "section %r: placeholder absent and replacement absent — the section "
            "was filled with something else; refusing to overwrite" % section_header)
    if body.count(placeholder) != 1:
        raise FillConflict("section %r: %d occurrences of placeholder, need exactly 1"
                           % (section_header, body.count(placeholder)))
    new_body = body.replace(placeholder, replacement, 1)
    new_text = '\n'.join(before) + ('\n' if before else '') + new_body + \
               ('\n' + '\n'.join(after) if after else '')
    # BOUNDED assertion: everything outside the section is byte-identical
    if '\n'.join(before) != '\n'.join(new_text.split('\n')[:start]) or \
       '\n'.join(after)  != '\n'.join(new_text.split('\n')[start + len(new_body.split('\n')):]):
        raise AssertionError("fill leaked outside its section — refusing to return")
    return new_text, True

# ------------------------- fixtures: #43's exact shape -------------------------
LOCK_FIXTURE = """# PLAN LOCK — fixture
**WO-A1 — first item** (order: 1)
- Task: alpha.
- EVIDENCE: [UNFILLED]
**WO-A2 — second item** (order: 2)
- Task: beta.
- EVIDENCE: [UNFILLED]
"""

def selftest(out=sys.stdout, sabotage=False):
    ok = True
    def check(name, cond):
        nonlocal ok
        if not cond: ok = False; print("  FAIL %s" % name, file=out)
    t1, ch = fill(LOCK_FIXTURE, "**WO-A1 — first item** (order: 1)",
                  "[UNFILLED]", "[MEASURED: run X]")
    check("fills_target", ch and "[MEASURED: run X]" in t1)
    # THE #43 CASE: the other section must still be UNFILLED
    a2 = t1.split("**WO-A2")[1]
    check("does_not_cross_fill", "[UNFILLED]" in a2 and "[MEASURED: run X]" not in a2)
    t2, ch2 = fill(t1, "**WO-A1 — first item** (order: 1)",
                   "[UNFILLED]", "[MEASURED: run X]")
    check("idempotent_rerun", (not ch2) and t2 == t1)
    try:
        fill(t1, "**WO-A1 — first item** (order: 1)", "[UNFILLED]", "[MEASURED: DIFFERENT]")
        check("conflict_raises", sabotage)   # reaching here is a failure unless sabotaged
    except FillConflict:
        check("conflict_raises", not sabotage)
    try:
        fill(LOCK_FIXTURE, "**WO-MISSING** (order: 9)", "[UNFILLED]", "x")
        check("missing_section_raises", False)
    except FillTargetMissing:
        check("missing_section_raises", True)
    remaining = t1.count("[UNFILLED]")
    check("counted_sentinel", remaining == 1)
    print("fillsafe selftest: %s (REMAINING_UNFILLED=%d — measured, not assumed)"
          % ("GREEN" if ok else "RED", remaining), file=out)
    return ok

def selftest_meta():
    buf = io.StringIO()
    if selftest(out=buf, sabotage=True):
        print("selftest-meta: RED — selftest passed a sabotaged expectation"); return False
    print("selftest-meta: GREEN — selftest fails a sabotaged expectation"); return True

if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["--selftest"]:      sys.exit(0 if selftest() else 1)
    if a[:1] == ["--selftest-meta"]: sys.exit(0 if selftest_meta() else 1)
    print(__doc__)
