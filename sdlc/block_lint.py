#!/usr/bin/env python3
"""block_lint v1.0 — lint pasteable shell blocks BEFORE they are sent.

Every rule is parented to a titan-incident-register row. A violation report
cites its parent incident id (citation enforcement: a rule with no incident
parentage does not ship here — it goes to PROVISIONAL with an import label).

Verdicts: PASS | FAIL (violations listed) | UNLINTABLE (abstention — the
input is not a shell block; never guessed at, per the abstention-token rule).

Usage:
  python block_lint.py <file> [--kind exec|illustrative]
  python block_lint.py --selftest
  python block_lint.py --selftest-meta
Exit codes: 0 clean/selftest-green, 1 violations/selftest-red, 2 unlintable.
"""
import re, sys, io

BLOCKLINT_VERSION = "1.0"

DESTRUCTIVE = re.compile(r'\b(rm\s+-\w*[rf]|git\s+reset\s+--hard|git\s+clean\b|rmdir\b|unlink\b)')
PLACEHOLDER = re.compile(r'(?<!<)<[a-zA-Z][a-zA-Z0-9 _-]{1,40}>|_{4,}')
MARKUP      = re.compile(r'</?(?:parameter|invoke|antml[^>\s]*)')
INTERACTIVE = re.compile(r'^\s*(?:python3?|bash|sh|node)\s*$|^\s*read\s+')
DOWNLOADS   = re.compile(r'Downloads/([^\s\'";)]+)')
EXIST_GATE  = re.compile(r'test\s+-f|\[\s+-f')
SENTINEL    = re.compile(r'echo\s+["\'].*(?:empty|nothing|none)\b', re.I)
CD_ABS      = re.compile(r'^\s*cd\s+(?:/|~|\$HOME|"/|"~|"\$HOME)')

def _strip_heredocs(lines):
    """Return (kept_lines_with_index, heredoc_line_indices). Heredoc bodies are
    excluded from shell-rule scans but still scanned for markup/placeholders."""
    kept, body_idx, i = [], set(), 0
    while i < len(lines):
        m = re.search(r"<<-?\s*'?(\w+)'?", lines[i])
        kept.append((i, lines[i]))
        if m:
            tag, i = m.group(1), i + 1
            while i < len(lines) and lines[i].strip() != tag:
                body_idx.add(i); i += 1
            if i < len(lines): kept.append((i, lines[i]))
        i += 1
    return kept, body_idx

def lint(text, kind="exec"):
    """Return (verdict, violations). violations: [(rule, line_no1, msg, parents)]."""
    lines = text.splitlines()
    eff = [l for l in lines if l.strip() and not l.strip().startswith('#')]
    if not eff:
        return "UNLINTABLE", [("G0", 0, "empty or comment-only input — not lintable, not passed", "#5-abstention")]
    v = []
    if kind == "illustrative":
        if not lines[0].strip().startswith("# NOT-FOR-PASTING"):
            v.append(("G8", 1, "illustrative block lacks leading '# NOT-FOR-PASTING' marker; "
                      "it WILL be pasted and executed", "#34,#48"))
        return ("FAIL" if v else "PASS"), v
    shell, heredoc_body = _strip_heredocs(lines)
    # G1 absolute cd first (#35)
    first = next(l for l in lines if l.strip() and not l.strip().startswith('#'))
    if not CD_ABS.search(first):
        v.append(("G1", lines.index(first) + 1,
                  "first effective line is not an absolute cd", "#35"))
    for i, l in shell:
        if i in heredoc_body: continue
        n = i + 1
        # G2 destructive not &&-chained (#19)
        m = DESTRUCTIVE.search(l)
        if m and '&&' not in l[:m.start()]:
            v.append(("G2", n, "destructive step not &&-chained to its dependency: %r" % l.strip(), "#19"))
        # G5 interactive (#16)
        if INTERACTIVE.search(l):
            v.append(("G5", n, "interactive command in a paste block: %r" % l.strip(), "#16"))
        # G7 absence-claiming sentinel without computed count (#47)
        if SENTINEL.search(l) and '$(' not in l:
            v.append(("G7", n, "sentinel asserts absence without a computed count "
                      "(skipped and empty are indistinguishable)", "#47"))
    for i, l in enumerate(lines):
        n = i + 1
        # G3 placeholders (#17) — everywhere, including heredocs
        m = PLACEHOLDER.search(l)
        if m and not re.search(r"<<-?\s*'?\w+'?", l):
            v.append(("G3", n, "placeholder %r inside a paste-verbatim block" % m.group(0), "#17"))
        # G4 tool-markup residue (#44)
        if MARKUP.search(l):
            v.append(("G4", n, "tool markup residue: %r" % l.strip(), "#44"))
    # G6 Downloads consumed without existence gate (#11,#36)
    refs = [(i + 1, DOWNLOADS.search(l).group(0)) for i, l in enumerate(lines) if DOWNLOADS.search(l)]
    if refs and not any(EXIST_GATE.search(l) for l in lines):
        v.append(("G6", refs[0][0], "consumes %s with no existence check in the block" % refs[0][1], "#11,#36"))
    return ("FAIL" if v else "PASS"), v

# ---------------- fixtures: every rule carries its incident's shape ----------------
KNOWN_GOOD = """cd ~/01-Projects/titan-gate/sdlc && export PYTHONIOENCODING=utf-8
python - <<'PY' > probe_out.txt 2>&1
import json
d = json.load(open("claim_ledger-titan-v2.json", encoding="utf-8"))
print("ROW_COUNT=%d" % len(d.get("claims", d)))
PY
echo "PROBE_LINES=$(wc -l < probe_out.txt)"
"""
KNOWN_BAD = {
    "G1": "ls sdlc/\npython x.py\n",                                    # 35: no absolute cd
    "G2": "cd /abs/dir\nmv a b\nrm -rf sdlc/inbox\n",                    # 19: rm not chained
    "G3": "cd /abs/dir\n./g record --actual <the number>\n",             # 17: placeholder
    "G4": "cd /abs/dir\necho done\n</parameter>\n",                      # 44: markup residue
    "G5": "cd /abs/dir\n./x --flags\nread NAME\n",                       # 16: interactive
    "G6": "cd /abs/dir\ntar xzf $HOME/Downloads/pkg-v1.tar.gz\n",        # 11/36: no existence gate
    "G7": 'cd /abs/dir\ngrep -c pat f.py && echo "RECON_DONE (empty above = no LLM calls)"\n',  # 47
    "G8": ("illustrative", "if grep -q RED out.txt; then exit 1; fi\n"), # 34/48: unmarked illustrative
    "G0": ("exec", "# only a comment\n"),                                # abstention, not a pass
}
EXPECTED = {"G1": {"G1"}, "G2": {"G2"}, "G3": {"G3"}, "G4": {"G4"}, "G5": {"G5"},
            "G6": {"G6"}, "G7": {"G7"}, "G8": {"G8"}, "G0": {"G0"}}

def selftest(expected=EXPECTED, out=sys.stdout):
    ok = True
    verdict, v = lint(KNOWN_GOOD, "exec")
    if verdict != "PASS":
        ok = False; print("  FAIL known_good: %s %s" % (verdict, v), file=out)
    for key, fixture in KNOWN_BAD.items():
        kind, text = fixture if isinstance(fixture, tuple) else ("exec", fixture)
        _, v = lint(text, kind)
        got = {r for r, *_ in v}
        if got != expected[key]:
            ok = False; print("  FAIL %s: expected %s got %s" % (key, sorted(expected[key]), sorted(got)), file=out)
    print("block_lint selftest: %s (%d known-bads, exact id-set asserted)" %
          ("GREEN" if ok else "RED", len(KNOWN_BAD)), file=out)
    return ok

def selftest_meta():
    wrong = dict(EXPECTED); wrong["G2"] = {"G5"}   # deliberately wrong expectation
    buf = io.StringIO()
    if selftest(wrong, out=buf):
        print("selftest-meta: RED — selftest passed a wrong expectation (rubber stamp)"); return False
    print("selftest-meta: GREEN — selftest fails a wrong expectation"); return True

if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["--selftest"]:      sys.exit(0 if selftest() else 1)
    if a[:1] == ["--selftest-meta"]: sys.exit(0 if selftest_meta() else 1)
    kind = "illustrative" if "--kind" in a and "illustrative" in a else "exec"
    text = open(a[0], encoding="utf-8").read()
    verdict, v = lint(text, kind)
    for rule, n, msg, parents in v:
        print("%s@L%d: %s  [parents: register %s]" % (rule, n, msg, parents))
    print("VERDICT=%s VIOLATIONS=%d" % (verdict, len(v)))
    sys.exit({"PASS": 0, "FAIL": 1}.get(verdict, 2))
