#!/usr/bin/env python3
"""validate_zros.py v0.1 — encodes GATES-v1 tickets T1, T3, T4, T5 as runnable code.
Read-only. Exit 0 = clean, 1 = findings. Git Bash/MINGW64 compatible, stdlib only.

Usage:
  python validate_zros.py lint FILE [FILE...]   # T3 paste-safety + T4 destructive-verb lint
                                                #   on fenced bash/sh blocks in .md/.txt
  python validate_zros.py dedup DIR             # T5 version-stem duplicates lacking SUPERSEDED
  python validate_zros.py stale FILE_A FILE_B   # T1 canonical-vs-field drift (normalized diff)
"""
import sys, re, os, hashlib

FENCE = re.compile(r"```(?:bash|sh|shell)\s*\n(.*?)```", re.S)
PLACEHOLDER = re.compile(r"<[A-Za-z_][A-Za-z_ -]*>|YOUR_[A-Z_]+|REPLACE_ME|TODO")
DESTRUCTIVE = re.compile(r"\b(rm|rmdir|unlink|shred)\b|git\s+(reset\s+--hard|clean\s+-[a-z]*f|push\s+.*--force)|>\s*/mnt/project")
INTERACTIVE = re.compile(r"^\s*(vim|vi|nano|emacs|less|more|top|htop)\b|^\s*ssh\s+\S+\s*$")
TRUNCATING = re.compile(r"\b(head|tail)\s+-\d|\bgrep\b[^|\n]*\s-m\s*\d")
GO_MARK = "# GO-APPROVED"

def lint_block(block, loc, findings):
    lines = [l for l in block.strip().splitlines() if l.strip()]
    if not lines: return
    first = next((l for l in lines if not l.strip().startswith("#")), "")
    if not re.match(r"\s*(set -e\s*(&&|;)?\s*)?cd\s+(/|[A-Za-z]:)", first):
        findings.append(f"{loc}: G1-09 first command must be absolute cd (got: {first[:60]!r})")
    for i, l in enumerate(lines, 1):
        if PLACEHOLDER.search(l):
            findings.append(f"{loc}:{i}: G1-09 placeholder in executable block: {l.strip()[:60]!r}")
        if INTERACTIVE.search(l):
            findings.append(f"{loc}:{i}: G1-09 interactive command: {l.strip()[:60]!r}")
        if DESTRUCTIVE.search(l):
            chained = "&&" in l.split(DESTRUCTIVE.search(l).group(0))[0] or (i > 1 and lines[i-2].rstrip().endswith("&&"))
            approved = GO_MARK in block
            if not (chained and approved):
                need = [] 
                if not chained: need.append("&&-chain to a verified precondition")
                if not approved: need.append(f"operator token line '{GO_MARK}' (G1-10)")
                findings.append(f"{loc}:{i}: G1-10 destructive verb without {' + '.join(need)}: {l.strip()[:60]!r}")
        if TRUNCATING.search(l) and "TRUNCATED_AT" not in block:
            findings.append(f"{loc}:{i}: G1-05 bounded read without TRUNCATED_AT/TOTAL announcement")

def cmd_lint(paths):
    findings = []
    for p in paths:
        text = open(p, encoding="utf-8", errors="replace").read()
        for n, m in enumerate(FENCE.finditer(text), 1):
            lint_block(m.group(1), f"{os.path.basename(p)}#block{n}", findings)
    return findings

def cmd_dedup(d):
    findings, stems = [], {}
    for f in os.listdir(d):
        if not f.endswith(".md"): continue
        stem = re.sub(r"-v\d[\d_]*(?=\.md$)", "", f)
        stems.setdefault(stem, []).append(f)
    for stem, files in stems.items():
        if len(files) < 2: continue
        files.sort()  # version suffixes sort ascending
        for elder in files[:-1]:
            body = open(os.path.join(d, elder), encoding="utf-8", errors="replace").read()
            if "SUPERSEDED" not in body:
                findings.append(f"G1-16 duplicate stem '{stem}': elder {elder} lacks SUPERSEDED header (newest: {files[-1]})")
    return findings

def norm(p):
    t = open(p, encoding="utf-8", errors="replace").read()
    return "\n".join(" ".join(l.split()) for l in t.splitlines() if l.strip())

def cmd_stale(a, b):
    na, nb = norm(a), norm(b)
    if hashlib.sha256(na.encode()).hexdigest() == hashlib.sha256(nb.encode()).hexdigest():
        return []
    la, lb = na.splitlines(), nb.splitlines()
    for i, (x, y) in enumerate(zip(la, lb)):
        if x != y:
            return [f"G1-03 DRIFT at normalized line {i+1}:\n  A: {x[:70]}\n  B: {y[:70]}"]
    return [f"G1-03 DRIFT: length differs (A={len(la)} lines, B={len(lb)} lines; shorter file is stale or clipped)"]

def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(2)
    mode, args = sys.argv[1], sys.argv[2:]
    f = {"lint": lambda: cmd_lint(args), "dedup": lambda: cmd_dedup(args[0]),
         "stale": lambda: cmd_stale(args[0], args[1])}.get(mode)
    if not f: print(__doc__); sys.exit(2)
    findings = f()
    if findings:
        print(f"FINDINGS={len(findings)}"); [print(" -", x) for x in findings]; sys.exit(1)
    print("CLEAN=0 findings"); sys.exit(0)

if __name__ == "__main__": main()
