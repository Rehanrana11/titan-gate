#!/usr/bin/env python3
"""forge_check v0.2 -- lint pasteable blocks, and emit the output contract.

CHANGELOG
    v0.2  first-token whitelist. v0.1 flagged 2 of 3 bad lines in the incident-3
          fixture: `empty artifact, SOC2 controls attested...` passed because its
          first word parses as a command name. Measured, then fixed.
    v0.1  first cut. Caught incidents 1 and 3, zero false positives on a good
          block, one partial miss.

WHY THIS EXISTS
    Session 16 produced three G3 violations while quoting G3 in the same
    messages that violated it [claude/session-2026-08-23b-rework-report.md,
    incidents 1-3]. Register finding M9: awareness is not a control. Every
    control that held in that session was structural; every voluntary rule was
    broken at least once. This is the structural version of G3.

    It also emits the output-contract block with COUNTS computed rather than
    typed, and a hard ABSTAIN on every field that is a judgement. A tool that
    filled in RUNG or FALSIFIED_BY would be fabricating the exact thing the
    contract exists to make checkable.

USAGE
    python sdlc/forge_check_v0_1.py lint <file.md> [--max-lines 25]
    python sdlc/forge_check_v0_1.py contract [--outbound-log drills/OUTBOUND_LOG.md]

    lint     reads a markdown message and checks every ``` fenced block.
             Exit 0 = clean, 1 = findings. Findings print file:line: RULE: text.
    contract prints the output-contract block. Computed fields carry a value;
             judgement fields print ABSTAIN with the reason.

EXIT CODES
    0 clean · 1 findings · 2 usage error
"""
import argparse
import os
import re
import subprocess
import sys

# --- rules, each grounded in a numbered incident ---------------------------

INTERACTIVE = re.compile(r'^\s*(read|vim|vi|nano|less|more|top|htop|ssh|git\s+rebase\s+-i|git\s+add\s+-i)\b')
DESTRUCTIVE = re.compile(r'(^|[;&|]\s*)(rm|rmdir|unlink)\b|git\s+(reset\s+--hard|checkout\s+--|clean\s+-|stash\b)|--force\b|\bmv\s+\S+\s+\S+')
BUFFERING = re.compile(r'\|\s*(tail|head)\b')
LONG_RUNNING = re.compile(r'\b(pytest|npm\s+(run|test|install)|make|cargo|gradle|mvn|tox|nox)\b')
PLACEHOLDER = re.compile(r'<[a-z_][a-z0-9_ -]*>')
REDIRECT_OVERWRITE = re.compile(r'(?<![>0-9])>(?!>)\s*[^\s&|]')

# First tokens that are plausibly executable in this project. A whitelist is
# deliberate: false positives cost a glance, false negatives cost a terminal.
KNOWN = {
    "echo", "cd", "ls", "pwd", "cat", "printf", "cp", "mkdir", "touch", "wc",
    "grep", "sed", "awk", "sort", "uniq", "cut", "tr", "tee", "tail", "head",
    "find", "diff", "du", "df", "date", "env", "export", "unset", "read",
    "git", "gh", "python", "python3", "pip", "pip3", "bash", "sh", "node",
    "npm", "npx", "pytest", "sha256sum", "md5sum", "openssl", "curl", "wget",
    "test", "true", "false", "exit", "return", "set", "source", "eval",
    "if", "then", "else", "elif", "fi", "for", "while", "do", "done", "case",
    "esac", "function", "local", "declare", "timeout", "xargs", "tar", "unzip",
}
OPERATOR_START = re.compile(r'^\s*(&&|\|\||\||;|>|<|\)|\}|#|-)')


def _command_ish(line):
    """True if the line could plausibly be executed. Conservative by design."""
    s = line.strip()
    if not s or OPERATOR_START.match(s):
        return True
    tok = s.split()[0]
    if tok.endswith(","):                    # prose: "empty artifact, SOC2 ..."
        return False
    if re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', tok):   # VAR=value
        return True
    if tok.startswith(("./", "/", "~", "$", '"', "'", "\\")) or "/" in tok:
        return True
    return tok.lstrip("$(").rstrip(")") in KNOWN
# Output-looking lines: the exact shape that got pasted in incident #3.
OUTPUT_ISH = re.compile(
    r'^\s*\d+\s+(passed|failed|error|skipped|xfailed|tests?\b)'   # "33 passed, ..."
    r'|^\s*[A-Za-z][\w ]*[:=]\s*\S+\s*$'                          # "verdict=PASS"
    r'|^\s*\d+\s+(files?|insertions?|deletions?)\b'               # diffstat
)

FENCE = re.compile(r'^\s*```')


def _blocks(text):
    """Yield (start_line, [lines]) for each fenced block."""
    lines, out, cur, start = text.splitlines(), [], None, 0
    for i, line in enumerate(lines, 1):
        if FENCE.match(line):
            if cur is None:
                cur, start = [], i
            else:
                out.append((start, cur))
                cur = None
        elif cur is not None:
            cur.append((i, line))
    if cur is not None:                       # unterminated fence is itself a finding
        out.append((start, cur))
    return out


def lint(path, max_lines):
    text = open(path, encoding="utf-8").read()
    findings = []

    def flag(ln, rule, msg):
        findings.append(f"{path}:{ln}: {rule}: {msg}")

    for start, body in _blocks(text):
        if not body:
            continue
        code = [l for _, l in body]
        first = code[0].strip()

        # G3: sacrificial first line. Its absence in the paste-back is how
        # terminal corruption is detected.
        if not first.startswith("echo "):
            flag(start + 1, "NO_SACRIFICIAL_ECHO",
                 "block does not open with a disposable `echo` marker")

        # G3: absolute cd first.
        if not any(re.match(r'^\s*cd\s+/', l) for l in code):
            if any(re.match(r'^\s*cd\s+', l) for l in code):
                flag(start + 1, "RELATIVE_CD", "block cds to a non-absolute path")

        # G3: ~25 lines of OUTPUT; line count is the only proxy a linter has.
        if len(code) > max_lines:
            flag(start + 1, "BLOCK_TOO_LONG",
                 f"{len(code)} lines, cap is {max_lines}; chunk mechanically")

        for ln, line in body:
            s = line.strip()
            if not s:
                continue

            # INCIDENT 3 -- the expensive one. Results fenced as commands.
            if OUTPUT_ISH.match(line) or not _command_ish(line):
                flag(ln, "NOT_A_COMMAND",
                     f"fenced line is not a command: {s[:60]!r}")

            # INCIDENT 1 -- a long job piped to a buffering filter shows nothing.
            if LONG_RUNNING.search(line) and BUFFERING.search(line):
                flag(ln, "BUFFERED_LONG_JOB",
                     "long-running command piped to head/tail: no progress until it ends")

            if INTERACTIVE.match(line):
                flag(ln, "INTERACTIVE", f"interactive command in a paste block: {s[:40]!r}")

            if PLACEHOLDER.search(line) and "echo" not in s.split("|")[0]:
                flag(ln, "PLACEHOLDER", f"unfilled placeholder: {s[:60]!r}")

            # G1 -- destruction must be named and approved, never pasted casually.
            if DESTRUCTIVE.search(line):
                flag(ln, "DESTRUCTIVE",
                     f"destructive verb in a block: {s[:60]!r} -- needs a named approval")

            if REDIRECT_OVERWRITE.search(line) and ">>" not in line:
                flag(ln, "OVERWRITE_REDIRECT",
                     f"`>` truncates its target; use `>>` to append: {s[:50]!r}")

    for f in findings:
        print(f)
    print(f"forge_check lint: {len(findings)} finding(s) in {path}")
    return 1 if findings else 0


# --- contract ---------------------------------------------------------------

ABSTAIN = "ABSTAIN"


def _suite_counts():
    """Return the pytest summary line, or an ABSTAIN reason."""
    try:
        p = subprocess.run([sys.executable, "-m", "pytest", "-q", "--no-header",
                            "-p", "no:cacheprovider"],
                           capture_output=True, text=True, timeout=1800)
    except Exception as e:                       # noqa: BLE001 -- reason is the value
        return None, f"{ABSTAIN}: pytest did not run ({type(e).__name__})"
    for line in reversed(p.stdout.strip().splitlines()):
        if re.search(r'\d+ (passed|failed|error)', line):
            return line.strip(), None
    return None, f"{ABSTAIN}: no summary line in pytest output"


def _outbound(path):
    """Count non-RETRACTED rows in the outbound log. Never guesses."""
    if not os.path.exists(path):
        return None, f"{ABSTAIN}: {path} not found -- outbound is unmeasured, not zero"
    sent = replied = 0
    for line in open(path, encoding="utf-8", errors="replace"):
        if not line.strip().startswith("|") or "RETRACTED" in line:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2 or cells[0].lower() in ("date", "---", ""):
            continue
        sent += 1
        if any(c.lower() in ("y", "yes", "replied", "true") for c in cells[1:]):
            replied += 1
    if sent == 0:
        return None, f"{ABSTAIN}: no rows in {path} -- unmeasured, not zero"
    return f"{sent}/{replied}", None


def contract(outbound_log):
    counts, counts_abstain = _suite_counts()
    ob, ob_abstain = _outbound(outbound_log)
    under = ""
    if ob:
        n = int(ob.split("/")[0])
        if n < 40:
            under = f"  [UNDERPOWERED: n={n} < 40, records no evidence either way]"

    print("```")
    print(f"CLASS:        {ABSTAIN}: a judgement. Classify it yourself, out loud.")
    print(f"RECIPIENT:    {ABSTAIN}: name a human who is not the operator, or admit META.")
    print(f"RUNG:         {ABSTAIN}: R0..R5 is a judgement about who ran it, not a metric.")
    print(f"FALSIFIED_BY: {ABSTAIN}: name the concrete input you tried. If none, T3 did not run.")
    print(f"COUNTS:       {counts or counts_abstain}")
    print(f"COST:         {ABSTAIN}: calls x $/call. An uncosted plan is not a plan (G5).")
    print(f"NEXT_ACTION:  {ABSTAIN}: physical action, who, minutes.")
    print(f"META_RATIO:   {ABSTAIN}: count this session's outputs; no file tracks it yet.")
    print(f"OUTBOUND:     {ob or ob_abstain}{under}")
    print("```")
    print("", file=sys.stderr)
    print("forge_check contract: 2 of 9 fields computed; 7 ABSTAIN by design.",
          file=sys.stderr)
    print("A tool that filled in RUNG or FALSIFIED_BY would fabricate the exact",
          file=sys.stderr)
    print("thing the contract exists to make checkable.", file=sys.stderr)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    l = sub.add_parser("lint", help="check pasteable blocks in a markdown file")
    l.add_argument("path")
    l.add_argument("--max-lines", type=int, default=25)

    c = sub.add_parser("contract", help="emit the output contract, computed where possible")
    c.add_argument("--outbound-log", default="drills/OUTBOUND_LOG.md")

    a = ap.parse_args()
    if a.cmd == "lint":
        return lint(a.path, a.max_lines)
    return contract(a.outbound_log)


if __name__ == "__main__":
    sys.exit(main())
