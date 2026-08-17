#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""validate_zros v1 -- the machine check for a ZROS document + its gate file.

Implements the validator specified in ZROS-FORGE v1.1 <validator_spec id="V">.
Zero dependencies: Python standard library only. Written to run natively on
Windows / Git Bash (MINGW64) as well as POSIX.

Design commitments, each earned from a named source:

  * All file I/O is encoding="utf-8", newline="".  Parent: the mutate.py harness
    bug (text-mode CRLF translation left targets dirty) and the canonical.py
    ensure_ascii survivor, both recorded in session-2026-08-17-state.md.
  * A check that DID NOT RUN is a FAIL, not an absence of failure.  Parent:
    "Pre-commit hook reports green when a test file fails to import"
    (session-2026-08-17-state.md).  --skip is the only way to silence a check,
    and it is recorded loudly in the report.
  * --selftest asserts on the exact SET of violation ids, never on a count.
    Parent: ZROS-FORGE v1.1 APPENDIX-V warning 2.
  * Nothing here loosens under pressure quietly: --explain prints why a token
    was not exempt, so the fix is a tag or a fixture, not a wider regex.

Exit codes:
    0  clean (no FAIL, no CRITICAL, no unexplained NOT_RUN)
    1  at least one FAIL
    2  at least one CRITICAL (V7 tag-truth mismatch) -- strictly above FAIL
    3  usage / parse error (fail closed)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

__version__ = "1"

# --------------------------------------------------------------------------
# severity
# --------------------------------------------------------------------------

CRITICAL = "CRITICAL"
FAIL = "FAIL"
WARN = "WARN"
SEVERITY_RANK = {WARN: 1, FAIL: 2, CRITICAL: 3}

ALL_CHECKS = ["V%d" % n for n in range(1, 13)]

TIERS = {
    "CORE", "ANTICIPATED", "STANDARD", "PROVISIONAL",
    "PROVISIONAL-IMPORT", "RETIRED",
}
CONSEQUENCES = {"ROUTINE", "COSTLY", "EXISTENTIAL"}
PLACEMENTS = {
    "pre-claim", "pre-plan", "pre-paste",
    "pre-package", "pre-send", "pre-close",
}
TRIGGER_KINDS = {"regex", "event", "predicate"}
CHECK_KINDS = {"command", "predicate", "human"}
ON_FAIL = {"BLOCK", "WARN"}

GATE_ID_RE = re.compile(r"^G-[A-Za-z0-9]+(?:-\d+)?$")
GATE_ID_IN_TEXT = re.compile(r"\bG-[A-Za-z0-9]+(?:-\d+)?\b")

TAG_RE = re.compile(
    r"\[(MEASURED|QUOTED|DERIVED|EST|REPORTED|UNVERIFIED)\b[^\]]*\]"
)
MEASURED_RE = re.compile(r"\[MEASURED:\s*(?P<cmd>.+?)\s*(?:->|→)\s*(?P<frag>.+?)\]")

# Tokens that carry a numeral but are structurally exempt per
# <provenance_law> SCOPE: identifiers, version strings, section numbers,
# CLI flag arguments, quoted source text.  This list is CLOSED; widening it
# is a governed act (V10) and --explain exists so you do not need to.
STRUCTURAL_EXEMPT = [
    re.compile(r"^G-[A-Za-z0-9]+(?:-\d+)?$"),          # gate ids
    re.compile(r"^M\d+$"),                              # mechanism ids
    re.compile(r"^I-\d+$"),                             # incident ids
    re.compile(r"^CL-\d+$"),                            # claim ledger ids
    re.compile(r"^WO-[A-Za-z0-9]+$"),                   # work order ids
    re.compile(r"^W\d+$"),                              # work item ids
    re.compile(r"^V\d+$"),                              # validator check ids
    re.compile(r"^G\d+$"),                              # legacy gate ids
    re.compile(r"^S\d+$"),                              # stop condition ids
    re.compile(r"^L\d+$"),                              # law ids
    re.compile(r"^P\d+$"),                              # probe / principle ids
    re.compile(r"^D\d+$"),                              # defect ids
    re.compile(r"^C\d+$"),                              # control ids
    re.compile(r"^H\d+$"),                              # rule ids
    re.compile(r"^CC\d+\.\d+$"),                        # SOC 2 control ids
    # Version strings: a leading 'v', or three-or-more components.  A bare
    # "0.7" is NOT a version -- it is a threshold, and thresholds are exactly
    # the load-bearing numbers this sweep exists to catch.
    re.compile(r"^v\d+(?:\.\d+)*$"),
    re.compile(r"^\d+(?:\.\d+){2,}$"),
    re.compile(r"^§[A-Za-z0-9]+$"),                     # section numbers
    re.compile(r"^\d+\.$"),                             # ordered-list markers
    re.compile(r"^\d{4}-\d{2}-\d{2}$"),                 # ISO dates
    re.compile(r"^--[A-Za-z0-9][-A-Za-z0-9]*=?\S*$"),   # CLI flags + args
    re.compile(r"^-[A-Za-z]\d*$"),                      # short CLI flags
    re.compile(r"^#{1,6}$"),                            # heading markers
]

# Words whose presence makes a numeral on the same line a COUNT, and therefore
# subject to V8 (must be computed or [DERIVED:]).
COUNT_WORDS = re.compile(
    r"\b("
    r"incidents?|gates?|rows?|tests?|passed|failed|skipped|xfailed|"
    r"mechanisms?|controls?|claims?|violations?|probes?|entries|files?|"
    r"commits?|survivors?|mutants?|checks?|laws?|rituals?|sites?"
    r")\b",
    re.IGNORECASE,
)

RUNNABLE_INFO = {"bash", "sh", "shell", "console", "zsh", "bat", "cmd"}

PLACEHOLDER_PATTERNS = [
    (re.compile(r"<[^<>\n]{1,60}>"), "angle-bracket placeholder"),
    (re.compile(r"\bTODO\b"), "TODO"),
    (re.compile(r"\bFIXME\b"), "FIXME"),
    (re.compile(r"\bXXX\b"), "XXX"),
    (re.compile(r"\bYOUR_[A-Z_]+\b"), "YOUR_ placeholder"),
    (re.compile(r"\u2026"), "ellipsis character"),
    (re.compile(r"\{[A-Z][A-Z_]{2,}\}"), "brace placeholder"),
]

DESTRUCTIVE_RE = re.compile(
    r"(^|\s|\|)("
    r"rm\s|rmdir\s|mv\s|git\s+reset|git\s+clean|git\s+checkout\s+--|"
    r"pip\s+install|npm\s+install|apt-get\s+install|drop\s+table|truncate\s"
    r")",
    re.IGNORECASE,
)
REDIRECT_OVERWRITE_RE = re.compile(r"(?<![>\d])>(?!>)\s*\S")

INTERACTIVE_CMDS = re.compile(
    r"(^|\s|\|)("
    r"vi|vim|nano|emacs|less|more|top|htop|man|"
    r"read\s|ssh\s|ftp\s|telnet\s|python\s*$|python3\s*$|node\s*$|irb|"
    r"git\s+commit\s*$|git\s+rebase\s+-i|git\s+add\s+-i"
    r")(\s|$)",
    re.IGNORECASE,
)

ABS_CD_RE = re.compile(r'^cd\s+("?)(/|~|\$HOME|[A-Za-z]:[\\/])')


# --------------------------------------------------------------------------
# io -- pinned encoding and newline handling (pre-mortem failure mode 3)
# --------------------------------------------------------------------------

def read_text(path):
    """Read a file with an explicit encoding and NO newline translation.

    newline="" keeps '\r\n' intact so line numbers and byte-level checks are
    faithful; we split on '\n' ourselves and strip a trailing '\r'.
    """
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return fh.read()


def read_lines(path):
    text = read_text(path)
    return [ln[:-1] if ln.endswith("\r") else ln for ln in text.split("\n")]


def write_text(path, text):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


# --------------------------------------------------------------------------
# result model
# --------------------------------------------------------------------------

class Violation(object):
    __slots__ = ("check", "vid", "severity", "where", "message", "why")

    def __init__(self, check, locator, severity, where, message, why=""):
        self.check = check
        self.vid = "%s@%s" % (check, locator)
        self.severity = severity
        self.where = where
        self.message = message
        self.why = why

    def as_dict(self):
        return {
            "id": self.vid, "check": self.check, "severity": self.severity,
            "where": self.where, "message": self.message, "why": self.why,
        }


class CheckResult(object):
    __slots__ = ("check", "ran", "reason", "violations")

    def __init__(self, check, ran, reason="", violations=None):
        self.check = check
        self.ran = ran
        self.reason = reason
        self.violations = violations or []


# --------------------------------------------------------------------------
# document model
# --------------------------------------------------------------------------

HEADING_SECTION_RE = re.compile(r"^\s{0,3}#{1,6}\s+.*?§\s*([A-Za-z0-9]+)")
FENCE_RE = re.compile(r"^\s{0,3}(`{3,}|~{3,})\s*([A-Za-z0-9_+-]*)\s*$")


class Block(object):
    __slots__ = ("info", "start_line", "lines")

    def __init__(self, info, start_line, lines):
        self.info = (info or "").lower()
        self.start_line = start_line
        self.lines = lines

    @property
    def runnable(self):
        return self.info in RUNNABLE_INFO

    def text(self):
        return "\n".join(self.lines)


class Zros(object):
    """Parsed view of a ZROS markdown document."""

    def __init__(self, path):
        self.path = path
        self.lines = read_lines(path)
        self.blocks = []
        self.sections = {}      # "L" -> (start_index, end_index) over self.lines
        self.prose_lines = []   # (index, text) outside fenced blocks
        self._parse()

    def _parse(self):
        in_fence = False
        fence_marker = ""
        info = ""
        start = 0
        buf = []
        section_starts = []
        for i, raw in enumerate(self.lines):
            m = FENCE_RE.match(raw)
            if m and not in_fence:
                in_fence = True
                fence_marker = m.group(1)[0] * 3
                info = m.group(2)
                start = i
                buf = []
                continue
            if in_fence:
                if raw.strip().startswith(fence_marker):
                    self.blocks.append(Block(info, start, buf))
                    in_fence = False
                    info = ""
                    buf = []
                else:
                    buf.append(raw)
                continue
            self.prose_lines.append((i, raw))
            hm = HEADING_SECTION_RE.match(raw)
            if hm:
                section_starts.append((hm.group(1).upper(), i))
        if in_fence:
            # unterminated fence: keep what we have, fail closed elsewhere
            self.blocks.append(Block(info, start, buf))
        for idx, (name, line_no) in enumerate(section_starts):
            end = (section_starts[idx + 1][1]
                   if idx + 1 < len(section_starts) else len(self.lines))
            # last definition wins only if a section is not already present;
            # a duplicated section heading is itself reported by V11/V12 paths
            if name not in self.sections:
                self.sections[name] = (line_no, end)

    def section_lines(self, name):
        rng = self.sections.get(name.upper())
        if not rng:
            return None
        return [(i, self.lines[i]) for i in range(rng[0], rng[1])]

    def section_of(self, idx):
        for name, (start, end) in self.sections.items():
            if start <= idx < end:
                return name
        return None


# --------------------------------------------------------------------------
# gate file
# --------------------------------------------------------------------------

REQUIRED_GATE_FIELDS = [
    "id", "tier", "mechanism", "parents", "consequence", "consequence_model",
    "trigger", "check", "fail_closed", "on_fail", "placement", "fixtures",
    "tamper_signature", "cost_per_fire_s",
]


def load_gates(path):
    """Parse and schema-check zros_gates.json.  Returns (gates, errors)."""
    errors = []
    try:
        raw = json.loads(read_text(path))
    except Exception as exc:                      # noqa: BLE001 -- fail closed
        return None, ["gate file is not readable JSON: %s" % exc]
    if not isinstance(raw, list):
        return None, ["gate file must be a JSON array of gate objects"]

    seen = set()
    for pos, g in enumerate(raw):
        tag = "gate[%d]" % pos
        if not isinstance(g, dict):
            errors.append("%s is not an object" % tag)
            continue
        gid = g.get("id")
        if isinstance(gid, str):
            tag = gid
        for field in REQUIRED_GATE_FIELDS:
            if field not in g:
                errors.append("%s: missing required field '%s'" % (tag, field))
        if not isinstance(gid, str) or not GATE_ID_RE.match(gid or ""):
            errors.append("%s: id must match G-<MECHANISM>-<n> or G-A<n>" % tag)
        elif gid in seen:
            errors.append("%s: duplicate gate id" % tag)
        else:
            seen.add(gid)
        if g.get("tier") not in TIERS:
            errors.append("%s: tier %r not in %s" % (tag, g.get("tier"), sorted(TIERS)))
        if g.get("consequence") not in CONSEQUENCES:
            errors.append("%s: consequence %r not in %s"
                          % (tag, g.get("consequence"), sorted(CONSEQUENCES)))
        if g.get("placement") not in PLACEMENTS:
            errors.append("%s: placement %r not in %s"
                          % (tag, g.get("placement"), sorted(PLACEMENTS)))
        if g.get("on_fail") not in ON_FAIL:
            errors.append("%s: on_fail %r not in %s"
                          % (tag, g.get("on_fail"), sorted(ON_FAIL)))
        if not isinstance(g.get("parents"), list):
            errors.append("%s: parents must be an array" % tag)
        trig = g.get("trigger")
        if not isinstance(trig, dict) or trig.get("kind") not in TRIGGER_KINDS:
            errors.append("%s: trigger.kind must be one of %s"
                          % (tag, sorted(TRIGGER_KINDS)))
        chk = g.get("check")
        if not isinstance(chk, dict) or chk.get("kind") not in CHECK_KINDS:
            errors.append("%s: check.kind must be one of %s" % (tag, sorted(CHECK_KINDS)))
        elif not isinstance(chk.get("max_seconds"), int):
            errors.append("%s: check.max_seconds must be an integer" % tag)
        fx = g.get("fixtures")
        if not isinstance(fx, dict) or "known_bad" not in fx or "known_good" not in fx:
            errors.append("%s: fixtures must carry known_bad and known_good" % tag)
        if not isinstance(g.get("cost_per_fire_s"), int):
            errors.append("%s: cost_per_fire_s must be an integer" % tag)
        if not isinstance(g.get("tamper_signature"), str) or not g.get("tamper_signature"):
            errors.append("%s: tamper_signature must be a non-empty string" % tag)
    return raw, errors


def fixture_text(gate, which, base_dir):
    """Resolve a fixture to text.  A fixture is either a path or a literal."""
    fx = (gate.get("fixtures") or {}).get(which)
    if not isinstance(fx, str):
        return None, "fixture %s missing" % which
    candidate = fx if os.path.isabs(fx) else os.path.join(base_dir, fx)
    if os.path.isfile(candidate):
        try:
            return read_text(candidate), None
        except Exception as exc:                  # noqa: BLE001
            return None, "fixture %s unreadable: %s" % (which, exc)
    looks_like_path = (
        not re.search(r"\s", fx)
        and ("/" in fx or "\\" in fx or fx.endswith((".md", ".txt", ".json", ".sh")))
        and "://" not in fx
    )
    if looks_like_path:
        return None, "fixture %s looks like a path but does not exist: %s" % (which, fx)
    return fx, None


# --------------------------------------------------------------------------
# predicate engine (closed set -- unknown predicate fails closed)
# --------------------------------------------------------------------------

def eval_predicate(body, subject_text):
    """Return (passed, detail).  passed=False means the gate BLOCKS."""
    if not isinstance(body, str) or ":" not in body and body not in (
            "block_safety", "no_placeholder", "abs_cd_first", "tagged_numerals"):
        return None, "unknown predicate form %r" % body
    if body.startswith("absent:"):
        pat = body.split(":", 1)[1]
        try:
            rx = re.compile(pat, re.MULTILINE)
        except re.error as exc:
            return None, "bad regex in predicate: %s" % exc
        return (rx.search(subject_text) is None), "absent:%s" % pat
    if body.startswith("present:"):
        pat = body.split(":", 1)[1]
        try:
            rx = re.compile(pat, re.MULTILINE)
        except re.error as exc:
            return None, "bad regex in predicate: %s" % exc
        return (rx.search(subject_text) is not None), "present:%s" % pat
    if body == "no_placeholder":
        for rx, label in PLACEHOLDER_PATTERNS:
            if rx.search(subject_text):
                return False, "placeholder found: %s" % label
        return True, "no placeholder"
    if body == "abs_cd_first":
        for ln in subject_text.split("\n"):
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            return bool(ABS_CD_RE.match(s)), "first command: %s" % s
        return False, "block is empty"
    if body == "block_safety":
        problems = block_safety_problems(subject_text.split("\n"))
        return (not problems), "; ".join(problems) or "safe"
    if body == "tagged_numerals":
        bad = []
        for ln in subject_text.split("\n"):
            bad.extend(untagged_numerals(ln, set()))
        return (not bad), "untagged numerals: %s" % ", ".join(bad) if bad else "tagged"
    return None, "unknown predicate %r" % body


def block_safety_problems(lines):
    """V6 rules over one runnable block.  Returns a list of problem strings."""
    problems = []
    first_seen = False
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        if not first_seen:
            first_seen = True
            if not ABS_CD_RE.match(s):
                problems.append("first command is not an absolute cd: %r" % s[:60])
        destructive = bool(DESTRUCTIVE_RE.search(s)) or bool(REDIRECT_OVERWRITE_RE.search(s))
        if destructive and "&&" not in s:
            problems.append("destructive step not &&-chained: %r" % s[:60])
        if INTERACTIVE_CMDS.search(s):
            problems.append("command requires stdin / is interactive: %r" % s[:60])
    if not first_seen:
        problems.append("block contains no command")
    return problems


# --------------------------------------------------------------------------
# numeral sweep helpers (V4 / V8)
# --------------------------------------------------------------------------

NUMERAL_TOKEN_RE = re.compile(r"[^\s`|]*\d[^\s`|]*")
INLINE_CODE_RE = re.compile(r"`[^`]*`")

# Ordinal identifiers: the numeral names the thing, it does not measure it.
# Same class as G-04 / M2 / I-17, which the closed exemption list already
# covers -- this form just spells the prefix as a word.
#
# GOVERNED WIDENING (V10 discipline applied to this validator's own source):
# added only after the known-bad fixture `selftest_known_bad_zros-v1.md`
# already contained the breaking form ("LAW 4"), and the same fixture still
# proves the sweep fires on a real untagged threshold (0.7) and a real
# untagged count (38). If you widen this further, add the fixture first.
ORDINAL_IDENT_RE = re.compile(
    r"\b(?:LAW|STAGE|MODE|PASS|PHASE|STEP|LEVEL|TIER|RULE|SECTION|APPENDIX|"
    r"TABLE|FIGURE|NOTE|ITEM|PART|CHAPTER|VERSION|REV|WARNING|RUNG|DEFECT|"
    r"MECHANISM|GATE|CHECK|INCIDENT|CLAIM|WORK ORDER)\s+\d+\b",
    re.IGNORECASE,
)


def strip_inline_code(line):
    return INLINE_CODE_RE.sub(" ", line)


def untagged_numerals(line, derived_exempt):
    """Numeral tokens on a prose line that no exemption covers."""
    if TAG_RE.search(line):
        return []                      # a provenance tag covers its own line
    if re.match(r"^\s*\|?[\s:\-|]+\|?\s*$", line):
        return []                      # markdown table separator
    scrubbed = ORDINAL_IDENT_RE.sub(" ", strip_inline_code(line))
    out = []
    for tok in NUMERAL_TOKEN_RE.findall(scrubbed):
        bare = tok.strip("().,:;*_[]\"'")
        if not bare:
            continue
        if bare in derived_exempt:
            continue
        if any(rx.match(bare) for rx in STRUCTURAL_EXEMPT):
            continue
        out.append(bare)
    return out


def arithmetic_verified_row(zros, idx, line):
    """True for table rows whose numerals ANOTHER check verifies arithmetically.

    §R runbook rows and §7 friction-ledger rows carry per-fire costs and phase
    subtotals; V11 proves each subtotal equals the sum of its rows. A numeral
    that a different check re-computes is not an unsourced assertion, so V4/V8
    stand down there -- and only there. This exemption is narrow on purpose:
    widening it to any other section is exactly the tamper V10 watches for.
    """
    if not line.lstrip().startswith("|"):
        return False
    return zros.section_of(idx) in ("R", "7")


def build_derived_exemptions(gates, base_dir):
    """V4 requirement: derive the exemption list FROM THE FIXTURES, not guess.

    Every numeral-bearing token that appears in a known_good fixture is an
    accepted form, because a known_good fixture is by definition material the
    gate set has agreed passes.
    """
    exempt = set()
    for g in gates or []:
        text, _err = fixture_text(g, "known_good", base_dir)
        if not text:
            continue
        for tok in NUMERAL_TOKEN_RE.findall(text):
            bare = tok.strip("().,:;*_[]\"'")
            if bare:
                exempt.add(bare)
    return exempt


# --------------------------------------------------------------------------
# section parsers for §R and §L
# --------------------------------------------------------------------------

RUNBOOK_ROW_RE = re.compile(r"^\s*\|(?P<cells>.+)\|\s*$")
SUBTOTAL_RE = re.compile(r"subtotal", re.IGNORECASE)
PHASE_RE = re.compile(
    r"^\s*(?:#{1,6}\s+|\*\*)\s*(SESSION START|BEFORE CLAIM|BEFORE PLAN|"
    r"BEFORE PASTE|BEFORE PACKAGE|BEFORE SEND|WHEN STUCK|BEFORE CLOSE|"
    r"SESSION END)\b",
    re.IGNORECASE,
)
LAW_RE = re.compile(r"^\s*(?:\*\*)?(?:LAW\s*\d+|L\d+)\b")
CACHES_RE = re.compile(r"caches\s+([^)]*)", re.IGNORECASE)
UNCACHED_RE = re.compile(r"^\s*UNCACHED\b", re.IGNORECASE)


SEPARATOR_ROW_RE = re.compile(r"^\s*\|[\s:\-|]+\|\s*$")


def parse_runbook(zros):
    """Return (phases, orphan_rows). phases: list of dict(name, rows, subtotal)."""
    sec = zros.section_lines("R")
    if sec is None:
        return None, []
    phases = []
    current = None
    orphans = []
    header_lines = set()
    for pos, (idx, _line) in enumerate(sec):
        # a markdown header row is the line immediately above a separator row
        if pos + 1 < len(sec) and SEPARATOR_ROW_RE.match(sec[pos + 1][1]):
            header_lines.add(idx)
    for idx, line in sec:
        if idx in header_lines:
            continue
        pm = PHASE_RE.match(line)
        if pm:
            current = {"name": pm.group(1).upper(), "rows": [], "subtotal": None,
                       "line": idx}
            phases.append(current)
            continue
        rm = RUNBOOK_ROW_RE.match(line)
        if not rm:
            continue
        cells = [c.strip() for c in rm.group("cells").split("|")]
        joined = " ".join(cells)
        if re.match(r"^[\s:\-]+$", "".join(cells)):
            continue
        nums = [int(n) for n in re.findall(r"\b(\d+)\b", cells[-1])] if cells else []
        if SUBTOTAL_RE.search(joined):
            if current is not None and nums:
                current["subtotal"] = nums[-1]
            continue
        ids = GATE_ID_IN_TEXT.findall(joined)
        row = {"line": idx, "ids": ids, "cost": nums[-1] if nums else None,
               "text": joined}
        if current is None:
            orphans.append(row)
        else:
            current["rows"].append(row)
    return phases, orphans


def parse_laws(zros):
    """Return (laws, uncached_ids). laws: list of dict(line, text, cited)."""
    sec = zros.section_lines("L")
    if sec is None:
        return None, []
    laws = []
    uncached = []
    in_uncached = False
    for idx, line in sec:
        if UNCACHED_RE.match(line):
            in_uncached = True
            uncached.extend(GATE_ID_IN_TEXT.findall(line))
            continue
        if in_uncached:
            if line.strip() and not line.strip().startswith(("-", "*", "|")):
                in_uncached = False
            else:
                uncached.extend(GATE_ID_IN_TEXT.findall(line))
                continue
        if LAW_RE.match(line):
            laws.append({"line": idx, "text": line, "cited": []})
            continue
        if laws:
            laws[-1]["text"] += "\n" + line
    for law in laws:
        m = CACHES_RE.search(law["text"])
        law["cited"] = GATE_ID_IN_TEXT.findall(m.group(1)) if m else []
    return laws, uncached


# --------------------------------------------------------------------------
# the checks
# --------------------------------------------------------------------------

def check_V1(ctx):
    """PARENTAGE."""
    vs = []
    for g in ctx["gates"]:
        gid = g.get("id") or "?"
        tier = g.get("tier")
        parents = g.get("parents") or []
        cm = g.get("consequence_model")
        if tier == "ANTICIPATED":
            if g.get("consequence") != "EXISTENTIAL":
                vs.append(Violation(
                    "V1", gid, FAIL, gid,
                    "ANTICIPATED tier requires consequence=EXISTENTIAL; found %r "
                    "-- this is the laundering channel V1 exists to ban"
                    % g.get("consequence")))
                continue
            missing = []
            if not isinstance(cm, dict):
                missing = ["first_occurrence", "why_no_second_chance", "adoption_basis"]
            else:
                for f in ("first_occurrence", "why_no_second_chance", "adoption_basis"):
                    if not cm.get(f):
                        missing.append(f)
            if missing:
                vs.append(Violation("V1", gid, FAIL, gid,
                                    "ANTICIPATED gate missing consequence_model "
                                    "field(s): %s" % ", ".join(missing)))
            elif not re.match(r"^\[REPORTED:.+\]$", str(cm.get("adoption_basis")).strip()):
                vs.append(Violation("V1", gid, FAIL, gid,
                                    "adoption_basis must match [REPORTED: ...]; found %r"
                                    % cm.get("adoption_basis")))
            continue
        if tier == "PROVISIONAL-IMPORT":
            continue
        if not parents:
            vs.append(Violation("V1", gid, FAIL, gid,
                                "gate has no parent incident and is not "
                                "PROVISIONAL-IMPORT or ANTICIPATED"))
        if tier in ("CORE", "STANDARD") and g.get("fail_closed") is not True:
            vs.append(Violation("V1", gid + ":fail_closed", FAIL, gid,
                                "tier %s requires fail_closed=true" % tier))
    return CheckResult("V1", True, "", vs)


def check_V2(ctx):
    """COVERAGE -- every usable incident id is a parent, ACCEPTED or CALIBRATION."""
    universe = ctx["incident_universe"]
    if universe is None:
        return CheckResult(
            "V2", False,
            "incident universe unknown: pass --register <path> so the set of "
            "usable incident ids can be counted rather than inferred")
    covered = set()
    for g in ctx["gates"]:
        for p in (g.get("parents") or []):
            covered.add(str(p))
    dispositioned = ctx["dispositioned_incidents"]
    vs = []
    for iid in sorted(universe, key=_incident_sort_key):
        if iid in covered or iid in dispositioned:
            continue
        vs.append(Violation("V2", iid, FAIL, ctx["register_path"] or "§6",
                            "incident %s maps to no gate and appears on no "
                            "ACCEPTED / CALIBRATION list" % iid))
    return CheckResult("V2", True, "", vs)


def _incident_sort_key(iid):
    m = re.search(r"(\d+)", iid)
    return (int(m.group(1)) if m else 0, iid)


def check_V3(ctx):
    """FIXTURE PROOF -- known_bad must BLOCK, known_good must PASS."""
    vs = []
    base = ctx["base_dir"]
    for g in ctx["gates"]:
        gid = g.get("id") or "?"
        chk = g.get("check") or {}
        kind = chk.get("kind")
        bad, bad_err = fixture_text(g, "known_bad", base)
        good, good_err = fixture_text(g, "known_good", base)
        if bad_err or good_err:
            vs.append(Violation("V3", gid + ":fixture", FAIL, gid,
                                bad_err or good_err))
            continue
        if kind == "human":
            sev = FAIL if g.get("tier") in ("CORE", "STANDARD") else WARN
            vs.append(Violation(
                "V3", gid + ":human", sev, gid,
                "check.kind=human cannot be proven to fire on its known_bad; "
                "a gate that has never been proven to fire is a decoration"))
            continue
        if kind == "predicate":
            ok_bad, why_bad = eval_predicate(chk.get("body"), bad)
            ok_good, why_good = eval_predicate(chk.get("body"), good)
            if ok_bad is None or ok_good is None:
                vs.append(Violation("V3", gid + ":predicate", FAIL, gid,
                                    "predicate not evaluable: %s"
                                    % (why_bad if ok_bad is None else why_good)))
                continue
            if ok_bad:
                vs.append(Violation("V3", gid + ":known_bad", FAIL, gid,
                                    "known_bad fixture PASSES the check (%s) -- "
                                    "the gate does not fire on the case it claims "
                                    "to catch" % why_bad))
            if not ok_good:
                vs.append(Violation("V3", gid + ":known_good", FAIL, gid,
                                    "known_good fixture BLOCKS (%s)" % why_good))
            continue
        if kind == "command":
            if not ctx["run_commands"]:
                vs.append(Violation(
                    "V3", gid + ":command", FAIL, gid,
                    "check.kind=command was not executed (pass --run-commands to "
                    "prove this gate fires); NOT RUN is a FAIL, not an absence "
                    "of failure"))
                continue
            rb = _run_check_command(chk, bad, ctx)
            rg = _run_check_command(chk, good, ctx)
            if rb is None or rg is None:
                vs.append(Violation("V3", gid + ":command", FAIL, gid,
                                    "check command timed out or could not run"))
                continue
            if rb == 0:
                vs.append(Violation("V3", gid + ":known_bad", FAIL, gid,
                                    "known_bad fixture exits 0 -- gate does not fire"))
            if rg != 0:
                vs.append(Violation("V3", gid + ":known_good", FAIL, gid,
                                    "known_good fixture exits %d -- gate blocks "
                                    "material it must pass" % rg))
    return CheckResult("V3", True, "", vs)


def _run_check_command(chk, fixture, ctx):
    fd, tmp = tempfile.mkstemp(suffix=".fixture", text=False)
    os.close(fd)
    try:
        write_text(tmp, fixture)
        cmd = "%s %s" % (chk.get("body"), tmp)
        try:
            proc = subprocess.run(
                cmd, shell=True, cwd=ctx["base_dir"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=max(1, int(chk.get("max_seconds") or 60)),
            )
            return proc.returncode
        except Exception:                          # noqa: BLE001 -- fail closed
            return None
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def check_V4(ctx):
    """UNTAGGED NUMERAL SWEEP over prose."""
    vs = []
    exempt = ctx["derived_exempt"]
    for idx, line in ctx["zros"].prose_lines:
        if arithmetic_verified_row(ctx["zros"], idx, line):
            continue
        bad = untagged_numerals(line, exempt)
        for tok in bad:
            vs.append(Violation(
                "V4", "L%d:%s" % (idx + 1, tok), FAIL,
                "%s:%d" % (ctx["zros"].path, idx + 1),
                "untagged numeral %r" % tok,
                why="not in the structural exemption list and not a token form "
                    "present in any known_good fixture; tag the line "
                    "([MEASURED:/QUOTED:/DERIVED:/EST:/REPORTED:/UNVERIFIED]) "
                    "or add a fixture containing this form"))
    return CheckResult("V4", True, "", vs)


def check_V5(ctx):
    """PLACEHOLDER BAN inside runnable destinations only."""
    vs = []
    for blk in ctx["zros"].blocks:
        if not blk.runnable:
            continue
        for off, ln in enumerate(blk.lines):
            for rx, label in PLACEHOLDER_PATTERNS:
                m = rx.search(ln)
                if m:
                    line_no = blk.start_line + off + 2
                    vs.append(Violation(
                        "V5", "L%d" % line_no, FAIL,
                        "%s:%d" % (ctx["zros"].path, line_no),
                        "%s in a runnable block: %r" % (label, m.group(0)),
                        why="a placeholder in a shell-destined block is executed "
                            "verbatim and recorded as if it were a measurement"))
                    break
    for g in ctx["gates"]:
        chk = g.get("check") or {}
        if chk.get("kind") != "command":
            continue
        body = str(chk.get("body") or "")
        for rx, label in PLACEHOLDER_PATTERNS:
            if rx.search(body):
                vs.append(Violation("V5", (g.get("id") or "?") + ":check", FAIL,
                                    g.get("id") or "?",
                                    "%s in a runnable check body: %r" % (label, body)))
                break
    return CheckResult("V5", True, "", vs)


def check_V6(ctx):
    """BLOCK SAFETY."""
    vs = []
    zros = ctx["zros"]
    runnable_infos = set()
    for blk in zros.blocks:
        if blk.runnable:
            runnable_infos.add(blk.info)
    for blk in zros.blocks:
        line_no = blk.start_line + 1
        if blk.runnable:
            for problem in block_safety_problems(blk.lines):
                vs.append(Violation(
                    "V6", "L%d:%s" % (line_no, problem.split(":")[0].replace(" ", "-")),
                    FAIL, "%s:%d" % (zros.path, line_no), problem))
            # a runnable-fenced block whose content is plainly not shell
            body = blk.text().lstrip()
            if body.startswith("{") or body.startswith("["):
                vs.append(Violation(
                    "V6", "L%d:non-executable-fenced-as-executable" % line_no,
                    FAIL, "%s:%d" % (zros.path, line_no),
                    "non-executable content is fenced with the runnable info "
                    "string %r -- give it a different marker and label it "
                    "'not for pasting'" % blk.info))
        elif blk.info == "" and runnable_infos:
            body = blk.text().lstrip()
            if body.startswith("{") or body.startswith("["):
                vs.append(Violation(
                    "V6", "L%d:unmarked-fence" % line_no, WARN,
                    "%s:%d" % (zros.path, line_no),
                    "non-executable block carries no info string while runnable "
                    "blocks exist in the same document"))
    return CheckResult("V6", True, "", vs)


def check_V7(ctx):
    """TAG-TRUTH SAMPLING.  Severity CRITICAL on mismatch."""
    text = "\n".join(ctx["zros"].lines)
    samples = MEASURED_RE.findall(text)
    if not samples:
        return CheckResult("V7", True, "no [MEASURED:] tags to sample", [])
    if not ctx["tag_audit"]:
        return CheckResult(
            "V7", False,
            "%d [MEASURED:] tag(s) present and none re-executed; pass "
            "--tag-audit to re-run them. V4 proves a tag is PRESENT; only this "
            "check touches whether it is TRUE." % len(samples))
    vs = []
    for cmd, frag in samples:
        cmd = cmd.strip().strip("`")
        frag = frag.strip().strip("`")
        try:
            proc = subprocess.run(cmd, shell=True, cwd=ctx["base_dir"],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=120)
            out = proc.stdout.decode("utf-8", "replace")
        except Exception as exc:                   # noqa: BLE001
            vs.append(Violation("V7", cmd, CRITICAL, ctx["zros"].path,
                                "tagged command could not be re-executed (%s): %s"
                                % (exc, cmd)))
            continue
        if frag not in out:
            vs.append(Violation(
                "V7", cmd, CRITICAL, ctx["zros"].path,
                "tag claims %r but re-running %r produced output not containing "
                "it -- the instrument is lying and every downstream result is "
                "suspect" % (frag, cmd)))
    return CheckResult("V7", True, "", vs)


def check_V8(ctx):
    """NO HARDCODED COUNTS."""
    vs = []
    for idx, line in ctx["zros"].prose_lines:
        if not COUNT_WORDS.search(line):
            continue
        if TAG_RE.search(line):
            continue
        if arithmetic_verified_row(ctx["zros"], idx, line):
            continue
        scrubbed = ORDINAL_IDENT_RE.sub(" ", strip_inline_code(line))
        nums = []
        for tok in NUMERAL_TOKEN_RE.findall(scrubbed):
            bare = tok.strip("().,:;*_[]\"'")
            if not bare or not re.match(r"^\d+$", bare):
                continue
            if bare in ctx["derived_exempt"]:
                continue
            nums.append(bare)
        for n in nums:
            vs.append(Violation(
                "V8", "L%d:%s" % (idx + 1, n), FAIL,
                "%s:%d" % (ctx["zros"].path, idx + 1),
                "count %r stated in prose with no [DERIVED:]/[MEASURED:] "
                "computation" % n,
                why="a literal count drifts the moment a later edit moves what "
                    "it counts; compute it or show the operation"))
    return CheckResult("V8", True, "", vs)


def check_V9(ctx):
    """SELFTEST-BEFORE-SHIP -- reported by the --selftest entry point."""
    return CheckResult(
        "V9", True,
        "selftest is an entry point, not a document check; run "
        "'python validate_zros.py --selftest'", [])


def check_V10(ctx):
    """EXEMPTION TAMPER GUARD -- runs against a diff."""
    diff_path = ctx["tamper_diff"]
    if not diff_path:
        return CheckResult(
            "V10", False,
            "no diff supplied; V10 guards a CHANGE, not a state. Run "
            "'python validate_zros.py --tamper-diff <diff-file>' in the "
            "pre-commit hook, or --skip V10 for a standalone document run")
    try:
        lines = read_lines(diff_path)
    except Exception as exc:                       # noqa: BLE001
        return CheckResult("V10", False, "diff unreadable: %s" % exc)
    added = [ln[1:] for ln in lines if ln.startswith("+") and not ln.startswith("+++")]
    removed = [ln[1:] for ln in lines if ln.startswith("-") and not ln.startswith("---")]
    loosenings = []
    for ln in added:
        if re.search(r'"fail_closed"\s*:\s*false', ln):
            loosenings.append(("fail_closed flipped to false", ln.strip()))
        if re.search(r'"on_fail"\s*:\s*"WARN"', ln):
            loosenings.append(("on_fail downgraded to WARN", ln.strip()))
        if re.search(r"or reasonably inferred|or equivalent|best effort", ln, re.I):
            loosenings.append(("check softened with an inference escape", ln.strip()))
        if re.search(r"RED\s*=|GREEN\s*=|YELLOW\s*=|zone", ln, re.I) and re.search(r"\d", ln):
            loosenings.append(("§12 metric zone threshold changed", ln.strip()))
    for ln in removed:
        if re.search(r'"fail_closed"\s*:\s*true', ln):
            loosenings.append(("fail_closed=true removed", ln.strip()))
    old_ex = _exemption_size(removed)
    new_ex = _exemption_size(added)
    if new_ex is not None and old_ex is not None and new_ex > old_ex:
        loosenings.append(("exemption list widened (%d -> %d alternations)"
                           % (old_ex, new_ex), ""))
    fixture_added = any(
        re.search(r"known_bad|known-bad|fixtures/|log_sample", ln, re.I)
        for ln in added)
    vs = []
    if loosenings and not fixture_added:
        for label, ln in loosenings:
            vs.append(Violation(
                "V10", label.replace(" ", "-"), FAIL, diff_path,
                "loosened under pressure -- add the fixture that proves the "
                "gate still fires. (%s) %s" % (label, ln[:80])))
    return CheckResult("V10", True, "", vs)


def _exemption_size(lines):
    best = None
    for ln in lines:
        if "exempt" in ln.lower() or "EXEMPT" in ln:
            n = ln.count("|")
            best = n if best is None else max(best, n)
    return best


def check_V11(ctx):
    """RUNBOOK PROJECTION."""
    phases, orphans = parse_runbook(ctx["zros"])
    if phases is None:
        return CheckResult("V11", False,
                           "§R not found in the document; a gate set with no "
                           "runbook is a gate set that never runs")
    vs = []
    known_ids = {g.get("id") for g in ctx["gates"]}
    seen = {}
    for ph in phases:
        for row in ph["rows"]:
            if not row["ids"]:
                vs.append(Violation("V11", "L%d:theater" % (row["line"] + 1), FAIL,
                                    "%s:%d" % (ctx["zros"].path, row["line"] + 1),
                                    "runbook row references no gate id -- theater"))
            for gid in row["ids"]:
                if gid not in known_ids:
                    vs.append(Violation("V11", "L%d:%s" % (row["line"] + 1, gid), FAIL,
                                        "%s:%d" % (ctx["zros"].path, row["line"] + 1),
                                        "runbook cites %s which is absent from "
                                        "§3 / zros_gates.json" % gid))
                else:
                    seen.setdefault(gid, 0)
                    seen[gid] += 1
        if ph["subtotal"] is not None:
            total = sum(r["cost"] or 0 for r in ph["rows"])
            if total != ph["subtotal"]:
                vs.append(Violation(
                    "V11", "%s:subtotal" % ph["name"].replace(" ", "-"), FAIL,
                    "%s:%d" % (ctx["zros"].path, ph["line"] + 1),
                    "phase %s subtotal is %d but its rows sum to %d"
                    % (ph["name"], ph["subtotal"], total)))
    for row in orphans:
        vs.append(Violation("V11", "L%d:orphan" % (row["line"] + 1), WARN,
                            "%s:%d" % (ctx["zros"].path, row["line"] + 1),
                            "runbook row sits under no session phase"))
    for g in ctx["gates"]:
        gid = g.get("id")
        if g.get("tier") not in ("CORE", "ANTICIPATED", "STANDARD"):
            continue
        n = seen.get(gid, 0)
        if n == 0:
            vs.append(Violation("V11", "%s:missing" % gid, FAIL, "§R",
                                "tier %s gate %s appears in no runbook phase -- "
                                "a gate missing from the runbook never runs"
                                % (g.get("tier"), gid)))
        elif n > 1:
            vs.append(Violation("V11", "%s:duplicate" % gid, FAIL, "§R",
                                "gate %s appears in the runbook %d times; the "
                                "projection must be exactly once" % (gid, n)))
    return CheckResult("V11", True, "", vs)


def check_V12(ctx):
    """LAW CACHE COHERENCE."""
    laws, uncached = parse_laws(ctx["zros"])
    if laws is None:
        return CheckResult("V12", False, "§L not found in the document")
    vs = []
    if len(laws) > 7:
        vs.append(Violation("V12", "count", FAIL, "§L",
                            "§L contains %d laws; the ceiling is seven "
                            "(a law set nobody can hold is not a cache)"
                            % len(laws)))
    known_ids = {g.get("id") for g in ctx["gates"]}
    cited_count = {}
    for law in laws:
        head = law["text"].split("\n")[0].strip()
        if not law["cited"]:
            vs.append(Violation("V12", "L%d:slogan" % (law["line"] + 1), FAIL,
                                "%s:%d" % (ctx["zros"].path, law["line"] + 1),
                                "law cites no gate ids -- it is a slogan: %s"
                                % head[:70]))
            continue
        for gid in law["cited"]:
            if gid not in known_ids:
                vs.append(Violation("V12", "L%d:%s" % (law["line"] + 1, gid), FAIL,
                                    "%s:%d" % (ctx["zros"].path, law["line"] + 1),
                                    "law cites %s which is not in the gate file"
                                    % gid))
            cited_count[gid] = cited_count.get(gid, 0) + 1
    for g in ctx["gates"]:
        if g.get("tier") != "CORE":
            continue
        gid = g.get("id")
        n = cited_count.get(gid, 0)
        if n == 0 and gid not in uncached:
            vs.append(Violation("V12", "%s:uncached" % gid, FAIL, "§L",
                                "CORE gate %s is cited by no law and is not on "
                                "the UNCACHED list with a reason" % gid))
        elif n > 1:
            vs.append(Violation("V12", "%s:multi-cached" % gid, FAIL, "§L",
                                "CORE gate %s is cached by %d laws; it must be "
                                "exactly one" % (gid, n)))
    return CheckResult("V12", True, "", vs)


CHECK_FUNCS = {
    "V1": check_V1, "V2": check_V2, "V3": check_V3, "V4": check_V4,
    "V5": check_V5, "V6": check_V6, "V7": check_V7, "V8": check_V8,
    "V9": check_V9, "V10": check_V10, "V11": check_V11, "V12": check_V12,
}

# Order matters: cheap graph checks, then fixtures, then text sweeps, then
# selftest, then tag-truth (executes), then tamper.  APPENDIX-V build order.
CHECK_ORDER = ["V1", "V2", "V11", "V12", "V3", "V4", "V5", "V6", "V8",
               "V9", "V7", "V10"]


# --------------------------------------------------------------------------
# register parsing (for V2's incident universe)
# --------------------------------------------------------------------------

INCIDENT_ID_RE = re.compile(r"\bI-\d+\b")
UNUSABLE_RE = re.compile(r"UNUSABLE\s*--?\s*no evidence", re.IGNORECASE)


def parse_register(path):
    """Return (usable_ids, unusable_ids) from a rework register markdown file."""
    usable, unusable = set(), set()
    for line in read_lines(path):
        ids = INCIDENT_ID_RE.findall(line)
        if not ids:
            continue
        target = unusable if UNUSABLE_RE.search(line) else usable
        for i in ids:
            target.add(i)
    return usable - unusable, unusable


DISPOSITION_RE = re.compile(r"\b(ACCEPTED|CALIBRATION)\b")


def parse_dispositions(zros):
    """Incident ids sitting on an ACCEPTED / CALIBRATION line in §6."""
    out = set()
    sec = zros.section_lines("6")
    if not sec:
        return out
    for _idx, line in sec:
        if DISPOSITION_RE.search(line):
            out.update(INCIDENT_ID_RE.findall(line))
    return out


# --------------------------------------------------------------------------
# runner
# --------------------------------------------------------------------------

def run(zros_path, gates_path, opts):
    errors = []
    gates, gate_errors = load_gates(gates_path)
    if gate_errors:
        errors.extend(gate_errors)
    if gates is None:
        return None, errors, 3
    try:
        zros = Zros(zros_path)
    except Exception as exc:                       # noqa: BLE001
        return None, ["ZROS document unreadable: %s" % exc], 3

    base_dir = os.path.dirname(os.path.abspath(zros_path)) or "."
    universe = None
    if opts.register:
        usable, _unusable = parse_register(opts.register)
        universe = usable

    ctx = {
        "zros": zros,
        "gates": gates,
        "base_dir": base_dir,
        "derived_exempt": build_derived_exemptions(gates, base_dir),
        "incident_universe": universe,
        "register_path": opts.register,
        "dispositioned_incidents": parse_dispositions(zros),
        "tag_audit": opts.tag_audit,
        "run_commands": opts.run_commands,
        "tamper_diff": opts.tamper_diff,
    }

    results = []
    for cid in CHECK_ORDER:
        if cid in opts.skip:
            results.append(CheckResult(cid, False, "SKIPPED by --skip %s" % cid))
            continue
        try:
            results.append(CHECK_FUNCS[cid](ctx))
        except Exception as exc:                   # noqa: BLE001 -- fail closed
            results.append(CheckResult(
                cid, False, "check raised %s: %s" % (type(exc).__name__, exc)))
    results.sort(key=lambda r: int(r.check[1:]))
    return results, errors, None


def exit_code(results, errors, opts):
    if errors:
        return 3
    worst = 0
    for r in results:
        if not r.ran and r.check not in opts.skip:
            worst = max(worst, SEVERITY_RANK[FAIL])
        for v in r.violations:
            worst = max(worst, SEVERITY_RANK[v.severity])
    if worst >= SEVERITY_RANK[CRITICAL]:
        return 2
    if worst >= SEVERITY_RANK[FAIL]:
        return 1
    return 0


def render(results, errors, opts, zros_path, gates_path):
    out = []
    out.append("validate_zros v%s" % __version__)
    out.append("  document : %s" % zros_path)
    out.append("  gates    : %s" % gates_path)
    out.append("")
    for e in errors:
        out.append("  GATE-FILE SCHEMA ERROR: %s" % e)
    if errors:
        out.append("")
    out.append("  CHECK  STATUS   SEV       COUNT  NOTE")
    ran_all = True
    for r in results:
        if not r.ran and r.check not in opts.skip:
            ran_all = False
        sev = ""
        if r.violations:
            sev = max(r.violations, key=lambda v: SEVERITY_RANK[v.severity]).severity
        status = "RAN" if r.ran else ("SKIPPED" if r.check in opts.skip else "NOT_RUN")
        out.append("  %-5s  %-8s %-9s %5d  %s"
                   % (r.check, status, sev, len(r.violations), r.reason))
    out.append("")
    for r in results:
        if not r.violations:
            continue
        out.append("  %s -- %d violation(s)" % (r.check, len(r.violations)))
        shown = r.violations if opts.all else r.violations[:opts.max_per_check]
        for v in shown:
            out.append("    [%s] %s" % (v.severity, v.vid))
            out.append("        %s" % v.message)
            out.append("        at %s" % v.where)
            if opts.explain and opts.explain.upper() == r.check and v.why:
                out.append("        why: %s" % v.why)
        hidden = len(r.violations) - len(shown)
        if hidden > 0:
            out.append("    ... %d more (use --all)" % hidden)
        out.append("")
    if not ran_all:
        out.append("  NOT_RUN is a FAIL. A validator that reports green while a "
                   "check did not execute")
        out.append("  is the pre-commit defect this project already has. Supply "
                   "the missing input")
        out.append("  or --skip the check explicitly.")
        out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------
# selftest
# --------------------------------------------------------------------------

def selftest(opts, expected_name="selftest_expected-v1.json", quiet=False):
    here = os.path.dirname(os.path.abspath(__file__))
    fx = os.path.join(here, "fixtures")
    zros_path = os.path.join(fx, "selftest_known_bad_zros-v1.md")
    gates_path = os.path.join(fx, "selftest_known_bad_gates-v1.json")
    expect_path = os.path.join(fx, expected_name)
    for p in (zros_path, gates_path, expect_path):
        if not os.path.isfile(p):
            print("SELFTEST FAIL: missing fixture %s" % p)
            return 3
    expected = json.loads(read_text(expect_path))

    class O(object):
        register = os.path.join(fx, "selftest_register-v1.md")
        # V7 is exercised for real: the fixture's only [MEASURED:] tag names
        # `echo hello`, which is portable to cmd.exe and to bash, and whose
        # recorded fragment is deliberately wrong.
        tag_audit = True
        # V3's command path is exercised through its NOT-EXECUTED disposition,
        # so the selftest never runs an arbitrary interpreter.
        run_commands = False
        tamper_diff = os.path.join(fx, "selftest_loosening-v1.diff")
        skip = set()
        explain = None
        max_per_check = 200
        all = True

    results, errors, early = run(zros_path, gates_path, O())
    if early == 3:
        print("SELFTEST FAIL: fixture gate file did not parse:")
        for e in errors:
            print("   %s" % e)
        return 3

    got_ids = sorted(v.vid for r in results for v in r.violations)
    want_ids = sorted(expected["violation_ids"])
    ran = sorted(r.check for r in results if r.ran)
    want_ran = sorted(expected["checks_that_must_run"])

    if quiet:
        buf = []

        def emit(msg):
            buf.append(msg)
    else:
        def emit(msg):
            print(msg)

    ok = True
    missing = [i for i in want_ids if i not in got_ids]
    extra = [i for i in got_ids if i not in want_ids]
    if missing:
        ok = False
        emit("SELFTEST FAIL: expected violation ids not produced (%d):" % len(missing))
        for i in missing:
            emit("   MISSING  %s" % i)
    if extra:
        ok = False
        emit("SELFTEST FAIL: unexpected violation ids produced (%d):" % len(extra))
        for i in extra:
            emit("   EXTRA    %s" % i)
    not_ran = [c for c in want_ran if c not in ran]
    if not_ran:
        ok = False
        emit("SELFTEST FAIL: checks that must run did not run: %s"
             % ", ".join(not_ran))
        for r in results:
            if r.check in not_ran:
                emit("   %s: %s" % (r.check, r.reason))
    schema_errs = sorted(errors)
    want_schema = sorted(expected.get("gate_schema_errors", []))
    if schema_errs != want_schema:
        ok = False
        emit("SELFTEST FAIL: gate schema error set differs")
        for e in want_schema:
            if e not in schema_errs:
                emit("   MISSING  %s" % e)
        for e in schema_errs:
            if e not in want_schema:
                emit("   EXTRA    %s" % e)

    if ok:
        emit("SELFTEST PASS")
        emit("  violation ids matched exactly : %d" % len(got_ids))
        emit("  checks proven to have run     : %s" % ", ".join(ran))
        emit("  (asserted on ids, never on a count -- APPENDIX-V warning 2)")
        return 0
    return 1


def selftest_meta():
    """V9's own known-bad case: point the selftest at a WRONG expectation and
    assert it fails. An instrument that cannot fail is a rubber stamp (L6), and
    that includes this one."""
    here = os.path.dirname(os.path.abspath(__file__))
    wrong = os.path.join(here, "fixtures", "selftest_expected_WRONG-v1.json")
    if not os.path.isfile(wrong):
        print("META FAIL: missing fixture %s" % wrong)
        return 3
    rc_good = selftest(None, "selftest_expected-v1.json", quiet=True)
    rc_bad = selftest(None, "selftest_expected_WRONG-v1.json", quiet=True)
    print("META: selftest vs correct expectation -> %d (want 0)" % rc_good)
    print("META: selftest vs wrong   expectation -> %d (want 1)" % rc_bad)
    if rc_good == 0 and rc_bad == 1:
        print("META PASS: the selftest is provably able to fail")
        return 0
    print("META FAIL: the selftest cannot distinguish a wrong expectation from "
          "a right one")
    return 1


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="validate_zros",
        description="Validate a ZROS document against its gate file "
                    "(ZROS-FORGE v1.1 §V).")
    ap.add_argument("zros", nargs="?", help="path to the ZROS markdown file")
    ap.add_argument("gates", nargs="?", help="path to zros_gates.json")
    ap.add_argument("--register", help="rework register markdown, for V2 coverage")
    ap.add_argument("--tamper-diff", help="unified diff file, for V10")
    ap.add_argument("--tag-audit", action="store_true",
                    help="V7: re-execute [MEASURED:] commands (runs shell commands)")
    ap.add_argument("--run-commands", action="store_true",
                    help="V3: execute check.kind=command gates against fixtures")
    ap.add_argument("--skip", default="",
                    help="comma-separated check ids to skip, e.g. V7,V10")
    ap.add_argument("--explain", help="print the 'why' line for one check id")
    ap.add_argument("--all", action="store_true", help="print every violation")
    ap.add_argument("--max-per-check", type=int, default=10)
    ap.add_argument("--json", action="store_true", help="machine-readable report")
    ap.add_argument("--selftest", action="store_true",
                    help="run against the bundled known-bad fixture and assert "
                         "the exact violation-id set")
    ap.add_argument("--selftest-meta", action="store_true",
                    help="prove the selftest itself can fail, by running it "
                         "against a deliberately wrong expectation")
    ap.add_argument("--version", action="store_true")
    opts = ap.parse_args(argv)

    if opts.version:
        print("validate_zros v%s" % __version__)
        return 0
    if opts.selftest_meta:
        return selftest_meta()
    if opts.selftest:
        return selftest(opts)
    if not opts.zros or not opts.gates:
        ap.print_usage()
        print("error: both <zros> and <gates> are required (or use --selftest)")
        return 3
    for p in (opts.zros, opts.gates):
        if not os.path.isfile(p):
            print("error: no such file: %s" % p)
            return 3
    opts.skip = {s.strip().upper() for s in opts.skip.split(",") if s.strip()}
    unknown = opts.skip - set(ALL_CHECKS)
    if unknown:
        print("error: unknown check id(s) in --skip: %s" % ", ".join(sorted(unknown)))
        return 3

    results, errors, early = run(opts.zros, opts.gates, opts)
    if early == 3:
        for e in errors:
            print("GATE-FILE ERROR: %s" % e)
        return 3
    if opts.json:
        payload = {
            "document": opts.zros, "gates": opts.gates,
            "checks": [{"check": r.check, "ran": r.ran, "reason": r.reason,
                        "violations": [v.as_dict() for v in r.violations]}
                       for r in results],
            "gate_schema_errors": errors,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(render(results, errors, opts, opts.zros, opts.gates))
    return exit_code(results, errors, opts)


if __name__ == "__main__":
    sys.exit(main())
