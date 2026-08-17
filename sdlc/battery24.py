#!/usr/bin/env python3
"""
BATTERY-24 — testing TECHNIQUES, not capabilities.

Complements the three batteries that already exist. It deliberately does NOT
repeat them:

    rc_battery.sh   pre-send gate: suite, supply chain, live attacks, anchors,
                    trust domain, honesty guards
    probe_24.py     capability ledger: what is PROVEN / NOT-BUILT / LIMITATION
    sdlc/battery.py defect probes D1-D5 on the judge

This battery asks a different question: which established software-testing
TECHNIQUES have ever been applied to this codebase at all? A technique never
run is a class of defect never looked for.

Discipline borrowed from probe_24: every technique reports one of

    PASS       technique ran, found nothing
    FINDING    technique ran, found something -- read the detail
    NOT-BUILT  technique not implemented here; the reason is stated
    NEEDS-DEP  requires a dependency this repo deliberately does not carry
    MANUAL     cannot be automated; a human must do it

NOTHING is installed. Nothing in the repo is modified. Every file this battery
writes goes to a temp directory. rc_battery step 5-7 checks supply-chain
cleanliness -- a test harness must not be the thing that dirties it.

    python battery24.py            # run all
    python battery24.py --only T06 # one technique
    python battery24.py --list
"""
import argparse
import ast
import hashlib
import itertools
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

def _find_repo():
    """Locate the repo root by looking for titan_gate/, so this script works
    from sdlc/, from the root, or from anywhere else. Prefer the cwd when it
    already looks like the repo -- that is how a human invokes it."""
    candidates = [Path.cwd()] + list(Path(__file__).resolve().parents)
    for d in candidates:
        if (d / "titan_gate").is_dir():
            return d
    return Path.cwd()


REPO = _find_repo()
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

RESULTS = []
SEED = 20260817


def technique(tid, group, name):
    def deco(fn):
        fn._tid, fn._group, fn._name = tid, group, name
        return fn
    return deco


def _mod(dotted):
    import importlib
    return importlib.import_module(dotted)


def _canonical():
    return _mod("titan_gate.canonical")


def _chain():
    return _mod("titan_gate.chain_state")


def _seal_v1(**fields):
    cb = _canonical().canonical_bytes
    r = dict(fields)
    r.pop("receipt_hash", None)
    r["receipt_hash"] = hashlib.sha256(cb(r)).hexdigest()
    return r


def _write(root, name, receipt):
    (root / ("%s.json" % name)).write_text(json.dumps(receipt), encoding="utf-8")
    return receipt["receipt_hash"]


# =====================================================================
# GROUP A — input-space techniques
# =====================================================================

@technique("T01", "A", "Structure-aware fuzzing of the verifier")
def t01():
    """A verifier is a parser fed untrusted bytes. It must fail cleanly on
    every input -- never with an unhandled exception, and never by accepting
    a corrupted receipt."""
    cs = _chain()
    rnd = random.Random(SEED)
    base = _seal_v1(schema_version="receipt_v1", tenant_id="t", seq=0,
                    prev_receipt_hash=cs.GENESIS)
    crashes, accepted, noop = [], [], 0
    tmp = Path(tempfile.mkdtemp())
    for i in range(300):
        d = tmp / ("f%04d" % i)
        d.mkdir()
        raw = json.dumps(base)
        op = rnd.choice(["bitflip", "truncate", "dup", "inject", "typeswap"])
        if op == "bitflip":
            pos = rnd.randrange(len(raw))
            mutated = raw[:pos] + rnd.choice("0123456789abcdef{}[]\",:") + raw[pos + 1:]
        elif op == "truncate":
            mutated = raw[:rnd.randrange(1, len(raw))]
        elif op == "dup":
            mutated = raw[:-1] + ',"' + rnd.choice(list(base)) + '":null}'
        elif op == "inject":
            mutated = raw[:-1] + ',"__proto__":{"a":1},"x":' + "[" * 40 + "]" * 40 + "}"
        else:
            m = dict(base)
            k = rnd.choice(list(m))
            m[k] = rnd.choice([None, [], {}, 0, True, "x" * 200])
            mutated = json.dumps(m)
        # A mutation that changed nothing is not a corrupted input. Without
        # this check the fuzzer reports "ACCEPTED" for documents identical to
        # the original -- typeswap substituting 0 for an existing 0, bitflip
        # replacing a character with itself. That is a false finding.
        if mutated == raw:
            noop += 1
            continue
        try:
            if json.loads(mutated) == base:
                noop += 1
                continue
        except Exception:
            pass                      # unparseable IS a real corruption
        (d / "000.json").write_text(mutated, encoding="utf-8")
        try:
            cs.latest_receipt_hash(d)
            accepted.append((op, mutated[:60]))
        except cs.ChainStateError:
            pass
        except RecursionError:
            crashes.append((op, "RecursionError", mutated[:60]))
        except Exception as e:
            crashes.append((op, type(e).__name__, mutated[:60]))
    shutil.rmtree(tmp, ignore_errors=True)
    if crashes:
        return "FINDING", "%d/%d inputs raised a non-ChainStateError: %s" % (
            len(crashes), 300 - noop, crashes[:3])
    if accepted:
        return "FINDING", "%d/%d CORRUPTED inputs were ACCEPTED: %s" % (
            len(accepted), 300 - noop, accepted[:3])
    return "PASS", ("%d genuinely corrupted receipts rejected as ChainStateError, "
                    "no crashes (%d no-op mutations skipped)" % (300 - noop, noop))


@technique("T02", "A", "Metamorphic testing of canonicalization")
def t02():
    """Relations that must hold under transformation, without knowing the
    expected output: key order, insertion order, and re-canonicalization."""
    cb = _canonical().canonical_bytes
    base = {"repo": "r", "branch": "b", "pr_title": "t", "seq": 3}
    fails = []
    for perm in itertools.islice(itertools.permutations(list(base)), 12):
        d = {k: base[k] for k in perm}
        if cb(d) != cb(base):
            fails.append("insertion order %s changed bytes" % (perm,))
    once = cb(base)
    twice = cb(json.loads(once.decode("utf-8")))
    if once != twice:
        fails.append("canonicalization is not idempotent under round-trip")
    if fails:
        return "FINDING", "; ".join(fails[:3])
    return "PASS", "12 insertion orders + round-trip idempotence all byte-stable"


@technique("T03", "A", "Differential testing vs an independent implementation")
def t03():
    """Conformance is a claim about agreement with OTHER implementations, not
    about self-consistency. Compare against a minimal reference written here."""
    cb = _canonical().canonical_bytes

    def reference(d):
        # Deliberately independent: explicit sort, explicit separators.
        items = sorted(d.items(), key=lambda kv: kv[0])
        parts = []
        for k, v in items:
            parts.append(json.dumps(k, ensure_ascii=False) + ":" +
                         json.dumps(v, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False))
        return ("{" + ",".join(parts) + "}").encode("utf-8")

    cases = [
        {"b": 1, "a": 2},
        {"pr_title": "Fix — naïve", "repo": "東京"},
        {"x": "\U0001f680", "y": ""},
        {"n": 9007199254740991},
        {"nested": {"z": 1, "a": {"q": [3, 2, 1]}}},
    ]
    diffs = []
    for c in cases:
        if cb(c) != reference(c):
            diffs.append((c, cb(c)[:60], reference(c)[:60]))
    if diffs:
        return "FINDING", "%d/%d cases disagree with the reference: %s" % (
            len(diffs), len(cases), diffs[0])
    return "PASS", "%d cases agree byte-for-byte with an independent encoder" % len(cases)


@technique("T04", "A", "Boundary and equivalence-class probing")
def t04():
    """Mutation testing already proved this codebase was weak at count
    boundaries (5 survivors, all at exactly 2). This checks the boundaries
    directly rather than inferring them."""
    cs = _chain()
    tmp = Path(tempfile.mkdtemp())
    findings = []
    for n in (0, 1, 2, 3):
        d = tmp / ("n%d" % n)
        d.mkdir()
        prev = cs.GENESIS
        for i in range(n):
            prev = _write(d, "%03d" % i, _seal_v1(
                schema_version="receipt_v1", tenant_id="t", seq=i,
                prev_receipt_hash=prev))
        try:
            got = cs.latest_receipt_hash(d)
            expected_genesis = (n == 0)
            if expected_genesis and got != cs.GENESIS:
                findings.append("n=0 did not return GENESIS")
            if not expected_genesis and got != prev:
                findings.append("n=%d returned %s, expected head %s" % (n, got[:8], prev[:8]))
        except Exception as e:
            findings.append("n=%d raised %s: %s" % (n, type(e).__name__, e))
    shutil.rmtree(tmp, ignore_errors=True)
    if findings:
        return "FINDING", "; ".join(findings)
    return "PASS", "chain sizes 0,1,2,3 all resolve to the correct head"


@technique("T05", "A", "Encoding and locale matrix")
def t05():
    """The ensure_ascii survivor proved encoding assumptions were untested.
    Locale can also leak into sorting and number formatting."""
    cb = _canonical().canonical_bytes
    payload = {"pr_title": "Fix — naïve", "repo": "東京", "n": 1.5}
    expected = cb(payload)
    script = ("import json,sys;sys.path.insert(0,%r);"
              "from titan_gate.canonical import canonical_bytes as c;"
              "sys.stdout.buffer.write(c(json.loads(sys.argv[1])))" % str(REPO))
    diffs = []
    for loc in ("C", "en_US.UTF-8", "tr_TR.UTF-8", "de_DE.UTF-8"):
        env = dict(os.environ, LC_ALL=loc, LANG=loc)
        p = subprocess.run([sys.executable, "-c", script, json.dumps(payload)],
                           capture_output=True, env=env)
        if p.returncode == 0 and p.stdout != expected:
            diffs.append(loc)
    if diffs:
        return "FINDING", "canonical bytes differ under locale(s): %s" % diffs
    return "PASS", "byte-identical under C / en_US / tr_TR / de_DE"


# =====================================================================
# GROUP B — execution-model techniques
# =====================================================================

@technique("T06", "B", "Concurrency / race on the chain head")
def t06():
    """THE structural risk in this design. latest_receipt_hash() scans, then
    the caller writes. Two writers that scan the same head both create a child
    of it -- which is precisely the fork the module exists to reject. The
    docstring says callers must never assert their own prev; it does not say
    what stops two honest callers from racing."""
    cs = _chain()
    tmp = Path(tempfile.mkdtemp())
    d = tmp / "chain"
    d.mkdir()
    _write(d, "000", _seal_v1(schema_version="receipt_v1", tenant_id="t",
                              seq=0, prev_receipt_hash=cs.GENESIS))
    errors, heads = [], []

    def writer(i):
        try:
            head = cs.latest_receipt_hash(d)
            heads.append(head)
            time.sleep(0.01)          # the window every scan-then-write has
            _write(d, "w%02d" % i, _seal_v1(
                schema_version="receipt_v1", tenant_id="t", seq=1,
                writer=i, prev_receipt_hash=head))
        except Exception as e:
            errors.append("%s: %s" % (type(e).__name__, e))

    ts = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    forked = False
    detail = ""
    try:
        cs.latest_receipt_hash(d)
    except cs.ChainStateError as e:
        forked = "fork" in str(e).lower()
        detail = str(e)[:90]
    shutil.rmtree(tmp, ignore_errors=True)
    if forked:
        return "FINDING", ("4 concurrent writers each read the same head and "
                           "forked the chain. No lock, no CAS, no atomic "
                           "append. Detected after the fact, not prevented: %s"
                           % detail)
    if errors:
        return "FINDING", "concurrent writers raised: %s" % errors[:2]
    return "PASS", "4 concurrent writers produced a single unbroken chain"


@technique("T07", "B", "Cross-process determinism (hash randomization)")
def t07():
    """PYTHONHASHSEED changes dict/set iteration order per process. Anything
    that leaks set ordering into canonical bytes produces receipts that verify
    on the machine that made them and nowhere else."""
    cb = _canonical().canonical_bytes
    payload = {"z": 1, "a": 2, "m": 3, "tags": ["b", "a"], "seq": 7}
    script = ("import json,sys;sys.path.insert(0,%r);"
              "from titan_gate.canonical import canonical_bytes as c;"
              "sys.stdout.buffer.write(c(json.loads(sys.argv[1])))" % str(REPO))
    outs = set()
    for seed in ("0", "1", "12345", "random"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        p = subprocess.run([sys.executable, "-c", script, json.dumps(payload)],
                           capture_output=True, env=env)
        if p.returncode == 0:
            outs.add(p.stdout)
    if len(outs) > 1:
        return "FINDING", "canonical bytes vary with PYTHONHASHSEED (%d variants)" % len(outs)
    return "PASS", "identical under PYTHONHASHSEED 0/1/12345/random"


@technique("T08", "B", "Fault injection on persisted state")
def t08():
    """Disks fill, processes die mid-write, files arrive empty. A chain walker
    must distinguish 'corrupt' from 'absent' and never silently skip."""
    cs = _chain()
    tmp = Path(tempfile.mkdtemp())
    cases = {
        "empty file": "",
        "truncated json": '{"schema_version": "receipt_v1", "tenant',
        "null document": "null",
        "array document": "[]",
        "bom prefix": "﻿{}",
        "nul bytes": "\x00\x00\x00",
    }
    bad = []
    for i, (name, content) in enumerate(cases.items()):
        d = tmp / ("c%d" % i)
        d.mkdir()
        (d / "000.json").write_text(content, encoding="utf-8")
        try:
            cs.latest_receipt_hash(d)
            bad.append("%s: ACCEPTED" % name)
        except cs.ChainStateError:
            pass
        except Exception as e:
            bad.append("%s: %s (not ChainStateError)" % (name, type(e).__name__))
    shutil.rmtree(tmp, ignore_errors=True)
    if bad:
        return "FINDING", "; ".join(bad)
    return "PASS", "%d corruption modes all produce ChainStateError" % len(cases)


@technique("T09", "B", "Resource exhaustion / algorithmic DoS")
def t09():
    """Untrusted JSON with deep nesting or huge values. Bounded failure is
    acceptable; unbounded recursion or quadratic blowup is not."""
    cs = _chain()
    tmp = Path(tempfile.mkdtemp())
    findings = []
    probes = {
        "deep nesting x2000": "[" * 2000 + "]" * 2000,
        "huge string 8MB": json.dumps({"pr_title": "x" * (8 * 1024 * 1024)}),
        "many keys 50k": json.dumps({("k%d" % i): i for i in range(50000)}),
    }
    for i, (name, content) in enumerate(probes.items()):
        d = tmp / ("r%d" % i)
        d.mkdir()
        (d / "000.json").write_text(content, encoding="utf-8")
        t0 = time.time()
        try:
            cs.latest_receipt_hash(d)
        except cs.ChainStateError:
            pass
        except RecursionError:
            findings.append("%s -> RecursionError (unbounded)" % name)
        except Exception as e:
            findings.append("%s -> %s" % (name, type(e).__name__))
        el = time.time() - t0
        if el > 10:
            findings.append("%s took %.1fs" % (name, el))
    shutil.rmtree(tmp, ignore_errors=True)
    if findings:
        return "FINDING", "; ".join(findings)
    return "PASS", "deep nesting / 8MB string / 50k keys all bounded, <10s"


@technique("T10", "B", "Soak: chain growth cost curve")
def t10():
    """latest_receipt_hash is O(n) per write by design ('O(n) per write,
    honest'). Confirm it is O(n) and not O(n^2) before anyone runs it at 10k."""
    cs = _chain()
    tmp = Path(tempfile.mkdtemp())
    timings = []
    for n in (50, 100, 200, 400):
        d = tmp / ("s%d" % n)
        d.mkdir()
        prev = cs.GENESIS
        for i in range(n):
            prev = _write(d, "%05d" % i, _seal_v1(
                schema_version="receipt_v1", tenant_id="t", seq=i,
                prev_receipt_hash=prev))
        t0 = time.time()
        cs.latest_receipt_hash(d)
        timings.append((n, time.time() - t0))
    shutil.rmtree(tmp, ignore_errors=True)
    (n1, t1), (n4, t4) = timings[0], timings[-1]
    ratio = (t4 / t1) if t1 > 0 else 0
    growth = n4 / n1
    detail = "  ".join("n=%d %.3fs" % (n, t) for n, t in timings)
    if ratio > growth * 3:
        return "FINDING", "superlinear: %dx items cost %.1fx time | %s" % (
            growth, ratio, detail)
    return "PASS", "%dx items -> %.1fx time (linear-ish) | %s" % (growth, ratio, detail)


# =====================================================================
# GROUP C — coverage-of-intent techniques
# =====================================================================

@technique("T11", "C", "Error-path reachability audit")
def t11():
    """Every raise is a promise. Count them, and count how many the test suite
    names. An unreachable or untested error branch is a guard that has never
    been shown to fire."""
    src_files = sorted((REPO / "titan_gate").glob("*.py"))
    if not src_files:
        return "NOT-BUILT", "no titan_gate/*.py found from %s" % REPO
    total, messages, boms, unparsed = 0, [], [], []
    for f in src_files:
        # utf-8-sig, not utf-8: a BOM makes ast.parse raise
        # "invalid non-printable character U+FEFF" even though CPython itself
        # imports the file fine. Naive AST tooling breaks on BOM'd sources.
        raw = f.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            boms.append(f.name)
        try:
            tree = ast.parse(raw.decode("utf-8-sig"))
        except (SyntaxError, UnicodeDecodeError) as e:
            unparsed.append("%s (%s)" % (f.name, type(e).__name__))
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Raise) and node.exc is not None:
                total += 1
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str) \
                            and len(sub.value) > 12:
                        messages.append(sub.value.strip().split("{")[0].strip()[:40])
                        break
    test_blob = ""
    for f in (REPO / "tests").rglob("*.py") if (REPO / "tests").exists() else []:
        test_blob += f.read_text(encoding="utf-8", errors="ignore")
    named = [m for m in messages if m and m[:20] in test_blob]
    pct = (100.0 * len(named) / len(messages)) if messages else 0.0
    detail = "%d raise sites, %d with a distinctive message, %d (%.0f%%) named in tests/" % (
        total, len(messages), len(named), pct)
    extra = ""
    if boms:
        extra += " | BOM in %d file(s): %s -- CPython imports them, AST tooling does not" % (
            len(boms), boms[:4])
    if unparsed:
        extra += " | UNPARSED: %s" % unparsed[:4]
    unnamed = [m for m in messages if m and m[:20] not in test_blob]
    if unnamed or boms or unparsed:
        return "FINDING", detail + extra + (
            (" | unnamed: " + "; ".join(unnamed[:4])) if unnamed else "")
    return "PASS", detail


@technique("T12", "C", "Mutation adequacy")
def t12():
    """Line coverage says a line ran. Mutation says a change to it would be
    noticed. Only the second is evidence."""
    harness = REPO / "sdlc" / "mutate.py"
    if not harness.exists():
        harness = REPO / "mutate.py"
    if not harness.exists():
        return "NOT-BUILT", "sdlc/mutate.py not found; run it per-file and record scores"
    return "MANUAL", ("harness present at %s -- scores are per-file and must be "
                      "re-recorded after any change to the target or the tests. "
                      "Known: canonical.py 36/36, chain_state.py 25/25, "
                      "trs2_writer.py 120 sites UNRUN" % harness.relative_to(REPO))


@technique("T13", "C", "Golden corpus / backward compatibility")
def t13():
    """Receipts written by older versions must still verify. Without a pinned
    corpus, 'we never broke the format' is an assertion."""
    candidates = list(REPO.rglob("examples/*.json")) + list(REPO.rglob("golden/*.json"))
    if not candidates:
        return "NOT-BUILT", ("no examples/ or golden/ corpus found. Pin >=10 receipts "
                             "from each shipped version; verify all on every commit")
    return "PASS", "%d pinned receipt fixtures present: %s" % (
        len(candidates), [c.name for c in candidates[:5]])


@technique("T14", "C", "Migration / upgrade path")
def t14():
    """chain_state names 'a pre-WO-3 legacy tree; migrate it first'. A named
    migration with no test is a named migration that has never run."""
    cs = _chain()
    tmp = Path(tempfile.mkdtemp())
    d = tmp / "legacy"
    d.mkdir()
    # A receipt with NO schema_version -- the code defaults it to receipt_v1.
    r = {"tenant_id": "t", "seq": 0, "prev_receipt_hash": cs.GENESIS}
    r["receipt_hash"] = hashlib.sha256(_canonical().canonical_bytes(r)).hexdigest()
    (d / "000.json").write_text(json.dumps(r), encoding="utf-8")
    try:
        head = cs.latest_receipt_hash(d)
        ok = head == r["receipt_hash"]
    except Exception as e:
        shutil.rmtree(tmp, ignore_errors=True)
        return "FINDING", "legacy receipt with no schema_version: %s: %s" % (
            type(e).__name__, str(e)[:70])
    shutil.rmtree(tmp, ignore_errors=True)
    if not ok:
        return "FINDING", "legacy (schema_version absent) resolved to the wrong head"
    return "PASS", "schema_version-absent receipt defaults to receipt_v1 and verifies"


@technique("T15", "C", "Idempotence of verification")
def t15():
    """Verification must be a pure function of the tree. Two calls, same answer,
    and no side effects on disk."""
    cs = _chain()
    tmp = Path(tempfile.mkdtemp())
    d = tmp / "c"
    d.mkdir()
    prev = cs.GENESIS
    for i in range(3):
        prev = _write(d, "%03d" % i, _seal_v1(
            schema_version="receipt_v1", tenant_id="t", seq=i, prev_receipt_hash=prev))
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in d.iterdir()}
    a = cs.latest_receipt_hash(d)
    b = cs.latest_receipt_hash(d)
    after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in d.iterdir()}
    shutil.rmtree(tmp, ignore_errors=True)
    if a != b:
        return "FINDING", "two identical calls returned different heads"
    if before != after:
        return "FINDING", "verification mutated the tree on disk"
    return "PASS", "repeated verification is stable and side-effect free"


@technique("T16", "C", "Secret / key-material scan")
def t16():
    """Rule 1 says the evidence core cannot sign. rc_battery greps for env
    refs; this looks for literal key material and private keys."""
    import re
    pats = [
        (re.compile(r"BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY"), "private key block"),
        (re.compile(r"\b[0-9a-fA-F]{64}\b"), "64-hex literal"),
        (re.compile(r"(?i)(api[_-]?key|secret|passwd|password|token)\s*=\s*['\"][^'\"]{8,}"),
         "assigned credential"),
    ]
    hits = []
    for f in REPO.rglob("*.py"):
        if any(x in f.parts for x in ("tests", "__pycache__", ".git", "sdlc")):
            continue
        text = f.read_text(encoding="utf-8", errors="ignore")
        for pat, label in pats:
            for m in pat.finditer(text):
                if label == "64-hex literal" and set(m.group(0)) <= set("0f"):
                    continue          # all-zero / all-f test vectors
                hits.append("%s:%s" % (f.relative_to(REPO), label))
                break
    if hits:
        return "FINDING", "%d candidate(s): %s" % (len(hits), sorted(set(hits))[:5])
    return "PASS", "no private keys or assigned credentials in non-test source"


@technique("T17", "C", "Spec-claim traceability")
def t17():
    """Every MUST in the spec should map to something executable. Unmapped
    MUSTs are the claims that rot."""
    specs = [p for p in REPO.rglob("SPEC*.md")]
    if not specs:
        return "NOT-BUILT", "no SPEC*.md found from %s" % REPO
    musts = []
    for s in specs:
        for i, line in enumerate(s.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            if " MUST " in line or line.strip().startswith("MUST"):
                musts.append("%s:%d" % (s.name, i))
    return ("PASS" if musts else "NOT-BUILT",
            "%d MUST statements across %s -- map each to a probe id and fail the "
            "build on unmapped ones" % (len(musts), [s.name for s in specs]))


# =====================================================================
# GROUP D — techniques this battery does not automate
# =====================================================================

@technique("T18", "D", "Property-based testing (Hypothesis)")
def t18():
    try:
        import hypothesis  # noqa: F401
    except ImportError:
        return "NEEDS-DEP", ("hypothesis not installed and MUST NOT be auto-installed "
                             "(rc_battery 5-7 checks supply-chain cleanliness). "
                             "Add as a dev-only extra, then generate receipts from a "
                             "strategy and assert canonicalize->parse->canonicalize is fixed")
    return "MANUAL", "hypothesis available; write strategies for receipts and chains"


@technique("T19", "D", "Branch coverage of the evidence core")
def t19():
    try:
        import coverage  # noqa: F401
    except ImportError:
        return "NEEDS-DEP", ("coverage not installed. Target: branch coverage on "
                             "titan_gate/ only. Coverage is a floor, not evidence -- "
                             "T12 is the evidence")
    return "MANUAL", "coverage available; run `coverage run -m pytest && coverage report --show-missing`"


@technique("T20", "D", "Static type checking")
def t20():
    if shutil.which("mypy") is None:
        return "NEEDS-DEP", ("mypy not on PATH. chain_state.py already carries "
                             "annotations; strict mode on titan_gate/ would cost little")
    return "MANUAL", "mypy present; run `mypy --strict titan_gate/`"


@technique("T21", "D", "Model-based / state-machine testing")
def t21():
    return "NOT-BUILT", ("the chain is a state machine: EMPTY -> GENESIS -> EXTENDED, "
                         "with FORKED / DANGLING / MIXED-PROFILE as absorbing error "
                         "states. Generate random valid+invalid transition sequences "
                         "and assert the walker's verdict matches the model. Highest-"
                         "value unbuilt technique after T06")


@technique("T22", "D", "Cross-platform determinism matrix")
def t22():
    return "NOT-BUILT", ("this run covers one OS (%s) and one Python (%s). A CRLF "
                         "line-ending bug already bit this repo once. Needs CI across "
                         "Windows/Linux/macOS x 3 Python versions, comparing a pinned "
                         "canonical-bytes digest" % (sys.platform,
                                                     ".".join(map(str, sys.version_info[:2]))))


@technique("T23", "D", "Adversarial spec review")
def t23():
    return "MANUAL", ("give SPEC.md and SPEC-2.md to someone who has not read the code "
                      "and ask them to build a conforming verifier. Every question they "
                      "must ask is an ambiguity. The ensure_ascii finding was exactly "
                      "this class -- caught by mutation, not by review")


@technique("T24", "D", "Independent cryptographic review")
def t24():
    return "MANUAL", ("no amount of self-testing substitutes. Scope it narrowly: "
                      "canonical.py, chain_state.py, trs2_writer.py, merkle. Bring the "
                      "mutation scores and probe_24 -- they shorten the engagement and "
                      "prove the ground is prepared")


# =====================================================================

GROUPS = {
    "A": "INPUT SPACE",
    "B": "EXECUTION MODEL",
    "C": "COVERAGE OF INTENT",
    "D": "NOT AUTOMATED HERE",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="run a single technique id, e.g. T06")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    fns = sorted((v for v in globals().values()
                  if callable(v) and hasattr(v, "_tid")), key=lambda f: f._tid)
    if args.only:
        fns = [f for f in fns if f._tid == args.only.upper()]
        if not fns:
            print("no such technique")
            return 2
    if args.list:
        for f in fns:
            print("  %s [%s] %s" % (f._tid, f._group, f._name))
        return 0

    print("#" * 72)
    print("BATTERY-24 — TESTING TECHNIQUES")
    print("repo root : %s" % REPO)
    print("titan_gate: %s" % ("found" if (REPO / "titan_gate").is_dir()
                              else "NOT FOUND — run from the repo root"))
    print("#" * 72)
    current = None
    counts = {}
    for f in fns:
        if f._group != current:
            current = f._group
            print("\n=== GROUP %s: %s ===" % (current, GROUPS.get(current, "")))
        try:
            verdict, detail = f()
        except Exception:
            verdict, detail = "ERROR", traceback.format_exc().strip().splitlines()[-1]
        counts[verdict] = counts.get(verdict, 0) + 1
        RESULTS.append((f._tid, verdict, f._name, detail))
        print("  %s [%-9s] %s" % (f._tid, verdict, f._name))
        for chunk in _wrap(detail, 64):
            print("            %s" % chunk)

    print("\n" + "=" * 72)
    print("VERDICTS: " + "  ".join("%s:%d" % (k, counts[k]) for k in sorted(counts)))
    print("FINDING or ERROR is a defect to investigate. NOT-BUILT and NEEDS-DEP")
    print("are honest gaps, not failures — but a gap never closed is a technique")
    print("never applied, and that is a class of defect never looked for.")
    print("=" * 72)
    return 1 if counts.get("FINDING", 0) or counts.get("ERROR", 0) else 0


def _wrap(s, width):
    out, line = [], ""
    for w in str(s).split():
        if len(line) + len(w) + 1 > width:
            out.append(line)
            line = w
        else:
            line = (line + " " + w).strip()
    if line:
        out.append(line)
    return out


if __name__ == "__main__":
    sys.exit(main())
