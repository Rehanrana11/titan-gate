#!/usr/bin/env python3
"""
battery.py -- 24 probes against titan-gate's ACTUAL behaviour.

Run from the repo root:   python sdlc/battery.py

Every probe is defensive: a failure prints SKIP with the reason rather than
aborting the run. Paste the whole output back. Nothing here writes to disk or
mutates the repo.

Design notes (the techniques, applied to the probe set rather than to prose):
  SCHEMA      every line is  ID  name  value  -- machine-readable, diffable
  VERIFICATION each capability claim is probed by trying to BREAK it, not
              by confirming it (tamper probes, key-swap probes)
  VERSIONING  A1 pins every version constant so a rerun is comparable
  RUBRIC      D-section separates WORKS / BROKEN / UNKNOWN explicitly
  XML/structure sections are fixed and ordered so the output is parseable
"""
import glob
import importlib
import json
import os
import subprocess
import sys
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "src"))

W = 30


def out(pid, name, value):
    print(f"{pid:<5}{name:<{W}} {value}")


def probe(pid, name):
    def deco(fn):
        try:
            out(pid, name, fn())
        except Exception as e:
            out(pid, name, f"SKIP {type(e).__name__}: {str(e)[:70]}")
        return fn
    return deco


def head(t):
    print(f"\n== {t} ==")


KEY = "00" * 32
ARGS = dict(tenant_id="probe", repo="r", repo_full_name="o/r", pr_number=1,
            pr_title="t", branch="b", base_branch="main", commit_sha="deadbeef")

head("A. INVENTORY")


@probe("A1", "version constants")
def _():
    c = importlib.import_module("api.constants")
    keys = [k for k in dir(c) if k.isupper()]
    return " ".join(f"{k}={getattr(c,k)}" for k in sorted(keys))[:200]


@probe("A2", "score weights")
def _():
    e = importlib.import_module("judge_engine.v1.engine")
    return f"structural={e.STRUCTURAL_WEIGHT} semantic={e.SEMANTIC_WEIGHT}"


@probe("A3", "soc2 control set")
def _():
    p = importlib.import_module("judge_engine.v1.policy_judge")
    return f"{len(p.SOC2)} controls: {list(p.SOC2)}"


@probe("A4", "top-level surfaces")
def _():
    want = ["action.yml", "api", "evalspine", "policy_packs", "r-package",
            "deploy", "demo_kit", "dist", "titan_gate", "examples", "scripts"]
    return " ".join(w + ("+" if os.path.exists(w) else "-") for w in want)


@probe("A5", "test file count")
def _():
    return f"{len(glob.glob('tests/**/*.py', recursive=True))} in tests/, " \
           f"{len(glob.glob('sdlc/evals/test_*.py'))} in sdlc/evals/"


@probe("A6", "pre-existing tooling")
def _():
    return " ".join(f + ("+" if os.path.exists(f) else "-")
                    for f in ["probe_24.py", "rc_battery.sh", "run_tests.py",
                              "CONTINUATION_PROMPT.md", "PROCESS.md", "SPEC.md"])


head("B. YOUR EXISTING BATTERY (run first, not replaced)")


@probe("B1", "probe_24.py header")
def _():
    if not os.path.exists("probe_24.py"):
        return "absent"
    txt = open("probe_24.py", encoding="utf-8", errors="replace").read()
    first = [l for l in txt.splitlines() if l.strip()][:3]
    return f"{len(txt.splitlines())} lines | " + " / ".join(x.strip()[:44] for x in first)


@probe("B2", "rc_battery.sh header")
def _():
    if not os.path.exists("rc_battery.sh"):
        return "absent"
    txt = open("rc_battery.sh", encoding="utf-8", errors="replace").read()
    first = [l for l in txt.splitlines() if l.strip() and not l.startswith("#!")][:3]
    return f"{len(txt.splitlines())} lines | " + " / ".join(x.strip()[:44] for x in first)


@probe("B3", "probe_24 run (60s cap)")
def _():
    if not os.path.exists("probe_24.py"):
        return "absent"
    r = subprocess.run([sys.executable, "probe_24.py"], capture_output=True,
                       text=True, timeout=60)
    tail = (r.stdout or r.stderr).strip().splitlines()[-4:]
    return f"rc={r.returncode} | " + " | ".join(t[:60] for t in tail)


head("C. WHAT ACTUALLY WORKS -- CRYPTO / CHAIN")

_R1 = _R2 = None


@probe("C1", "receipt generated + signed")
def _():
    global _R1
    e = importlib.import_module("judge_engine.v1.engine")
    _R1 = e.evaluate("def add(a, b):\n    return a + b\n", {}, key_hex=KEY, **ARGS)
    return f"fields={len(_R1)} sig={_R1['signature'][:16]}... hash={_R1['receipt_hash'][:16]}..."


@probe("C2", "artifact hash deterministic")
def _():
    global _R2
    e = importlib.import_module("judge_engine.v1.engine")
    _R2 = e.evaluate("def add(a, b):\n    return a + b\n", {}, key_hex=KEY, **ARGS)
    same = _R1["artifact_hash"] == _R2["artifact_hash"] and _R1["provenance_hash"] == _R2["provenance_hash"]
    return f"{'YES' if same else 'NO'} (receipt_hash equal: {_R1['receipt_hash'] == _R2['receipt_hash']})"


@probe("C3", "tamper changes receipt hash")
def _():
    e = importlib.import_module("judge_engine.v1.engine")
    t = dict(_R1); t["composite_score"] = 0.99
    t.pop("receipt_hash", None); t.pop("signature", None)
    return "DETECTED" if e.compute_receipt_hash(t) != _R1["receipt_hash"] else "NOT DETECTED"


@probe("C4", "wrong key changes signature")
def _():
    e = importlib.import_module("judge_engine.v1.engine")
    base = {k: v for k, v in _R1.items() if k != "signature"}
    return "YES" if e.compute_signature(base, "11" * 32) != _R1["signature"] else "NO"


@probe("C5", "chain links to prev")
def _():
    e = importlib.import_module("judge_engine.v1.engine")
    r2 = e.evaluate("x = 1\n", {}, key_hex=KEY, prev_receipt_hash=_R1["receipt_hash"], **ARGS)
    return f"{'YES' if r2['prev_receipt_hash'] == _R1['receipt_hash'] else 'NO'}"


@probe("C6", "verifier module present")
def _():
    found = []
    for m in ["titan_gate.verify", "api.verify", "judge_engine.v1.verify", "titan.verify"]:
        try:
            importlib.import_module(m); found.append(m)
        except Exception:
            pass
    hits = subprocess.run(["git", "grep", "-l", "def verify"], capture_output=True, text=True)
    return f"imports={found or 'none'} files={hits.stdout.split() or 'none'}"


@probe("C7", "proof bundle shape")
def _():
    d = json.load(open("proof_bundle.json"))
    return f"receipts={d.get('receipt_count')} merkle_root={str(d.get('merkle_root'))[:16]}... anchor={str(d.get('anchor'))[:40]}"


@probe("C8", "demo_kit tamper pair differs")
def _():
    a = sorted(glob.glob("demo_kit/bundle/**/*", recursive=True))
    b = sorted(glob.glob("demo_kit/bundle_tampered/**/*", recursive=True))
    return f"clean={len(a)} files, tampered={len(b)} files"


head("D. WHAT IS BROKEN -- JUDGING")


@probe("D1", "semantic: correct vs wrong")
def _():
    s = importlib.import_module("judge_engine.v1.semantic_judge")
    a = s.evaluate("def add(a,b): return a+b", {})["semantic_score"]
    b = s.evaluate("def add(a,b): return a-b", {})["semantic_score"]
    return f"{a} vs {b} -> {'IDENTICAL (blind)' if a == b else 'differs'}"


@probe("D2", "structural: empty artifact")
def _():
    st = importlib.import_module("judge_engine.v1.structural_judge")
    return f"empty={st.evaluate('', {})['structural_score']} code={st.evaluate('def f(a,b): return a+b', {})['structural_score']}"


@probe("D3", "EMPTY FILE -> full receipt")
def _():
    e = importlib.import_module("judge_engine.v1.engine")
    r = e.evaluate("", {}, key_hex=KEY, **ARGS)
    sat = sum(1 for c in r["soc2_controls"] if c["status"] == "satisfied")
    unev = sum(1 for c in r["soc2_controls"] if c["status"] == "unevaluated")
    return (f"verdict={r['verdict']} composite={r['composite_score']} "
            f"soc2_satisfied={sat}/{len(r['soc2_controls'])} "
            f"soc2_unevaluated={unev}/{len(r['soc2_controls'])} "
            f"ai_attributed={r['ai_attributed']} signed={bool(r['signature'])}")


@probe("D4", "composite discrimination")
def _():
    e = importlib.import_module("judge_engine.v1.engine")
    corpus = ["", "def f(): pass", "def add(a,b): return a+b", "def add(a,b): return a-b",
              "TODO", "import os\nclass K:\n    def m(self) -> int:\n        return 1\n",
              "x = sum(v for v in data if v > 0)", "eval(input())", "rm -rf /",
              "def f(a: int, b: int) -> int:\n    return a + b\n"]
    vals = [e.evaluate(c, {}, key_hex=KEY, **ARGS)["composite_score"] for c in corpus]
    return f"{len(set(vals))} distinct scores over {len(corpus)} inputs: {sorted(set(vals))}"


@probe("D5", "hostile input verdict")
def _():
    e = importlib.import_module("judge_engine.v1.engine")
    r = e.evaluate("eval(input())  # arbitrary code execution", {}, key_hex=KEY, **ARGS)
    return f"verdict={r['verdict']} hard_violations={r['hard_violations']}"


@probe("D6", "PASS threshold")
def _():
    e = importlib.import_module("judge_engine.v1.engine")
    import inspect
    return " ".join(inspect.getsource(e.classify).split())[:180]


head("E. INTERFACE SURFACE")


@probe("E1", "action.yml io")
def _():
    txt = open("action.yml", encoding="utf-8", errors="replace").read()
    ins = [l.strip() for l in txt.splitlines() if l.strip().endswith(":") and "  " in l[:4]]
    return f"{len(txt.splitlines())} lines | " + " ".join(ins[:12])[:180]


@probe("E2", "api endpoints")
def _():
    r = subprocess.run(["git", "grep", "-n", "-E", r"@app\.(get|post|put)"],
                       capture_output=True, text=True)
    return " | ".join(l.split(":", 2)[-1].strip() for l in r.stdout.splitlines()[:8]) or "none"


@probe("E3", "console scripts")
def _():
    txt = open("pyproject.toml", encoding="utf-8", errors="replace").read()
    i = txt.find("[project.scripts]")
    return txt[i:i + 200].replace("\n", " ") if i >= 0 else "none declared"


@probe("E4", "policy packs")
def _():
    f = sorted(glob.glob("policy_packs/**/*", recursive=True))
    return f"{len(f)} files: {[os.path.basename(x) for x in f[:8]]}"


@probe("E5", "evalspine")
def _():
    f = sorted(glob.glob("evalspine/**/*.py", recursive=True))
    return f"{len(f)} py files: {[os.path.basename(x) for x in f[:8]]}"


@probe("E6", "r-package + deploy")
def _():
    return (f"r-package={len(glob.glob('r-package/**/*', recursive=True))} files, "
            f"deploy={[os.path.basename(x) for x in sorted(glob.glob('deploy/*'))[:6]]}")


@probe("E7", "examples")
def _():
    return f"{[os.path.basename(x) for x in sorted(glob.glob('examples/*'))[:10]]}"


print("\n== END. Paste everything above. ==")
