"""WO-S4 (PLAN_LOCK_WO_S_v1): contrastive negatives per rubric level.

Each rubric level carries an annotated known-bad that must provably score
below that level's positive twin. Two strict xfails pin known dead spots:
P1 is defined in the rubric dict and fired by no rule; semantic scoring is
correctness-blind (a+b vs a-b identical). If either xfail starts XPASSing,
the capability arrived and the pin flips to a real guard.
"""
import importlib.util
import pathlib

_base = pathlib.Path(__file__).resolve().parents[1] / "judge_engine" / "v1"


def _load(name):
    spec = importlib.util.spec_from_file_location("wo_s4_" + name, _base / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


st = _load("structural_judge")
se = _load("semantic_judge")

import pytest


def test_h2_credential_negative_scores_below_clean_positive():
    bad = 'password = "hunter2"'                       # H2: hardcoded credential
    good = 'connect(credential_source=env_lookup())'   # same job, no literal secret
    b = st.evaluate(bad, {})
    g = st.evaluate(good, {})
    assert b["structural_score"] < g["structural_score"]
    assert any(v["code"] == "H2" for v in b["hard_violations"])
    assert all(v["severity"] == "blocking" for v in b["hard_violations"])


def test_h3_no_error_handling_negative_scores_below_handled_positive():
    body = "x = compute_value(item) -> None\n" * 12    # >200 chars, no try/except
    bad = body
    good = "try:\n" + body + "except ValueError:\n    raise\n"
    b = st.evaluate(bad, {})
    g = st.evaluate(good, {})
    assert len(bad) > 200
    assert b["structural_score"] < g["structural_score"]
    assert any(v["code"] == "H3" for v in b["hard_violations"])
    assert not any(v["code"] == "H3" for v in g["hard_violations"])


def test_p3_missing_type_hints_negative_scores_below_hinted_positive():
    bad = "def f(x): return x"
    good = "def f(x) -> int: return x"
    b = st.evaluate(bad, {})
    g = st.evaluate(good, {})
    assert b["structural_score"] < g["structural_score"]
    assert any(v["code"] == "P3" for v in b["process_violations"])
    assert not any(v["code"] == "P3" for v in g["process_violations"])


def test_semantic_marker_negatives_each_score_below_clean_twin():
    clean = "def f(): return 1"
    base = se.evaluate(clean, {})["semantic_score"]
    for marker in ("TODO", "FIXME", "HACK", "XXX"):
        marked = clean + "  # " + marker
        assert se.evaluate(marked, {})["semantic_score"] < base, marker


@pytest.mark.xfail(strict=True, reason="P1 'Missing docstring' is defined in "
                   "the rubric dict and fired by no rule -- dead rubric entry, "
                   "same class as the old decorative CC7.2")
def test_p1_missing_docstring_is_reachable():
    out = st.evaluate("def f(x) -> int: return x", {})
    assert any(v["code"] == "P1" for v in out["process_violations"])


@pytest.mark.xfail(strict=True, reason="semantic scoring is correctness-blind: "
                   "a+b and a-b carry identical keyword profiles (register "
                   "PRE-EXISTING)")
def test_semantic_score_distinguishes_correct_from_incorrect():
    add = se.evaluate("def add(a,b): return a+b", {})["semantic_score"]
    sub = se.evaluate("def add(a,b): return a-b", {})["semantic_score"]
    assert add != sub
