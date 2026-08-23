"""
Characterisation tests for structural_judge and policy_judge.

Every assertion here was observed by direct call on 2026-08-17. They pass today.
They exist so that any change to these judges is announced rather than silent.

The xfail(strict=True) tests assert what these judges SHOULD do. They fail today.
"""
import pytest
from judge_engine.v1 import structural_judge, policy_judge


def s(a):
    return structural_judge.evaluate(a, {})["structural_score"]


def test_empty_artifact_scores_perfect():
    """Writing nothing is the highest-scoring input."""
    assert s("") == 1.0


def test_todo_fixme_only_scores_perfect():
    assert s("TODO FIXME") == 1.0


def test_structural_score_is_blind_to_correctness():
    assert s("def add(a,b): return a+b") == s("def add(a,b): return a-b") == 0.95


def test_writing_code_scores_worse_than_writing_nothing():
    """Anti-correlated: the only way to lose points is to write a function."""
    assert s("def add(a,b): return a+b") < s("")


def test_policy_judge_ignores_the_artifact_entirely():
    a = policy_judge.evaluate("anything at all", {}, [], [])
    b = policy_judge.evaluate("", {}, [], [])
    assert a == b


def test_no_soc2_control_defaults_to_satisfied():
    """W1: inverted. This test formerly asserted the D3 bug as correct
    behaviour -- `all(c["satisfied"])` on an empty artifact -- and would have
    gone red the moment anyone fixed it. Absence of evidence is not compliance.
    """
    out = policy_judge.evaluate("", {}, [], [])
    assert not any(c["satisfied"] for c in out["soc2_controls"])
    assert len(out["soc2_controls"]) > 1


def test_unevaluated_controls_are_not_satisfied():
    """W1: was xfail(strict=True). Now a plain assertion."""
    out = policy_judge.evaluate("", {}, [], [])
    assert all(c["status"] == "unevaluated" for c in out["soc2_controls"])
    assert not all(c["satisfied"] for c in out["soc2_controls"])


@pytest.mark.xfail(strict=True, reason="BUG: empty artifact scores 1.0")
def test_empty_artifact_should_not_score_perfect():
    assert s("") < 1.0
