"""WO-S1 evidence obligation: an exception inside the judge yields the
abstention token, never a numeric score (PLAN_LOCK_WO_S_v1)."""
import importlib.util
import pathlib

_p = pathlib.Path(__file__).resolve().parents[1] / "judge_engine" / "v1" / "semantic_judge.py"
_spec = importlib.util.spec_from_file_location("semantic_judge_wo_s1", _p)
sj = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sj)


def test_exception_yields_token_never_a_number():
    out = sj.evaluate(None, {})  # non-str input raises TypeError inside _score
    assert out["semantic_score"] is None
    assert out["abstention"] == "INSUFFICIENT_CONTEXT"
    assert "TypeError" in out["abstention_reason"]


def test_happy_path_is_numeric_and_carries_no_token():
    out = sj.evaluate("def f(): return 1", {})
    assert isinstance(out["semantic_score"], float)
    assert "abstention" not in out
