#!/usr/bin/env python3
"""
W4 acceptance: "a test asserting some input produces verdict FAIL".

The work order assumed FAIL was unreachable, reading D5 ("eval(input()) -> PASS,
hard_violations []") as proof that hard_violations is never populated. It is not.
structural_judge.py fires H2 on a hardcoded-credential regex and H3 on a long
artifact with no try/except, and engine.classify() short-circuits to FAIL on any
hard violation. D5's input simply matches neither rule.

No wire-format change. This file is pure measurement of existing behaviour.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from judge_engine.v1 import structural_judge  # noqa: E402
from judge_engine.v1.engine import classify  # noqa: E402
from api.constants import VERDICT_FAIL, VERDICT_PASS, SCORE_PASS  # noqa: E402

# A composite comfortably above SCORE_PASS, so any FAIL below is caused by the
# hard-violation short-circuit and not by the score falling through a threshold.
CLEAN_COMPOSITE = 0.88


def _verdict(artifact):
    st = structural_judge.evaluate(artifact, {})
    return classify(CLEAN_COMPOSITE, st["hard_violations"]), st


# --- W4 acceptance ---------------------------------------------------------

@pytest.mark.parametrize("artifact", [
    'password = "hunter2"',
    "api_key = 'sk-live-abc123'",
    'SECRET = "topsecret"',          # CREDS match is case-insensitive
])
def test_hardcoded_credentials_produce_verdict_fail(artifact):
    """W4 acceptance, verbatim: some input produces verdict FAIL."""
    verdict, st = _verdict(artifact)
    assert st["hard_violations"], "H2 did not fire on %r" % artifact
    assert verdict == VERDICT_FAIL, (verdict, st["hard_violations"])


def test_fail_survives_an_above_threshold_composite():
    """The FAIL must come from the violation, not from the score."""
    assert CLEAN_COMPOSITE > SCORE_PASS
    verdict, _ = _verdict('password = "hunter2"')
    assert verdict == VERDICT_FAIL


def test_missing_error_handling_on_a_long_artifact_fails():
    verdict, st = _verdict("x = 1\n" * 60)
    assert [h["code"] for h in st["hard_violations"]] == ["H3"]
    assert verdict == VERDICT_FAIL


def test_clean_artifact_still_passes():
    """Guard the other direction: FAIL must not become universal."""
    verdict, st = _verdict("def f(a: int) -> int:\n    return a\n")
    assert st["hard_violations"] == []
    assert verdict == VERDICT_PASS


# --- the gap D5 actually measured, pinned honestly -------------------------

def test_d5_input_matches_no_rule_and_therefore_passes():
    """D5 verbatim. Documented, not fixed: no rule covers dynamic eval.

    This asserts the CURRENT limitation on purpose. When a rule for unsafe
    dynamic execution is added, this test goes red and must be deleted --
    that redness is the signal, not a regression.
    """
    verdict, st = _verdict("eval(input())")
    assert st["hard_violations"] == []
    assert verdict == VERDICT_PASS


@pytest.mark.xfail(strict=True, reason=(
    "GAP: no structural rule covers dynamic execution. eval/exec of untrusted "
    "input is a blocking defect and produces no violation."))
def test_dynamic_eval_should_be_a_hard_violation():
    _, st = _verdict("eval(input())")
    assert st["hard_violations"]


@pytest.mark.xfail(strict=True, reason=(
    "GAP: H3 is gated on len(artifact) > 200, so a short unsafe artifact "
    "escapes the error-handling rule entirely."))
def test_short_artifact_is_not_exempt_from_error_handling():
    _, st = _verdict("os.remove(sys.argv[1])")
    assert st["hard_violations"]
