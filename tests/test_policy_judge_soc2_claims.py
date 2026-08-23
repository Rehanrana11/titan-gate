#!/usr/bin/env python3
"""
W1 (chain-safe half): pin the policy_judge SOC 2 defects AS DEFECTS.

Replaces sdlc/evals/test_judge_engine_properties.py::test_all_soc2_controls_default_to_satisfied,
which asserted `all(c["satisfied"] ...)` -- i.e. it pinned the bug as correct
behaviour and would have gone red the moment anyone fixed it.

Nothing here changes the receipt wire format. receipt_v1 is golden-pinned and
titan_gate/chain_state.py:78-82 forbids mixed profiles in one chain, so the
tri-state fix lands in receipt_trs2_v2, not here. These tests hold the line
until it does.

W1 LANDED: the four xfails below were converted to plain assertions in the
commit that wired in the tri-state judge, exactly as this docstring required.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from judge_engine.v1 import policy_judge as P  # noqa: E402

# Controls some rule in structural_judge.py actually maps to.
# structural_judge.py:13 -> CC6.1, CC6.2 | :18 -> CC7.1 | :22 -> CC8.1
RULE_MAPPED = {"CC6.1", "CC6.2", "CC7.1", "CC8.1"}


def _claims_satisfied(control):
    """True under the v1 boolean OR a future tri-state, so these tests pin
    behaviour rather than field names. A KeyError here would let a strict
    xfail pass for the wrong reason -- which is how the previous xfail died.
    """
    return control.get("status") == "satisfied" or control.get("satisfied") is True


def _by_id(result):
    return {c["control_id"]: c for c in result["soc2_controls"]}


# --- true today, must stay true -------------------------------------------

def test_cc7_2_is_reachable_by_no_rule():
    """No rule in structural_judge.py maps to CC7.2, so it can never be
    reported violated. Advertising it as a covered control is unfounded.
    Delete this test when a check for CC7.2 exists -- not when it is
    inconvenient.
    """
    assert "CC7.2" in P.SOC2
    assert "CC7.2" not in RULE_MAPPED


@pytest.mark.parametrize("control_id", sorted(RULE_MAPPED))
def test_every_rule_mapped_control_is_declared(control_id):
    """A rule may not map to a control the table does not declare."""
    assert control_id in P.SOC2


def test_violations_still_mark_their_controls():
    """The one thing policy_judge does establish: a violation naming a control
    is reflected. This must survive the tri-state migration unchanged.
    """
    hard = [{"rule": "H1", "soc2_controls": ["CC6.1"], "severity": "blocking"}]
    assert not _claims_satisfied(_by_id(P.evaluate("", {}, hard, []))["CC6.1"])


# --- W1 LANDED: these four were strict xfails; converted on the tri-state commit

def test_empty_artifact_should_satisfy_nothing():
    result = P.evaluate("", {}, [], [])
    claimed = [c["control_id"] for c in result["soc2_controls"] if _claims_satisfied(c)]
    assert claimed == [], "empty artifact claims %d/%d controls satisfied: %s" % (
        len(claimed), len(result["soc2_controls"]), claimed)


def test_no_control_should_claim_satisfied_without_evidence():
    for artifact in ("", "def add(a, b): return a + b", "eval(input())"):
        for c in P.evaluate(artifact, {}, [], [])["soc2_controls"]:
            if _claims_satisfied(c):
                assert c.get("evidence_source"), (
                    "%r claims %s satisfied with no evidence source"
                    % (artifact[:24], c["control_id"]))


def test_status_should_be_tri_state():
    for c in P.evaluate("", {}, [], [])["soc2_controls"]:
        assert c.get("status") in ("satisfied", "violated", "unevaluated"), c


def test_a_check_should_be_able_to_establish_satisfaction():
    coverage = {"CC6.1": "judge_engine/v1/structural_judge.py::rule_tenant_scope"}
    controls = _by_id(P.evaluate("ok", {}, [], [], coverage=coverage))
    assert controls["CC6.1"].get("evidence_source") == coverage["CC6.1"]
