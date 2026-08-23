#!/usr/bin/env python3
"""W1 — the tri-state contract, as plain assertions against policy_judge_v2.

These are the four strict xfails of tests/test_policy_judge_soc2_claims.py
re-stated as assertions that must pass, plus the two properties that file says
must survive the migration unchanged, plus a differential test that shows the
exact v1 -> v2 behaviour change, plus the one hole v2 does NOT close (pinned as
a strict xfail, the same way v1's defects were pinned).

Nothing in this file imports or mutates policy_judge (v1). It is additive:
v1 and its existing tests keep passing untouched while this file proves the
replacement green.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from judge_engine.v1 import policy_judge as V1  # noqa: E402
from judge_engine.v1 import policy_judge_v2 as V2  # noqa: E402

# Controls some rule in structural_judge.py actually maps to.
RULE_MAPPED = {"CC6.1", "CC6.2", "CC7.1", "CC8.1"}

REAL_LOCATOR = "judge_engine/v1/structural_judge.py::rule_tenant_scope"


def _by_id(result):
    return {c["control_id"]: c for c in result["soc2_controls"]}


def _claims_satisfied(control):
    """Identical to the helper in test_policy_judge_soc2_claims.py, so the two
    files agree on what 'claims satisfied' means on the wire."""
    return control.get("status") == "satisfied" or control.get("satisfied") is True


# --- the four pinned defects, now required to be fixed ---------------------

def test_empty_artifact_satisfies_nothing():
    """D3, the headline defect: an empty artifact must attest zero controls."""
    result = V2.evaluate("", {}, [], [])
    claimed = [c["control_id"] for c in result["soc2_controls"] if _claims_satisfied(c)]
    assert claimed == [], "empty artifact claims %d/%d controls satisfied: %s" % (
        len(claimed), len(result["soc2_controls"]), claimed)


@pytest.mark.parametrize("artifact", ["", "def add(a, b): return a + b", "eval(input())"])
def test_no_control_claims_satisfied_without_evidence(artifact):
    """H2: satisfied without an evidence_source is absence-of-evidence sold as
    compliance. Runs across three artifacts so the property is not an accident
    of the empty string."""
    for c in V2.evaluate(artifact, {}, [], [])["soc2_controls"]:
        if _claims_satisfied(c):
            assert c.get("evidence_source"), (
                "%r claims %s satisfied with no evidence source"
                % (artifact[:24], c["control_id"]))


def test_status_is_tri_state_for_every_control():
    """'not violated' and 'not checked' must be distinguishable on the wire."""
    for c in V2.evaluate("", {}, [], [])["soc2_controls"]:
        assert c.get("status") in V2.STATUSES, c
    assert set(V2.STATUSES) == {"satisfied", "violated", "unevaluated"}


def test_a_check_can_establish_satisfaction():
    """Satisfaction must be earnable, not only defaultable -- otherwise the
    tri-state collapses to 'violated or unknown' and the judge can never say
    anything positive that is true."""
    coverage = {"CC6.1": REAL_LOCATOR}
    controls = _by_id(V2.evaluate("ok", {}, [], [], coverage=coverage))
    assert controls["CC6.1"]["status"] == "satisfied"
    assert controls["CC6.1"]["evidence_source"] == REAL_LOCATOR
    assert controls["CC6.1"]["satisfied"] is True
    # and nothing else was dragged along
    assert controls["CC6.2"]["status"] == "unevaluated"


# --- properties test_policy_judge_soc2_claims.py says must survive ---------

def test_violations_still_mark_their_controls():
    hard = [{"rule": "H1", "soc2_controls": ["CC6.1"], "severity": "blocking"}]
    control = _by_id(V2.evaluate("", {}, hard, []))["CC6.1"]
    assert not _claims_satisfied(control)
    assert control["status"] == "violated"
    assert control["evidence_source"] == "H1"


def test_cc7_2_is_reachable_by_no_rule():
    """No rule maps to CC7.2. Under v1 that made it permanently 'satisfied'.
    Under v2 it is permanently 'unevaluated', which is the true statement."""
    assert "CC7.2" in V2.SOC2 and "CC7.2" not in RULE_MAPPED
    assert _by_id(V2.evaluate("", {}, [], []))["CC7.2"]["status"] == "unevaluated"


@pytest.mark.parametrize("control_id", sorted(RULE_MAPPED))
def test_every_rule_mapped_control_is_declared(control_id):
    assert control_id in V2.SOC2


def test_control_set_and_descriptions_are_unchanged_from_v1():
    """v2 changes what is claimed, not which controls exist. A silently
    shrunken control table would make the empty-artifact test pass for the
    wrong reason."""
    assert V2.SOC2 == V1.SOC2
    assert V2.DESCRIPTIONS == V1.DESCRIPTIONS


# --- contrastive pair: the exact v1 -> v2 delta ----------------------------

@pytest.mark.skipif(
    "status" in V1.evaluate("", {}, [], [])["soc2_controls"][0],
    reason=("W1 has landed -- policy_judge is itself tri-state now, so there is no "
            "v1/v2 delta left to measure. This test is only meaningful while the "
            "pre-W1 boolean judge is still in place."))
def test_differential_v1_claims_five_v2_claims_none():
    """One delta, stated as a number: same inputs, same control table, and the
    count of controls attested satisfied goes 5 -> 0."""
    args = ("", {}, [], [])
    v1_claimed = [c for c in V1.evaluate(*args)["soc2_controls"] if _claims_satisfied(c)]
    v2_claimed = [c for c in V2.evaluate(*args)["soc2_controls"] if _claims_satisfied(c)]
    assert len(v1_claimed) == 5, "v1 baseline moved; re-derive this test"
    assert len(v2_claimed) == 0


def test_v2_still_ignores_the_artifact_and_that_is_now_honest():
    """v1's test_policy_judge_ignores_the_artifact_entirely stays true of v2.
    That was never the defect on its own -- the defect was claiming compliance
    while ignoring it. v2 ignores it and claims nothing."""
    assert V2.evaluate("anything at all", {}, [], []) == V2.evaluate("", {}, [], [])
    assert all(c["status"] == "unevaluated"
               for c in V2.evaluate("anything at all", {}, [], [])["soc2_controls"])


# --- hostile input: coverage must not become a second defaulting path ------

@pytest.mark.parametrize("bad", [None, "", "   ", 0, 1, True, [], {}, ["x"]])
def test_falsy_or_non_string_coverage_does_not_mint_satisfaction(bad):
    controls = _by_id(V2.evaluate("", {}, [], [], coverage={"CC6.1": bad}))
    assert controls["CC6.1"]["status"] == "unevaluated", bad
    assert controls["CC6.1"]["evidence_source"] is None


def test_coverage_cannot_invent_controls():
    result = V2.evaluate("", {}, [], [], coverage={"CC9.9": REAL_LOCATOR})
    assert [c["control_id"] for c in result["soc2_controls"]] == V2.SOC2


def test_violation_outranks_coverage():
    """If a check says violated and coverage says satisfied, violated wins.
    The opposite ordering would let a coverage entry paper over a real finding."""
    hard = [{"rule": "H1", "soc2_controls": ["CC6.1"]}]
    controls = _by_id(V2.evaluate("", {}, hard, [], coverage={"CC6.1": REAL_LOCATOR}))
    assert controls["CC6.1"]["status"] == "violated"


@pytest.mark.parametrize("violations", [
    [None],
    ["not-a-dict"],
    [{"rule": "H1"}],
    [{"rule": "H1", "soc2_controls": None}],
    [{"soc2_controls": ["CC6.1"]}],
])
def test_malformed_violations_do_not_raise(violations):
    result = V2.evaluate("", {}, violations, [])
    assert len(result["soc2_controls"]) == len(V2.SOC2)


def test_unnamed_rule_still_records_the_violation():
    controls = _by_id(V2.evaluate("", {}, [{"soc2_controls": ["CC6.1"]}], []))
    assert controls["CC6.1"]["status"] == "violated"
    assert controls["CC6.1"]["evidence_source"] == "unnamed_rule"


def test_unevaluated_carries_a_reason():
    """T5: an abstention with no reason is a hedge. Every unevaluated control
    must say why it is unevaluated."""
    for c in V2.evaluate("", {}, [], [])["soc2_controls"]:
        assert c["status"] == "unevaluated" and c["reason"] == V2.NO_CHECK_RAN


# --- the hole v2 does NOT close, pinned as a defect ------------------------

@pytest.mark.xfail(strict=True, reason=(
    "OPEN (W1 follow-on): `coverage` is caller-asserted, not proven. A caller "
    "that passes a syntactically valid locator for a check that never ran mints "
    "a satisfied control. Closing this requires coverage to be EMITTED by the "
    "judges that ran, not accepted as an argument. Unreachable today -- no "
    "caller in this repo passes coverage -- which is a fact about the callers, "
    "not a property of the module. Convert to a plain assert when coverage "
    "becomes judge-emitted."))
def test_coverage_cannot_be_forged_by_a_caller():
    forged = {"CC6.1": "judge_engine/v1/structural_judge.py::rule_that_does_not_exist"}
    controls = _by_id(V2.evaluate("", {}, [], [], coverage=forged))
    assert controls["CC6.1"]["status"] == "unevaluated", (
        "a locator naming a non-existent check was accepted as evidence")
