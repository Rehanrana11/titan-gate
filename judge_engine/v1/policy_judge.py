"""Tri-state SOC 2 policy judge (W1, landed).

Supersedes the 16-line boolean judge that defaulted every control to satisfied.

THE DEFECT IT REMOVES
    v1 `evaluate()` accepts `artifact` and never reads it, and reports
    `satisfied: True` for every control that no violation happened to name.
    An empty artifact therefore attests 5 of 5 SOC 2 controls satisfied,
    signed and hashed. Absence of evidence is serialized as compliance.

THE RULE THIS MODULE ENFORCES
    A control may be reported `satisfied` ONLY when a named check established
    it. Nothing defaults into satisfaction. The three legal states are:

      violated     a check ran and failed        -> evidence_source = rule id
      satisfied    a check ran and passed        -> evidence_source = check locator
      unevaluated  no check ran (the default)    -> reason = why, evidence None

    `satisfied` (bool) is retained so any v1 consumer keeps working; it is now
    computed from `status` rather than defaulted, so the same field that used
    to read True on an empty artifact now reads False.

KNOWN RESIDUAL HOLE — pinned as a defect in the accompanying tests, not fixed
    `coverage` is supplied by the caller and is not proof that a check ran.
    A caller that passes {"CC6.1": "anything"} mints a satisfied control.
    This module validates only that the locator is a non-empty string.
    Closing it requires coverage to be *emitted by the judges that ran*, which
    is a separate work order. Today no caller in this repo passes `coverage`
    at all, so the hole is unreachable in shipped paths -- that is a fact about
    the callers, not a property of this module.

SCOPE
    Wire format only. This module does NOT touch verdict/score. An empty
    artifact still classifies PASS via composite >= SCORE_PASS; that is the
    score path (D4/D6), a different defect with a different work order.
"""

SOC2 = ["CC6.1", "CC6.2", "CC7.1", "CC7.2", "CC8.1"]

DESCRIPTIONS = {
    "CC6.1": "Logical access security",
    "CC6.2": "Authentication and credentials",
    "CC7.1": "System monitoring and error detection",
    "CC7.2": "Incident response",
    "CC8.1": "Change management",
}

STATUS_SATISFIED = "satisfied"
STATUS_VIOLATED = "violated"
STATUS_UNEVALUATED = "unevaluated"
STATUSES = (STATUS_SATISFIED, STATUS_VIOLATED, STATUS_UNEVALUATED)

NO_CHECK_RAN = "no check mapped to this control ran on this artifact"


def _is_locator(value):
    """A usable evidence locator: a non-empty, non-blank string.

    Deliberately weak. It rejects None/""/0/[] -- the shapes that would let a
    falsy value be serialized as evidence -- and nothing else. A stronger
    check would have to resolve the locator, which this module cannot do.
    """
    return isinstance(value, str) and value.strip() != ""


def _violated_controls(violations):
    """Map control_id -> the rule id that impacted it.

    First rule to name a control wins, so the mapping is deterministic under a
    stable violation order. Entries missing `soc2_controls`, or carrying None,
    contribute nothing rather than raising -- violation producers are several
    modules and none of them are in this work order's scope.
    """
    impacted = {}
    for violation in violations:
        if not isinstance(violation, dict):
            continue
        controls = violation.get("soc2_controls") or []
        rule = violation.get("rule") or violation.get("rule_id") or "unnamed_rule"
        for control_id in controls:
            impacted.setdefault(control_id, rule)
    return impacted


def evaluate(artifact, scope, hard_v, proc_v, coverage=None):
    """Return {"soc2_controls": [...]} with one tri-state entry per control.

    `coverage` maps control_id -> a locator for the check that established it,
    e.g. {"CC6.1": "judge_engine/v1/structural_judge.py::rule_tenant_scope"}.
    Omitted or falsy locators leave the control unevaluated. Keys that are not
    declared in SOC2 are ignored: coverage may not invent controls.

    `artifact` and `scope` remain unread here by design. Reading the artifact
    is the job of the judges that produce violations and coverage; this module
    reports what they established. The v1 defect was not that it ignored the
    artifact -- it is that it claimed compliance while ignoring it.
    """
    coverage = coverage if isinstance(coverage, dict) else {}
    impacted = _violated_controls(list(hard_v or []) + list(proc_v or []))

    controls = []
    for control_id in SOC2:
        if control_id in impacted:
            status = STATUS_VIOLATED
            evidence = impacted[control_id]
            reason = None
        elif _is_locator(coverage.get(control_id)):
            status = STATUS_SATISFIED
            evidence = coverage[control_id]
            reason = None
        else:
            status = STATUS_UNEVALUATED
            evidence = None
            reason = NO_CHECK_RAN

        controls.append({
            "control_id": control_id,
            "description": DESCRIPTIONS.get(control_id, control_id),
            "status": status,
            "satisfied": status == STATUS_SATISFIED,
            "evidence_source": evidence,
            "reason": reason,
        })

    return {"soc2_controls": controls}
