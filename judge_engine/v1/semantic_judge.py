from typing import Dict, Any

ABSTENTION = "INSUFFICIENT_CONTEXT"


def evaluate(artifact: str, scope: Dict[str, Any]) -> Dict[str, Any]:
    try:
        return {"semantic_score": _score(artifact), "hard_violations": [], "process_violations": []}
    except Exception as exc:
        # WO-S1: abstain loudly instead of defaulting silently. A judge that
        # cannot read its input has no opinion; the old 0.5 was a silent
        # default inside a scoring instrument -- the defect class W1
        # diagnosed in policy_judge.
        return {
            "semantic_score": None,
            "abstention": ABSTENTION,
            "abstention_reason": "%s: %s" % (type(exc).__name__, exc),
            "hard_violations": [],
            "process_violations": [],
        }


def _score(a: str) -> float:
    s = 0.7
    for p in ["def ", "class ", "return ", "import "]:
        if p in a:
            s = min(1.0, s + 0.02)
    for n in ["TODO", "FIXME", "HACK", "XXX"]:
        if n in a:
            s = max(0.0, s - 0.05)
    return round(s, 4)
