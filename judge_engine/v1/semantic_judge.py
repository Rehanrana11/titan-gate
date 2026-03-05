from typing import Dict, Any


def evaluate(artifact: str, scope: Dict[str, Any]) -> Dict[str, Any]:
    try:
        return {"semantic_score": _score(artifact), "hard_violations": [], "process_violations": []}
    except Exception:
        return {"semantic_score": 0.5, "hard_violations": [], "process_violations": []}


def _score(a: str) -> float:
    s = 0.7
    for p in ["def ", "class ", "return ", "import "]:
        if p in a:
            s = min(1.0, s + 0.02)
    for n in ["TODO", "FIXME", "HACK", "XXX"]:
        if n in a:
            s = max(0.0, s - 0.05)
    return round(s, 4)
