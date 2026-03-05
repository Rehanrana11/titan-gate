import re

CREDS = ["password", "secret", "api_key"]
HV = {"H2": "Hardcoded credentials detected", "H3": "Missing error handling"}
PV = {"P1": "Missing docstring", "P3": "Missing type hints"}


def evaluate(artifact, scope):
    hv, pv, score = [], [], 1.0
    for c in CREDS:
        if re.search(c + r"\s*=\s*[\x27\x22][^\x27\x22]+[\x27\x22]", artifact, re.I):
            hv.append({"code": "H2", "description": HV["H2"],
                       "soc2_controls": ["CC6.1", "CC6.2"], "severity": "blocking"})
            score -= 0.3
            break
    if "try" not in artifact and "except" not in artifact and len(artifact) > 200:
        hv.append({"code": "H3", "description": HV["H3"],
                   "soc2_controls": ["CC7.1"], "severity": "blocking"})
        score -= 0.2
    if "def " in artifact and "->" not in artifact:
        pv.append({"code": "P3", "description": PV["P3"],
                   "soc2_controls": ["CC8.1"], "severity": "warning"})
        score -= 0.05
    return {"structural_score": max(0.0, min(1.0, score)),
            "hard_violations": hv, "process_violations": pv}
