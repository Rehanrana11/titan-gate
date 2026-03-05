SOC2 = ["CC6.1", "CC6.2", "CC7.1", "CC7.2", "CC8.1"]
DESCRIPTIONS = {
    "CC6.1": "Logical access security",
    "CC6.2": "Authentication and credentials",
    "CC7.1": "System monitoring and error detection",
    "CC7.2": "Incident response",
    "CC8.1": "Change management",
}


def evaluate(artifact, scope, hard_v, proc_v):
    imp = set(c for v in hard_v + proc_v for c in v.get("soc2_controls", []))
    return {"soc2_controls": [
        {"control_id": c, "description": DESCRIPTIONS.get(c, c), "satisfied": c not in imp}
        for c in SOC2
    ]}
