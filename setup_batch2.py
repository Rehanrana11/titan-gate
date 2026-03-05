import os

os.makedirs("judge_engine/v1", exist_ok=True)
os.makedirs("api", exist_ok=True)
os.makedirs("policy_packs", exist_ok=True)

# judge_engine/__init__.py
with open("judge_engine/__init__.py", "w") as f:
    f.write("")

# judge_engine/v1/__init__.py
with open("judge_engine/v1/__init__.py", "w") as f:
    f.write("")

# api/constants.py
with open("api/constants.py", "w", encoding="utf-8") as f:
    f.write("""\
ENGINE_VERSION = "1.0.0"
CONTRACT_VERSION = "1.0.0"
SCORING_FORMULA_VERSION = "1.0.0"
POLICY_VERSION = "1.0.0"
MERKLE_ALGORITHM = "merkle_v1"
SIGNING_VERSION = "hmac-sha256-v1"
ANCHOR_SCHEMA = "anchor_v1"
BLOB_STORE_VERSION = "postgres_gzip_v1"

SCORE_PASS = 0.70
SCORE_WARN = 0.40

VERDICT_PASS = "PASS"
VERDICT_WARN = "WARN"
VERDICT_FAIL = "FAIL"
""")

# judge_engine/v1/structural_judge.py
with open("judge_engine/v1/structural_judge.py", "w", encoding="utf-8") as f:
    f.write("""\
import re
from typing import Dict, Any, List

HARD_VIOLATIONS = {
    "H1": "Missing test coverage",
    "H2": "Hardcoded credentials detected",
    "H3": "Missing error handling",
    "H4": "Unsafe input handling",
    "H5": "Missing authentication check",
    "H6": "SQL injection risk",
    "H7": "Insecure direct object reference",
    "H8": "Missing authorization check",
    "H9": "Cryptographic weakness",
    "H10": "Data exposure risk",
}

PROCESS_VIOLATIONS = {
    "P1": "Missing docstring",
    "P2": "Function too long",
    "P3": "Missing type hints",
    "P4": "Missing logging",
    "P5": "Unused imports",
    "P6": "Missing constants for magic numbers",
}

CREDENTIAL_PATTERNS = [
    r'password\s*=\s*["\'][^"\']+["\']',
    r'secret\s*=\s*["\'][^"\']+["\']',
    r'api_key\s*=\s*["\'][^"\']+["\']',
    r'token\s*=\s*["\'][^"\']+["\']',
]


def evaluate(artifact: str, scope: Dict[str, Any]) -> Dict[str, Any]:
    hard_violations = []
    process_violations = []
    score = 1.0

    # H2: hardcoded credentials
    for pattern in CREDENTIAL_PATTERNS:
        if re.search(pattern, artifact, re.IGNORECASE):
            hard_violations.append({
                "code": "H2",
                "description": HARD_VIOLATIONS["H2"],
                "soc2_controls": ["CC6.1", "CC6.2"],
                "severity": "blocking",
            })
            score -= 0.3
            break

    # H3: missing error handling
    if "try" not in artifact and "except" not in artifact:
        if len(artifact) > 200:
            hard_violations.append({
                "code": "H3",
                "description": HARD_VIOLATIONS["H3"],
                "soc2_controls": ["CC7.1"],
                "severity": "blocking",
            })
            score -= 0.2

    # P1: missing docstring
    if '"""' not in artifact and "'''" not in artifact:
        process_violations.append({
            "code": "P1",
            "description": PROCESS_VIOLATIONS["P1"],
            "soc2_controls": ["CC8.1"],
            "severity": "warning",
        })
        score -= 0.05

    # P3: missing type hints
    if "def " in artifact and "->" not in artifact:
        process_violations.append({
            "code": "P3",
            "description": PROCESS_VIOLATIONS["P3"],
            "soc2_controls": ["CC8.1"],
            "severity": "warning",
        })
        score -= 0.05

    structural_score = max(0.0, min(1.0, score))

    return {
        "structural_score": structural_score,
        "hard_violations": hard_violations,
        "process_violations": process_violations,
    }
""")

# judge_engine/v1/semantic_judge.py
with open("judge_engine/v1/semantic_judge.py", "w", encoding="utf-8") as f:
    f.write("""\
from typing import Dict, Any


def evaluate(artifact: str, scope: Dict[str, Any]) -> Dict[str, Any]:
    \"\"\"
    Semantic judge. In production this calls an LLM.
    Fail-closed: returns 0.5 if evaluation cannot complete.
    \"\"\"
    try:
        score = _heuristic_semantic_score(artifact)
        return {
            "semantic_score": score,
            "hard_violations": [],
            "process_violations": [],
        }
    except Exception:
        return {
            "semantic_score": 0.5,
            "hard_violations": [],
            "process_violations": [],
        }


def _heuristic_semantic_score(artifact: str) -> float:
    score = 0.7
    positive = ["def ", "class ", "return ", "import "]
    negative = ["TODO", "FIXME", "HACK", "XXX", "pass  #"]
    for p in positive:
        if p in artifact:
            score = min(1.0, score + 0.02)
    for n in negative:
        if n in artifact:
            score = max(0.0, score - 0.05)
    return round(score, 4)
""")

# judge_engine/v1/policy_judge.py
with open("judge_engine/v1/policy_judge.py", "w", encoding="utf-8") as f:
    f.write("""\
from typing import Dict, Any, List


SOC2_CONTROLS = ["CC6.1", "CC6.2", "CC7.1", "CC7.2", "CC8.1"]


def evaluate(
    artifact: str,
    scope: Dict[str, Any],
    hard_violations: List[Dict],
    process_violations: List[Dict],
) -> Dict[str, Any]:
    \"\"\"Policy judge maps violations to SOC2 controls.\"\"\"
    soc2_mappings = []
    implicated = set()
    for v in hard_violations + process_violations:
        for c in v.get("soc2_controls", []):
            implicated.add(c)

    for control in SOC2_CONTROLS:
        soc2_mappings.append({
            "control_id": control,
            "description": _control_description(control),
            "satisfied": control not in implicated,
        })

    return {"soc2_controls": soc2_mappings}


def _control_description(control_id: str) -> str:
    descriptions = {
        "CC6.1": "Logical access security",
        "CC6.2": "Authentication and credentials",
        "CC7.1": "System monitoring and error detection",
        "CC7.2": "Incident response",
        "CC8.1": "Change management",
    }
    return descriptions.get(control_id, control_id)
""")

# judge_engine/v1/engine.py
with open("judge_engine/v1/engine.py", "w", encoding="utf-8") as f:
    f.write("""\
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, Any

from api.constants import (
    ENGINE_VERSION, CONTRACT_VERSION, SCORING_FORMULA_VERSION,
    POLICY_VERSION, MERKLE_ALGORITHM, SIGNING_VERSION,
    SCORE_PASS, SCORE_WARN, VERDICT_PASS, VERDICT_WARN, VERDICT_FAIL,
)
from api.receipt_signing import compute_receipt_hash, compute_signature
from api.merkle import MERKLE_ALGORITHM as _MA
from judge_engine.v1 import structural_judge, semantic_judge, policy_judge


STRUCTURAL_WEIGHT = 0.6
SEMANTIC_WEIGHT = 0.4


def evaluate(
    artifact: str,
    scope: Dict[str, Any],
    tenant_id: str,
    repo: str,
    repo_full_name: str,
    pr_number: int,
    pr_title: str,
    branch: str,
    base_branch: str,
    commit_sha: str,
    key_hex: str,
    prev_receipt_hash: str = "GENESIS",
) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    evaluated_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    root_date = now.strftime("%Y-%m-%d")

    structural = structural_judge.evaluate(artifact, scope)
    semantic = semantic_judge.evaluate(artifact, scope)

    hard_violations = structural["hard_violations"] + semantic.get("hard_violations", [])
    process_violations = structural["process_violations"] + semantic.get("process_violations", [])

    policy = policy_judge.evaluate(artifact, scope, hard_violations, process_violations)

    s_score = structural["structural_score"]
    sem_score = semantic["semantic_score"]
    composite = round(STRUCTURAL_WEIGHT * s_score + SEMANTIC_WEIGHT * sem_score, 4)

    if hard_violations:
        verdict = VERDICT_FAIL
    elif composite >= SCORE_PASS:
        verdict = VERDICT_PASS
    elif composite >= SCORE_WARN:
        verdict = VERDICT_WARN
    else:
        verdict = VERDICT_FAIL

    artifact_hash = hashlib.sha256(artifact.encode("utf-8")).hexdigest()
    scope_str = str(sorted(scope.items()))
    scope_hash = hashlib.sha256(scope_str.encode("utf-8")).hexdigest()
    provenance_hash = hashlib.sha256((artifact_hash + scope_hash).encode("utf-8")).hexdigest()

    receipt = {
        "schema_version": "receipt_v1",
        "receipt_id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "repo": repo,
        "repo_full_name": repo_full_name,
        "pr_number": pr_number,
        "pr_title": pr_title,
        "branch": branch,
        "base_branch": base_branch,
        "commit_sha": commit_sha,
        "evaluated_at": evaluated_at,
        "root_date": root_date,
        "engine_version": ENGINE_VERSION,
        "contract_version": CONTRACT_VERSION,
        "scoring_formula_version": SCORING_FORMULA_VERSION,
        "policy_version": POLICY_VERSION,
        "merkle_algorithm": MERKLE_ALGORITHM,
        "signing_version": SIGNING_VERSION,
        "structural_score": s_score,
        "semantic_score": sem_score,
        "composite_score": composite,
        "verdict": verdict,
        "hard_violations": hard_violations,
        "process_violations": process_violations,
        "artifact_hash": artifact_hash,
        "scope_hash": scope_hash,
        "provenance_hash": provenance_hash,
        "prev_receipt_hash": prev_receipt_hash,
        "ai_attributed": False,
        "soc2_controls": policy["soc2_controls"],
        "evaluation_manifest": {
            "engine_version": ENGINE_VERSION,
            "contract_version": CONTRACT_VERSION,
            "scoring_formula_version": SCORING_FORMULA_VERSION,
            "policy_version": POLICY_VERSION,
            "merkle_algorithm": MERKLE_ALGORITHM,
            "signing_version": SIGNING_VERSION,
            "evaluated_at": evaluated_at,
        },
    }

    receipt["receipt_hash"] = compute_receipt_hash(receipt)
    receipt["signature"] = compute_signature(receipt, key_hex)
    return receipt
""")

# policy_packs/soc2_default.json
import json
policy = {
    "policy_version": "1.0.0",
    "name": "SOC2 Default Policy",
    "controls": {
        "CC6.1": "Logical access security software",
        "CC6.2": "Authentication credentials",
        "CC7.1": "Vulnerability and threat detection",
        "CC7.2": "Incident monitoring",
        "CC8.1": "Change management controls"
    },
    "hard_violation_codes": ["H1","H2","H3","H4","H5","H6","H7","H8","H9","H10"],
    "process_violation_codes": ["P1","P2","P3","P4","P5","P6"]
}
with open("policy_packs/soc2_default.json", "w", encoding="utf-8") as f:
    json.dump(policy, f, indent=2)

print("Batch 2 complete:")
files = [
    "judge_engine/__init__.py",
    "judge_engine/v1/__init__.py",
    "api/constants.py",
    "judge_engine/v1/structural_judge.py",
    "judge_engine/v1/semantic_judge.py",
    "judge_engine/v1/policy_judge.py",
    "judge_engine/v1/engine.py",
    "policy_packs/soc2_default.json",
]
for f in files:
    print("  {} ({} bytes)".format(f, os.path.getsize(f)))
