import unittest
from judge_engine.v1.engine import evaluate

TEST_KEY = "0" * 64

GOOD_ARTIFACT = """
import hashlib
from typing import Dict, Any

def compute_hash(data: str) -> str:
    try:
        return hashlib.sha256(data.encode()).hexdigest()
    except Exception as e:
        raise ValueError("Hash failed") from e
"""

SIMPLE_SCOPE = {
    "files": ["main.py"],
    "language": "python",
}


def make_receipt(artifact=GOOD_ARTIFACT, scope=SIMPLE_SCOPE,
                 prev="GENESIS", pr_number=1):
    return evaluate(
        artifact=artifact,
        scope=scope,
        tenant_id="tenant_test",
        repo="test-repo",
        repo_full_name="tenant/test-repo",
        pr_number=pr_number,
        pr_title="Test PR",
        branch="feature/test",
        base_branch="main",
        commit_sha="a" * 40,
        key_hex=TEST_KEY,
        prev_receipt_hash=prev,
    )


class TestEngineOutputStructure(unittest.TestCase):
    def test_returns_dict(self):
        r = make_receipt()
        self.assertIsInstance(r, dict)

    def test_schema_version(self):
        r = make_receipt()
        self.assertEqual(r["schema_version"], "receipt_v1")

    def test_required_fields_present(self):
        r = make_receipt()
        required = [
            "schema_version", "receipt_id", "tenant_id", "repo",
            "repo_full_name", "pr_number", "pr_title", "branch",
            "base_branch", "commit_sha", "evaluated_at", "root_date",
            "engine_version", "contract_version", "scoring_formula_version",
            "policy_version", "merkle_algorithm", "signing_version",
            "structural_score", "semantic_score", "composite_score",
            "verdict", "hard_violations", "process_violations",
            "artifact_hash", "scope_hash", "provenance_hash",
            "prev_receipt_hash", "receipt_hash", "signature", "ai_attributed",
        ]
        for field in required:
            self.assertIn(field, r, "Missing field: {}".format(field))

    def test_verdict_valid_values(self):
        r = make_receipt()
        self.assertIn(r["verdict"], ["PASS", "WARN", "FAIL"])

    def test_scores_in_range(self):
        r = make_receipt()
        self.assertGreaterEqual(r["structural_score"], 0.0)
        self.assertLessEqual(r["structural_score"], 1.0)
        self.assertGreaterEqual(r["semantic_score"], 0.0)
        self.assertLessEqual(r["semantic_score"], 1.0)
        self.assertGreaterEqual(r["composite_score"], 0.0)
        self.assertLessEqual(r["composite_score"], 1.0)

    def test_receipt_id_is_string(self):
        r = make_receipt()
        self.assertIsInstance(r["receipt_id"], str)
        self.assertGreater(len(r["receipt_id"]), 0)

    def test_evaluated_at_format(self):
        r = make_receipt()
        self.assertRegex(r["evaluated_at"], r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

    def test_signing_version(self):
        r = make_receipt()
        self.assertEqual(r["signing_version"], "hmac-sha256-v1")

    def test_merkle_algorithm(self):
        r = make_receipt()
        self.assertEqual(r["merkle_algorithm"], "merkle_v1")


class TestEngineChaining(unittest.TestCase):
    def test_genesis_receipt(self):
        r = make_receipt()
        self.assertEqual(r["prev_receipt_hash"], "GENESIS")

    def test_chained_receipt(self):
        r1 = make_receipt()
        r2 = make_receipt(prev=r1["receipt_hash"], pr_number=2)
        self.assertEqual(r2["prev_receipt_hash"], r1["receipt_hash"])

    def test_receipt_hash_length(self):
        r = make_receipt()
        self.assertEqual(len(r["receipt_hash"]), 64)

    def test_signature_length(self):
        r = make_receipt()
        self.assertEqual(len(r["signature"]), 64)

    def test_receipt_hash_lowercase(self):
        r = make_receipt()
        self.assertEqual(r["receipt_hash"], r["receipt_hash"].lower())

    def test_signature_lowercase(self):
        r = make_receipt()
        self.assertEqual(r["signature"], r["signature"].lower())


class TestEngineScoring(unittest.TestCase):
    def test_good_code_passes(self):
        r = make_receipt(artifact=GOOD_ARTIFACT)
        self.assertIn(r["verdict"], ["PASS", "WARN"])

    def test_composite_score_formula(self):
        r = make_receipt()
        expected = round(0.6 * r["structural_score"] + 0.4 * r["semantic_score"], 4)
        self.assertAlmostEqual(r["composite_score"], expected, places=4)

    def test_hard_violation_forces_fail(self):
        bad_artifact = "x" * 300
        r = make_receipt(artifact=bad_artifact)
        if r["hard_violations"]:
            self.assertEqual(r["verdict"], "FAIL")


class TestEngineManifest(unittest.TestCase):
    def test_manifest_present(self):
        r = make_receipt()
        self.assertIn("evaluation_manifest", r)

    def test_manifest_fields(self):
        r = make_receipt()
        m = r["evaluation_manifest"]
        for field in ["engine_version", "contract_version",
                      "scoring_formula_version", "policy_version",
                      "merkle_algorithm", "signing_version", "evaluated_at"]:
            self.assertIn(field, m)

    def test_manifest_versions_match(self):
        r = make_receipt()
        m = r["evaluation_manifest"]
        self.assertEqual(m["engine_version"], r["engine_version"])
        self.assertEqual(m["merkle_algorithm"], r["merkle_algorithm"])


if __name__ == "__main__":
    unittest.main()
