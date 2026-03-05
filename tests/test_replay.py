import unittest
from api.receipt_signing import compute_receipt_hash, compute_signature
from api.replay import replay_verify

TEST_KEY = "0" * 64

def make_valid_receipt():
    receipt = {
        "schema_version": "receipt_v1",
        "receipt_id": "test-001",
        "tenant_id": "tenant_test",
        "repo": "test-repo",
        "repo_full_name": "tenant/test-repo",
        "pr_number": 1,
        "pr_title": "Test PR",
        "branch": "feature/test",
        "base_branch": "main",
        "commit_sha": "a" * 40,
        "evaluated_at": "2026-03-04T10:00:00Z",
        "root_date": "2026-03-04",
        "engine_version": "1.0.0",
        "contract_version": "1.0.0",
        "scoring_formula_version": "1.0.0",
        "policy_version": "1.0.0",
        "merkle_algorithm": "merkle_v1",
        "signing_version": "hmac-sha256-v1",
        "structural_score": 0.9,
        "semantic_score": 0.8,
        "composite_score": 0.86,
        "verdict": "PASS",
        "hard_violations": [],
        "process_violations": [],
        "artifact_hash": "b" * 64,
        "scope_hash": "c" * 64,
        "provenance_hash": "d" * 64,
        "prev_receipt_hash": "GENESIS",
        "ai_attributed": False,
    }
    receipt["receipt_hash"] = compute_receipt_hash(receipt)
    receipt["signature"] = compute_signature(receipt, TEST_KEY)
    return receipt


class TestReplayVerifyValid(unittest.TestCase):
    def test_valid_receipt_ok(self):
        r = make_valid_receipt()
        result = replay_verify(r, TEST_KEY)
        self.assertTrue(result["ok"])
        self.assertEqual(result["anomalies"], [])

    def test_returns_dict(self):
        r = make_valid_receipt()
        result = replay_verify(r, TEST_KEY)
        self.assertIn("ok", result)
        self.assertIn("anomalies", result)


class TestReplayVerifyTampered(unittest.TestCase):
    def test_tampered_verdict(self):
        r = make_valid_receipt()
        r["verdict"] = "FAIL"
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])
        types = [a["type"] for a in result["anomalies"]]
        self.assertIn("RECEIPT_HASH_MISMATCH", types)

    def test_tampered_score(self):
        r = make_valid_receipt()
        r["composite_score"] = 0.0
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])

    def test_wrong_key(self):
        r = make_valid_receipt()
        result = replay_verify(r, "f" * 64)
        self.assertFalse(result["ok"])
        types = [a["type"] for a in result["anomalies"]]
        self.assertIn("SIGNATURE_MISMATCH", types)

    def test_tampered_hash(self):
        r = make_valid_receipt()
        r["receipt_hash"] = "0" * 64
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])
        types = [a["type"] for a in result["anomalies"]]
        self.assertIn("RECEIPT_HASH_MISMATCH", types)


class TestReplayAnomalyStructure(unittest.TestCase):
    def test_anomaly_has_type(self):
        r = make_valid_receipt()
        r["verdict"] = "FAIL"
        result = replay_verify(r, TEST_KEY)
        for anomaly in result["anomalies"]:
            self.assertIn("type", anomaly)

    def test_multiple_anomalies(self):
        r = make_valid_receipt()
        r["verdict"] = "FAIL"
        r["receipt_hash"] = "0" * 64
        result = replay_verify(r, TEST_KEY)
        self.assertGreaterEqual(len(result["anomalies"]), 1)


if __name__ == "__main__":
    unittest.main()
