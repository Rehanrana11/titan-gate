import unittest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["TITAN_SIGNING_KEY"] = "0" * 64

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

GOOD_ARTIFACT = "import hashlib\n\ndef compute_hash(data: str) -> str:\n    try:\n        return hashlib.sha256(data.encode()).hexdigest()\n    except Exception as e:\n        raise ValueError(str(e))\n"

BASE_REQUEST = {
    "artifact": GOOD_ARTIFACT,
    "tenant_id": "tenant_test",
    "repo": "test-repo",
    "repo_full_name": "tenant/test-repo",
    "pr_number": 1,
    "pr_title": "Test PR",
    "branch": "feature/test",
    "base_branch": "main",
    "commit_sha": "a" * 40,
    "scope": {"language": "python"},
    "prev_receipt_hash": "GENESIS",
}


class TestHealthEndpoint(unittest.TestCase):
    def test_health_returns_200(self):
        r = client.get("/health")
        self.assertEqual(r.status_code, 200)

    def test_health_status_ok(self):
        r = client.get("/health")
        self.assertEqual(r.json()["status"], "ok")

    def test_health_engine_version(self):
        r = client.get("/health")
        self.assertEqual(r.json()["engine_version"], "1.0.0")

    def test_health_contract_version(self):
        r = client.get("/health")
        self.assertEqual(r.json()["contract_version"], "1.0.0")


class TestRootEndpoint(unittest.TestCase):
    def test_root_returns_200(self):
        r = client.get("/")
        self.assertEqual(r.status_code, 200)

    def test_root_has_service(self):
        r = client.get("/")
        self.assertIn("service", r.json())


class TestEvaluateEndpoint(unittest.TestCase):
    def test_evaluate_returns_200(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(r.status_code, 200)

    def test_evaluate_returns_receipt(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        data = r.json()
        self.assertIn("receipt_id", data)
        self.assertIn("receipt_hash", data)
        self.assertIn("signature", data)

    def test_evaluate_verdict_valid(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertIn(r.json()["verdict"], ["PASS", "WARN", "FAIL"])

    def test_evaluate_scores_in_range(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        data = r.json()
        self.assertGreaterEqual(data["composite_score"], 0.0)
        self.assertLessEqual(data["composite_score"], 1.0)

    def test_evaluate_tenant_id_correct(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(r.json()["tenant_id"], "tenant_test")

    def test_evaluate_schema_version(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(r.json()["schema_version"], "receipt_v1")

    def test_evaluate_receipt_hash_length(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(len(r.json()["receipt_hash"]), 64)

    def test_evaluate_signature_length(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(len(r.json()["signature"]), 64)

    def test_evaluate_genesis_chain(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(r.json()["prev_receipt_hash"], "GENESIS")

    def test_evaluate_chained_receipt(self):
        r1 = client.post("/evaluate", json=BASE_REQUEST).json()
        req2 = dict(BASE_REQUEST)
        req2["prev_receipt_hash"] = r1["receipt_hash"]
        req2["pr_number"] = 2
        r2 = client.post("/evaluate", json=req2).json()
        self.assertEqual(r2["prev_receipt_hash"], r1["receipt_hash"])

    def test_evaluate_missing_field_returns_422(self):
        bad = dict(BASE_REQUEST)
        del bad["tenant_id"]
        r = client.post("/evaluate", json=bad)
        self.assertEqual(r.status_code, 422)


if __name__ == "__main__":
    unittest.main()
