import unittest
from api.anchor import build_anchor, compute_anchor_payload_hash, ANCHOR_SCHEMA
from api.merkle import compute_merkle_root, make_leaf_string


def make_receipts(n, tenant_id="tenant1", date="2026-03-04"):
    return [
        {"receipt_id": "r{}".format(i), "receipt_hash": "a" * 63 + str(i)}
        for i in range(n)
    ]


class TestAnchorSchema(unittest.TestCase):
    def test_schema_value(self):
        self.assertEqual(ANCHOR_SCHEMA, "anchor_v1")


class TestBuildAnchor(unittest.TestCase):
    def test_returns_dict(self):
        receipts = make_receipts(2)
        anchor = build_anchor("tenant1", "tenant1/repo", "2026-03-04", receipts)
        self.assertIsInstance(anchor, dict)

    def test_required_fields(self):
        receipts = make_receipts(2)
        anchor = build_anchor("tenant1", "tenant1/repo", "2026-03-04", receipts)
        for field in ["schema", "tenant_id", "repo_full_name", "date",
                      "merkle_root", "merkle_algorithm", "receipt_count",
                      "status", "payload_hash"]:
            self.assertIn(field, anchor)

    def test_schema_version(self):
        receipts = make_receipts(2)
        anchor = build_anchor("tenant1", "tenant1/repo", "2026-03-04", receipts)
        self.assertEqual(anchor["schema"], "anchor_v1")

    def test_merkle_algorithm(self):
        receipts = make_receipts(2)
        anchor = build_anchor("tenant1", "tenant1/repo", "2026-03-04", receipts)
        self.assertEqual(anchor["merkle_algorithm"], "merkle_v1")

    def test_receipt_count(self):
        receipts = make_receipts(5)
        anchor = build_anchor("tenant1", "tenant1/repo", "2026-03-04", receipts)
        self.assertEqual(anchor["receipt_count"], 5)

    def test_default_status_pending(self):
        receipts = make_receipts(2)
        anchor = build_anchor("tenant1", "tenant1/repo", "2026-03-04", receipts)
        self.assertEqual(anchor["status"], "pending")

    def test_promoted_status(self):
        receipts = make_receipts(2)
        anchor = build_anchor("tenant1", "tenant1/repo", "2026-03-04",
                               receipts, status="promoted")
        self.assertEqual(anchor["status"], "promoted")

    def test_merkle_root_correct(self):
        receipts = make_receipts(2, tenant_id="t1", date="2026-03-04")
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", receipts)
        leaves = [make_leaf_string("t1", "2026-03-04", r["receipt_id"], r["receipt_hash"])
                  for r in receipts]
        expected_root = compute_merkle_root(leaves)
        self.assertEqual(anchor["merkle_root"], expected_root)

    def test_empty_receipts(self):
        anchor = build_anchor("tenant1", "tenant1/repo", "2026-03-04", [])
        self.assertEqual(anchor["receipt_count"], 0)

    def test_deterministic(self):
        receipts = make_receipts(3)
        a1 = build_anchor("t1", "t1/repo", "2026-03-04", receipts)
        a2 = build_anchor("t1", "t1/repo", "2026-03-04", receipts)
        self.assertEqual(a1["merkle_root"], a2["merkle_root"])
        self.assertEqual(a1["payload_hash"], a2["payload_hash"])


class TestPayloadHash(unittest.TestCase):
    def test_payload_hash_present(self):
        receipts = make_receipts(2)
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", receipts)
        self.assertIn("payload_hash", anchor)
        self.assertEqual(len(anchor["payload_hash"]), 64)

    def test_payload_hash_changes_on_modification(self):
        receipts = make_receipts(2)
        a1 = build_anchor("t1", "t1/repo", "2026-03-04", receipts)
        a2 = build_anchor("t1", "t1/repo", "2026-03-04", receipts, status="promoted")
        self.assertNotEqual(a1["payload_hash"], a2["payload_hash"])

    def test_payload_hash_lowercase(self):
        receipts = make_receipts(2)
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", receipts)
        h = anchor["payload_hash"]
        self.assertEqual(h, h.lower())


if __name__ == "__main__":
    unittest.main()
