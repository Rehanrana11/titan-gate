import unittest
import hashlib
import hmac
import json
from api.receipt_signing import (
    canonical_bytes, compute_receipt_hash, compute_signature, verify_signature,
    SIGNING_VERSION, EXCLUSION_FIELDS
)

TEST_KEY = "0" * 64

SAMPLE_RECEIPT = {
    "schema_version": "receipt_v1",
    "receipt_id": "test-receipt-001",
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


class TestSigningVersion(unittest.TestCase):
    def test_signing_version_value(self):
        self.assertEqual(SIGNING_VERSION, "hmac-sha256-v1")


class TestExclusionFields(unittest.TestCase):
    def test_signature_excluded(self):
        self.assertIn("signature", EXCLUSION_FIELDS)

    def test_prev_receipt_hash_verified_excluded(self):
        self.assertIn("prev_receipt_hash_verified", EXCLUSION_FIELDS)

    def test_debug_excluded(self):
        self.assertIn("_debug", EXCLUSION_FIELDS)

    def test_meta_excluded(self):
        self.assertIn("_meta", EXCLUSION_FIELDS)

    def test_receipt_hash_not_excluded(self):
        self.assertIn("receipt_hash", EXCLUSION_FIELDS)


class TestCanonicalBytes(unittest.TestCase):
    def test_returns_bytes(self):
        receipt = dict(SAMPLE_RECEIPT)
        self.assertIsInstance(canonical_bytes(receipt), bytes)

    def test_deterministic(self):
        receipt = dict(SAMPLE_RECEIPT)
        self.assertEqual(canonical_bytes(receipt), canonical_bytes(receipt))

    def test_excludes_signature(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["signature"] = "sig123"
        cb = canonical_bytes(receipt)
        self.assertNotIn(b"sig123", cb)

    def test_sorted_keys(self):
        r1 = {"b": 2, "a": 1}
        r2 = {"a": 1, "b": 2}
        self.assertEqual(canonical_bytes(r1), canonical_bytes(r2))

    def test_utf8_encoding(self):
        receipt = {"key": "value"}
        cb = canonical_bytes(receipt)
        self.assertIsInstance(cb, bytes)
        cb.decode("utf-8")

    def test_no_spaces_in_separators(self):
        receipt = {"a": 1, "b": 2}
        cb = canonical_bytes(receipt)
        parsed = json.loads(cb)
        self.assertEqual(parsed["a"], 1)


class TestComputeReceiptHash(unittest.TestCase):
    def test_returns_hex_string(self):
        receipt = dict(SAMPLE_RECEIPT)
        h = compute_receipt_hash(receipt)
        self.assertIsInstance(h, str)
        self.assertEqual(len(h), 64)

    def test_deterministic(self):
        receipt = dict(SAMPLE_RECEIPT)
        self.assertEqual(compute_receipt_hash(receipt), compute_receipt_hash(receipt))

    def test_lowercase(self):
        receipt = dict(SAMPLE_RECEIPT)
        h = compute_receipt_hash(receipt)
        self.assertEqual(h, h.lower())

    def test_changes_on_modification(self):
        r1 = dict(SAMPLE_RECEIPT)
        r2 = dict(SAMPLE_RECEIPT)
        r2["verdict"] = "FAIL"
        self.assertNotEqual(compute_receipt_hash(r1), compute_receipt_hash(r2))

    def test_matches_sha256(self):
        receipt = dict(SAMPLE_RECEIPT)
        cb = canonical_bytes(receipt)
        expected = hashlib.sha256(cb).hexdigest()
        self.assertEqual(compute_receipt_hash(receipt), expected)


class TestComputeSignature(unittest.TestCase):
    def test_returns_hex_string(self):
        receipt = dict(SAMPLE_RECEIPT)
        sig = compute_signature(receipt, TEST_KEY)
        self.assertIsInstance(sig, str)
        self.assertEqual(len(sig), 64)

    def test_deterministic(self):
        receipt = dict(SAMPLE_RECEIPT)
        self.assertEqual(
            compute_signature(receipt, TEST_KEY),
            compute_signature(receipt, TEST_KEY)
        )

    def test_lowercase(self):
        receipt = dict(SAMPLE_RECEIPT)
        sig = compute_signature(receipt, TEST_KEY)
        self.assertEqual(sig, sig.lower())

    def test_changes_on_receipt_modification(self):
        r1 = dict(SAMPLE_RECEIPT)
        r2 = dict(SAMPLE_RECEIPT)
        r2["verdict"] = "FAIL"
        self.assertNotEqual(
            compute_signature(r1, TEST_KEY),
            compute_signature(r2, TEST_KEY)
        )

    def test_changes_on_key_modification(self):
        receipt = dict(SAMPLE_RECEIPT)
        key2 = "1" * 64
        self.assertNotEqual(
            compute_signature(receipt, TEST_KEY),
            compute_signature(receipt, key2)
        )


class TestVerifySignature(unittest.TestCase):
    def test_valid_signature(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["signature"] = compute_signature(receipt, TEST_KEY)
        self.assertTrue(verify_signature(receipt, TEST_KEY))

    def test_invalid_signature(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["signature"] = "0" * 64
        self.assertFalse(verify_signature(receipt, TEST_KEY))

    def test_missing_signature(self):
        receipt = dict(SAMPLE_RECEIPT)
        self.assertFalse(verify_signature(receipt, TEST_KEY))

    def test_tampered_receipt(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["signature"] = compute_signature(receipt, TEST_KEY)
        receipt["verdict"] = "FAIL"
        self.assertFalse(verify_signature(receipt, TEST_KEY))

    def test_wrong_key(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["signature"] = compute_signature(receipt, TEST_KEY)
        wrong_key = "f" * 64
        self.assertFalse(verify_signature(receipt, wrong_key))


if __name__ == "__main__":
    unittest.main()
