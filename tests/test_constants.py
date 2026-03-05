import unittest
from api.constants import (
    ENGINE_VERSION, CONTRACT_VERSION, SCORING_FORMULA_VERSION,
    POLICY_VERSION, MERKLE_ALGORITHM, SIGNING_VERSION,
    ANCHOR_SCHEMA, BLOB_STORE_VERSION,
    SCORE_PASS, SCORE_WARN, VERDICT_PASS, VERDICT_WARN, VERDICT_FAIL,
)


class TestVersionConstants(unittest.TestCase):
    def test_engine_version(self):
        self.assertEqual(ENGINE_VERSION, "1.0.0")

    def test_contract_version(self):
        self.assertEqual(CONTRACT_VERSION, "1.0.0")

    def test_scoring_formula_version(self):
        self.assertEqual(SCORING_FORMULA_VERSION, "1.0.0")

    def test_policy_version(self):
        self.assertEqual(POLICY_VERSION, "1.0.0")

    def test_merkle_algorithm(self):
        self.assertEqual(MERKLE_ALGORITHM, "merkle_v1")

    def test_signing_version(self):
        self.assertEqual(SIGNING_VERSION, "hmac-sha256-v1")

    def test_anchor_schema(self):
        self.assertEqual(ANCHOR_SCHEMA, "anchor_v1")

    def test_blob_store_version(self):
        self.assertEqual(BLOB_STORE_VERSION, "postgres_gzip_v1")


class TestScoringThresholds(unittest.TestCase):
    def test_pass_threshold(self):
        self.assertEqual(SCORE_PASS, 0.70)

    def test_warn_threshold(self):
        self.assertEqual(SCORE_WARN, 0.40)

    def test_pass_greater_than_warn(self):
        self.assertGreater(SCORE_PASS, SCORE_WARN)

    def test_warn_greater_than_zero(self):
        self.assertGreater(SCORE_WARN, 0.0)

    def test_pass_less_than_one(self):
        self.assertLess(SCORE_PASS, 1.0)


class TestVerdictConstants(unittest.TestCase):
    def test_verdict_pass(self):
        self.assertEqual(VERDICT_PASS, "PASS")

    def test_verdict_warn(self):
        self.assertEqual(VERDICT_WARN, "WARN")

    def test_verdict_fail(self):
        self.assertEqual(VERDICT_FAIL, "FAIL")

    def test_verdicts_distinct(self):
        self.assertNotEqual(VERDICT_PASS, VERDICT_WARN)
        self.assertNotEqual(VERDICT_PASS, VERDICT_FAIL)
        self.assertNotEqual(VERDICT_WARN, VERDICT_FAIL)


if __name__ == "__main__":
    unittest.main()
