import unittest
import json
import os
import sys
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.generate_proof_bundle import generate_proof_bundle, build_merkle_proof
from api.merkle import compute_merkle_root, make_leaf_string, leaf_hash

TV1 = "tests/vectors/TV1.json"
TV2 = "tests/vectors/TV2.json"
TV3 = "tests/vectors/TV3.json"
BUNDLE = "tests/vectors/proof_bundle.json"


def load_json(path):
    with open(path) as f:
        return json.load(f)


def make_bundle(output="tests/vectors/test_bundle_tmp.json"):
    receipts = [load_json(TV1), load_json(TV2), load_json(TV3)]
    return generate_proof_bundle(receipts, "tenant_test", "tenant/test-repo", output)


class TestBundleStructure(unittest.TestCase):
    def setUp(self):
        self.bundle = make_bundle()

    def test_schema_version(self):
        self.assertEqual(self.bundle["schema"], "proof_bundle_v1")

    def test_required_fields(self):
        for field in ["schema", "generated_at", "engine_version", "contract_version",
                      "merkle_algorithm", "tenant_id", "repo_full_name", "root_date",
                      "merkle_root", "receipt_count", "anchor", "receipts",
                      "bundle_hash", "verification_instructions"]:
            self.assertIn(field, self.bundle)

    def test_receipt_count(self):
        self.assertEqual(self.bundle["receipt_count"], 3)

    def test_merkle_algorithm(self):
        self.assertEqual(self.bundle["merkle_algorithm"], "merkle_v1")

    def test_tenant_id(self):
        self.assertEqual(self.bundle["tenant_id"], "tenant_test")

    def test_bundle_hash_present(self):
        self.assertIsInstance(self.bundle["bundle_hash"], str)
        self.assertEqual(len(self.bundle["bundle_hash"]), 64)


class TestBundleMerkleRoot(unittest.TestCase):
    def setUp(self):
        self.bundle = make_bundle()
        self.receipts = [load_json(TV1), load_json(TV2), load_json(TV3)]

    def test_merkle_root_correct(self):
        leaves = [
            make_leaf_string(
                r["tenant_id"], r["root_date"], r["receipt_id"], r["receipt_hash"]
            )
            for r in self.receipts
        ]
        expected = compute_merkle_root(leaves)
        self.assertEqual(self.bundle["merkle_root"], expected)

    def test_merkle_root_matches_anchor(self):
        self.assertEqual(
            self.bundle["merkle_root"],
            self.bundle["anchor"]["merkle_root"]
        )

    def test_merkle_root_deterministic(self):
        b2 = make_bundle("tests/vectors/test_bundle_tmp2.json")
        self.assertEqual(self.bundle["merkle_root"], b2["merkle_root"])


class TestBundleReceiptProofs(unittest.TestCase):
    def setUp(self):
        self.bundle = make_bundle()

    def test_each_receipt_has_required_fields(self):
        for r in self.bundle["receipts"]:
            for field in ["receipt_id", "receipt_hash", "leaf_string",
                          "leaf_hash", "merkle_proof", "verdict",
                          "composite_score", "evaluated_at"]:
                self.assertIn(field, r)

    def test_leaf_hash_correct(self):
        for r in self.bundle["receipts"]:
            expected = leaf_hash(r["leaf_string"])
            self.assertEqual(r["leaf_hash"], expected)

    def test_verdicts_present(self):
        verdicts = [r["verdict"] for r in self.bundle["receipts"]]
        self.assertIn("PASS", verdicts)
        self.assertIn("WARN", verdicts)

    def test_receipt_ids_match(self):
        ids = [r["receipt_id"] for r in self.bundle["receipts"]]
        self.assertIn("tv1-genesis", ids)
        self.assertIn("tv2-chained", ids)
        self.assertIn("tv3-chained", ids)


class TestBundleCLI(unittest.TestCase):
    def _run(self, *args):
        cmd = [sys.executable, "scripts/generate_proof_bundle.py"] + list(args)
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_cli_exits_zero(self):
        r = self._run(TV1, TV2, TV3, "--tenant", "tenant_test",
                      "--repo", "tenant/test-repo",
                      "--output", "tests/vectors/cli_test_bundle.json")
        self.assertEqual(r.returncode, 0)

    def test_cli_output_contains_merkle_root(self):
        r = self._run(TV1, TV2, TV3, "--tenant", "tenant_test",
                      "--repo", "tenant/test-repo",
                      "--output", "tests/vectors/cli_test_bundle2.json")
        self.assertIn("Merkle root", r.stdout)

    def test_cli_missing_file_exits_two(self):
        r = self._run("nonexistent.json", "--tenant", "t", "--repo", "t/r",
                      "--output", "tests/vectors/cli_test_bundle3.json")
        self.assertEqual(r.returncode, 2)

    def test_cli_verbose_shows_verdicts(self):
        r = self._run(TV1, TV2, TV3, "--tenant", "tenant_test",
                      "--repo", "tenant/test-repo",
                      "--output", "tests/vectors/cli_test_bundle4.json",
                      "--verbose")
        self.assertIn("PASS", r.stdout)
        self.assertIn("WARN", r.stdout)


if __name__ == "__main__":
    unittest.main()
