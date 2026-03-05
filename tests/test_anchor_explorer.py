import unittest
import json
import os
import sys
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.anchor_explorer import verify_anchor_integrity, load_anchor, display_anchor

ANCHOR_FILE = "tests/vectors/anchor_2026-03-04.json"
EXPLORER = "scripts/anchor_explorer.py"


def run_explorer(*args):
    cmd = [sys.executable, EXPLORER] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


class TestAnchorIntegrity(unittest.TestCase):
    def setUp(self):
        self.anchor = load_anchor(ANCHOR_FILE)

    def test_valid_anchor_no_anomalies(self):
        anomalies = verify_anchor_integrity(self.anchor)
        self.assertEqual(anomalies, [])

    def test_schema_mismatch_detected(self):
        bad = dict(self.anchor)
        bad["schema"] = "wrong_schema"
        anomalies = verify_anchor_integrity(bad)
        self.assertIn("SCHEMA_MISMATCH", anomalies)

    def test_algorithm_mismatch_detected(self):
        bad = dict(self.anchor)
        bad["merkle_algorithm"] = "wrong_algo"
        anomalies = verify_anchor_integrity(bad)
        self.assertIn("ALGORITHM_MISMATCH", anomalies)

    def test_payload_hash_mismatch_detected(self):
        bad = dict(self.anchor)
        bad["payload_hash"] = "0" * 64
        anomalies = verify_anchor_integrity(bad)
        self.assertIn("PAYLOAD_HASH_MISMATCH", anomalies)

    def test_tampered_merkle_root_detected(self):
        bad = dict(self.anchor)
        bad["merkle_root"] = "0" * 64
        anomalies = verify_anchor_integrity(bad)
        self.assertIn("PAYLOAD_HASH_MISMATCH", anomalies)


class TestAnchorExplorerCLI(unittest.TestCase):
    def test_inspect_valid_exits_zero(self):
        rc, _, _ = run_explorer("inspect", ANCHOR_FILE)
        self.assertEqual(rc, 0)

    def test_inspect_output_contains_pass(self):
        _, out, _ = run_explorer("inspect", ANCHOR_FILE)
        self.assertIn("PASS", out)

    def test_inspect_output_contains_tenant(self):
        _, out, _ = run_explorer("inspect", ANCHOR_FILE)
        self.assertIn("tenant_test", out)

    def test_inspect_output_contains_merkle_root(self):
        _, out, _ = run_explorer("inspect", ANCHOR_FILE)
        self.assertIn("011c3a6f", out)

    def test_inspect_missing_file_exits_two(self):
        rc, _, _ = run_explorer("inspect", "nonexistent.json")
        self.assertEqual(rc, 2)

    def test_inspect_json_output(self):
        _, out, _ = run_explorer("inspect", ANCHOR_FILE, "--json")
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertEqual(data["anomalies"], [])

    def test_inspect_json_fields(self):
        _, out, _ = run_explorer("inspect", ANCHOR_FILE, "--json")
        data = json.loads(out)
        for field in ["ok", "tenant_id", "date", "status",
                      "merkle_root", "receipt_count", "anomalies"]:
            self.assertIn(field, data)

    def test_inspect_tampered_exits_nonzero(self):
        anchor = load_anchor(ANCHOR_FILE)
        anchor["merkle_root"] = "0" * 64
        tmp = "tests/vectors/tampered_anchor.json"
        with open(tmp, "w") as f:
            json.dump(anchor, f)
        rc, _, _ = run_explorer("inspect", tmp)
        self.assertNotEqual(rc, 0)
        os.remove(tmp)

    def test_inspect_verbose(self):
        _, out, _ = run_explorer("inspect", ANCHOR_FILE, "--verbose")
        self.assertIn("PASS", out)


if __name__ == "__main__":
    unittest.main()
