import unittest
import json
import os
import sys
import subprocess

TV1 = "tests/vectors/TV1.json"
TV2 = "tests/vectors/TV2.json"
GOOD_KEY = "0" * 64
BAD_KEY = "f" * 64
VERIFIER = "scripts/titan_verify.py"


def run_verifier(*args):
    cmd = [sys.executable, VERIFIER] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


class TestVerifierValidReceipt(unittest.TestCase):
    def test_tv1_exits_zero(self):
        rc, _, _ = run_verifier(TV1, "--key", GOOD_KEY)
        self.assertEqual(rc, 0)

    def test_tv2_exits_zero(self):
        rc, _, _ = run_verifier(TV2, "--key", GOOD_KEY)
        self.assertEqual(rc, 0)

    def test_output_contains_pass(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY)
        self.assertIn("PASS", out)

    def test_output_contains_receipt_id(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY)
        self.assertIn("tv1-genesis", out)

    def test_output_contains_tenant(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY)
        self.assertIn("tenant_test", out)


class TestVerifierInvalidKey(unittest.TestCase):
    def test_wrong_key_exits_nonzero(self):
        rc, _, _ = run_verifier(TV1, "--key", BAD_KEY)
        self.assertNotEqual(rc, 0)

    def test_wrong_key_shows_fail(self):
        _, out, _ = run_verifier(TV1, "--key", BAD_KEY)
        self.assertIn("FAIL", out)

    def test_wrong_key_shows_anomaly(self):
        _, out, _ = run_verifier(TV1, "--key", BAD_KEY)
        self.assertIn("SIGNATURE_MISMATCH", out)


class TestVerifierJsonOutput(unittest.TestCase):
    def test_json_output_valid(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY, "--json")
        data = json.loads(out)
        self.assertIn("ok", data)
        self.assertTrue(data["ok"])

    def test_json_output_fields(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY, "--json")
        data = json.loads(out)
        for field in ["ok", "receipt_id", "tenant_id", "verdict",
                      "composite_score", "anomalies"]:
            self.assertIn(field, data)

    def test_json_fail_has_anomalies(self):
        _, out, _ = run_verifier(TV1, "--key", BAD_KEY, "--json")
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertGreater(len(data["anomalies"]), 0)


class TestVerifierMissingFile(unittest.TestCase):
    def test_missing_file_exits_two(self):
        rc, _, err = run_verifier("nonexistent.json", "--key", GOOD_KEY)
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
