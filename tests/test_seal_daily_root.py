import unittest
import json
import os
import sys
import shutil
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.seal_daily_root import seal_daily_root, get_anchor_path, load_receipts_for_date
from api.anchor import compute_anchor_payload_hash

TV1 = "tests/vectors/TV1.json"
TV2 = "tests/vectors/TV2.json"
TV3 = "tests/vectors/TV3.json"
TEST_DIR = "tests/vectors/seal_test_tmp"


def load_json(path):
    with open(path) as f:
        return json.load(f)


class TestSealDailyRoot(unittest.TestCase):
    def setUp(self):
        self.receipts = [load_json(TV1), load_json(TV2), load_json(TV3)]
        self.tenant = "tenant_test"
        self.repo = "tenant/test-repo"
        self.date = "2026-03-04"
        if os.path.exists(TEST_DIR):
            shutil.rmtree(TEST_DIR)
        os.makedirs(TEST_DIR)

    def tearDown(self):
        if os.path.exists(TEST_DIR):
            shutil.rmtree(TEST_DIR)

    def test_seal_creates_anchor_file(self):
        anchor, is_new = seal_daily_root(
            self.tenant, self.repo, self.date, self.receipts, TEST_DIR
        )
        repo_name = self.repo.replace("/", "_")
        path = get_anchor_path(TEST_DIR, self.tenant, repo_name, self.date)
        self.assertTrue(os.path.exists(path))

    def test_seal_returns_is_new_true(self):
        _, is_new = seal_daily_root(
            self.tenant, self.repo, self.date, self.receipts, TEST_DIR
        )
        self.assertTrue(is_new)

    def test_seal_idempotent(self):
        anchor1, _ = seal_daily_root(
            self.tenant, self.repo, self.date, self.receipts, TEST_DIR
        )
        anchor2, is_new2 = seal_daily_root(
            self.tenant, self.repo, self.date, self.receipts, TEST_DIR
        )
        self.assertFalse(is_new2)
        self.assertEqual(anchor1["merkle_root"], anchor2["merkle_root"])

    def test_seal_merkle_root_correct(self):
        anchor, _ = seal_daily_root(
            self.tenant, self.repo, self.date, self.receipts, TEST_DIR
        )
        self.assertEqual(
            anchor["merkle_root"],
            "011c3a6fbb0185e583b4af7716d3d2fdfede450f863d084634e92c935404804c"
        )

    def test_seal_status_promoted(self):
        anchor, _ = seal_daily_root(
            self.tenant, self.repo, self.date, self.receipts, TEST_DIR
        )
        self.assertEqual(anchor["status"], "promoted")

    def test_seal_payload_hash_valid(self):
        anchor, _ = seal_daily_root(
            self.tenant, self.repo, self.date, self.receipts, TEST_DIR
        )
        computed = compute_anchor_payload_hash(anchor)
        self.assertEqual(anchor["payload_hash"], computed)

    def test_seal_receipt_count(self):
        anchor, _ = seal_daily_root(
            self.tenant, self.repo, self.date, self.receipts, TEST_DIR
        )
        self.assertEqual(anchor["receipt_count"], 3)

    def test_seal_empty_receipts(self):
        anchor, is_new = seal_daily_root(
            self.tenant, self.repo, self.date, [], TEST_DIR
        )
        self.assertTrue(is_new)
        self.assertEqual(anchor["receipt_count"], 0)


class TestSealCLI(unittest.TestCase):
    def setUp(self):
        if os.path.exists(TEST_DIR):
            shutil.rmtree(TEST_DIR)
        os.makedirs(TEST_DIR)

    def tearDown(self):
        if os.path.exists(TEST_DIR):
            shutil.rmtree(TEST_DIR)

    def _run(self, *args):
        cmd = [sys.executable, "scripts/seal_daily_root.py"] + list(args)
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_cli_exits_zero(self):
        r = self._run(
            "--tenant", "tenant_test",
            "--repo", "tenant/test-repo",
            "--date", "2026-03-04",
            "--receipt-files", TV1, TV2, TV3,
            "--dir", TEST_DIR
        )
        self.assertEqual(r.returncode, 0)

    def test_cli_output_contains_sealed(self):
        r = self._run(
            "--tenant", "tenant_test",
            "--repo", "tenant/test-repo",
            "--date", "2026-03-04",
            "--receipt-files", TV1, TV2, TV3,
            "--dir", TEST_DIR
        )
        self.assertIn("SEALED", r.stdout)

    def test_cli_output_contains_merkle_root(self):
        r = self._run(
            "--tenant", "tenant_test",
            "--repo", "tenant/test-repo",
            "--date", "2026-03-04",
            "--receipt-files", TV1, TV2, TV3,
            "--dir", TEST_DIR
        )
        self.assertIn("011c3a6f", r.stdout)

    def test_cli_idempotent(self):
        self._run(
            "--tenant", "tenant_test",
            "--repo", "tenant/test-repo",
            "--date", "2026-03-04",
            "--receipt-files", TV1, TV2, TV3,
            "--dir", TEST_DIR
        )
        r = self._run(
            "--tenant", "tenant_test",
            "--repo", "tenant/test-repo",
            "--date", "2026-03-04",
            "--receipt-files", TV1, TV2, TV3,
            "--dir", TEST_DIR
        )
        self.assertIn("SKIPPED", r.stdout)


if __name__ == "__main__":
    unittest.main()
