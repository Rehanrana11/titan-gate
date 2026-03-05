import unittest
import hashlib
from api.merkle import (
    leaf_hash, node_hash, compute_merkle_root,
    make_leaf_string, EMPTY_HASH, MERKLE_ALGORITHM
)


class TestMerkleConstants(unittest.TestCase):
    def test_empty_hash_value(self):
        expected = hashlib.sha256(b"L|EMPTY").hexdigest()
        self.assertEqual(EMPTY_HASH, expected)

    def test_merkle_algorithm_name(self):
        self.assertEqual(MERKLE_ALGORITHM, "merkle_v1")


class TestLeafHash(unittest.TestCase):
    def test_leaf_hash_deterministic(self):
        h1 = leaf_hash("v1|t1|2026-03-04|r1|abc")
        h2 = leaf_hash("v1|t1|2026-03-04|r1|abc")
        self.assertEqual(h1, h2)

    def test_leaf_hash_prefix(self):
        data = "v1|tenant|2026-03-04|receipt-id|hash"
        expected = hashlib.sha256(b"L|" + data.encode("utf-8")).hexdigest()
        self.assertEqual(leaf_hash(data), expected)

    def test_leaf_hash_different_inputs(self):
        self.assertNotEqual(leaf_hash("a"), leaf_hash("b"))

    def test_leaf_hash_lowercase(self):
        h = leaf_hash("test")
        self.assertEqual(h, h.lower())

    def test_leaf_hash_length(self):
        self.assertEqual(len(leaf_hash("test")), 64)


class TestNodeHash(unittest.TestCase):
    def test_node_hash_deterministic(self):
        left = "a" * 64
        right = "b" * 64
        self.assertEqual(node_hash(left, right), node_hash(left, right))

    def test_node_hash_prefix(self):
        left = hashlib.sha256(b"left").hexdigest()
        right = hashlib.sha256(b"right").hexdigest()
        expected = hashlib.sha256(
            b"N|" + bytes.fromhex(left) + bytes.fromhex(right)
        ).hexdigest()
        self.assertEqual(node_hash(left, right), expected)

    def test_node_hash_not_commutative(self):
        left = "a" * 64
        right = "b" * 64
        self.assertNotEqual(node_hash(left, right), node_hash(right, left))

    def test_node_hash_lowercase(self):
        left = "a" * 64
        right = "b" * 64
        h = node_hash(left, right)
        self.assertEqual(h, h.lower())


class TestComputeMerkleRoot(unittest.TestCase):
    def test_empty_tree(self):
        self.assertEqual(compute_merkle_root([]), EMPTY_HASH)

    def test_single_leaf(self):
        leaves = ["v1|t|2026-03-04|r1|h1"]
        root = compute_merkle_root(leaves)
        self.assertEqual(root, leaf_hash(leaves[0]))

    def test_two_leaves(self):
        leaves = ["v1|t|2026-03-04|r1|h1", "v1|t|2026-03-04|r2|h2"]
        root = compute_merkle_root(leaves)
        sorted_leaves = sorted(leaves)
        expected = node_hash(leaf_hash(sorted_leaves[0]), leaf_hash(sorted_leaves[1]))
        self.assertEqual(root, expected)

    def test_deterministic(self):
        leaves = ["leaf1", "leaf2", "leaf3"]
        self.assertEqual(compute_merkle_root(leaves), compute_merkle_root(leaves))

    def test_order_independent(self):
        leaves = ["leaf1", "leaf2", "leaf3"]
        shuffled = ["leaf3", "leaf1", "leaf2"]
        self.assertEqual(compute_merkle_root(leaves), compute_merkle_root(shuffled))

    def test_odd_number_of_leaves(self):
        leaves = ["leaf1", "leaf2", "leaf3"]
        root = compute_merkle_root(leaves)
        self.assertIsInstance(root, str)
        self.assertEqual(len(root), 64)

    def test_root_is_lowercase_hex(self):
        leaves = ["leaf1", "leaf2"]
        root = compute_merkle_root(leaves)
        self.assertEqual(root, root.lower())
        self.assertTrue(all(c in "0123456789abcdef" for c in root))


class TestMakeLeafString(unittest.TestCase):
    def test_format(self):
        s = make_leaf_string("tenant1", "2026-03-04", "receipt-uuid", "abc" * 21 + "d")
        self.assertTrue(s.startswith("v1|tenant1|2026-03-04|receipt-uuid|"))

    def test_deterministic(self):
        s1 = make_leaf_string("t", "2026-03-04", "r", "h")
        s2 = make_leaf_string("t", "2026-03-04", "r", "h")
        self.assertEqual(s1, s2)


if __name__ == "__main__":
    unittest.main()
