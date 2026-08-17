#!/usr/bin/env python3
"""
Kills the five mutants that survived the chain_state.py mutation run (20/25 = 80%).

Every survivor was a count boundary at exactly 2:

    line 78   `not stored or not prev`  ->  `and`   receipt missing only ONE field
    line 82   `len(profiles) > 1`       ->  `> 2`   two profiles in one tree
    line 104  `len(genesis_children) > 1` -> `> 2`  fork at root
    line 110  `len(children) > 1`       ->  `> 2`   mid-chain fork
    line 114  `children[0]`             ->  `[1]`   dangling-prev message

The existing tests exercise trees of size 0 and 1. None constructs a tree with
TWO of anything, so every "more than one X is an error" guard is unproven --
including both fork checks. A two-branch fork is the canonical attack on an
append-only chain: split it, show the auditor the branch you prefer. The code
is correct today; nothing held it there.

No signing key is needed: chain_state validates receipt_hash and never touches
signatures, so receipts can be sealed with canonical_bytes alone.

Each test matches on the ERROR MESSAGE, not just ChainStateError. A mutant that
swaps which guard fires would otherwise still raise ChainStateError and survive.
"""
import hashlib
import json

import pytest

from titan_gate.canonical import canonical_bytes
from titan_gate.chain_state import GENESIS, ChainStateError, latest_receipt_hash


def _seal(**fields):
    """Build a receipt_v1 whose stored receipt_hash matches its own body."""
    r = dict(fields)
    r.pop("receipt_hash", None)
    r["receipt_hash"] = hashlib.sha256(canonical_bytes(r)).hexdigest()
    return r


def _write(root, name, receipt):
    p = root / ("%s.json" % name)
    p.write_text(json.dumps(receipt), encoding="utf-8")
    return receipt["receipt_hash"]


def _chain(root, n, tenant="t"):
    """n linked receipts, genesis first. Returns the list of hashes in order."""
    hashes, prev = [], GENESIS
    for i in range(n):
        r = _seal(schema_version="receipt_v1", tenant_id=tenant, seq=i,
                  prev_receipt_hash=prev)
        prev = _write(root, "%03d" % i, r)
        hashes.append(prev)
    return hashes


# --- positive control: the happy path must keep working --------------------

def test_empty_tree_is_genesis(tmp_path):
    assert latest_receipt_hash(tmp_path) == GENESIS


def test_single_clean_chain_returns_its_head(tmp_path):
    hashes = _chain(tmp_path, 3)
    assert latest_receipt_hash(tmp_path) == hashes[-1]


# --- line 104: fork at root, exactly two genesis children ------------------

def test_two_receipts_claiming_genesis_is_a_fork_at_root(tmp_path):
    """`len(genesis_children) > 1` -> `> 2` survived: two roots were accepted."""
    _write(tmp_path, "a", _seal(schema_version="receipt_v1", tenant_id="t",
                                seq=0, prev_receipt_hash=GENESIS))
    _write(tmp_path, "b", _seal(schema_version="receipt_v1", tenant_id="OTHER",
                                seq=0, prev_receipt_hash=GENESIS))
    # Match text unique to the ROOT check. "claim prev=GENESIS" alone also
    # appears in the mid-chain fork message, so the mutant would fall
    # through to that guard and still satisfy a looser match.
    with pytest.raises(ChainStateError, match="forked at root"):
        latest_receipt_hash(tmp_path)


# --- line 110: mid-chain fork, exactly two children of one prev ------------

def test_two_children_of_the_same_prev_is_a_fork(tmp_path):
    """`len(children) > 1` -> `> 2` survived: a split chain was accepted.

    This is the attack the whole module exists to stop -- branch the chain,
    then present whichever branch suits you.
    """
    root_hash = _write(tmp_path, "000", _seal(
        schema_version="receipt_v1", tenant_id="t", seq=0,
        prev_receipt_hash=GENESIS))
    _write(tmp_path, "001a", _seal(schema_version="receipt_v1", tenant_id="t",
                                   seq=1, prev_receipt_hash=root_hash))
    _write(tmp_path, "001b", _seal(schema_version="receipt_v1", tenant_id="t",
                                   seq=1, pr_title="branch",
                                   prev_receipt_hash=root_hash))
    with pytest.raises(ChainStateError, match="fork:"):
        latest_receipt_hash(tmp_path)


# --- line 82: exactly two profiles in one tree -----------------------------

def test_two_profiles_in_one_tree_is_rejected(tmp_path):
    """`len(profiles) > 1` -> `> 2` survived: SPEC-2 s1.3 was unenforced.

    A chain has ONE profile, declared at genesis. Mixing them is how a
    canonicalization-steering attack gets a foothold.
    """
    _write(tmp_path, "000", _seal(schema_version="receipt_v1", tenant_id="t",
                                  seq=0, prev_receipt_hash=GENESIS))
    trs2 = {"schema_version": "receipt_trs2_v1", "tenant_id": "t", "seq": 1,
            "prev_receipt_hash": "f" * 64}
    trs2["receipt_hash"] = hashlib.sha256(
        json.dumps(trs2, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False).encode("utf-8")).hexdigest()
    _write(tmp_path, "001", trs2)
    with pytest.raises(ChainStateError, match="mixed profiles"):
        latest_receipt_hash(tmp_path)


# --- line 78: missing exactly ONE of the two required fields ---------------

def test_receipt_missing_only_prev_receipt_hash_is_rejected(tmp_path):
    """`not stored or not prev` -> `and` survived: one-of-two was accepted."""
    r = _seal(schema_version="receipt_v1", tenant_id="t", seq=0,
              prev_receipt_hash=GENESIS)
    del r["prev_receipt_hash"]
    (tmp_path / "000.json").write_text(json.dumps(r), encoding="utf-8")
    with pytest.raises(ChainStateError, match="missing receipt_hash/prev_receipt_hash"):
        latest_receipt_hash(tmp_path)


def test_receipt_missing_only_receipt_hash_is_rejected(tmp_path):
    r = {"schema_version": "receipt_v1", "tenant_id": "t", "seq": 0,
         "prev_receipt_hash": GENESIS}
    (tmp_path / "000.json").write_text(json.dumps(r), encoding="utf-8")
    with pytest.raises(ChainStateError, match="missing receipt_hash/prev_receipt_hash"):
        latest_receipt_hash(tmp_path)


# --- line 114: the dangling-prev message must render -----------------------

def test_dangling_prev_names_the_referencing_receipt(tmp_path):
    """`children[0]` -> `children[1]` survived: nothing rendered the message.

    Asserting on the text forces the f-string to evaluate; an IndexError from
    children[1] is not a ChainStateError and fails the raises() match.
    """
    _write(tmp_path, "000", _seal(schema_version="receipt_v1", tenant_id="t",
                                  seq=0, prev_receipt_hash=GENESIS))
    _write(tmp_path, "002", _seal(schema_version="receipt_v1", tenant_id="t",
                                  seq=2, prev_receipt_hash="a" * 64))
    with pytest.raises(ChainStateError, match="dangling prev"):
        latest_receipt_hash(tmp_path)
