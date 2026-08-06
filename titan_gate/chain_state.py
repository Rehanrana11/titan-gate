"""Chain-head discovery for Titan Gate writers — the ONE way to learn prev.

WO-3 item 2. Writers call latest_receipt_hash(receipts_root) and use the
result as the new receipt's prev_receipt_hash. Callers never assert their
own prev: a caller who can set prev can fork the chain by construction.

Design decisions (logged):
- No HEAD pointer file: a pointer is a second source of truth that can lie.
  We scan and reconstruct linkage every time — O(n) per write, honest.
- Any ambiguity is a hard error, never a guess: fork, double-genesis,
  dangling prev, hash mismatch, or headlessness all raise ChainStateError.
  Writing on top of a broken chain would launder the break.
"""
import hashlib
import json
from pathlib import Path
from typing import Any, Dict

from titan_gate.canonical import canonical_bytes

GENESIS = "GENESIS"


class ChainStateError(Exception):
    """The persisted chain is absent where required, forked, or invalid."""


def _recomputed_hash(receipt: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(receipt)).hexdigest()


def latest_receipt_hash(receipts_root) -> str:
    """Return the chain head's receipt_hash, or GENESIS for an empty tree.

    Scans all *.json under receipts_root (recursively), validates that they
    form exactly one unbroken chain from a single GENESIS receipt, and
    returns the hash of the unique receipt no other receipt links to.
    """
    root = Path(receipts_root)
    paths = sorted(root.rglob("*.json")) if root.exists() else []
    if not paths:
        return GENESIS

    receipts = []
    for p in paths:
        try:
            r = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise ChainStateError(f"unreadable receipt {p}: {e}") from e
        stored = r.get("receipt_hash")
        prev = r.get("prev_receipt_hash")
        if not stored or not prev:
            raise ChainStateError(
                f"receipt {p} missing receipt_hash/prev_receipt_hash")
        if _recomputed_hash(r) != stored:
            raise ChainStateError(
                f"receipt {p}: stored receipt_hash does not match recomputed "
                f"hash — refusing to extend a tampered chain")
        receipts.append((p, r))

    by_hash = {}
    prev_refs: Dict[str, list] = {}
    for p, r in receipts:
        h = r["receipt_hash"]
        if h in by_hash:
            raise ChainStateError(f"duplicate receipt_hash {h} ({p})")
        by_hash[h] = (p, r)
        prev_refs.setdefault(r["prev_receipt_hash"], []).append(p)

    genesis_children = prev_refs.get(GENESIS, [])
    if len(genesis_children) == 0:
        raise ChainStateError("no GENESIS receipt: chain has no root")
    if len(genesis_children) > 1:
        raise ChainStateError(
            f"multiple receipts claim prev=GENESIS: {genesis_children} — "
            f"forked at root (or a pre-WO-3 legacy tree; migrate it first)")

    for prev, children in prev_refs.items():
        if len(children) > 1:
            raise ChainStateError(f"fork: {children} all claim prev={prev}")
        if prev != GENESIS and prev not in by_hash:
            raise ChainStateError(
                f"dangling prev {prev} referenced by {children[0]}: "
                f"predecessor receipt is missing")

    heads = [h for h in by_hash if h not in prev_refs]
    if len(heads) != 1:
        raise ChainStateError(
            f"expected exactly one chain head, found {len(heads)}")
    return heads[0]
