"""Offline RFC 6962 inclusion-proof and checkpoint-signature verification
for Rekor anchors (WO-4.1; FRD AT-16 first half).

Domain separation note (load-bearing): RFC 6962 hashing is
  leaf = SHA-256(0x00 || data)
  node = SHA-256(0x01 || left || right)
This is REKOR'S convention, distinct from Titan's own 'L|'-prefixed
Merkle tree. Two trees, two conventions; this module implements 6962
and must never share code with titan's merkle module — the domain
prefixes are the defense against node-as-leaf second-preimage forgery,
and mixing conventions would silently void it.

Verification here is pure math + one Ed25519 check: no network, no
sigstore machinery, no dependency beyond `cryptography` (already the
verifier's only dependency). Checkpoint signed-note FORMAT parsing
(base64 signature lines, key hints) lives in the anchor-record layer
(WO-4.2), which hands this module raw bytes.
"""
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = [
    "verify_inclusion_proof",
    "verify_checkpoint_signature",
    "RekorVerificationError",
]


class RekorVerificationError(ValueError):
    """Inclusion proof or checkpoint signature failed verification."""


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_inclusion_proof(*, leaf_data: bytes, leaf_index: int,
                           tree_size: int, proof_hashes, expected_root: bytes) -> None:
    """Verify an RFC 6962 audit path. Raises RekorVerificationError on
    any failure; returns None on success.

    Algorithm (RFC 6962 s2.1.1 / RFC 9162): walk leaf-to-root; at each
    level, if the current node is a right child (index odd) OR the
    remaining subtree has no right sibling to consume, combine with the
    proof hash on the left; otherwise on the right. A left-position
    node at the exact end of an odd level is promoted without a
    sibling — the proof supplies no hash for that step.
    """
    if not isinstance(leaf_data, bytes):
        raise RekorVerificationError("leaf_data must be bytes")
    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool) or leaf_index < 0:
        raise RekorVerificationError(f"leaf_index must be a non-negative int, got {leaf_index!r}")
    if not isinstance(tree_size, int) or isinstance(tree_size, bool) or tree_size <= 0:
        raise RekorVerificationError(f"tree_size must be a positive int, got {tree_size!r}")
    if leaf_index >= tree_size:
        raise RekorVerificationError(
            f"leaf_index {leaf_index} out of range for tree_size {tree_size}")
    for i, h in enumerate(proof_hashes):
        if not isinstance(h, bytes) or len(h) != 32:
            raise RekorVerificationError(f"proof hash {i} must be 32 bytes")
    if not isinstance(expected_root, bytes) or len(expected_root) != 32:
        raise RekorVerificationError("expected_root must be 32 bytes")

    node = _leaf_hash(leaf_data)
    index, size = leaf_index, tree_size
    proof = list(proof_hashes)
    pos = 0
    while size > 1:
        if index % 2 == 1:
            # right child: sibling on the left, always exists
            if pos >= len(proof):
                raise RekorVerificationError(
                    "proof truncated: ran out of hashes before reaching root")
            node = _node_hash(proof[pos], node)
            pos += 1
        elif index < size - 1:
            # left child with a right sibling
            if pos >= len(proof):
                raise RekorVerificationError(
                    "proof truncated: ran out of hashes before reaching root")
            node = _node_hash(node, proof[pos])
            pos += 1
        # else: lone node at odd level end — promoted, no proof hash consumed
        index //= 2
        size = (size + 1) // 2
    if pos != len(proof):
        raise RekorVerificationError(
            f"proof has {len(proof) - pos} unconsumed hash(es): "
            f"wrong proof for this index/size, or padded")
    if node != expected_root:
        raise RekorVerificationError(
            "recomputed root does not match expected root: leaf not "
            "included in this tree (or proof/index/size inconsistent)")


def verify_checkpoint_signature(body: bytes, signature: bytes,
                                log_public_key: Ed25519PublicKey) -> None:
    """Verify the log's Ed25519 signature over checkpoint body bytes
    against the PINNED log key. Raises RekorVerificationError on failure.

    The pinned key is the trust anchor that makes offline verification
    meaningful: an attacker who forges a checkpoint must forge this
    signature, and possession of the public key alone cannot do it.
    """
    if not isinstance(body, bytes) or not body:
        raise RekorVerificationError("checkpoint body must be non-empty bytes")
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise RekorVerificationError("checkpoint signature must be 64 bytes")
    try:
        log_public_key.verify(signature, body)
    except InvalidSignature as e:
        raise RekorVerificationError(
            "checkpoint signature invalid against the pinned log key: "
            "checkpoint is forged, tampered, or from a different log") from e
