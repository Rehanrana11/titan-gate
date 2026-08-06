"""TRS-2 receipt writer: build, digest, and verify agent-action receipts.

Trust-domain seam (Rule 1, FRD FR-KEY-1): this module holds NO key
material and cannot sign. Signing is requested via an injected sign_fn
callable — the V3->C1 relationship at module scale. sign_fn receives
the 32 raw SHA-256 digest bytes and returns the Ed25519 signature
bytes; today's callers inject a local signer, WO-7 swaps in an HTTP
call to the customer-side container with no change here.

Verification requires only a PUBLIC key. This module may import the
public-key type; it must never import a signing-capable type, key
env-var name, or anything from the api/ layer (executable lint:
tests/test_wo34_trs2_writer.py::test_writer_module_imports_no_key_material).

Digest rule (SPEC-2 §4 / FRD §2.2): body = receipt minus sig and the
stored receipt_hash; digest = SHA-256(JCS(body)). The body INCLUDES
prev_receipt_hash — the chain link is under the signature.
"""
import hashlib
import re
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from titan_gate.canonical import canonical_bytes_jcs, JCSError
from titan_gate.trs2 import build_trs2_event, TRS2SchemaError

__all__ = [
    "build_trs2_receipt",
    "verify_trs2_receipt",
    "TRS2ReceiptError",
    "TRS2_SCHEMA_VERSION",
]

TRS2_SCHEMA_VERSION = "receipt_trs2_v1"
_SIG_ALG = "ed25519-v1"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

RECEIPT_FIELDS = frozenset({
    "schema_version", "receipt_id", "tenant_id", "seq",
    "prev_receipt_hash", "event", "receipt_hash", "sig",
})
SIG_FIELDS = frozenset({"key_id", "alg", "value"})


class TRS2ReceiptError(ValueError):
    """Receipt failed structural validation or cryptographic verification."""


def _body_digest_hex(body: dict) -> str:
    try:
        return hashlib.sha256(canonical_bytes_jcs(body)).hexdigest()
    except JCSError as e:
        raise TRS2ReceiptError(f"body not canonicalizable: {e}") from e


def _check_prev(prev: str) -> None:
    if prev != "GENESIS" and not _HEX64.fullmatch(prev or ""):
        raise TRS2ReceiptError(
            f"prev_receipt_hash must be 'GENESIS' or 64 lowercase hex, got {prev!r}"
        )


def build_trs2_receipt(*, event: dict, tenant_id: str, seq: int,
                       prev_receipt_hash: str, sign_fn, key_id: str) -> dict:
    """Assemble, digest, and sign one TRS-2 receipt.

    event MUST already be valid per titan_gate.trs2 (re-validated here
    so an unvalidated dict cannot slip through a second entry point).
    """
    # Re-validate the event: defense in depth, and rejects a dict that
    # was mutated after build_trs2_event returned it.
    event = build_trs2_event(
        source_id=event.get("source_id"),
        source_event_id=event.get("source_event_id"),
        event_time=event.get("event_time"),
        ingest_time=event.get("ingest_time"),
        agent_ref=event.get("agent_ref"),
        principal_ref=event.get("principal_ref"),
        action=dict(event.get("action") or {}),
        outcome=dict(event.get("outcome") or {}),
    )
    if not isinstance(tenant_id, str) or not tenant_id:
        raise TRS2ReceiptError(f"tenant_id must be a non-empty string, got {tenant_id!r}")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise TRS2ReceiptError(f"seq must be a non-negative int, got {seq!r}")
    if seq == 0 and prev_receipt_hash != "GENESIS":
        raise TRS2ReceiptError("seq 0 requires prev_receipt_hash 'GENESIS'")
    if seq > 0 and prev_receipt_hash == "GENESIS":
        raise TRS2ReceiptError("non-genesis receipt cannot claim GENESIS prev")
    _check_prev(prev_receipt_hash)
    if not isinstance(key_id, str) or not key_id:
        raise TRS2ReceiptError(f"key_id must be a non-empty string, got {key_id!r}")

    body = {
        "schema_version": TRS2_SCHEMA_VERSION,
        # NOTE: FRD §2.2 specifies UUIDv7; stdlib uuid7 lands in 3.14.
        # uuid4 used deliberately for now — seq carries ordering, the id
        # only needs uniqueness. Revisit at 3.14 or if an external
        # consumer needs time-sortable ids. (Conscious deviation, not drift.)
        "receipt_id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "seq": seq,
        "prev_receipt_hash": prev_receipt_hash,
        "event": event,
    }
    digest_hex = _body_digest_hex(body)
    sig_bytes = sign_fn(bytes.fromhex(digest_hex))
    if not isinstance(sig_bytes, bytes) or len(sig_bytes) != 64:
        raise TRS2ReceiptError(
            f"sign_fn must return 64 signature bytes, got {type(sig_bytes).__name__}"
            f"/{len(sig_bytes) if isinstance(sig_bytes, bytes) else 'n-a'}"
        )
    receipt = dict(body)
    receipt["receipt_hash"] = digest_hex
    receipt["sig"] = {"key_id": key_id, "alg": _SIG_ALG, "value": sig_bytes.hex()}
    return receipt


def verify_trs2_receipt(receipt: dict, public_key: Ed25519PublicKey) -> None:
    """Verify one receipt structurally and cryptographically. Raises on any failure.

    Checks: closed field sets, schema_version, prev format, seq/GENESIS
    consistency, event validity, digest recomputation over JCS(body),
    and the Ed25519 signature over the raw digest bytes.
    """
    if not isinstance(receipt, dict):
        raise TRS2ReceiptError("receipt must be a dict")
    unknown = set(receipt) - RECEIPT_FIELDS
    if unknown:
        raise TRS2ReceiptError(f"unknown receipt field(s): {sorted(unknown)}")
    missing = RECEIPT_FIELDS - set(receipt)
    if missing:
        raise TRS2ReceiptError(f"missing receipt field(s): {sorted(missing)}")
    if receipt["schema_version"] != TRS2_SCHEMA_VERSION:
        raise TRS2ReceiptError(
            f"schema_version must be {TRS2_SCHEMA_VERSION!r}, "
            f"got {receipt['schema_version']!r}"
        )
    seq = receipt["seq"]
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise TRS2ReceiptError(f"seq must be a non-negative int, got {seq!r}")
    prev = receipt["prev_receipt_hash"]
    _check_prev(prev)
    if (seq == 0) != (prev == "GENESIS"):
        raise TRS2ReceiptError("seq/GENESIS mismatch")

    sig = receipt["sig"]
    if not isinstance(sig, dict) or set(sig) != SIG_FIELDS:
        raise TRS2ReceiptError("sig must contain exactly key_id, alg, value")
    if sig["alg"] != _SIG_ALG:
        raise TRS2ReceiptError(f"sig.alg must be {_SIG_ALG!r}, got {sig['alg']!r}")

    ev = receipt["event"]
    if not isinstance(ev, dict):
        raise TRS2ReceiptError("event must be a dict")
    try:
        _rebuilt = build_trs2_event(
            source_id=ev.get("source_id"),
            source_event_id=ev.get("source_event_id"),
            event_time=ev.get("event_time"),
            ingest_time=ev.get("ingest_time"),
            agent_ref=ev.get("agent_ref"),
            principal_ref=ev.get("principal_ref"),
            action=dict(ev.get("action") or {}),
            outcome=dict(ev.get("outcome") or {}),
        )
    except TRS2SchemaError as e:
        raise TRS2ReceiptError(f"event invalid: {e}") from e
    else:
        # P11 fix: the rebuild above cherry-picks known fields, so an
        # unknown TOP-LEVEL event field would escape it (nested extras
        # are caught inside build_trs2_event). Rebuilt must equal
        # stored exactly — closes smuggling at every level.
        if _rebuilt != ev:
            extra = sorted(set(ev) - set(_rebuilt))
            raise TRS2ReceiptError(
                f"event contains field(s) outside the closed schema: "
                f"{extra or 'value divergence'} — no field to fill")

    body = {k: v for k, v in receipt.items() if k not in ("sig", "receipt_hash")}
    digest_hex = _body_digest_hex(body)
    if digest_hex != receipt["receipt_hash"]:
        raise TRS2ReceiptError(
            "receipt_hash mismatch: body was altered after signing"
        )
    if not isinstance(sig["value"], str) or not re.fullmatch(r"[0-9a-f]{128}", sig["value"]):
        raise TRS2ReceiptError("sig.value must be 128 lowercase hex chars")
    try:
        public_key.verify(bytes.fromhex(sig["value"]), bytes.fromhex(digest_hex))
    except InvalidSignature as e:
        raise TRS2ReceiptError(
            "signature invalid for this public key over the recomputed digest"
        ) from e
