import hashlib
import hmac as _hmac
import json
from typing import Any, Dict

SIGNING_VERSION = "hmac-sha256-v1"
EXCLUSION_FIELDS = {"signature", "receipt_hash", "prev_receipt_hash_verified", "_debug", "_meta"}


def canonical_bytes(receipt: Dict[str, Any]) -> bytes:
    filtered = {k: v for k, v in receipt.items() if k not in EXCLUSION_FIELDS}
    return json.dumps(
        filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def compute_receipt_hash(receipt: Dict[str, Any]) -> str:
    cb = canonical_bytes(receipt)
    return hashlib.sha256(cb).hexdigest()


def compute_signature(receipt: Dict[str, Any], key_hex: str) -> str:
    cb = canonical_bytes(receipt)
    key = bytes.fromhex(key_hex)
    return _hmac.new(key, cb, hashlib.sha256).hexdigest()


def verify_signature(receipt: Dict[str, Any], key_hex: str) -> bool:
    expected = compute_signature(receipt, key_hex)
    actual = receipt.get("signature", "")
    return _hmac.compare_digest(expected, actual)
