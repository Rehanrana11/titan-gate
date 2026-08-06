"""Canonical serialization for Titan Gate receipts — the ONE definition.

Extracted in WO-3 from the duplicated copies in api/receipt_signing.py and
titan_gate/verify.py (which were byte-identical but independently maintained;
the stale-verify.py incident proved that duplication can diverge silently).
Both writer and verifier import from here. Do not redefine these symbols
anywhere else — tests/test_wo3_canonical_module.py enforces this by identity.

TRS-1 semantics, golden-pinned: sorted-keys compact JSON, UTF-8, with
signature-adjacent fields excluded from the signed/hashed body.
TRS-2 (JCS/RFC 8785) will be added here as a separate function, never by
modifying this one.
"""
import json
from typing import Any, Dict

EXCLUSION_FIELDS = {"signature", "receipt_hash", "prev_receipt_hash_verified", "_debug", "_meta"}


def canonical_bytes(receipt: Dict[str, Any]) -> bytes:
    filtered = {k: v for k, v in receipt.items() if k not in EXCLUSION_FIELDS}
    return json.dumps(
        filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
