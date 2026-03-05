from api.receipt_signing import canonical_bytes, verify_signature
import hashlib


def replay_verify(receipt: dict, key_hex: str) -> dict:
    anomalies = []
    cb = canonical_bytes(receipt)
    computed_hash = hashlib.sha256(cb).hexdigest()
    if computed_hash != receipt.get("receipt_hash"):
        anomalies.append({
            "type": "RECEIPT_HASH_MISMATCH",
            "expected": computed_hash,
            "actual": receipt.get("receipt_hash"),
        })
    if not verify_signature(receipt, key_hex):
        anomalies.append({"type": "SIGNATURE_MISMATCH"})
    return {"ok": len(anomalies) == 0, "anomalies": anomalies}

