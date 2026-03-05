import hashlib
import json
from api.merkle import compute_merkle_root, make_leaf_string

ANCHOR_SCHEMA = "anchor_v1"


def compute_anchor_payload_hash(anchor: dict) -> str:
    exclude = {"payload_hash", "signature"}
    filtered = {k: v for k, v in anchor.items() if k not in exclude}
    cb = json.dumps(
        filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(cb).hexdigest()


def build_anchor(tenant_id, repo_full_name, date, receipts, status="pending"):
    leaves = [
        make_leaf_string(tenant_id, date, r["receipt_id"], r["receipt_hash"])
        for r in receipts
    ]
    root = compute_merkle_root(leaves)
    anchor = {
        "schema": ANCHOR_SCHEMA,
        "tenant_id": tenant_id,
        "repo_full_name": repo_full_name,
        "date": date,
        "merkle_root": root,
        "merkle_algorithm": "merkle_v1",
        "receipt_count": len(receipts),
        "status": status,
        "anchored_at": None,
        "promoted_at": None,
    }
    anchor["payload_hash"] = compute_anchor_payload_hash(anchor)
    return anchor
