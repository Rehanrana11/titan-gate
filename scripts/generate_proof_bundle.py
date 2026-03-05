#!/usr/bin/env python3
import argparse
import json
import os
import sys
import hashlib
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.merkle import compute_merkle_root, make_leaf_string, leaf_hash, MERKLE_ALGORITHM
from api.anchor import build_anchor
from api.constants import ENGINE_VERSION, CONTRACT_VERSION


def load_receipts(paths):
    receipts = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            receipts.append(json.load(f))
    return receipts


def build_merkle_proof(leaves, target_leaf):
    sorted_leaves = sorted(leaves)
    if not sorted_leaves:
        return []
    proof = []
    idx = sorted_leaves.index(target_leaf)
    hashes = [leaf_hash(l) for l in sorted_leaves]
    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        sibling_idx = idx ^ 1
        proof.append({
            "sibling": hashes[sibling_idx],
            "position": "right" if idx % 2 == 0 else "left",
        })
        hashes = [
            hashlib.sha256(
                b"N|" + bytes.fromhex(hashes[i]) + bytes.fromhex(hashes[i+1])
            ).hexdigest()
            for i in range(0, len(hashes), 2)
        ]
        idx //= 2
    return proof


def generate_proof_bundle(receipts, tenant_id, repo_full_name, output_path):
    if not receipts:
        raise ValueError("No receipts provided")

    root_date = receipts[0].get("root_date", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    leaves = [
        make_leaf_string(
            r.get("tenant_id", tenant_id),
            r.get("root_date", root_date),
            r["receipt_id"],
            r["receipt_hash"],
        )
        for r in receipts
    ]

    merkle_root = compute_merkle_root(leaves)
    anchor = build_anchor(tenant_id, repo_full_name, root_date, receipts)

    receipt_proofs = []
    for i, receipt in enumerate(receipts):
        proof = build_merkle_proof(leaves, leaves[i])
        receipt_proofs.append({
            "receipt_id": receipt["receipt_id"],
            "receipt_hash": receipt["receipt_hash"],
            "leaf_string": leaves[i],
            "leaf_hash": leaf_hash(leaves[i]),
            "merkle_proof": proof,
            "verdict": receipt.get("verdict"),
            "composite_score": receipt.get("composite_score"),
            "evaluated_at": receipt.get("evaluated_at"),
        })

    bundle = {
        "schema": "proof_bundle_v1",
        "generated_at": generated_at,
        "engine_version": ENGINE_VERSION,
        "contract_version": CONTRACT_VERSION,
        "merkle_algorithm": MERKLE_ALGORITHM,
        "tenant_id": tenant_id,
        "repo_full_name": repo_full_name,
        "root_date": root_date,
        "merkle_root": merkle_root,
        "receipt_count": len(receipts),
        "anchor": anchor,
        "receipts": receipt_proofs,
        "verification_instructions": {
            "step1": "Verify each receipt signature using titan_verify.py",
            "step2": "Recompute leaf hash: SHA256('L|' + leaf_string)",
            "step3": "Walk merkle_proof to recompute root",
            "step4": "Compare computed root with merkle_root field",
            "step5": "Compare merkle_root with anchor.merkle_root",
        },
    }

    bundle_hash = hashlib.sha256(
        json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    bundle["bundle_hash"] = bundle_hash

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)

    return bundle


def main():
    parser = argparse.ArgumentParser(
        description="Titan Gate Proof Bundle Generator",
        epilog="Generates a self-contained cryptographic proof bundle from receipts."
    )
    parser.add_argument("receipts", nargs="+", help="Paths to receipt JSON files")
    parser.add_argument("--tenant", required=True, help="Tenant ID")
    parser.add_argument("--repo", required=True, help="Repo full name (org/repo)")
    parser.add_argument("--output", "-o", default="proof_bundle.json",
                        help="Output path (default: proof_bundle.json)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    missing = [p for p in args.receipts if not os.path.exists(p)]
    if missing:
        for m in missing:
            print(f"ERROR: File not found: {m}", file=sys.stderr)
        sys.exit(2)

    receipts = load_receipts(args.receipts)
    bundle = generate_proof_bundle(receipts, args.tenant, args.repo, args.output)

    print(f"Proof bundle generated: {args.output}")
    print(f"  Receipts   : {bundle['receipt_count']}")
    print(f"  Merkle root: {bundle['merkle_root']}")
    print(f"  Bundle hash: {bundle['bundle_hash']}")

    if args.verbose:
        for r in bundle["receipts"]:
            print(f"  [{r['verdict']}] {r['receipt_id']} score={r['composite_score']}")

    sys.exit(0)


if __name__ == "__main__":
    main()
