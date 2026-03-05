#!/usr/bin/env python3
import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.anchor import build_anchor, compute_anchor_payload_hash
from api.merkle import compute_merkle_root, make_leaf_string
from api.constants import ENGINE_VERSION


def load_receipts_for_date(receipts_dir, tenant_id, root_date):
    receipts = []
    if not os.path.exists(receipts_dir):
        return receipts
    for fname in sorted(os.listdir(receipts_dir)):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(receipts_dir, fname)
        try:
            with open(path) as f:
                r = json.load(f)
            if (r.get("tenant_id") == tenant_id and
                    r.get("root_date") == root_date):
                receipts.append(r)
        except Exception:
            continue
    return receipts


def get_anchor_path(base_dir, tenant_id, repo_name, root_date):
    return os.path.join(
        base_dir, ".titan-gate", "anchors",
        tenant_id, repo_name, f"{root_date}.json"
    )


def seal_daily_root(tenant_id, repo_full_name, root_date, receipts, base_dir):
    repo_name = repo_full_name.replace("/", "_")
    anchor_path = get_anchor_path(base_dir, tenant_id, repo_name, root_date)

    if os.path.exists(anchor_path):
        existing = json.load(open(anchor_path))
        if existing.get("status") == "promoted":
            print(f"SEALED: anchor already promoted for {root_date}")
            return existing, False

    os.makedirs(os.path.dirname(anchor_path), exist_ok=True)

    sealed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    anchor = build_anchor(tenant_id, repo_full_name, root_date, receipts)
    anchor["sealed_at"] = sealed_at
    anchor["status"] = "promoted"
    anchor["promoted_at"] = sealed_at
    anchor["engine_version"] = ENGINE_VERSION
    anchor["payload_hash"] = compute_anchor_payload_hash(anchor)

    with open(anchor_path, "w") as f:
        json.dump(anchor, f, indent=2)

    return anchor, True


def main():
    parser = argparse.ArgumentParser(
        description="Titan Gate Daily Merkle Root Sealer"
    )
    parser.add_argument("--tenant", required=True, help="Tenant ID")
    parser.add_argument("--repo", required=True, help="Repo full name (org/repo)")
    parser.add_argument("--date", help="Date to seal (YYYY-MM-DD, default: today)")
    parser.add_argument("--receipts-dir", default="receipts",
                        help="Directory containing receipt JSON files")
    parser.add_argument("--dir", default=".", help="Project root directory")
    parser.add_argument("--receipt-files", nargs="*",
                        help="Explicit receipt files to include")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    root_date = args.date or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if args.receipt_files:
        receipts = []
        for path in args.receipt_files:
            with open(path) as f:
                receipts.append(json.load(f))
    else:
        receipts = load_receipts_for_date(
            args.receipts_dir, args.tenant, root_date
        )

    if not receipts:
        print(f"WARNING: No receipts found for {args.tenant} on {root_date}")
        print("Sealing empty anchor.")

    anchor, is_new = seal_daily_root(
        args.tenant, args.repo, root_date, receipts, args.dir
    )

    if is_new:
        print(f"SEALED: {root_date}")
        print(f"  Tenant       : {anchor['tenant_id']}")
        print(f"  Repo         : {anchor['repo_full_name']}")
        print(f"  Receipts     : {anchor['receipt_count']}")
        print(f"  Merkle Root  : {anchor['merkle_root']}")
        print(f"  Payload Hash : {anchor['payload_hash']}")
        print(f"  Sealed At    : {anchor['sealed_at']}")
        repo_name = args.repo.replace("/", "_")
        path = get_anchor_path(args.dir, args.tenant, repo_name, root_date)
        print(f"  Anchor Path  : {path}")
    else:
        print(f"SKIPPED: already sealed")

    if args.verbose and receipts:
        print(f"\nReceipts included ({len(receipts)}):")
        for r in receipts:
            print(f"  [{r.get('verdict')}] {r.get('receipt_id')} score={r.get('composite_score')}")

    sys.exit(0)


if __name__ == "__main__":
    main()
