#!/usr/bin/env python3
import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.anchor import compute_anchor_payload_hash, ANCHOR_SCHEMA
from api.merkle import compute_merkle_root, make_leaf_string, MERKLE_ALGORITHM


def load_anchor(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def verify_anchor_integrity(anchor):
    anomalies = []
    if anchor.get("schema") != ANCHOR_SCHEMA:
        anomalies.append("SCHEMA_MISMATCH")
    if anchor.get("merkle_algorithm") != MERKLE_ALGORITHM:
        anomalies.append("ALGORITHM_MISMATCH")
    stored_hash = anchor.get("payload_hash")
    computed_hash = compute_anchor_payload_hash(anchor)
    if stored_hash != computed_hash:
        anomalies.append("PAYLOAD_HASH_MISMATCH")
    return anomalies


def display_anchor(anchor, verbose=False):
    print("=" * 60)
    print("TITAN GATE ANCHOR")
    print("=" * 60)
    print(f"Schema        : {anchor.get('schema')}")
    print(f"Tenant        : {anchor.get('tenant_id')}")
    print(f"Repo          : {anchor.get('repo_full_name')}")
    print(f"Date          : {anchor.get('date')}")
    print(f"Status        : {anchor.get('status', 'unknown').upper()}")
    print(f"Receipt Count : {anchor.get('receipt_count', 0)}")
    print(f"Merkle Root   : {anchor.get('merkle_root')}")
    print(f"Payload Hash  : {anchor.get('payload_hash')}")
    anomalies = verify_anchor_integrity(anchor)
    if anomalies:
        print(f"Integrity     : FAIL")
        for a in anomalies:
            print(f"  ANOMALY: {a}")
    else:
        print(f"Integrity     : PASS")
    if verbose:
        sealed = anchor.get("sealed_at")
        promoted = anchor.get("promoted_at")
        if sealed:
            print(f"Sealed At     : {sealed}")
        if promoted:
            print(f"Promoted At   : {promoted}")
        notes = anchor.get("notes")
        if notes:
            print(f"Notes         : {notes}")
    print("=" * 60)
    return len(anomalies) == 0


def scan_anchor_directory(base_dir, tenant_id=None, verbose=False):
    anchor_base = os.path.join(base_dir, ".titan-gate", "anchors")
    if not os.path.exists(anchor_base):
        print(f"No anchor directory found at: {anchor_base}", file=sys.stderr)
        return []

    results = []
    for tid in sorted(os.listdir(anchor_base)):
        if tenant_id and tid != tenant_id:
            continue
        tenant_path = os.path.join(anchor_base, tid)
        if not os.path.isdir(tenant_path):
            continue
        for repo in sorted(os.listdir(tenant_path)):
            repo_path = os.path.join(tenant_path, repo)
            if not os.path.isdir(repo_path):
                continue
            for fname in sorted(os.listdir(repo_path)):
                if not fname.endswith(".json"):
                    continue
                fpath = os.path.join(repo_path, fname)
                try:
                    anchor = load_anchor(fpath)
                    ok = display_anchor(anchor, verbose=verbose)
                    results.append({"path": fpath, "ok": ok, "anchor": anchor})
                except Exception as e:
                    print(f"ERROR loading {fpath}: {e}", file=sys.stderr)
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Titan Gate Anchor Explorer",
        epilog="Inspect and verify Titan Gate anchor files."
    )
    subparsers = parser.add_subparsers(dest="command")

    inspect_p = subparsers.add_parser("inspect", help="Inspect a single anchor file")
    inspect_p.add_argument("anchor", help="Path to anchor JSON file")
    inspect_p.add_argument("--verbose", "-v", action="store_true")
    inspect_p.add_argument("--json", dest="json_output", action="store_true")

    scan_p = subparsers.add_parser("scan", help="Scan anchor directory")
    scan_p.add_argument("--dir", default=".", help="Project root directory")
    scan_p.add_argument("--tenant", help="Filter by tenant ID")
    scan_p.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    if args.command == "inspect":
        if not os.path.exists(args.anchor):
            print(f"ERROR: File not found: {args.anchor}", file=sys.stderr)
            sys.exit(2)
        anchor = load_anchor(args.anchor)
        if args.json_output:
            anomalies = verify_anchor_integrity(anchor)
            print(json.dumps({
                "ok": len(anomalies) == 0,
                "tenant_id": anchor.get("tenant_id"),
                "date": anchor.get("date"),
                "status": anchor.get("status"),
                "merkle_root": anchor.get("merkle_root"),
                "receipt_count": anchor.get("receipt_count"),
                "anomalies": anomalies,
            }, indent=2))
            sys.exit(0 if not anomalies else 1)
        ok = display_anchor(anchor, verbose=args.verbose)
        sys.exit(0 if ok else 1)

    elif args.command == "scan":
        results = scan_anchor_directory(args.dir, args.tenant, args.verbose)
        total = len(results)
        passed = sum(1 for r in results if r["ok"])
        print(f"Scanned {total} anchor(s): {passed} passed, {total-passed} failed")
        sys.exit(0 if total == passed else 1)

    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
