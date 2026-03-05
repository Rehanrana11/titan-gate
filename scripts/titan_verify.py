#!/usr/bin/env python3
import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.replay import replay_verify


def load_receipt(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def print_result(receipt, result, verbose=False):
    rid = receipt.get("receipt_id", "unknown")
    tenant = receipt.get("tenant_id", "unknown")
    repo = receipt.get("repo_full_name", "unknown")
    verdict = receipt.get("verdict", "unknown")
    score = receipt.get("composite_score", "unknown")
    evaluated = receipt.get("evaluated_at", "unknown")

    print("=" * 60)
    print("TITAN GATE RECEIPT VERIFICATION")
    print("=" * 60)
    print(f"Receipt ID   : {rid}")
    print(f"Tenant       : {tenant}")
    print(f"Repo         : {repo}")
    print(f"Verdict      : {verdict}")
    print(f"Score        : {score}")
    print(f"Evaluated At : {evaluated}")
    print("-" * 60)

    if result["ok"]:
        print("VERIFICATION  : PASS")
        print("Signature     : VALID")
        print("Hash          : VALID")
    else:
        print("VERIFICATION  : FAIL")
        for anomaly in result["anomalies"]:
            atype = anomaly.get("type", "UNKNOWN")
            print(f"  ANOMALY: {atype}")
            if verbose:
                for k, v in anomaly.items():
                    if k != "type":
                        print(f"    {k}: {v}")

    if verbose:
        print("-" * 60)
        hv = receipt.get("hard_violations", [])
        pv = receipt.get("process_violations", [])
        if hv:
            print(f"Hard Violations ({len(hv)}):")
            for v in hv:
                print(f"  [{v.get('code')}] {v.get('description')}")
        if pv:
            print(f"Process Violations ({len(pv)}):")
            for v in pv:
                print(f"  [{v.get('code')}] {v.get('description')}")
        controls = receipt.get("soc2_controls", [])
        if controls:
            failed = [c for c in controls if not c.get("satisfied")]
            print(f"SOC2 Controls : {len(controls) - len(failed)}/{len(controls)} satisfied")

    print("=" * 60)
    return result["ok"]


def main():
    parser = argparse.ArgumentParser(
        description="Titan Gate Receipt Verifier",
        epilog="Verifies HMAC signature and hash integrity of a Titan Gate receipt."
    )
    parser.add_argument("receipt", help="Path to receipt.json file")
    parser.add_argument("--key", required=True, help="HMAC key (hex string)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show full details")
    parser.add_argument("--json", dest="json_output", action="store_true",
                        help="Output result as JSON")
    args = parser.parse_args()

    if not os.path.exists(args.receipt):
        print(f"ERROR: File not found: {args.receipt}", file=sys.stderr)
        sys.exit(2)

    try:
        receipt = load_receipt(args.receipt)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON: {e}", file=sys.stderr)
        sys.exit(2)

    result = replay_verify(receipt, args.key)

    if args.json_output:
        output = {
            "ok": result["ok"],
            "receipt_id": receipt.get("receipt_id"),
            "tenant_id": receipt.get("tenant_id"),
            "verdict": receipt.get("verdict"),
            "composite_score": receipt.get("composite_score"),
            "anomalies": result["anomalies"],
        }
        print(json.dumps(output, indent=2))
        sys.exit(0 if result["ok"] else 1)

    ok = print_result(receipt, result, verbose=args.verbose)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
