#!/usr/bin/env python3
"""
Titan Gate Receipt Verifier
TRS-1 (Titan Receipt Standard) v1.0.0 — plus ed25519-v1 signing (WO-1)

HMAC path (signing_version: hmac-sha256-v1): Python standard library only,
zero dependencies, behavior byte-identical to titan-verify 1.0.0.
Ed25519 path (signing_version: ed25519-v1): requires the `cryptography`
package, imported lazily — installing nothing still gives a fully working
legacy verifier.

Usage:
    titan-verify <receipt.json> --key <hex_key>            # legacy TRS-1 / HMAC
    titan-verify <receipt.json> --pubkey <pubkey_file>     # ed25519-v1 (public key only)
"""

import argparse
import hashlib
import hmac
import json
import sys

__version__ = "1.1.0"
__spec__ = "TRS-1 v1.0.0 (+ ed25519-v1)"

# NOTE (WO-3): api/receipt_signing.py defines an identical EXCLUSION_FIELDS and
# canonical_bytes. Confirmed IDENTICAL as of this patch (the divergence logged
# for WO-3 did not reproduce). Two definitions is still one too many — unify
# into a single shared module in TRS-2 (WO-3). Do NOT edit one without the
# other; the ed25519 branch below verifies bytes signed via the api copy.
EXCLUSION_FIELDS = {"signature", "receipt_hash", "prev_receipt_hash_verified", "_debug", "_meta"}


REQUIRED_FIELDS = [
    "schema_version", "receipt_id", "tenant_id", "repo", "repo_full_name",
    "pr_number", "evaluated_at", "root_date", "engine_version",
    "contract_version", "scoring_formula_version", "policy_version",
    "merkle_algorithm", "signing_version", "structural_score",
    "semantic_score", "composite_score", "verdict",
    "hard_violations", "process_violations",
    "artifact_hash", "scope_hash", "provenance_hash",
    "prev_receipt_hash", "receipt_hash", "signature", "ai_attributed",
]


def canonical_bytes(receipt):
    filtered = {k: v for k, v in receipt.items() if k not in EXCLUSION_FIELDS}
    return json.dumps(filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_receipt(path, key_hex=None, fmt="text", quiet=False, pubkey_path=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            receipt = json.load(f)
    except FileNotFoundError:
        _output(fmt, ok=False, err_code="ERR_FILE_NOT_FOUND", message=f"File not found: {path}", quiet=quiet)
        return 2
    except json.JSONDecodeError as e:
        _output(fmt, ok=False, err_code="ERR_JSON_INVALID", message=f"Invalid JSON: {e}", quiet=quiet)
        return 2

    # Guarded, not moved: preserves the legacy error-precedence exactly when
    # --key is supplied (case check fires before required-field checks, as in
    # 1.0.0). Only skipped when no --key was given (pubkey-mode invocations).
    if key_hex is not None:
        key_hex = key_hex.strip()
        if key_hex != key_hex.lower():
            _output(fmt, ok=False, err_code="ERR_HEX_CASE_INVALID", message="Key must be lowercase hex", quiet=quiet)
            return 2

    for field in REQUIRED_FIELDS:
        if field not in receipt:
            _output(fmt, ok=False, err_code="ERR_SCHEMA_INVALID", message=f"Missing required field: {field}", quiet=quiet)
            return 1

    if receipt.get("schema_version") != "receipt_v1":
        _output(fmt, ok=False, err_code="ERR_SCHEMA_VERSION", message=f"Unsupported schema version", quiet=quiet)
        return 1

    signing_version = receipt.get("signing_version")
    if signing_version == "hmac-sha256-v1":
        return _verify_hmac(receipt, key_hex, fmt, quiet)
    if signing_version == "ed25519-v1":
        return _verify_ed25519(receipt, pubkey_path, fmt, quiet)
    _output(fmt, ok=False, err_code="ERR_SIGNING_VERSION_UNKNOWN", message=f"Unsupported signing version: {signing_version}", quiet=quiet)
    return 1


def _verify_hmac(receipt, key_hex, fmt, quiet):
    """Legacy TRS-1 verification. Body below is the 1.0.0 code moved verbatim;
    only the missing-key guard is new (previously argparse enforced --key)."""
    if key_hex is None:
        _output(fmt, ok=False, err_code="ERR_KEY_REQUIRED",
                message="hmac-sha256-v1 receipts require --key <hex_key>", quiet=quiet)
        return 2

    signing_version = receipt.get("signing_version")

    sig = receipt.get("signature", "")
    if len(sig) != 64:
        _output(fmt, ok=False, err_code="ERR_SIG_INVALID_LENGTH", message=f"Signature must be 64 hex chars, got {len(sig)}", quiet=quiet)
        return 1

    canon = canonical_bytes(receipt)
    computed_hash = hashlib.sha256(canon).hexdigest()
    stored_hash = receipt.get("receipt_hash", "")
    hash_valid = hmac.compare_digest(computed_hash, stored_hash)

    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        _output(fmt, ok=False, err_code="ERR_KEY_INVALID", message="Key is not valid hex", quiet=quiet)
        return 2

    expected_sig = hmac.new(key_bytes, canon, hashlib.sha256).hexdigest()
    sig_valid = hmac.compare_digest(expected_sig, sig)

    prev_hash = receipt.get("prev_receipt_hash", "")
    if prev_hash == "GENESIS":
        chain_status = "GENESIS"
    elif prev_hash and len(prev_hash) == 64:
        chain_status = "VALID"
    else:
        chain_status = "UNKNOWN"

    overall_valid = hash_valid and sig_valid

    receipt_id = receipt.get("receipt_id", "unknown")
    tenant = receipt.get("tenant_id", "unknown")
    repo = receipt.get("repo_full_name", receipt.get("repo", "unknown"))
    verdict = receipt.get("verdict", "unknown")
    score = receipt.get("composite_score", 0)
    evaluated_at = receipt.get("evaluated_at", "unknown")
    receipt_hash = receipt.get("receipt_hash", "unknown")

    if overall_valid:
        _output(fmt, ok=True, receipt_id=receipt_id, tenant=tenant, repo=repo,
                verdict=verdict, score=score, evaluated_at=evaluated_at,
                receipt_hash=receipt_hash, sig_valid=sig_valid, hash_valid=hash_valid,
                chain_status=chain_status, signing_version=signing_version,
                merkle_algorithm=receipt.get("merkle_algorithm", "merkle_v1"), quiet=quiet)
        return 0
    else:
        err_code = "ERR_SIG" if not sig_valid else "ERR_HASH"
        anomaly = "SIGNATURE_MISMATCH" if not sig_valid else "HASH_MISMATCH"
        _output(fmt, ok=False, err_code=err_code, message=f"ANOMALY: {anomaly}",
                receipt_id=receipt_id, tenant=tenant, repo=repo,
                verdict=verdict, score=score, evaluated_at=evaluated_at, quiet=quiet)
        return 1


def _verify_ed25519(receipt, pubkey_path, fmt, quiet):
    """ed25519-v1 verification with the PUBLIC key only (WO-1, kills G1:
    the auditor's verify input can no longer forge). `cryptography` is
    imported lazily so the HMAC path remains zero-dependency."""
    if pubkey_path is None:
        _output(fmt, ok=False, err_code="ERR_PUBKEY_REQUIRED",
                message="ed25519-v1 receipts require --pubkey <pubkey_file>", quiet=quiet)
        return 2

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        _output(fmt, ok=False, err_code="ERR_DEPENDENCY_MISSING",
                message="ed25519-v1 verification requires the 'cryptography' package: pip install cryptography",
                quiet=quiet)
        return 2

    try:
        with open(pubkey_path, "r", encoding="utf-8") as f:
            pub_hex = f.read().strip()
    except FileNotFoundError:
        _output(fmt, ok=False, err_code="ERR_PUBKEY_NOT_FOUND",
                message=f"Public key file not found: {pubkey_path}", quiet=quiet)
        return 2
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    except (ValueError, TypeError) as e:
        _output(fmt, ok=False, err_code="ERR_PUBKEY_INVALID",
                message=f"Public key file is not a valid 32-byte hex Ed25519 key: {e}", quiet=quiet)
        return 2

    signing_version = receipt.get("signing_version")

    sig_hex = receipt.get("signature", "")
    if len(sig_hex) != 128:
        _output(fmt, ok=False, err_code="ERR_SIG_INVALID_LENGTH",
                message=f"Ed25519 signature must be 128 hex chars, got {len(sig_hex)}", quiet=quiet)
        return 1
    try:
        signature = bytes.fromhex(sig_hex)
    except ValueError:
        _output(fmt, ok=False, err_code="ERR_SIG_INVALID",
                message="Signature is not valid hex", quiet=quiet)
        return 1

    # signing_version sits INSIDE the signed body (api/signers.py writes it
    # before signing), so a downgrade edit to the version field invalidates
    # the signature here as well — the CLI inherits the downgrade protection.
    canon = canonical_bytes(receipt)
    computed_hash = hashlib.sha256(canon).hexdigest()
    stored_hash = receipt.get("receipt_hash", "")
    hash_valid = hmac.compare_digest(computed_hash, stored_hash)

    try:
        pub.verify(signature, canon)
        sig_valid = True
    except InvalidSignature:
        sig_valid = False

    prev_hash = receipt.get("prev_receipt_hash", "")
    if prev_hash == "GENESIS":
        chain_status = "GENESIS"
    elif prev_hash and len(prev_hash) == 64:
        chain_status = "VALID"
    else:
        chain_status = "UNKNOWN"

    overall_valid = hash_valid and sig_valid

    receipt_id = receipt.get("receipt_id", "unknown")
    tenant = receipt.get("tenant_id", "unknown")
    repo = receipt.get("repo_full_name", receipt.get("repo", "unknown"))
    verdict = receipt.get("verdict", "unknown")
    score = receipt.get("composite_score", 0)
    evaluated_at = receipt.get("evaluated_at", "unknown")
    receipt_hash = receipt.get("receipt_hash", "unknown")

    if overall_valid:
        _output(fmt, ok=True, receipt_id=receipt_id, tenant=tenant, repo=repo,
                verdict=verdict, score=score, evaluated_at=evaluated_at,
                receipt_hash=receipt_hash, sig_valid=sig_valid, hash_valid=hash_valid,
                chain_status=chain_status, signing_version=signing_version,
                merkle_algorithm=receipt.get("merkle_algorithm", "merkle_v1"), quiet=quiet)
        return 0
    else:
        err_code = "ERR_SIG" if not sig_valid else "ERR_HASH"
        anomaly = "SIGNATURE_MISMATCH" if not sig_valid else "HASH_MISMATCH"
        _output(fmt, ok=False, err_code=err_code, message=f"ANOMALY: {anomaly}",
                receipt_id=receipt_id, tenant=tenant, repo=repo,
                verdict=verdict, score=score, evaluated_at=evaluated_at, quiet=quiet)
        return 1


def _output(fmt, ok, err_code=None, message=None, receipt_id=None,
            tenant=None, repo=None, verdict=None, score=None,
            evaluated_at=None, receipt_hash=None, sig_valid=None,
            hash_valid=None, chain_status=None, signing_version=None,
            merkle_algorithm=None, quiet=False):

    if fmt == "json":
        result = {
            "ok": ok, "result": "VALID" if ok else "INVALID",
            "err_code": err_code, "message": message,
            "receipt_id": receipt_id, "receipt_hash": receipt_hash,
            "signature_valid": sig_valid, "receipt_hash_valid": hash_valid,
            "chain_status": chain_status, "signing_version": signing_version,
            "merkle_algorithm": merkle_algorithm, "verdict": verdict,
        }
        if not quiet:
            print(json.dumps(result, indent=2))
        return

    if quiet and ok:
        return

    print("=" * 60)
    print("TITAN GATE RECEIPT VERIFICATION")
    print("=" * 60)
    if receipt_id:
        print(f"Receipt ID   : {receipt_id}")
    if tenant:
        print(f"Tenant       : {tenant}")
    if repo:
        print(f"Repo         : {repo}")
    if verdict:
        print(f"Verdict      : {verdict}")
    if score is not None:
        print(f"Score        : {score}")
    if evaluated_at:
        print(f"Evaluated At : {evaluated_at}")
    print("-" * 60)
    if ok:
        print(f"VERIFICATION  : PASS")
        print(f"Signature     : VALID")
        print(f"Hash          : VALID")
        if chain_status:
            print(f"Chain         : {chain_status}")
    else:
        print(f"VERIFICATION  : FAIL")
        if message:
            print(f"  {message}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        prog="titan-verify",
        description="Titan Gate Receipt Verifier — TRS-1 v1.0.0 (+ ed25519-v1)",
    )
    parser.add_argument("receipt", help="Path to receipt JSON file")
    parser.add_argument("--key", help="Hex-encoded HMAC signing key (hmac-sha256-v1 receipts)")
    parser.add_argument("--pubkey", help="Path to Ed25519 public key file, 32-byte hex (ed25519-v1 receipts)")
    parser.add_argument("--format", default="text", choices=["text", "json"])
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args()

    if args.version:
        print(f"titan-verify {__version__} ({__spec__})")
        sys.exit(0)

    sys.exit(verify_receipt(path=args.receipt, key_hex=args.key, fmt=args.format,
                            quiet=args.quiet, pubkey_path=args.pubkey))


if __name__ == "__main__":
    main()
