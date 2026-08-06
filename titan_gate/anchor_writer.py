"""Anchor writer (WO-4.3 part 2a): sign interval root -> submit to
Rekor -> persist the anchor record beside the chain; on external
failure, persist an honest disclosure and proceed.

Trust boundary (Rule 1): holds NO keys. The signature is requested
through the injected sign_fn, which receives the RAW 32 digest bytes
(prehashed contract — plain hash-again signing double-hashes and
Rekor rejects, wire-proven 2026-08-07).

Failure philosophy (FR-RCP-2 shape at one leg):
  - EXTERNAL failure (network, HTTP): write anchor_status.json
    {attempted, ok:false, error, root_hash, timestamp}, RETURN
    degraded status, do not raise. Recording proceeds unanchored but
    DISCLOSED — the degradation is itself evidence.
  - CALLER bug (malformed root, bad signature bytes): RAISE. A
    programming error must never be laundered into a polite
    operational disclosure.
  - Recovery: a later success for the same root overwrites the stale
    failure disclosure, so recovery is as visible as degradation.

Admin-receipt form of this disclosure arrives when TRS-2 gains
receipt_type (WO-6, per the (a)-decision: gap receipts need the spec
change anyway; it lands once, not twice).
"""
import base64
import json
import os
import re
import time
from dataclasses import dataclass

from titan_gate.rekor_client import (
    submit_hashedrekord,
    parse_entry_to_anchor_record,
    RekorClientError,
)

__all__ = ["anchor_root", "AnchorWriteStatus", "AnchorWriterError"]

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class AnchorWriterError(ValueError):
    """Caller-side error: malformed input or a misbehaving sign_fn."""


@dataclass(frozen=True)
class AnchorWriteStatus:
    ok: bool
    root_hash: str
    record_path: str = ""
    error: str = ""


def _status_path(out_dir: str) -> str:
    return os.path.join(out_dir, "anchor_status.json")


def _write_json(path: str, obj: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)  # atomic on same filesystem


def anchor_root(*, root_hash_hex: str, sign_fn, public_key_pem: str,
                base_url: str, out_dir: str,
                timeout: float = 30.0) -> AnchorWriteStatus:
    """Anchor one interval root. Returns status; raises only on caller
    bugs. See module docstring for the failure philosophy."""
    # --- caller-input validation: bugs RAISE, never disclose ---
    if not isinstance(root_hash_hex, str) or not _HEX64.fullmatch(root_hash_hex):
        raise AnchorWriterError(
            f"root_hash_hex must be 64 lowercase hex chars, got "
            f"{root_hash_hex!r}")
    if not callable(sign_fn):
        raise AnchorWriterError("sign_fn must be callable")
    if not isinstance(out_dir, str) or not out_dir:
        raise AnchorWriterError("out_dir must be a non-empty path")
    os.makedirs(out_dir, exist_ok=True)

    # --- sign the RAW digest (prehashed contract) ---
    digest = bytes.fromhex(root_hash_hex)
    sig = sign_fn(digest)
    if not isinstance(sig, bytes) or not sig:
        raise AnchorWriterError(
            f"sign_fn must return non-empty signature bytes, got "
            f"{type(sig).__name__}")

    # --- submit; EXTERNAL failure -> disclosure, not exception ---
    try:
        entry = submit_hashedrekord(
            artifact_hash_hex=root_hash_hex,
            signature_b64=base64.b64encode(sig).decode("ascii"),
            public_key_pem=public_key_pem,
            base_url=base_url, timeout=timeout)
        record = parse_entry_to_anchor_record(entry)
    except RekorClientError as e:
        err = str(e)
        _write_json(_status_path(out_dir), {
            "attempted": True, "ok": False, "root_hash": root_hash_hex,
            "error": err, "timestamp": int(time.time()),
        })
        return AnchorWriteStatus(ok=False, root_hash=root_hash_hex, error=err)

    # --- persist record + recovery-visible status ---
    record_path = os.path.join(out_dir, f"anchor_{root_hash_hex[:16]}.json")
    _write_json(record_path, record)
    _write_json(_status_path(out_dir), {
        "attempted": True, "ok": True, "root_hash": root_hash_hex,
        "error": "", "timestamp": int(time.time()),
    })
    return AnchorWriteStatus(ok=True, root_hash=root_hash_hex,
                             record_path=record_path)
