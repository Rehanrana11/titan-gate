#!/usr/bin/env python3
"""
chain_state must reject hostile input as ChainStateError, never by escaping
with an unhandled exception.

Found by BATTERY-24 T01 (structure-aware fuzzing), T08 (fault injection) and
T09 (resource exhaustion). All three are ONE defect: latest_receipt_hash
assumes json.loads returned a dict, and assumes schema_version is hashable.

    json.loads("null")          -> None    -> r.get(...)   AttributeError
    json.loads("[]")            -> []      -> r.get(...)   AttributeError
    json.loads("[[[[...]]]]")   -> list    -> r.get(...)   AttributeError
    {"schema_version": {}}      -> dict    -> profiles.add() TypeError

Why it matters beyond tidiness: chain_state is the ONE way writers learn the
chain head, and receipts_root is a directory. Anything that can drop a file
there -- a partial write, a synced folder, a misrouted upload, an attacker with
write access to a share -- can make every subsequent write crash with a
traceback instead of a named, catchable ChainStateError. The module's own
docstring promises: "Any ambiguity is a hard error, never a guess." An
AttributeError is not a hard error, it is an unhandled one.

These are plain assertions, not xfails: this is a defect to fix, not a
limitation to record.
"""
import json

import pytest

from titan_gate.chain_state import ChainStateError, latest_receipt_hash

NON_OBJECT_DOCUMENTS = [
    pytest.param("null", id="null-document"),
    pytest.param("[]", id="empty-array"),
    pytest.param('["receipt_hash", "prev_receipt_hash"]', id="array-of-strings"),
    pytest.param('"a string"', id="bare-string"),
    pytest.param("42", id="bare-number"),
    pytest.param("true", id="bare-bool"),
    pytest.param("[" * 200 + "]" * 200, id="deeply-nested-array"),
]

UNHASHABLE_SCHEMA_VERSIONS = [
    pytest.param({}, id="dict"),
    pytest.param([], id="list"),
    pytest.param(["receipt_v1"], id="list-wrapping-a-valid-value"),
]


def _put(tmp_path, content):
    (tmp_path / "000.json").write_text(content, encoding="utf-8")


@pytest.mark.parametrize("document", NON_OBJECT_DOCUMENTS)
def test_non_object_json_is_a_chain_state_error(tmp_path, document):
    """Valid JSON that is not an object must be named, not crashed on."""
    _put(tmp_path, document)
    with pytest.raises(ChainStateError):
        latest_receipt_hash(tmp_path)


@pytest.mark.parametrize("value", UNHASHABLE_SCHEMA_VERSIONS)
def test_unhashable_schema_version_is_a_chain_state_error(tmp_path, value):
    """profiles.add() requires a hashable. An attacker picks the type."""
    _put(tmp_path, json.dumps({
        "schema_version": value,
        "receipt_hash": "a" * 64,
        "prev_receipt_hash": "GENESIS",
    }))
    with pytest.raises(ChainStateError):
        latest_receipt_hash(tmp_path)


def test_one_bad_file_does_not_hide_behind_a_good_one(tmp_path):
    """Files are walked in sorted order. A later bad file must still be named,
    not skipped because an earlier one parsed."""
    (tmp_path / "000.json").write_text(json.dumps({
        "schema_version": "receipt_v1",
        "receipt_hash": "b" * 64,
        "prev_receipt_hash": "GENESIS",
    }), encoding="utf-8")
    (tmp_path / "001.json").write_text("null", encoding="utf-8")
    with pytest.raises(ChainStateError):
        latest_receipt_hash(tmp_path)


def test_error_names_the_offending_file(tmp_path):
    """Operators need to know WHICH file. Every other error in this module
    names its path; these must too."""
    _put(tmp_path, "null")
    with pytest.raises(ChainStateError) as exc:
        latest_receipt_hash(tmp_path)
    assert "000.json" in str(exc.value), (
        "error did not name the offending file: %s" % exc.value)


def test_valid_object_still_works(tmp_path):
    """Scope guard: the type check must not reject well-formed receipts."""
    import hashlib
    from titan_gate.canonical import canonical_bytes
    r = {"schema_version": "receipt_v1", "tenant_id": "t", "seq": 0,
         "prev_receipt_hash": "GENESIS"}
    r["receipt_hash"] = hashlib.sha256(canonical_bytes(r)).hexdigest()
    _put(tmp_path, json.dumps(r))
    assert latest_receipt_hash(tmp_path) == r["receipt_hash"]
