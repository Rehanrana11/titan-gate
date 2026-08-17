#!/usr/bin/env python3
"""
Kills the one mutant that survived the canonical.py mutation run (35/36 = 97.2%).

Survivor: `ensure_ascii=False -> True` at titan_gate/canonical.py:23.

It survived because every existing canonicalization test uses pure-ASCII
fixtures. With ensure_ascii=True the function still returns valid JSON, still
round-trips, and is byte-identical for ASCII input -- it only diverges when the
receipt contains a non-ASCII character, which it then emits as \\uXXXX.

That divergence is not cosmetic. Receipt fields carry free text: pr_title,
repo, repo_full_name, branch, commit message excerpts. An em-dash in a PR
title is enough to change the bytes, and therefore the receipt_hash, and
therefore every signature over it. Two implementations disagreeing on this
flag compute different hashes for the same logical receipt -- a
canonicalization ambiguity in the exact function the product's tamper-evidence
rests on.

Measured divergence (sha256 of canonical_bytes, first 12 hex):
    "Fix - naive"   (ASCII)      identical under both settings
    "Fix - naive"   (em-dash)    3da95e887e90 vs 86c43f5675de
    "review by Jose" (accent)    6f77c5bf0edd vs 5b87e1124f01
    CJK repo name                6ed5e3cc27fd vs 338c2d8107f5
    emoji in title               3fcc3563a849 vs db1360b174d7
"""
import hashlib
import json

import pytest

from titan_gate.canonical import canonical_bytes

NON_ASCII_CASES = [
    pytest.param("Fix — naive encoding", "—", id="em-dash"),
    pytest.param("review by José", "é", id="latin-1-accent"),
    pytest.param("東京-service", "東", id="cjk"),
    pytest.param("ship it \U0001f680", "\U0001f680", id="astral-emoji"),
]


@pytest.mark.parametrize("text,needle", NON_ASCII_CASES)
def test_non_ascii_is_emitted_as_utf8_not_backslash_escaped(text, needle):
    """The mutant killer. ensure_ascii=True would emit \\uXXXX instead."""
    out = canonical_bytes({"pr_title": text})
    assert needle.encode("utf-8") in out, (
        "canonicalization escaped %r instead of emitting UTF-8: %r" % (needle, out))
    # Control chars legitimately escape as \\uXXXX per JSON; these cases carry none,
    # so any \\u here means the encoder escaped a printable non-ASCII character.
    assert b"\\u" not in out, "found a backslash-u escape in canonical bytes: %r" % out


def test_non_ascii_canonicalization_is_byte_pinned():
    """Golden pin. Any change to the TRS-1 canonicalization breaks this first.

    receipt_v1 is golden-pinned and chain_state.py:37 recomputes every stored
    hash through this path, so a silent change here invalidates the whole chain.
    """
    receipt = {
        "branch": "feature/naïve",
        "pr_title": "Fix — encoding",
        "repo": "東京-service",
        "receipt_hash": "excluded-from-canonical-bytes",
    }
    out = canonical_bytes(receipt)
    assert out == (
        b'{"branch":"feature/na\xc3\xafve",'
        b'"pr_title":"Fix \xe2\x80\x94 encoding",'
        b'"repo":"\xe6\x9d\xb1\xe4\xba\xac-service"}'
    )
    assert hashlib.sha256(out).hexdigest() == (
        "49889e09f9a14b4bbf5fcdd07279a6400ff38587818d89e682b23b8b697786bc")


def test_output_is_valid_utf8_and_round_trips():
    """Guard: emitting raw UTF-8 must not produce bytes we cannot read back."""
    receipt = {"pr_title": "Fix — naïve \U0001f680", "repo": "東京"}
    out = canonical_bytes(receipt)
    assert json.loads(out.decode("utf-8")) == receipt


def test_ascii_only_input_is_unaffected():
    """Scope guard: this pin is about non-ASCII, not a general format change.

    If this ever fails, the canonicalization changed for ALL receipts, not just
    the non-ASCII ones -- a far larger break than the mutant this file targets.
    """
    out = canonical_bytes({"pr_title": "Test PR 1", "repo": "test-repo"})
    assert out == b'{"pr_title":"Test PR 1","repo":"test-repo"}'


def test_key_order_is_independent_of_insertion_order():
    """sort_keys=True is the sibling mutant at the same line; it was killed,
    but nothing pinned it together with the encoding. Both now travel together.
    """
    a = canonical_bytes({"repo": "r", "branch": "b", "pr_title": "t"})
    b = canonical_bytes({"pr_title": "t", "repo": "r", "branch": "b"})
    assert a == b == b'{"branch":"b","pr_title":"t","repo":"r"}'
