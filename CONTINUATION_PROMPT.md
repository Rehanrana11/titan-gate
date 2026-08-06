CONTINUATION — Agent Evidence Plane build session
Read MASTER_STATE_v1 first; this is the delta (supersedes prior delta).

DONE (this cycle, Aug 6, cont.):
- WO-3 COMPLETE. Sub-commits:
  - WO-3.4a (a2e1770): titan_gate/trs2.py — TRS-2 event profile per FRD
    §2.1. Closed schema every level; NO payload-bearing field (AT-17);
    outcome.recorded_by_source structural constant true (identity check,
    non-true = schema error); digests fullmatch 64 LOWERCASE hex.
  - WO-3.4b (9c6075b): canonical_bytes_jcs() in canonical.py, ADDITIVE
    (TRS-1 sorted-keys golden-pinned, untouched). RFC 8785 with domain
    restriction: NO floats, ints within ±(2^53-1), reject-not-coerce;
    byte-identical to full JCS over admitted domain. UTF-16 code-unit
    key sort (non-BMP adversarial vector pinned). TRS-1 can NEVER
    migrate to JCS (its schema has score floats) — profile-bound.
  - WO-3.4c (562e53b): docs/SPEC-2.md v2.0.0-DRAFT (stabilizes at first
    external verification, not before — Rule 3). docs/SPEC.md (TRS-1
    v1.0.0) declared FROZEN. Post-publication verifier extensions
    (ed25519-v1, chain-walk) recorded honestly as extensions. AARM
    R5/R6 mapping with IMPLEMENTED/SPECIFIED status column ("an
    executable AT passes in the public repo" = the definition).
  - WO-3.4d (b89dcc3): titan_gate/trs2_writer.py — build/verify TRS-2
    receipts over JCS, ed25519-v1, digest covers body INCL prev, EXCL
    sig/stored hash. Core holds NO key material: sign_fn injected
    (V3→C1 pattern at module scale; WO-7 swaps in HTTP signer with
    zero change here). Executable Rule-1 lint: module source may not
    contain signing symbols/key env names/api imports. Bidirectional
    seq/GENESIS check kills mid-chain genesis splice per-receipt.
    uuid4 not UUIDv7 (documented deviation, revisit Py3.14).
  - WO-3.5a (5d6505b): chain_state.py per-profile hash dispatch +
    one-profile-per-tree explicit check (fails on stated rule, not
    incidental hash mismatch). Unknown schema_version = hard error,
    NO fallback (a defaulting walker can be steered).
  - WO-3.5b (f79488b): titan-verify --chain dispatches on genesis
    profile. TRS-1 walk byte-untouched. TRS-2 walk DELEGATES per-
    receipt checks to verify_trs2_receipt (lazy import; single impl).
    New codes: ERR_CHAIN_PROFILE_MISMATCH (+position),
    ERR_RECEIPT_INVALID (+position), ERR_PUBKEY_REQUIRED (TRS-2 has
    no HMAC mode), ERR_SCHEMA_VERSION at genesis.
- Q-C RESOLVED BY ACTION: Rehanrana11 is canonical (published SPEC.md
  URL, pyproject, now git origin). origin repointed from dead
  Rmasood1122 URL; old-origin removed; ALL COMMITS PUSHED
  (0e1d536..f79488b on Rehanrana11/titan-gate). Later sweep for stray
  Rmasood1122 refs in docs — nothing blocks.
- Housekeeping ACTUALLY done this time: .gitignore was UTF-16-corrupted
  (a PowerShell echo >> appended UTF-16; git silently parsed NOTHING
  new) — rewritten UTF-8 with full original entry set restored incl.
  .titan/; verified with git check-ignore (the missing AT for a
  gitignore edit). __pycache__ untracked. write_readme.py deleted.
  Downloads dup deleted. Mystery "26.2.1" resolved/gone.
- Suite: 666 passing (pending confirmation of pre-f79488b run — see
  PROCESS NOTE).

PROCESS NOTES (additions to the ruleset, learned this session):
- "Done" for config/one-liners needs an AT too: the gitignore entry was
  marked done while silently unparsed. git check-ignore is the AT for
  ignore rules.
- Anchored-edit scripts with uniqueness asserts caught a bad edit
  (helper duplicated its own anchor) and aborted BEFORE writing. Keep
  the pattern: assert anchors unique, write last, never half-edit.
- One commit (f79488b) went in without the full-suite tail visible in
  session. Rule stands: suite output immediately before commit, pasted.

HONEST CLAIM AS OF f79488b (Rule 3): "The writer produces TRS-2
agent-action receipts (closed no-payload schema, source-attributed
outcomes) over RFC 8785 JCS with a keyless core, and the offline
verifier walks both TRS-1 and TRS-2 chains, detecting deletion,
reordering, alteration, and profile tampering with position,
public-key-only." NOT yet claimable: production ingest emitting TRS-2
(WO-6); customer-held keys (WO-7 — sign_fn seam ready, API still
in-process); anchoring (WO-4/5); bundles carrying chains (WO-8).

OPEN / UNDECIDED:
- Gate 0b: KPMG clock running, checkpoint Nov 6. Touch 2 ~Aug 20.
- Gate 0a: Lloyd parked. FLAGGED RECOMMENDATION (undecided): start one
  direct CISO thread in parallel rather than waiting — R5 clock (zero
  non-NWN meetings by Nov 30) runs regardless. FIRST AGENDA ITEM.
- SPEC-2 stabilization gate: v2.0.0-draft → stable only when a third
  party completes verification of a TRS-2 bundle (WO-8 AT).
- Verifier packaging: now verify.py + canonical.py + trs2.py +
  trs2_writer.py (delegation chosen over duplication — divergence
  class beats file count). Single-file question deferred to WO-8.

NEXT: WO-4 — Rekor anchoring (kills G3a). Per MASTER_STATE: daily/
interval root → Rekor entry via pinned log key; store inclusion proof
+ checkpoint; export bundles verify inclusion OFFLINE (FRD AT-16
first half: networking disabled, verify passes from bundled proof).
First action: failing AT. Note sigstore-python is a NEW dependency —
scope its footprint before committing to it vs a minimal rekor client;
the verifier side must stay offline-capable with pinned key, no
sigstore machinery required at verification time.
