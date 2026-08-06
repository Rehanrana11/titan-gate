CONTINUATION — Agent Evidence Plane build session
Read MASTER_STATE_v1 + STRATEGY_DELTA_v1 first; this is the delta
(supersedes prior delta). D1 sequence governs: 4.2/4.3 -> 6 -> 5 -> 7 -> 8.

DONE (Aug 7 cycle):
- probe_24 audit run (24 probes): 13 PROVEN / P11 FAIL->fixed same day
  (5c27fc7, regression-pinned) / 7 NOT-BUILT recorded / P04 verdict
  invalid (passed for wrong reason; capability separately proven by
  3.5b AT) / P20 resolved NOT-BUILT (env key in api/main.py +
  ci_evaluate.py). probe_24.py is a repo artifact; STRATEGY_DELTA D3
  makes it quarterly + citable in Gate 0b touch 2.
- STRATEGY_DELTA_v1.md written + uploaded to project (D1-D6).
- WO-4.2a (post-714 commit): signed-note parsing + ECDSA P-256
  checkpoint verification. DISCOVERY: production Rekor signs
  checkpoints ECDSA P-256/DER, NOT Ed25519 (live STH inspected);
  4.1's Ed25519 check was synthetic-mechanics only. Caller selects
  algorithm by PINNED KEY TYPE, never by sniffing sig bytes
  (downgrade-attack shape). Real STH = parsing fixture.
- WO-4.2b (0c6693d + live commit): Rekor submission client, stdlib
  urllib only, NEVER signs (signature is an argument; sign-lint
  includes method calls and caught its own docstring — lint stays
  dumb-strict). Closed-schema anchor record: checkpoint VERBATIM,
  entry_body_b64 kept (log leaf = entry body hash, not artifact hash).
- LIVE ANCHOR (permanent, public, citable):
  uuid=108e9186e8c5677a7015408d5199952a0fcaa833146393431731f43b16d86278011afd7dfa2a59e4
  log_index=2238835089 @ rekor.sigstore.dev, 2026-08-07.
  [F]-WIRE FACT for WO-4.3: sign the raw digest PREHASHED — plain
  ECDSA(SHA256) double-hashes and Rekor 400s (confirmed live).
- Cross-repo push audit: titan CLEAN. ARE: 2 stragglers committed
  (639a8a4), origin repointed Rmasood1122->Rehanrana11 (existed
  private), pushed, CLEAN. NOTE: 639a8a4 deleted 269 lines of
  docs/competitive/microsoft-response.md — intentionality UNCONFIRMED;
  recoverable via `git show 20603c2:docs/competitive/microsoft-response.md`.
  ARE re-shelved until WO-8.
- Suite: 723 passed + 1 skipped (gated live test). Pre-commit hook
  (local-only — REINSTALL ON NEW MACHINE) enforcing full suite.

PROCESS NOTES:
- Guards fired on their authors twice: anchor-uniqueness assert caught
  a duplicated anchor pre-write; sign-lint caught its own docstring.
  Keep guards dumb-strict, no comment carve-outs, into CI.
- My "=== CLEAN ===" verification one-liner passed on failure (echoed
  on command success, not empty output). Fixed with wc -l count.
  Session-close rule, BOTH repos: git status --short empty AND
  unpushed count 0, output pasted as the closing claim.
- Live tests earn their keep: the wire corrected us once (Prehashed).

HONEST CLAIM AS OF THIS COMMIT (Rule 3): prior claim (TRS-2 writer +
dual-profile verifier, deletion/reorder/alteration/profile-tamper with
position, public-key-only) PLUS: "our anchoring client has written a
real entry to Sigstore's public transparency log, and our verifier's
inclusion math is proven offline against adversarial vectors." NOT yet
claimable: end-to-end anchored chains (WO-4.3 wiring — leaf recompute
vs entry_body_b64 has a known doc-vs-wire question), production TRS-2
ingest (WO-6), second anchor leg (WO-5), customer-held keys (WO-7),
chain-carrying bundles (WO-8).

OPEN / UNDECIDED:
- Gate 0a: STILL OPEN, first agenda item; blocks past WO-6 per D6.
- Gate 0b: touch 2 ~Aug 20 (cite probe_24/5c27fc7 + live anchor).
  Checkpoint Nov 6.
- microsoft-response.md deletion intentionality (ARE, low priority).
- WO-7 ledger: no key defaults (ci_evaluate "0"*64 default); absent
  key = refuse to sign.

NEXT: WO-4.3 — wire the CI writer: seal interval root -> sign digest
PREHASHED via sign_fn seam -> submit_hashedrekord -> store anchor
record beside the chain; degraded path (Rekor unreachable -> proceed
unanchored + disclosure marker, FR-RCP-2 single-leg pattern); then
offline-verify the LIVE anchor's inclusion proof end-to-end (leaf =
sha256(0x00 || canonicalized entry body) — resolve the body-bytes
question against the stored entry_body_b64 from the live entry).
First action: failing AT for the anchor-record offline verification
using the LIVE entry as fixture.
