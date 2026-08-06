CONTINUATION — Agent Evidence Plane build session
Read MASTER_STATE_v1 + STRATEGY_DELTA_v1 first; this is the delta
(supersedes prior delta). D1 governs: next is WO-6, and D6's Gate 0a
wall now stands directly in front of it.

WO-4 COMPLETE (G3a KILLED). This cycle:
- WO-4.3 p1 (7582030): verify_anchor_record_offline — REAL Rekor entry
  verified offline [F]: schema -> record coherence (equivocation shape
  fails pre-crypto) -> checkpoint ECDSA vs PINNED production key ->
  6962 inclusion (leaf = VERBATIM entry body, wire-proven) -> artifact
  binding. Live entry + production log pubkey are repo fixtures.
- WO-4.3 p2a (9edb395): anchor_root — sign PREHASHED via seam (no
  keys, linted), submit, persist atomically; external failure ->
  anchor_status.json disclosure + degraded return; caller bugs raise.
- WO-4.3 p2b (53f1a02): promote_anchor — pending->anchored state
  machine on anchor_v1 files, payload_hash RECOMPUTED both paths,
  idempotent by urlopen count (resubmission would dupe public entries).
- CLI (85d1c21): --promote/--anchor-key/--rekor-url; keyless promote
  exits 2 quoting no-key-defaults; promo failure discloses, exits 0.
- Fix (cd98a7f): promote_anchor was BELOW the __main__ guard —
  import-tests structurally can't catch it; script-mode NameError'd
  live. Moved + two regressions: def-order lint, subprocess smoke.
- *** THE ARTIFACT (cite in Gate 0b touch 2): production chain root
  4933083c6ced22f47e00238703dd4a17e02bc5398035601c2ddf03eaf1a9fbbb
  (receipts: 1, the real chain) anchored in rekor.sigstore.dev:
  uuid 108e9186e8c5677abcf20b23d57c9978bddccf127b9a629e49670ac5e2d8d37a4c3a239ae7732601
  log_index 2239591431. Offline-verified by our own machinery, PASS.
  Evidence files committed under .titan-gate/anchors/ so any clone
  can re-verify — the product notarizing itself. ***
- Suite: 746 passed + 1 skipped (gated live test).

PROCESS NOTES (hard-won this cycle, additive to prior):
- TERMINAL INCIDENT: a paste replayed scrollback AS COMMANDS —
  re-appended a heredoc onto canonical.py (restored via git checkout,
  goldens re-verified) and destroyed uncommitted anchor_writer.py
  (recreated from session record). STANDING RULE: terminal output
  goes to chat, NEVER back into the terminal.
- Windows encoding: THREE bugs, one root cause (cp1252 default) —
  curl -o mojibaked a fixture (refetch via Python byte-writes only),
  bare open() re-mojibaked it, .gitignore was UTF-16 earlier.
  RULE: every text open() carries encoding='utf-8'. CI lint queued.
- Guards: mention-vs-use fired 3x (docstring, comment false-positive).
  RULES: guards match CALLS not strings; a fired guard means READ THE
  FILE, never infer state from the firing.
- Import-based tests cannot catch below-__main__-guard definitions;
  script-mode subprocess smoke is the missing test class — now exists.
- Wire lessons total 4: ECDSA-not-Ed25519 checkpoints, Prehashed
  signing, verbatim-body-is-leaf, mojibake. Synthetic tests prove our
  math agrees with itself; wire tests prove it agrees with the world.

WO-7 LEDGER (accumulating): no key defaults ever (ci_evaluate "0"*64);
anchor_key.pem UNENCRYPTED at ~/.titan (interim, revisit); anchoring
key + in-process TITAN_SIGNING_KEY both evict to customer container.

OPEN / UNDECIDED:
- Gate 0a: OPEN — BLOCKS WO-6 START per D6. First agenda item, no
  exceptions this time. If target selection is the stall, say "no
  warm path" and the shortlist gets built as parallel work.
- Gate 0b touch 2 ~Aug 20: cite probe_24/5c27fc7 AND the live anchor.
- GitHub Pages: disable (Settings->Pages->Source: None) — decided,
  awaiting the click. microsoft-response.md deletion (ARE): unconfirmed.
- Pre-commit hook is LOCAL-ONLY — reinstall on any new machine.

NEXT: WO-6 — Copilot export ingest (poller -> TRS-2 receipts -> chain
-> anchor, AT-1 shape + AT-6 gap receipts; TRS-2 gains receipt_type
here per the (a)-decision). BUT Gate 0a resolves first. Q-E note:
WO-6's AT needs a test tenant or recorded export fixtures — scope
that question in the first hour, not after building the poller.
