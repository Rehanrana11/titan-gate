# Titan Gate

Cryptographic change control for AI-assisted software engineering.

Every code change evaluated by Titan Gate produces a **signed, chained, verifiable receipt** — proof that the change was reviewed, scored, and not tampered with.
```json
{
  "receipt_id": "3ae452f4-3a75-44fb-899f-cef8f0fd79b0",
  "tenant_id": "Rehanrana11",
  "verdict": "PASS",
  "composite_score": 0.88,
  "prev_receipt_hash": "GENESIS",
  "receipt_hash": "de103ff...",
  "signature": "7969d20...",
  "VERIFICATION": "PASS"
}
```

---

## Why Titan Gate

AI writes code fast. SOC2 auditors ask: *how do you know what changed, who approved it, and that the record wasn't altered?*

Titan Gate answers that question with cryptographic receipts — not process docs.

- **Deterministic** — same input always produces same receipt hash
- **Chained** — each receipt links to the previous via `prev_receipt_hash`
- **Tamper-evident** — HMAC-SHA256 signature detects any modification
- **Auditable** — receipts travel with the repo at `.titan/receipts/`
- **SOC2-aligned** — maps directly to CC6, CC7, CC8 controls

---

## Quickstart (2 minutes)

### 1. Add the secret
```
GitHub repo → Settings → Secrets → Actions → New secret
Name:  TITAN_SIGNING_KEY
Value: <output of: python -c "import secrets; print(secrets.token_hex(32))">
```

### 2. Add the workflow

Create `.github/workflows/titan-gate.yml`:
```yaml
name: Titan Gate

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  evaluate:
    name: Cryptographic Change Evaluation
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: Rehanrana11/titan-gate@v1.0.0
        with:
          signing-key: ${{ secrets.TITAN_SIGNING_KEY }}
```

### 3. Open a PR

Every PR now gets a cryptographic receipt stored at:
```
.titan/receipts/{date}/{receipt_id}.json
```

---

## Verify a Receipt

Any party with the signing key can independently verify a receipt:
```bash
python scripts/titan_verify.py .titan/receipts/2026-03-06/<receipt_id>.json \
  --key <your-signing-key>
```

Output:
```
============================================================
TITAN GATE RECEIPT VERIFICATION
============================================================
Receipt ID   : 3ae452f4-3a75-44fb-899f-cef8f0fd79b0
Tenant       : Rehanrana11
Verdict      : PASS
Score        : 0.88
------------------------------------------------------------
VERIFICATION  : PASS
Signature     : VALID
Hash          : VALID
============================================================
```

---

## How It Works
```
PR opened
  → Three-judge engine evaluates (structural + semantic + policy)
  → Composite score computed
  → Verdict: PASS / WARN / FAIL
  → Receipt signed with HMAC-SHA256
  → Receipt chained via prev_receipt_hash
  → Receipt stored at .titan/receipts/{date}/{receipt_id}.json
  → Daily Merkle root sealed
  → Receipt verifiable by anyone with the key
```

### Scoring
```
composite_score = weighted(structural_score, semantic_score)

PASS  >= 0.70
WARN  >= 0.40
FAIL  <  0.40
```

Hard violations force FAIL regardless of score.

---

## SOC2 Controls

| Control | Coverage |
|---------|----------|
| CC6.1 | Logical access — tenant isolation on all queries |
| CC6.7 | Change management — signed receipt on every PR |
| CC7.1 | Anomaly detection — tamper detection raises structured anomalies |
| CC7.2 | Monitoring — evaluation manifest records all version constants |
| CC8.1 | Change control — PASS/WARN/FAIL gate on every PR |

---

## Architecture

Five cryptographic layers:

1. **Three-Judge Engine** — structural, semantic, policy judges
2. **Receipt Chain** — HMAC-SHA256, canonical JSON, `prev_receipt_hash`
3. **Merkle Ledger** — `merkle_v1`, daily root sealing, immutable
4. **Replay Engine** — byte-identical replay, zero tolerance for drift
5. **Anchor Notarization** — daily Merkle roots anchored to GitHub

---

## Test Suite
```bash
python run_tests.py
```
```
Ran 555 tests in 8.3s — OK
```

555 tests across 11 files. Zero regressions policy.

---

## Codebase
```
judge_engine/v1/     Three-judge deterministic evaluation engine
api/                 Receipts, replay, Merkle, anchoring, key management
scripts/             titan_verify.py, ci_evaluate.py, seal_daily_root.py
tests/               555 tests + test vectors TV1/TV2/TV3
examples/            Sample repo integration
docs/                SPEC.md, architecture, auditor docs
deploy/              Dockerfile + docker-compose
action.yml           GitHub Action — installable as uses: Rehanrana11/titan-gate@v1.0.0
```

---

## Docs

- [Public Verification Spec](docs/SPEC.md)
- [Architecture Decisions](docs/ARCHITECTURE_DECISIONS.md)
- [Session Log](docs/TITAN_GATE_SESSION_LOG.md)
- [Example Integration](examples/sample-repo/)

---

## Version
```
ENGINE_VERSION          1.0.0
MERKLE_ALGORITHM        merkle_v1
SIGNING_VERSION         hmac-sha256-v1
```

---

## License

Apache 2.0