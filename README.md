# Titan Gate

Cryptographic change control for AI-assisted software engineering.

Every code change evaluated by Titan Gate produces a **signed, chained, verifiable receipt** -- proof that the change was reviewed, scored, and not tampered with.

```json
{
  "receipt_id": "3ae452f4-3a75-44fb-899f-cef8f0fd79b0",
  "tenant_id": "Rehanrana11",
  "verdict": "PASS",
  "composite_score": 0.88,
  "prev_receipt_hash": "GENESIS",
  "receipt_hash": "de103ff...",
  "signature": "7969d20...",
  "signing_version": "hmac-sha256-v1"
}
```

---

## Install

**Python / CLI**
```bash
pip install titan-gate
titan-verify receipt.json --key <hex>
```

**GitHub Actions**
```yaml
- uses: Rehanrana11/titan-gate/.github/actions/verify@main
  with:
    receipt: .titan/receipts/latest.json
    key: ${{ secrets.TITAN_SIGNING_KEY }}
```

**R**
```r
install.packages('titangate', repos = NULL, type = 'source')
library(titangate)
verify_receipt('receipt.json', key_hex = Sys.getenv('TITAN_SIGNING_KEY'))
```

---

## Why Titan Gate

AI writes code fast. SOC2 auditors ask: *how do you know what changed, who approved it, and that the record was not altered?*

Titan Gate answers that question with cryptographic receipts -- not process docs.

- **Deterministic** -- same input always produces same receipt hash
- **Chained** -- each receipt links to the previous via `prev_receipt_hash`
- **Tamper-evident** -- HMAC-SHA256 signature detects any modification
- **Auditable** -- receipts travel with the repo at `.titan/receipts/`
- **Control-mapped** -- three static pattern checks, each mapped to named
  SOC 2 criteria. A mapping, not an audit and not an attestation.

---

## Quickstart

### 1. Add the secret

```
GitHub repo -> Settings -> Secrets -> Actions -> New secret
Name:  TITAN_SIGNING_KEY
Value: <output of: python -c "import secrets; print(secrets.token_hex(32))">
```

### 2. Add the workflow

Create `.github/workflows/titan-gate.yml`:

```yaml
name: Titan Gate
on: [pull_request]

jobs:
  evaluate:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - name: Evaluate
        run: python scripts/ci_evaluate.py
        env:
          TITAN_SIGNING_KEY: ${{ secrets.TITAN_SIGNING_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### 3. Verify a receipt

```bash
titan-verify .titan/receipts/receipt.json --key $TITAN_SIGNING_KEY
```

---

## SOC 2 Control Mapping

Titan Gate runs **three static pattern checks** and records which SOC 2 Trust
Services Criteria each one names. This is a mapping, not coverage, and not an
attestation. See `docs/SPEC.md` erratum E-2.

| Check | Mechanism | Criteria named |
|-------|-----------|----------------|
| Hardcoded credentials | regex on `password`/`secret`/`api_key` assignment | CC6.1, CC6.2 |
| Missing error handling | no `try`/`except` in artifacts over 200 chars | CC7.1 |
| Missing type hints | `def` without `->` | CC8.1 |

**Not implemented.** CC6.7 has no check and never had one; earlier revisions of
this table listed it. CC7.2 has no check either -- no rule can report it
violated. CC6.2 is emitted on every receipt and was missing from this table.

A passing receipt means these three checks did not fire. It does not mean the
change is compliant.

---

## Architecture

Five cryptographic layers:

1. **Three-Judge Engine** -- structural, semantic, policy judges
2. **Receipt Chain** -- HMAC-SHA256, canonical JSON, `prev_receipt_hash`
3. **Merkle Ledger** -- `merkle_v1`, daily root sealing, immutable
4. **Replay Engine** -- byte-identical replay, zero tolerance for drift
5. **Anchor Notarization** -- daily Merkle roots anchored to GitHub

---

## Public Verification Spec

The verification algorithm is open and language-neutral: [TRS-1 v1.0.0](docs/SPEC.md)

Anyone can verify a Titan Gate receipt without contacting Titan Gate infrastructure:

```bash
pip install titan-gate
titan-verify receipt.json --key <hex>
```

---

## Test Suite

```bash
python run_tests.py
```

```
Ran 555 tests -- OK
```

555 tests across 11 files. Zero regressions policy.

---

## Codebase

```
judge_engine/v1/     Three-judge deterministic evaluation engine
api/                 Receipts, replay, Merkle, anchoring, key management
scripts/             titan_verify.py, ci_evaluate.py, seal_daily_root.py
tests/               555 tests + test vectors TV1/TV2/TV3
r-package/titangate  R package -- wraps titan-verify CLI
examples/            Sample repo integration
docs/                SPEC.md, architecture, auditor docs
deploy/              Dockerfile + docker-compose
.github/actions/     Composite action for receipt verification
```

---

## Docs

- [Public Verification Spec](docs/SPEC.md)
- [Architecture Decisions](docs/ARCHITECTURE_DECISIONS.md)
- [Example Integration](examples/sample-repo/)

---

## Version

```
ENGINE_VERSION     1.0.0
MERKLE_ALGORITHM   merkle_v1
SIGNING_VERSION    hmac-sha256-v1
```

---

## License

Apache 2.0

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18891039.svg)](https://doi.org/10.5281/zenodo.18891039)
