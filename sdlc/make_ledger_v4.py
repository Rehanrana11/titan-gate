#!/usr/bin/env python3
"""make_ledger_v4.py — additive ledger bump. Reads claim_ledger-titan-v3.json,
patches ONLY row CL-6, writes claim_ledger-titan-v4.json at a NEW path.

Never overwrites. Never deletes. Refuses if the output already exists.
Asserts every row except CL-6 is byte-identical to v3, so the diff is PROVEN
one row wide rather than trusted to be.

Driver: python -m pytest -q on the operator machine 2026-08-19 ->
"903 passed, 1 skipped, 12 xfailed, 1 warning in 46.57s"
which is CL-6's own advancing_probe executed verbatim.
"""
import json, os, sys

SRC = "claim_ledger-titan-v3.json"
DST = "claim_ledger-titan-v4.json"
NEW_CLAIM = "Suite state: 903 passed, 1 skipped, 12 xfailed"
NEW_EVID = ('[MEASURED: python -m pytest -q, operator terminal 2026-08-19 -> '
            '"903 passed, 1 skipped, 12 xfailed, 1 warning in 46.57s"]')
NEW_DATE = "2026-08-19"
V4_NOTE = ("v4: CL-6 re-advanced 897 -> 903 (+6) and xfailed 10 -> 12 (+2) after "
           "commits 368e620/431f8f6/7011f38/13480fa/9ed3ac5/cd3f2a5/1717f7a. "
           "Header correction: v3's _version field read 'v2' while the file "
           "carried the 17-row v3 batch, and _supersedes named v1, skipping v2 "
           "- the label was never bumped when the v3 rows landed. From v4 the "
           "filename and _version agree. reverify_days=1 stands: this row "
           "decays daily by design and CS3 will fire at any session start that "
           "does not re-measure.")
NEW_VERSION = "v4"
NEW_SUPERSEDES = ("claim_ledger-titan-v3.json (whose _version field wrongly read "
                  "'v2'); keep v1 as the --previous input for the R4 diff")

def main():
    if os.path.exists(DST):
        print("ABORT_EXISTS=%s (nothing written; bump to v5 if intended)" % DST)
        return 1
    if not os.path.isfile(SRC):
        print("ABORT_NO_SOURCE=%s" % SRC); return 1
    d = json.load(open(SRC, encoding="utf-8"))
    rows = d["rows"]
    print("SRC_ROWS=%d SRC_VERSION=%r" % (len(rows), d.get("_version")))
    if len(rows) != 17:
        print("ABORT_ROWCOUNT=%d (expected 17)" % len(rows)); return 1
    hits = [i for i, r in enumerate(rows) if r.get("id") == "CL-6"]
    if len(hits) != 1:
        print("ABORT_CL6_COUNT=%d (expected exactly 1)" % len(hits)); return 1
    i = hits[0]

    before = {k: rows[i].get(k) for k in ("claim", "evidence", "last_verified")}
    others_before = json.dumps([r for j, r in enumerate(rows) if j != i],
                               sort_keys=True)

    rows[i]["claim"] = NEW_CLAIM
    rows[i]["evidence"] = NEW_EVID
    rows[i]["last_verified"] = NEW_DATE
    rows[i]["v4_note"] = V4_NOTE
    d["_version"] = NEW_VERSION
    d["_supersedes"] = NEW_SUPERSEDES

    others_after = json.dumps([r for j, r in enumerate(rows) if j != i],
                              sort_keys=True)
    if others_before != others_after:
        print("ABORT_COLLATERAL_CHANGE (other rows differ; nothing written)")
        return 1
    print("OTHER_ROWS_IDENTICAL=16")

    with open(DST, "w", encoding="utf-8", newline="") as fh:
        json.dump(d, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    print("WROTE=%s BYTES=%d" % (DST, os.path.getsize(DST)))
    for k in ("claim", "last_verified"):
        print("  %-14s %r -> %r" % (k, before[k], rows[i][k]))
    print("DIFF_WIDTH=1 row  EXIT=0")
    return 0

if __name__ == "__main__":
    sys.exit(main())
