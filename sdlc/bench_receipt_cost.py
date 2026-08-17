"""WO-S2 (PLAN_LOCK_WO_S_v1): cost per receipt, measured not estimated.
Zero LLM calls in the pipeline (RECON_MATCH_LINES=0, 2026-08-17), so cost
is wall-clock + bytes. Dollar conversion is deployment-specific and stays
[EST] -- this script publishes only what it measures."""
import json, os, statistics, sys, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from judge_engine.v1 import engine

ARTIFACT = ("def process(order) -> dict:\n"
            "    try:\n"
            "        validated = validate_order(order)\n"
            "        result = apply_pricing(validated)\n"
            "        return {'status': 'ok', 'total': result.total}\n"
            "    except ValueError:\n"
            "        raise\n") * 4
KEY = "ab" * 32
N = 200

times, sizes = [], []
prev = "GENESIS"
for i in range(N):
    t0 = time.perf_counter()
    r = engine.evaluate(ARTIFACT, {"files": ["order.py"]}, "bench-tenant",
                        "bench-repo", "bench/bench-repo", i, "bench pr",
                        "main", "main", "0" * 40, KEY, prev)
    times.append((time.perf_counter() - t0) * 1000.0)
    sizes.append(len(json.dumps(r, ensure_ascii=False).encode("utf-8")))
    prev = r["receipt_hash"]

times.sort()
print("receipts           : %d (chained, GENESIS-rooted)" % N)
print("ms/receipt median  : %.3f" % statistics.median(times))
print("ms/receipt p99     : %.3f" % times[int(N * 0.99) - 1])
print("bytes/receipt      : %d" % sizes[0])
print("receipts/second    : %.0f" % (1000.0 / statistics.median(times)))
