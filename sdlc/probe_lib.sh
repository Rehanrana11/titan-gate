#!/usr/bin/env bash
# probe_lib.sh v0.1 — GATES-v1 T2: self-announcing bounded reads (G1-05).
# Source it:  . ./probe_lib.sh   Then use tg_head/tg_tail/tg_grepm instead of bare commands.
tg_head() { local n="$1" f="$2"; head -n "$n" "$f"; echo "TRUNCATED_AT=$n TOTAL=$(wc -l < "$f") FILE=$f"; }
tg_tail() { local n="$1" f="$2"; tail -n "$n" "$f"; echo "TRUNCATED_AT=last-$n TOTAL=$(wc -l < "$f") FILE=$f"; }
tg_grepm(){ local m="$1" pat="$2" f="$3"; grep -m "$m" -n "$pat" "$f"; echo "TRUNCATED_AT=${m}matches TOTAL_MATCHES=$(grep -c "$pat" "$f") FILE=$f"; }
tg_ls()   { local d="$1"; ls "$d" | head -50; echo "TRUNCATED_AT=50 TOTAL=$(ls "$d" | wc -l) DIR=$d"; }
