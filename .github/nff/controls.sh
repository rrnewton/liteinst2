#!/usr/bin/env bash
# C1 positive controls for classify.sh (STRESS-PLAN-r2 section 2.3).
# Each controls.tsv line: FIXTURE RC ROW EXPECTED-VERDICT. Exits 1 on a mismatch.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
fail=0
while read -r fixture rc row expect; do
  case "$fixture" in
    ''|'#'*) continue ;;
  esac
  got=$(bash "$here/classify.sh" "$here/fixtures/$fixture" "$rc" control "$row" 0 | grep -o -E '^NFF-RESULT verdict=[a-z-]+' | sed 's/^NFF-RESULT verdict=//')
  if [ "$got" = "$expect" ]; then
    echo "NFF-CONTROL ok fixture=$fixture rc=$rc row=$row verdict=$got"
  else
    echo "NFF-CONTROL MISMATCH fixture=$fixture rc=$rc row=$row expected=$expect got=$got"
    fail=1
  fi
done < "$here/controls.tsv"
if [ "$fail" -eq 0 ]; then echo "NFF-CONTROLS result=pass"; else echo "NFF-CONTROLS result=FAIL"; fi
exit "$fail"
