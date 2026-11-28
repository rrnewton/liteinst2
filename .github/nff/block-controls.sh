#!/usr/bin/env bash
# STRESS-PLAN-r4 item 2: the stress step's run block, extracted from ci.yml,
# run under /usr/bin/bash -e with cargo and timeout stubbed, in four cases:
# cal, uncal and mix (item 2), and b3fail (lead-014 (c): a failing b3
# bracket prints a bounded tail of its output).
# Usage: block-controls.sh CI_YML WORKSPACE WORKDIR
#   WORKSPACE holds .github/nff/classify.sh and .github/nff/fixtures;
#   WORKDIR (existing, empty) receives the extracted block and one run
#   directory per case. Exits 0 only if all four cases match.
set -uo pipefail
ci=$1; ws=$2; wd=$3
step='      - name: Stress rows 12 and 13 by exact name, heads interleaved'
first=$(grep -n -x -F "$step" "$ci" | cut -d: -f1)
if [ -z "$first" ]; then echo "NFF-BLOCK-CONTROL ERROR no stress step"; exit 2; fi
rel=$(sed -n "$first,\$p" "$ci" | grep -n -x -F '        run: |' | head -n 1 | cut -d: -f1)
if [ -z "$rel" ]; then echo "NFF-BLOCK-CONTROL ERROR no run block"; exit 2; fi
start=$((first + rel))
if [ "$(sed -n "$start,\$p" "$ci" | grep -c -v -E '^(          .*)?$')" -ne 0 ]; then
  echo "NFF-BLOCK-CONTROL ERROR block indent"
  exit 2
fi
sed -n "$start,\$p" "$ci" | sed 's/^          //' > "$wd/stress-step.sh"
echo "NFF-BLOCK-CONTROL block lines=$(wc -l < "$wd/stress-step.sh") first=[$(head -n 1 "$wd/stress-step.sh")]"
b3n='blocked_exec_resolver_uses_original_deadline_and_owner_cleanup exec_full_comparator_rejects_each_state_input_map_and_identity_corruption original_exec_replacement_matches_raw_replay_and_native_full_state resolver_panic_after_actual_exec_keeps_original_failure_and_cleanup stale_exec_source_reply_preserves_actual_replacement_without_commit'
timeout() {
  if [ "$1" = -k ]; then shift 3; else shift 1; fi
  "$@"
}
cargo() {
  local name="" prev="" a n k
  for a in "$@"; do
    if [ "$prev" = --exact ]; then name=$a; fi
    prev=$a
  done
  case " $* " in
    *" b3_exec_admission "*)
      if [ "$NFF_CTL_CASE" = uncal ]; then
        for n in $b3n; do echo "test $n ... FAILED"; done
        echo 'called `Result::unwrap()` on an `Err` value: Control(Invalid("native selected full register completion differs"))'
        return 101
      fi
      if [ "$NFF_CTL_CASE" = b3fail ]; then
        for n in $(seq 1 59); do echo "b3fail line $n"; done
        printf 'b3fail line 60 %0500d\n' 0
        return 101
      fi
      for n in $b3n; do echo "test $n ... ok"; done
      return 0
      ;;
  esac
  if [ "$NFF_CTL_CASE" != mix ]; then echo "test $name ... ok"; return 0; fi
  k=$(cat "$NFF_CTL_COUNTER")
  echo $((k + 1)) > "$NFF_CTL_COUNTER"
  case $((k % 3)) in
    0) echo "test $name ... ok"; return 0 ;;
    1)
      if [ "$name" = selected_interpreter_and_executable_instruction_one_complete_exactly_once ]; then
        cat "$NFF_CTL_FIX/r13-site.txt"
      else
        cat "$NFF_CTL_FIX/r12-site.txt"
      fi
      return 101
      ;;
    *) return 124 ;;
  esac
}
export -f timeout cargo
export b3n
fail=0
run_case() {
  local case=$1 expect=$2 dir="$wd/run-$1" rc pre ex res job got tl tw tf v
  if ! mkdir "$dir" "$dir/main" "$dir/pr118"; then echo "NFF-BLOCK-CONTROL ERROR mkdir $dir"; fail=1; return; fi
  echo 0 > "$dir/counter"
  NFF_CTL_CASE=$case NFF_CTL_COUNTER="$dir/counter" NFF_CTL_FIX="$ws/.github/nff/fixtures" PROFILE=debug GITHUB_WORKSPACE="$ws" RUNNER_TEMP="$dir" NFF_R=10 /usr/bin/bash -e "$wd/stress-step.sh" > "$dir/out.txt" 2>&1
  rc=$?
  pre=$(grep -c -E '^NFF-JOB-PRE profile=debug class=[A-Z-]+$' "$dir/out.txt")
  ex=$(grep -c -E '^NFF-EXEC head=(main|pr118) row=(12|13) rep=([1-9]|10)$' "$dir/out.txt")
  res=$(grep -c -E '^NFF-RESULT verdict=[a-z-]+ ' "$dir/out.txt")
  job=$(grep -o -E '^NFF-JOB profile=debug class=[A-Z-]+' "$dir/out.txt" | sed 's/^NFF-JOB profile=debug class=//')
  got=$(grep -o -E '^NFF-RESULT verdict=[a-z-]+' "$dir/out.txt" | sed 's/^NFF-RESULT verdict=//' | LC_ALL=C sort | uniq -c | tr -s ' \n' ' ' | sed 's/^ //;s/ $//')
  tl=$(grep -c -E '^NFF-CAL-TAIL bracket=(pre|post): ' "$dir/out.txt")
  tw=$(grep -E '^NFF-CAL-TAIL bracket=(pre|post): ' "$dir/out.txt" | wc -L)
  tf=$(grep -m 1 -E '^NFF-CAL-TAIL bracket=pre: ' "$dir/out.txt" | sed 's/^NFF-CAL-TAIL bracket=pre: //')
  got="$job $got tail=$tl width=$tw first=[$tf]"
  if [ "$rc" -eq 0 ] && [ "$pre" -eq 1 ] && [ "$ex" -eq 40 ] && [ "$res" -eq 40 ] && [ "$got" = "$expect" ]; then v=ok; else v=MISMATCH; fail=1; fi
  echo "NFF-BLOCK-CONTROL $v case=$case rc=$rc jobpre=$pre exec=$ex result=$res got=[$got] expected=[$expect]"
}
run_case cal 'CALIBRATED 40 ok tail=0 width=0 first=[]'
run_case uncal 'UNCALIBRATED-BY-SIGNATURE 40 ok tail=12 width=140 first=[test blocked_exec_resolver_uses_original_deadline_and_owner_cleanup ... FAILED]'
run_case mix 'CALIBRATED 13 fail-at-site 14 ok 13 timeout tail=0 width=0 first=[]'
run_case b3fail 'UNCLEAR 40 ok tail=80 width=427 first=[b3fail line 21]'
if [ "$fail" -eq 0 ]; then echo "NFF-BLOCK-CONTROLS result=pass"; else echo "NFF-BLOCK-CONTROLS result=FAIL"; fi
exit "$fail"
