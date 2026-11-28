#!/usr/bin/env bash
# NFF stress classifier (STRESS-PLAN-r2 section 2.3; section 2 and r3 B1).
# Usage: classify.sh OUT RC HEAD ROW REP. Prints one NFF-RESULT line and, for
# a non-ok verdict, NFF-RECORD lines. Always exits 0 unless ROW is unknown.
set -uo pipefail
out=$1; rc=$2; head=$3; row=$4; rep=$5
case "$row" in
  13)
    name=selected_interpreter_and_executable_instruction_one_complete_exactly_once
    short=$name
    site='tests/selected_gate\.rs:561:5'
    need='assertion `left == right` failed'
    ;;
  12)
    name=linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::runtime_ordinary_single_step_stops_before_same_page_marker
    short=runtime_ordinary_single_step_stops_before_same_page_marker
    site='src/linux/remote/dynamic/owner/admission/runtime/ordinary/native_tests/support\.rs:227:30'
    need='owned ordinary changed non-arithmetic control state'
    ;;
  *)
    echo "NFF-CLASSIFY-ERROR unknown row $row"
    exit 2
    ;;
esac
own="thread '[A-Za-z0-9_:]*$short' \([0-9]+\) panicked at "
iso="runtime isolated case \"$name\" failed: "
rec() {
  grep -o -E "$1.{0,240}" "$out"
  grep -A1 -E "$1" "$out"
}
niso=$(grep -c -F "$iso" "$out")
if [ "$rc" -eq 0 ] && grep -q -x -F "test $name ... ok" "$out" && [ "$niso" -eq 0 ]; then result=ok
elif grep -q -x -F "test $name ... FAILED" "$out" || [ "$niso" -ge 1 ]; then result=FAILED
elif [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then result=timeout
else result=absent; fi
nown=$(grep -c -E "$own" "$out")
nsite=$(grep -c -E "${own}crates/liteinst-launch/${site}:" "$out")
nmsg=$(rec "${own}crates/liteinst-launch/${site}:" | grep -c -F "$need")
npois=$(rec "$own" | grep -c -F PoisonError)
if [ "$result" = ok ]; then verdict=ok
elif [ "$result" = FAILED ] && [ "$nsite" -ge 1 ] && [ "$nmsg" -ge 1 ]; then verdict=fail-at-site
elif [ "$result" = FAILED ] && [ "$npois" -ge 1 ]; then verdict=poisoned
elif [ "$result" = FAILED ]; then verdict=different
else verdict=$result; fi
echo "NFF-RESULT verdict=$verdict head=$head row=$row rep=$rep rc=$rc result=$result iso=$niso own=$nown site=$nsite msg=$nmsg poison=$npois"
if [ "$verdict" != ok ]; then
  rec "$own" | cut -c1-400 | sed "s/^/NFF-RECORD head=$head row=$row rep=$rep: /"
  grep -F "$iso" "$out" | cut -c1-400 | sed "s/^/NFF-RECORD head=$head row=$row rep=$rep: /"
fi
exit 0
