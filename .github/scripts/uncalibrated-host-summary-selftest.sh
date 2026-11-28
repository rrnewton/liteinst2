#!/usr/bin/env bash
# Planted controls for uncalibrated-host-summary.sh: one log per special
# path, listed in testdata/uncalibrated-summary/cases.tsv with the verdict,
# exit status and summary text each must produce. Exits 1 if the case file
# is unreadable, if the number of cases run is not exactly EXPECTED_CASES,
# or if any case differs.
set -u
EXPECTED_CASES=30
here="$(cd "$(dirname "$0")" && pwd)"
data="$here/testdata/uncalibrated-summary"
cases="$data/cases.tsv"
if [ ! -f "$cases" ] || [ ! -r "$cases" ]; then
  echo "FAIL: cannot read $cases"
  exit 1
fi
scratch="$(mktemp -d)"
fail=0
ran=0
while IFS=$'\t' read -r name file outcome want want_rc want_text; do
  case "$name" in '' | '#'*) continue ;; esac
  ran=$((ran + 1))
  log="$data/$file"
  [ "$file" = "-" ] && log="$scratch/no-such.log"
  out="$scratch/$name.md"
  : > "$out"
  GITHUB_STEP_SUMMARY="$out" bash "$here/uncalibrated-host-summary.sh" "$log" "$outcome" > "$scratch/$name.out" 2>&1
  rc=$?
  got="$(sed -n '1s/^### Native-CPUID verification: //p' "$out")"
  if [ "$got" != "$want" ] || [ "$rc" != "$want_rc" ]; then
    echo "FAIL $name: verdict '$got' exit $rc; want '$want' exit $want_rc"
    fail=1
  elif [ -z "$want_text" ] || ! grep -q -F -- "$want_text" "$out"; then
    echo "FAIL $name: summary lacks '$want_text'"
    fail=1
  fi
done < "$cases"
if [ "$ran" != "$EXPECTED_CASES" ]; then
  echo "FAIL: ran $ran cases, expected exactly $EXPECTED_CASES"
  fail=1
fi
if [ "$fail" = 0 ]; then echo "all $ran planted controls classified as expected"; fi
exit "$fail"
