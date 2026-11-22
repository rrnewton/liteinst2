#!/usr/bin/env bash
# Reports, never decides. Counts the native-CPUID tests that failed by name
# on an uncalibrated host (single-step trap lost after CPUID; issues 112 and
# 115) apart from every other failed test, from the test step's tee'd log.
# The job's result comes from the test step alone: this script always exits
# 0, so a bug here can never turn a red job green.
set -u
export LC_ALL=C # one collation for sort and comm

log="${1:?usage: uncalibrated-host-summary.sh TEST_LOG}"
summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

if [ ! -f "$log" ]; then
  echo "::warning title=no test log::$log was not written, so nothing was counted"
  exit 0
fi

# Strip colour codes; libtest prints one "test NAME ... FAILED" line per test.
clean="$(sed 's/\x1b\[[0-9;]*m//g' "$log")"
uncalibrated="$(printf '%s\n' "$clean" |
  sed -n 's/.*UNCALIBRATED HOST: \([^ ]*\): single-step trap lost after CPUID.*/\1/p' |
  sort -u)"
failed="$(printf '%s\n' "$clean" | sed -n 's/^test \(.*\) \.\.\. FAILED$/\1/p' | sort -u)"
# A gate name is "<binary>::<libtest name>"; drop the binary to match.
gated="$(printf '%s\n' "$uncalibrated" | sed -n 's/^[^:]*:://p' | sort -u)"
other="$(comm -23 <(printf '%s\n' "$failed" | sed '/^$/d') <(printf '%s\n' "$gated" | sed '/^$/d'))"
targets="$(printf '%s\n' "$clean" | sed -n '/^error: [0-9]* targets\{0,1\} failed:$/,/^[^ ]/{/^ /p}')"

count() {
  if [ -z "$1" ]; then echo 0; else printf '%s\n' "$1" | wc -l | tr -d ' '; fi
}
n="$(count "$uncalibrated")"
m="$(count "$other")"

if [ "$n" -gt 0 ]; then
  echo "::error title=uncalibrated host::$n native-CPUID tests could not be verified on this runner (single-step trap lost after CPUID; issues 112, 115)"
fi

{
  echo "### Native-CPUID verification"
  echo
  echo "Uncalibrated host (single-step trap lost after CPUID; issues 112, 115): $n"
  if [ "$n" -gt 0 ]; then
    echo
    echo "| Test that could not be verified |"
    echo "|---|"
    printf '%s\n' "$uncalibrated" | sed 's/.*/| `&` |/'
  fi
  echo
  echo "Other FAILED: $m"
  if [ "$m" -gt 0 ]; then
    echo
    echo "| Other failed test |"
    echo "|---|"
    printf '%s\n' "$other" | sed 's/.*/| `&` |/'
  fi
  if [ -n "$targets" ]; then
    echo
    echo "Failed targets:"
    echo
    printf '%s\n' "$targets" | sed 's/^ *\(.*\)$/- \1/'
  fi
} >> "$summary"
exit 0
