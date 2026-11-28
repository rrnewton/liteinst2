#!/usr/bin/env bash
# Classifies the failures in the test step's tee'd log for a human applying
# the named-class rule. The test step alone decides red or green; this step
# runs last and can only add red. It exits 1 when the log cannot be
# classified, so a missing, incomplete or inconsistent log is loud instead of
# reading as zero.
#
# Verdict, the first line of the step summary:
#   NO-FAILED-TARGETS  the test step succeeded and the log shows no failure
#   ONLY-NAMED         every failed target is only the named uncalibrated-host
#                      class (single-step trap lost after CPUID; issues 112, 115)
#   OUTSIDE(k)         k failed targets hold a failure outside that class
#   UNCLASSIFIED       the log is missing, incomplete or inconsistent (exit 1)
#
# A failed target is in the named class only when every failure in it is
# named by the gate's "UNCALIBRATED HOST:" line inside that same target, and
# it ended as libtest or an uncaught gate panic ends (exit 101): libtest's
# last "test result" line, with exactly as many FAILED lines as its
# "N failed" count, each one named; or, for a target with no libtest output,
# gate panics and no other panic. Cargo prints "process didn't exit
# successfully" for any other status of a process that ran; that puts the
# target outside. Cargo's own final "error: N target(s) failed:" list must
# match the failed targets found here, one for one.
#
# Failure evidence is a FAILED line, a gate line, an abnormal-exit line or
# cargo's failure lines. A "panicked at" line alone is not: passing tests in
# this workspace print panics from their own negative controls.
set -u
set -o pipefail
export LC_ALL=C

log="${1:-}"
outcome="${2:-}"
summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

# report VERDICT DETAIL BODY: writes the summary; exits 1 for UNCLASSIFIED.
report() {
  case "$1" in
    UNCLASSIFIED) echo "::error title=unclassified test log::$1: $2" ;;
    OUTSIDE*) echo "::error title=failures outside the named class::$1: $2" ;;
    *) echo "::notice title=test log classified::$1: $2" ;;
  esac
  {
    echo "### Native-CPUID verification: $1"
    echo
    echo "$2"
    if [ -n "$3" ]; then echo; printf '%s\n' "$3"; fi
  } >> "$summary"
  if [ "$1" = UNCLASSIFIED ]; then exit 1; fi
  exit 0
}

count() {
  if [ -z "$1" ]; then echo 0; else printf '%s\n' "$1" | wc -l | tr -d ' '; fi
}

if [ -z "$log" ] || [ -z "$outcome" ]; then
  report UNCLASSIFIED "usage: uncalibrated-host-summary.sh TEST_LOG TEST_STEP_OUTCOME" ""
fi
if [ ! -r "$log" ]; then
  report UNCLASSIFIED "no readable test log at $log (test step outcome: $outcome)" ""
fi
case "$outcome" in
  success | failure) ;;
  *) report UNCLASSIFIED "test step outcome is '$outcome', not success or failure" "" ;;
esac

# Records, tab-separated:
#   G <gate name>
#   T <target args> <NAMED|OUTSIDE|UNCLASSIFIED> <why> <FAILED tests without a gate line>
#   U <problem that makes the whole log unclassified>
#   F <cargo final list present 0|1> <failed targets found> <failure lines seen>
records="$(sed '1s/^\xEF\xBB\xBF//; s/\r$//; s/\x1b\[[0-9;]*m//g' "$log" | awk '
  BEGIN { seg = 0; haslist = 0; listed_n = 0; nlisted = 0; ntargets = 0; lines = 0; pre = 0 }
  /^[[:space:]]*(Running (unittests )?[^ ]+ \(.+\)|Doc-tests [^ ]+)$/ {
    seg++; label[seg] = $0; sub(/^[[:space:]]+/, "", label[seg]); inlist = 0; next
  }
  /^error: [0-9]+ targets? failed:$/ { haslist = 1; listed_n = $2 + 0; inlist = 1; next }
  inlist && /^    `[^`]+`$/ {
    t = $0; sub(/^    `/, "", t); sub(/`$/, "", t); listed[t] = 1; nlisted++; next
  }
  { inlist = 0 }
  /^test .* \.\.\. FAILED$/ || /^UNCALIBRATED HOST: [^ ]+: single-step trap lost after CPUID/ || /process didn.t exit successfully: / {
    lines++
    if (seg == 0) { pre++; next }
    content[seg] = 1
  }
  seg == 0 { next }
  /^running [0-9]+ tests?$/ { running[seg] = 1; next }
  /^test .* \.\.\. FAILED$/ {
    name = $0; sub(/^test /, "", name); sub(/ \.\.\. FAILED$/, "", name)
    nf[seg]++; fname[seg, nf[seg]] = name
    next
  }
  /^UNCALIBRATED HOST: [^ ]+: single-step trap lost after CPUID/ {
    gate = $0
    sub(/^UNCALIBRATED HOST: /, "", gate)
    sub(/: single-step trap lost after CPUID.*/, "", gate)
    if (!((seg, gate) in seen)) { seen[seg, gate] = 1; ng[seg]++; print "G\t" gate }
    bare = gate; sub(/^[^:]*::/, "", bare); named[seg, bare] = 1
    next
  }
  /panicked at / { if ($0 !~ /host_cpuid_step\.rs:[0-9]/) panics[seg]++; next }
  /^test result: / {
    result[seg] = 1; F[seg] = 0
    if ($0 ~ /^test result: FAILED\. [0-9]+ passed; [0-9]+ failed;/) {
      f = $0; sub(/^test result: FAILED\. [0-9]+ passed; /, "", f); sub(/ failed;.*$/, "", f)
      F[seg] = f + 0
    }
    next
  }
  /^error: (test|doctest) failed, to rerun pass `[^`]+`$/ {
    t = $0; sub(/^error: [a-z]+ failed, to rerun pass `/, "", t); sub(/`$/, "", t)
    target[seg] = t; ntargets++
    next
  }
  /process didn.t exit successfully: / {
    d = $0; sub(/.*process didn.t exit successfully: `[^`]*` */, "", d); exitnote[seg] = d
    next
  }
  END {
    if (pre > 0) print "U\t" pre " failure line(s) appear before the first test target"
    for (i = 1; i <= seg; i++) {
      if (!(i in target)) {
        if (i in content) print "U\ta section has failure lines but no cargo failure line: " label[i]
        continue
      }
      t = target[i]
      if (t in done) { print "U\tcargo reports target " t " twice"; continue }
      done[t] = 1
      if (haslist && !(t in listed)) print "U\ttarget " t " failed but is missing from cargo final list"
      cls = ""; why = ""
      unnamed = ""; nu = 0
      for (k = 1; k <= nf[i]; k++) {
        if (!((i, fname[i, k]) in named)) {
          unnamed = unnamed (nu > 0 ? ", " : "") fname[i, k]; nu++
        }
      }
      if (i in exitnote) { cls = "OUTSIDE"; why = "abnormal exit " exitnote[i] }
      else if (i in result) {
        if (F[i] != nf[i]) { cls = "UNCLASSIFIED"; why = "libtest reports " F[i] " failed but " nf[i] " FAILED lines were found" }
        else if (F[i] == 0) { cls = "UNCLASSIFIED"; why = "target failed but libtest reports no failed test" }
        else if (nu > 0) { cls = "OUTSIDE"; why = nu " of " F[i] " failed tests have no gate line" }
        else { cls = "NAMED"; why = F[i] " failed, each named by its gate line" }
      }
      else if (i in running) { cls = "UNCLASSIFIED"; why = "libtest section has no result line" }
      else if (nf[i] > 0) { cls = "UNCLASSIFIED"; why = nf[i] " FAILED lines without a libtest result" }
      else if (panics[i] > 0) { cls = "OUTSIDE"; why = "a panic outside the gate and no libtest result" }
      else if (ng[i] > 0) { cls = "NAMED"; why = "ended at the gate panic (exit 101)" }
      else { cls = "UNCLASSIFIED"; why = "target failed with no result line, gate line or exit note" }
      print "T\t" t "\t" cls "\t" why "\t" unnamed
    }
    for (t in listed) if (!(t in done)) print "U\tcargo lists " t " but no section reports it"
    if (haslist && listed_n != nlisted) print "U\tcargo says " listed_n " target(s) failed but lists " nlisted
    print "F\t" haslist "\t" ntargets "\t" lines
  }')" || report UNCLASSIFIED "the classifier itself failed (sed or awk exited non-zero)" ""

gates="$(printf '%s\n' "$records" | sed -n 's/^G\t//p')"
targets="$(printf '%s\n' "$records" | sed -n 's/^T\t//p')"
problems="$(printf '%s\n' "$records" | sed -n 's/^U\t//p')"
facts="$(printf '%s\n' "$records" | sed -n 's/^F\t//p')"
if [ "$(count "$facts")" != 1 ]; then
  report UNCLASSIFIED "the classifier produced no final fact record" ""
fi
haslist="$(printf '%s\n' "$facts" | cut -f1)"
lines="$(printf '%s\n' "$facts" | cut -f3)"

add() { problems="${problems:+$problems$'\n'}$1"; }
t="$(count "$targets")"
if [ "$outcome" = success ]; then
  if [ "$t" != 0 ] || [ "$haslist" != 0 ] || [ "$lines" != 0 ]; then
    add "the test step succeeded but the log shows failures"
  fi
else
  [ "$haslist" = 1 ] || add "the test step failed and the log has no cargo final failed-target list (build failure, truncated or killed run, or fail-fast)"
  [ "$t" != 0 ] || add "the test step failed and no failed target was found"
fi
add_targets="$(printf '%s\n' "$targets" | awk -F'\t' 'NF && $2 != "NAMED" && $2 != "OUTSIDE" { print "target " $1 ": " ($2 == "UNCLASSIFIED" ? $3 : "no class assigned (" $2 ")") }')"
if [ -n "$add_targets" ]; then add "$add_targets"; fi
outside="$(printf '%s\n' "$targets" | awk -F'\t' '$2 == "OUTSIDE"')"
k="$(count "$outside")"
n="$(count "$gates")"

body=""
if [ -n "$problems" ]; then
  body="$(printf '%s\n' "$problems" | sed 's/^/- /')"
fi
if [ "$n" -gt 0 ]; then
  body="$body"$'\n\n'"| Test named by the gate ($n) |"$'\n'"|---|"$'\n'"$(printf '%s\n' "$gates" | sed 's/.*/| `&` |/')"
fi
if [ "$t" -gt 0 ]; then
  body="$body"$'\n\n'"| Failed target | Class | Why | FAILED without a gate line |"$'\n'"|---|---|---|---|"$'\n'"$(printf '%s\n' "$targets" | awk -F'\t' '{ printf "| `%s` | %s | %s | %s |\n", $1, $2, $3, ($4 == "" ? "-" : $4) }')"
fi

if [ -n "$problems" ]; then
  report UNCLASSIFIED "$(count "$problems") problem(s); $t failed target(s) found; see below" "$body"
elif [ "$t" = 0 ]; then
  report NO-FAILED-TARGETS "the test step succeeded and the log shows no failure" "$body"
elif [ "$k" -gt 0 ]; then
  report "OUTSIDE($k)" "$k of $t failed targets hold a failure outside the named class" "$body"
else
  report ONLY-NAMED "all $t failed targets are only the named uncalibrated-host class ($n named tests)" "$body"
fi
