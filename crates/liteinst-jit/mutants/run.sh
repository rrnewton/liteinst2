#!/bin/sh
# Required mutation chains: green baseline, then per mutant a
# causal executed-test failure naming the expected assertion, then
# restored green on a clean tree. A compile/infrastructure error
# is NOT a kill. Run from anywhere:
#   sh crates/liteinst-jit/mutants/run.sh
set -u
cd "$(git rev-parse --show-toplevel)" || exit 1
if [ -n "$(git status --porcelain -- crates/liteinst-jit/src crates/liteinst-jit/tests)" ]; then
    echo "MUTANTS: refuse to run on a dirty liteinst-jit tree" >&2
    exit 1
fi
export CARGO_INCREMENTAL=0
echo "HEAD $(git rev-parse HEAD)"
sha256sum crates/liteinst-jit/mutants/0*.patch

run_suite() {
    cargo test --locked -p liteinst-jit >"$1" 2>&1
    return $?
}

# Mutants 06 and 07 change the remaining-RCB budget, which only the
# #[ignore]d corpus test exercises; run exactly that test for them.
# Its W1 assertion fails before any PMU witness, so the kill needs no
# PMU. Every other mutant runs the full default suite.
run_mutant() {
    case "$1" in
        06*|07*)
            cargo test --locked -p liteinst-jit --test budget_tail -- \
                --ignored --exact budget_tail_corpus_v1 >"$2" 2>&1
            return $?
            ;;
    esac
    run_suite "$2"
}

echo "=== BASELINE"
if run_suite /tmp/mutant-baseline.log; then
    echo "BASELINE green"
else
    echo "MUTANTS: baseline is RED — refusing to judge mutants" >&2
    exit 1
fi

# The budget corpus test is 06/07's only killing test, and it is not
# in the default suite. Run it once unmutated: its first failure must
# not already be W1, or a 06/07 "kill" would not be causal. Green is
# not required (its PMU witness may be unavailable on this host).
echo "=== BUDGET BASELINE (06/07)"
run_mutant 06-baseline /tmp/mutant-budget-baseline.log
if grep -Eq "first: .*W1: " /tmp/mutant-budget-baseline.log; then
    echo "MUTANTS: unmutated budget corpus already fails W1 — refusing to judge 06/07" >&2
    exit 1
fi
echo "BUDGET BASELINE: no W1 first failure"

expected_for() {
    case "$1" in
        01*) echo "retired branch credited exactly once" ;;
        02*) echo "sum_loop: branches" ;;
        03*) echo "StaleGeneration" ;;
        04*) echo "outside source range|fault pc offset" ;;
        05*) echo "fault_before_branch branches" ;;
        06*|07*) echo "first: .*W1: " ;;
        *) echo "FAILED" ;;
    esac
}

fail=0
for patch in crates/liteinst-jit/mutants/0*.patch; do
    name=$(basename "$patch" .patch)
    log=/tmp/mutant-$name.log
    rlog=/tmp/mutant-$name-restored.log
    echo "=== MUTANT $name: apply"
    if ! git apply "$patch"; then
        echo "MUTANTS: $name does not apply" >&2
        fail=1
        continue
    fi
    if run_mutant "$name" "$log"; then
        echo "MUTANT $name SURVIVED (suite green) — see $log"
        fail=1
    elif grep -q "could not compile" "$log"; then
        echo "MUTANT $name NOT KILLED (compile error, not a causal test failure) — see $log"
        fail=1
    elif grep -Eq "$(expected_for "$name")" "$log" && grep -q "test result: FAILED" "$log"; then
        echo "MUTANT $name KILLED (expected assertion failed)"
        grep -m2 -E "FAILED|panicked" "$log" || true
    else
        echo "MUTANT $name RED BUT UNCAUSAL (expected assertion not found) — see $log"
        fail=1
    fi
    git apply -R "$patch" || { echo "MUTANTS: restore failed for $name" >&2; exit 1; }
    if [ -n "$(git status --porcelain -- crates/liteinst-jit/src crates/liteinst-jit/tests)" ]; then
        echo "MUTANTS: restored tree dirty for $name" >&2
        fail=1
        continue
    fi
    if run_suite "$rlog"; then
        echo "MUTANT $name restored: suite green"
    else
        echo "MUTANTS: restored suite RED for $name — see $rlog" >&2
        fail=1
    fi
done
if [ "$fail" -eq 0 ]; then
    echo "MUTANTS: all chains green/red-causal/green as required"
else
    echo "MUTANTS: FAILURE" >&2
fi
exit "$fail"
