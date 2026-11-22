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
sha256sum crates/liteinst-jit/mutants/[0-9]*.patch

run_suite() {
    cargo test --locked -p liteinst-jit >"$1" 2>&1
    return $?
}

# The P1b.1 mutants (08-19) and the push mutants (23a/23b: no page
# crossing check; 24a/24b: a failed push write ignored) run only their
# named tests, each as "binary:fn"; every listed test must show its own
# FAILED line (see named_failures_ok). Empty for every other mutant.
# The O1 mutants (20-22) run the full default suite: their kill tests
# are src/o1.rs unit tests, which run before the integration binaries.
targets_for() {
    case "$1" in
        23a*) echo "indirect_resolve:push_crossing_inprocess" ;;
        23b*) echo "indirect_resolve:push_crossing_remote" ;;
        24a*) echo "indirect_resolve:push_fault_inprocess" ;;
        24b*) echo "indirect_resolve:push_fault_remote" ;;
        08*|09*) echo "o1_compare:p1b1_indirect_matches_o1 remote_compare:p1b1_indirect_remote_matches" ;;
        10*|11*) echo "indirect_resolve:resolver_forms" ;;
        12*) echo "indirect_resolve:refusal_inprocess indirect_resolve:refusal_remote" ;;
        13a*|13b*) echo "budget_tail:budget_tail_corpus_v1" ;;
        14*) echo "indirect_resolve:fault_inprocess indirect_resolve:fault_remote" ;;
        15*) echo "indirect_resolve:discovery_inprocess indirect_resolve:discovery_remote" ;;
        16*) echo "streaming_golden:streaming_translation_matches_golden_emission" ;;
        17*) echo "remote_signal:remote_signal_all" ;;
        18*) echo "indirect_resolve:install_failure_remote" ;;
        19*) echo "indirect_budget_handoff:budget_handoff_inprocess indirect_budget_handoff:budget_handoff_remote" ;;
        *) echo "" ;;
    esac
}

# Mutants 06 and 07 change the remaining-RCB budget, which only the
# #[ignore]d corpus test exercises; run exactly that test for them.
# Its W1 assertion fails before any PMU witness, so the kill needs no
# PMU. The P1b.1 mutants run their named tests (targets_for), the
# corpus test with --ignored. Every other mutant runs the full
# default suite.
run_mutant() {
    case "$1" in
        06*|07*)
            cargo test --locked -p liteinst-jit --test budget_tail -- \
                --ignored --exact budget_tail_corpus_v1 >"$2" 2>&1
            return $?
            ;;
    esac
    targets=$(targets_for "$1")
    if [ -n "$targets" ]; then
        : >"$2"
        mrc=0
        for bt in $targets; do
            bin=${bt%%:*}
            fn=${bt#*:}
            if [ "$bin" = budget_tail ]; then
                cargo test --locked -p liteinst-jit --test "$bin" -- \
                    --ignored --exact "$fn" >>"$2" 2>&1 || mrc=1
            else
                cargo test --locked -p liteinst-jit --test "$bin" -- \
                    --exact "$fn" >>"$2" 2>&1 || mrc=1
            fi
        done
        return "$mrc"
    fi
    run_suite "$2"
}

# A P1b.1 kill also needs every named test's own FAILED line, and 13b
# a Remote corpus row failing W1 (a non-zero exit alone is no kill).
named_failures_ok() {
    for bt in $(targets_for "$1"); do
        fn=${bt#*:}
        grep -Eq "^test $fn \.\.\. FAILED$" "$2" || return 1
    done
    case "$1" in
        13b*) grep -q "$(printf 'ROW\tRemote').*Fail(\"W1:" "$2" || return 1 ;;
    esac
    return 0
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
        08*) echo "ind_jmp_reg.*InteriorEntry" ;;
        09*) echo "indirect_call|ind_call_reg" ;;
        10*) echo "rax\*8" ;;
        11*) echo "rip\+" ;;
        12*) echo "rsp" ;;
        13a*) echo "first: InProcess .*W1: " ;;
        13b*) echo "first: Remote .*W1: " ;;
        14*) echo "instructions" ;;
        15*) echo "IndirectUnresolved" ;;
        16*) echo "golden mismatch: case=(indirect_jmp|indirect_call|jump_table)," ;;
        17b*) echo "proc_mem_writes" ;;
        17*) echo "live signal frame" ;;
        18*) echo "poisoned" ;;
        19*) echo "instructions" ;;
        20*) echo "O1 indirect prediction" ;;
        21*|22*) echo "passed the RIP-delta check" ;;
        23a*|23b*) echo "push crossing: want a named refusal" ;;
        24a*|24b*) echo "push fault: expected a fault" ;;
        *) echo "FAILED" ;;
    esac
}

fail=0
for patch in crates/liteinst-jit/mutants/[0-9]*.patch; do
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
    elif grep -Eq "$(expected_for "$name")" "$log" && grep -q "test result: FAILED" "$log" \
        && named_failures_ok "$name" "$log"; then
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
