#!/bin/sh
# Required mutation chains (Astra F5): each mutant must turn the
# crate test suite red, and the restored tree must return green.
# Run from the workspace root with a clean tree:
#   sh crates/liteinst-jit/mutants/run.sh
# Exits non-zero if any mutant passes (survives) or restoration fails.
set -u
cd "$(git rev-parse --show-toplevel)" || exit 1
if [ -n "$(git status --porcelain -- crates/liteinst-jit/src crates/liteinst-jit/tests)" ]; then
    echo "MUTANTS: refuse to run on a dirty liteinst-jit tree" >&2
    exit 1
fi
export CARGO_INCREMENTAL=0
fail=0
for patch in crates/liteinst-jit/mutants/0*.patch; do
    name=$(basename "$patch" .patch)
    echo "=== MUTANT $name: apply"
    if ! git apply "$patch"; then
        echo "MUTANTS: $name does not apply" >&2
        fail=1
        continue
    fi
    if cargo test --locked -p liteinst-jit >/tmp/mutant-$name.log 2>&1; then
        echo "MUTANT $name SURVIVED (suite green) — see /tmp/mutant-$name.log"
        fail=1
    else
        echo "MUTANT $name KILLED (suite red as required)"
        grep -m2 -E "FAILED|panicked" /tmp/mutant-$name.log || true
    fi
    git apply -R "$patch" || { echo "MUTANTS: restore failed for $name" >&2; exit 1; }
    if cargo test --locked -p liteinst-jit >/tmp/mutant-$name-restored.log 2>&1; then
        echo "MUTANT $name restored: suite green"
    else
        echo "MUTANTS: restored suite RED for $name — see /tmp/mutant-$name-restored.log" >&2
        fail=1
    fi
done
if [ "$fail" -eq 0 ]; then
    echo "MUTANTS: all chains pass/fail/pass as required"
else
    echo "MUTANTS: FAILURE" >&2
fi
exit "$fail"
