#!/bin/sh
# One actual fresh decoder archive; no Cargo work or alternate runtime tree.
set -eu
test "$#" -eq 3
archive=$1
output=$2
selected=$(CDPATH= cd -- "$3" && pwd)
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
parent=$(CDPATH= cd -- "$selected/.." && pwd)
cc_bin=${LI2_CC:-cc}
python_bin=${LI2_PYTHON:-python3}
"$python_bin" "$selected/tests/register_run/prepare.py" "$selected/tests/generic/fixture.c" "$output/run_support.base"
"$python_bin" "$selected/tests/maps_phase/adapt_support.py" "$output/run_support.base" "$output/run_support.inc"
"$python_bin" "$fixture/prepare.py" "$selected/tests/register_run/fixture.c" "$output/timing_support.inc"
for control in 0 1 2; do
  set --
  if test "$control" -eq 1; then set -- -DLI2_RUN_TIMING_TEST=1; fi
  "$cc_bin" -std=gnu11 -O2 -g -nostdlib -static -no-pie -fno-pie \
    -fno-builtin -fno-stack-protector -fno-tree-loop-distribute-patterns \
    -fno-tree-vectorize -mgeneral-regs-only -fno-asynchronous-unwind-tables \
    -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
    -DREGISTER_GROUP=0 -DTIMING_CONTROL="$control" -DLI2_MAPS_PHASE_REUSE=1 \
    -DLI2_RUN_TIMING=1 "$@" -I"$output" \
    -I"$selected/tests/register_run" -I"$selected/tests/generic" -I"$selected" -I"$parent" \
    -Wl,-e,_start,-z,noexecstack,--gc-sections,--build-id=none \
    "$selected/step_owner.c" "$selected/lifecycle_loader.c" \
    "$selected/register_run_plan.c" "$selected/register_run_owner.c" \
    "$selected/register_run_publish.c" "$selected/register_run_reset.c" \
    "$selected/register_run_timing.c" "$selected/tests/generic/tf_controls.c" \
    "$fixture/fixture.c" "$selected/tests/generic/fixture.S" "$archive" \
    -o "$output/register-timing-$control"
done
