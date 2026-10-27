#!/bin/sh
# The bounded runner generates/pins run_support.inc before this link command.
set -eu
test "$#" -eq 3
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
decoder_archive=$1
output_dir=$2
selected_dir=$(CDPATH= cd -- "$3" && pwd)
parent_dir=$(CDPATH= cd -- "$selected_dir/.." && pwd)
test -f "$decoder_archive"
test -f "$output_dir/run_support.inc"
test -f "$selected_dir/tests/generic/fixture.S"
cc_bin=${LI2_CC:-cc}
for group in 0 1 2 3; do
  "$cc_bin" -std=gnu11 -O2 -g -nostdlib -static -no-pie -fno-pie \
    -fno-builtin -fno-stack-protector -fno-tree-loop-distribute-patterns \
    -fno-tree-vectorize -mgeneral-regs-only -fno-asynchronous-unwind-tables \
    -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
    -DREGISTER_GROUP="$group" -I"$output_dir" -I"$fixture_dir" \
    -I"$selected_dir/tests/generic" -I"$selected_dir" -I"$parent_dir" \
    -Wl,-e,_start,-z,noexecstack,--gc-sections,--build-id=none \
    "$selected_dir/step_owner.c" "$selected_dir/lifecycle_loader.c" \
    "$selected_dir/register_run_plan.c" "$selected_dir/register_run_owner.c" \
    "$selected_dir/register_run_publish.c" "$selected_dir/register_run_reset.c" \
    "$selected_dir/tests/generic/tf_controls.c" "$fixture_dir/fixture.c" \
    "$selected_dir/tests/generic/fixture.S" "$decoder_archive" \
    -o "$output_dir/register-run-$group"
done
