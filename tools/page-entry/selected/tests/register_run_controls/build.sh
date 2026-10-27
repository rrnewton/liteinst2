#!/bin/sh
set -eu
test "$#" -eq 3
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
decoder_archive=$1
output_dir=$2
selected_dir=$(CDPATH= cd -- "$3" && pwd)
parent_dir=$(CDPATH= cd -- "$selected_dir/.." && pwd)
test -f "$decoder_archive"
test -f "$output_dir/control_support.inc"
test -f "$output_dir/run_support.inc"
cc_bin=${LI2_CC:-cc}
# Only this object uses the explicitly recorded negative raw-call adapter.
"$cc_bin" -std=gnu11 -O2 -g -fno-pie -fno-builtin -fno-stack-protector \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
  -Dli2_step_raw=li2_control_raw -I"$selected_dir" -I"$parent_dir" \
  -c "$selected_dir/register_run_publish.c" -o "$output_dir/publisher-controls.o"
"$cc_bin" -std=gnu11 -O2 -g -nostdlib -static -no-pie -fno-pie \
  -fno-builtin -fno-stack-protector -fno-tree-loop-distribute-patterns \
  -fno-tree-vectorize -mgeneral-regs-only -fno-asynchronous-unwind-tables \
  -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
  -DREGISTER_GROUP=0 -I"$output_dir" -I"$selected_dir/tests/register_run" \
  -I"$selected_dir/tests/generic" -I"$selected_dir" -I"$parent_dir" \
  -Wl,-e,_start,-z,noexecstack,--gc-sections,--build-id=none \
  "$selected_dir/step_owner.c" "$selected_dir/lifecycle_loader.c" \
  "$selected_dir/register_run_plan.c" "$selected_dir/register_run_owner.c" \
  "$selected_dir/register_run_reset.c" "$output_dir/publisher-controls.o" \
  "$selected_dir/tests/generic/tf_controls.c" "$fixture_dir/fixture.c" \
  "$selected_dir/tests/generic/fixture.S" "$decoder_archive" \
  -o "$output_dir/register-run-controls"
