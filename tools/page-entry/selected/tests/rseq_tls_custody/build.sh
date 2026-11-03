#!/bin/sh
# Recipe only: preparation, compiler, and each subject are separately bounded.
set -eu
test "$#" -eq 4
selected_dir=$(CDPATH= cd -- "$1" && pwd)
output_dir=$2
archive=$3
profile=$4
case "$profile" in
  projected) maps='-DLI2_MAPS_MAINTAINED=1 -DLI2_MAPS_CURRENT_TF=1' ;;
  verified) maps='-DLI2_MAPS_MAINTAINED=1 -DLI2_MAPS_CURRENT_TF=1 -DLI2_MAPS_DIFFERENTIAL=1' ;;
  fresh) maps= ;;
  *) exit 2 ;;
esac
test -f "$archive"
test -f "$output_dir/loader.inc"
test -f "$output_dir/support.inc"
test -f "$output_dir/rseq.c"
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
parent_dir=$(CDPATH= cd -- "$selected_dir/.." && pwd)
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -fno-stack-protector -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
  -Wall -Wextra -Werror -DLI2_MAPS_PHASE_REUSE=1 \
  -DLI2_TF_HANDOFF=1 -DLI2_TF_SAME_PAGE_LEASE=1 -DLI2_TF_SEALED_CUSTODY=1 \
  -DLI2_RSEQ_INACTIVE=1 $maps \
  -I"$output_dir" -I"$selected_dir" -I"$parent_dir" \
  -Wl,--gc-sections,-z,noexecstack,--build-id=none \
  "$fixture_dir/oracle.c" "$output_dir/rseq.c" "$selected_dir/step_owner.c" \
  "$archive" -ldl -lpthread -lm -o "$output_dir/rseq-tls-custody"
