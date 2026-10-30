#!/bin/sh
# Recipe only; the existing bounded process owner supervises all commands.
set -eu
test "$#" -eq 4
selected_dir=$(CDPATH= cd -- "$1" && pwd)
output_dir=$2
archive=$3
profile=$4
case "$profile" in
  projected) differential= ;;
  verified) differential=-DLI2_MAPS_DIFFERENTIAL=1 ;;
  *) exit 2 ;;
esac
test -f "$archive"
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
parent_dir=$(CDPATH= cd -- "$selected_dir/.." && pwd)
cc_bin=${LI2_CC:-cc}
mkdir -p "$output_dir"
"$cc_bin" -std=gnu11 -O2 -g -fno-stack-protector -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
  -Wall -Wextra -Werror -DLI2_MAPS_PHASE_REUSE=1 -DLI2_MAPS_MAINTAINED=1 \
  -DLI2_TF_HANDOFF=1 -DLI2_TF_SAME_PAGE_LEASE=1 -DLI2_TF_SEALED_CUSTODY=1 \
  -DLI2_RSEQ_INACTIVE=1 -DLI2_MAPS_CURRENT_TF=1 $differential \
  -I"$selected_dir" -I"$parent_dir" \
  -Wl,--gc-sections,-z,noexecstack,--build-id=none \
  "$fixture_dir/oracle.c" "$archive" -ldl -lpthread -lm \
  -o "$output_dir/maps-current-custody"
