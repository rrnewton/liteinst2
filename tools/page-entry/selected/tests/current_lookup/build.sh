#!/bin/sh
# Recipe only: metadata/build/native calls must be supervised independently.
set -eu
test "$#" -eq 3
owner_context=$1
selected_context=$2
output_dir=$3
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
parent_context=$(CDPATH= cd -- "$selected_context/.." && pwd)
cc_bin=${LI2_CC:-cc}
mkdir -p "$output_dir"
"$cc_bin" -std=gnu11 -O2 -g -fno-stack-protector -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
  -Wall -Wextra -Werror -DLI2_TF_HANDOFF=1 -DLI2_REGISTER_RUN=1 \
  -DLI2_MAPS_PHASE_REUSE=1 -DLI2_RSEQ_INACTIVE=1 -DLI2_NATIVE_PAGES=1 \
  -DLI2_FAST_MEMSET=1 -DLI2_FAST_EQUAL=1 -DLI2_ONESHOT_PUBLICATION=1 \
  -I"$owner_context" -I"$selected_context" -I"$parent_context" \
  -Wl,--gc-sections,-z,noexecstack,--build-id=none \
  "$fixture_dir/oracle.c" -o "$output_dir/current-lookup"
