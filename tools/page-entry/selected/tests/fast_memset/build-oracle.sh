#!/bin/sh
# Source-only recipe: does not run either binary.
set -eu
test "$#" -eq 3
bridge_source=$1
selected_dir=$2
output_dir=$3
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
parent_dir=$(CDPATH= cd -- "$selected_dir/.." && pwd)
cc_bin=${LI2_CC:-cc}
mkdir -p "$output_dir"
for mode in scalar fast; do
  extra=
  if test "$mode" = fast; then extra=-DLI2_FAST_MEMSET=1; fi
  "$cc_bin" -std=gnu11 -O2 -g -fPIC -fvisibility=hidden -fno-stack-protector \
    -fno-builtin -fno-tree-loop-distribute-patterns -fno-tree-vectorize \
    -mgeneral-regs-only -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
    -Wall -Wextra -Werror -Dmemset=li2_test_memset -Dmemcpy=li2_test_memcpy \
    -DLI2_TF_HANDOFF=1 -DLI2_REGISTER_RUN=1 -DLI2_MAPS_PHASE_REUSE=1 -DLI2_RSEQ_INACTIVE=1 \
    $extra -I"$parent_dir" -c "$bridge_source" -o "$output_dir/bridge-$mode.o"
  "$cc_bin" -std=gnu11 -O2 -g -fno-builtin -fno-stack-protector \
    -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
    -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
    -DLI2_TF_HANDOFF=1 -DLI2_REGISTER_RUN=1 -DLI2_MAPS_PHASE_REUSE=1 -DLI2_RSEQ_INACTIVE=1 \
    -Wall -Wextra -Werror -I"$selected_dir" -I"$parent_dir" \
    -Wl,--gc-sections,-z,noexecstack,--build-id=none \
    "$fixture_dir/oracle.c" "$output_dir/bridge-$mode.o" -o "$output_dir/memset-$mode"
done
