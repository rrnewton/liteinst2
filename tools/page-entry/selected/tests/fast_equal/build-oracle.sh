#!/bin/sh
# Source-only recipe. Actual commands must be supervised separately before use.
set -eu
test "$#" -eq 3
owner_source=$1
selected_context=$2
output_dir=$3
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
parent_context=$(CDPATH= cd -- "$selected_context/.." && pwd)
cc_bin=${LI2_CC:-cc}
mkdir -p "$output_dir"
for mode in scalar fast; do
  extra=
  if test "$mode" = fast; then extra=-DLI2_FAST_EQUAL=1; fi
  "$cc_bin" -std=gnu11 -O2 -g -fPIC -fvisibility=hidden -fno-stack-protector \
    -fno-builtin -fno-tree-loop-distribute-patterns -fno-tree-vectorize \
    -mgeneral-regs-only -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
    -Wall -Wextra -Werror -DLI2_EQUAL_ORACLE=1 \
    -DLI2_TF_HANDOFF=1 -DLI2_REGISTER_RUN=1 -DLI2_MAPS_PHASE_REUSE=1 -DLI2_RSEQ_INACTIVE=1 \
    -DLI2_NATIVE_PAGES=1 -DLI2_FAST_MEMSET=1 -DLI2_ONESHOT_PUBLICATION=1 \
    $extra -I"$selected_context" -I"$parent_context" -c "$owner_source" -o "$output_dir/owner-$mode.o"
  "$cc_bin" -std=gnu11 -O2 -g -fno-builtin -fno-stack-protector \
    -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
    -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
    -Wall -Wextra -Werror $extra -Wl,--gc-sections,-z,noexecstack,--build-id=none \
    "$fixture_dir/oracle.c" "$output_dir/owner-$mode.o" -o "$output_dir/equal-$mode"
done
