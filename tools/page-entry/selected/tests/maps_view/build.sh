#!/bin/sh
# Recipe only. The existing bounded process owner supervises compile/native.
set -eu
test "$#" -eq 2
selected_dir=$(CDPATH= cd -- "$1" && pwd)
output_dir=$2
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
parent_dir=$(CDPATH= cd -- "$selected_dir/.." && pwd)
cc_bin=${LI2_CC:-cc}
mkdir -p "$output_dir"
"$cc_bin" -std=gnu11 -O2 -g -fno-stack-protector -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
  -Wall -Wextra -Werror -DLI2_MAPS_PHASE_REUSE=1 \
  -DLI2_MAPS_MAINTAINED=1 -DLI2_MAPS_DIFFERENTIAL=1 \
  -I"$selected_dir" -I"$parent_dir" \
  -Wl,--gc-sections,-z,noexecstack,--build-id=none \
  "$fixture_dir/oracle.c" -o "$output_dir/maps-view"
