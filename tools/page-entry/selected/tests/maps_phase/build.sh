#!/bin/sh
set -eu
test "$#" -eq 2
selected_dir=$(CDPATH= cd -- "$1" && pwd)
output_dir=$2
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
parent_dir=$(CDPATH= cd -- "$selected_dir/.." && pwd)
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -nostdlib -static -no-pie -fno-pie \
  -fno-builtin -fno-stack-protector -fno-tree-loop-distribute-patterns \
  -fno-tree-vectorize -mgeneral-regs-only -fno-asynchronous-unwind-tables \
  -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
  -DLI2_MAPS_PHASE_REUSE=1 -DLI2_MAPS_PHASE_TEST=1 -I"$selected_dir" -I"$parent_dir" \
  -Wl,-e,_start,-z,noexecstack,--gc-sections,--build-id=none,--no-undefined \
  "$selected_dir/lifecycle_loader.c" "$fixture_dir/fixture.c" "$fixture_dir/fixture.S" \
  -o "$output_dir/maps-phase"
