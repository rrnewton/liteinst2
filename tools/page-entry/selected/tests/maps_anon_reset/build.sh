#!/bin/sh
# Compile only; retain the original maps-oracle 5 CPU / 15 wall / 512 MiB / 16 MiB bounds.
set -eu
test "$#" -eq 3
selected_dir=$(CDPATH= cd -- "$1" && pwd)
output_dir=$2
profile=$3
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
parent_dir=$(CDPATH= cd -- "$selected_dir/.." && pwd)
cc_bin=${LI2_CC:-cc}
case "$profile" in
  maintained) set -- ;;
  differential) set -- -DLI2_MAPS_DIFFERENTIAL=1 ;;
  *) exit 2 ;;
esac
mkdir -p "$output_dir"
"$cc_bin" -std=gnu11 -O2 -g -fno-stack-protector -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
  -Wall -Wextra -Werror -DLI2_MAPS_PHASE_REUSE=1 -DLI2_MAPS_MAINTAINED=1 "$@" \
  -I"$selected_dir" -I"$parent_dir" \
  -MD -MF "$output_dir/maps-anon-reset.d" \
  -Wl,--gc-sections,-z,noexecstack,--build-id=none \
  "$fixture_dir/oracle.c" -o "$output_dir/maps-anon-reset"
