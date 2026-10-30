#!/bin/sh
# The existing bounded Build/process owner supplies compiler/archive/headers.
set -eu
[ "$#" -eq 4 ] || { echo 'usage: build.sh ROOT SELECTED_DIR DECODER_ARCHIVE OUTPUT_DIR' >&2; exit 2; }
root=$(realpath "$1")
selected_dir=$(realpath "$2")
decoder_archive=$(realpath "$3")
output_dir=$(realpath -m "$4")
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cc_bin=${LI2_CC:-cc}
[ ! -e "$output_dir" ]
mkdir -p "$output_dir"
"$cc_bin" -std=gnu11 -O2 -g -fno-builtin -fno-stack-protector \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -fno-omit-frame-pointer \
  -Wall -Wextra -Werror -Wno-misleading-indentation \
  -DLI2_FAST_MEMSET=1 -DLI2_FAST_EQUAL=1 \
  -I"$selected_dir" -I"$root/tools/page-entry/selected" \
  -I"$root/tools/page-entry/selected/tests/region_cache" \
  "$fixture_dir/oracle.c" "$root/tools/page-entry/selected/tests/region_cache/machine.S" \
  "$selected_dir/unrolled_hash_plan.c" "$decoder_archive" \
  -Wl,-z,now,-z,relro,--no-undefined -ldl -lpthread -lm -o "$output_dir/unrolled-hash"
