#!/bin/sh
set -eu
[ "$#" = 4 ] || { echo 'usage: build.sh ROOT SELECTED_DIR DECODER_ARCHIVE OUTPUT_DIR' >&2; exit 2; }
root=$1
selected_dir=$2
archive=$3
output=$4
cc_bin=${CC:-cc}
mkdir -p "$output"
"$cc_bin" -std=gnu11 -O2 -g -fno-builtin -fno-stack-protector \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -fstack-usage \
  -Wall -Wextra -Werror -Wno-misleading-indentation \
  -I"$selected_dir" -I"$root/tools/page-entry/selected" \
  "$root/tools/page-entry/selected/tests/region_plan/oracle.c" \
  "$selected_dir/region_plan.c" "$archive" \
  -Wl,-z,now,-z,relro,--no-undefined -ldl -lpthread -lm \
  -o "$output/region-plan-oracle"
