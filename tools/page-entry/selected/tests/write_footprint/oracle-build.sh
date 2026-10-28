#!/bin/sh
set -eu
test "$#" -eq 3
archive=$1
output=$2
selected_dir=$(CDPATH= cd -- "$3" && pwd)
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test -f "$archive"
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -nostdlib -static -no-pie -fno-pie \
 -fno-builtin -fno-stack-protector -fno-tree-loop-distribute-patterns \
 -fno-tree-vectorize -mgeneral-regs-only -fno-asynchronous-unwind-tables \
 -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
 -I"$selected_dir" -I"$source_dir" \
 -Wl,-e,_start,-z,noexecstack,--gc-sections,--build-id=none \
 "$source_dir/oracle.c" "$source_dir/oracle.S" "$archive" -o "$output"
