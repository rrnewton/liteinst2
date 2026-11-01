#!/bin/sh
# Component only. Caller supplies an authenticated scalar-read decoder archive
# and the existing bounded process owner; this recipe does not build Rust/run.
set -eu
[ "$#" -eq 4 ] || { echo 'usage: build.sh ROOT SELECTED_DIR DECODER_ARCHIVE OUTPUT_DIR' >&2; exit 2; }
root=$(realpath "$1")
selected=$(realpath "$2")
archive=$(realpath "$3")
output=$(realpath -m "$4")
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cc_bin=${LI2_CC:-cc}
[ ! -e "$output" ]
mkdir -p "$output"
"$cc_bin" -std=gnu11 -O2 -g -fno-builtin -fno-stack-protector \
    -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
    -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -fstack-usage \
    -Wall -Wextra -Werror \
    -I"$selected" -I"$root/tools/page-entry/selected" \
    "$fixture/metadata.c" "$root/tools/page-entry/selected/tests/decoder/support.c" \
    "$archive" -Wl,-z,now,-z,relro,--no-undefined -ldl -lpthread -lm \
    -o "$output/scalar-read-metadata"
