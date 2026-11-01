#!/bin/sh
# Component only: authenticated scalar-read,mov-guard archive and bounded process owner
# supplied by the caller. This recipe neither builds Rust nor runs the oracle.
set -eu
[ "$#" -eq 5 ] || { echo 'usage: build.sh ROOT CHOOSER_SELECTED SCALAR_SELECTED DECODER_ARCHIVE OUTPUT_DIR' >&2; exit 2; }
root=$(realpath "$1")
chooser=$(realpath "$2")
scalar=$(realpath "$3")
archive=$(realpath "$4")
output=$(realpath -m "$5")
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cc_bin=${LI2_CC:-cc}
[ ! -e "$output" ]
mkdir -p "$output"
"$cc_bin" -std=gnu11 -O2 -g -fno-builtin -fno-stack-protector \
    -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
    -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -fstack-usage \
    -Wall -Wextra -Werror \
    -I"$chooser" -I"$scalar" -I"$root/tools/page-entry/selected" \
    "$fixture/oracle.c" "$chooser/loop_envelope.c" \
    "$root/tools/page-entry/selected/tests/decoder/support.c" \
    "$archive" -Wl,-z,now,-z,relro,--no-undefined -ldl -lpthread -lm \
    -o "$output/loop-envelope-component"
