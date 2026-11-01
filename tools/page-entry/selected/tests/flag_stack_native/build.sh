#!/bin/sh
set -eu
test "$#" -eq 3
selected=$(CDPATH= cd -- "$1" && pwd)
archive=$2
output=$3
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test -f "$archive"
test ! -e "$output"
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -fno-stack-protector -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -fstack-usage -no-pie \
  -Wall -Wextra -Werror \
  -I"$selected" "$fixture/probe.c" "$fixture/probe.S" \
  "$selected/flag_stack.c" "$selected/tests/generic/tf_controls.c" \
  "$selected/tests/decoder/support.c" "$archive" \
  -Wl,-z,now,-z,relro,--no-undefined -ldl -lpthread -lm -o "$output"
