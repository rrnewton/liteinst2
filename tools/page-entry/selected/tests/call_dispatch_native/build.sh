#!/bin/sh
# Separate native actual-emitter experiment. All old217 source files stay exact.
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
  -Wall -Wextra -Werror -Wno-misleading-indentation \
  -DLI2_PERSISTENT_GROUP=1 -DLI2_PERSISTENT_EPOCH=1 -DLI2_MOV_GUARD=1 \
  -DLI2_PERSISTENT_DISPATCH=1 -DLI2_PERSISTENT_ACTIVE_DOMAIN=1 -DLI2_PERSISTENT_CALL_DISPATCH=1 \
  -I"$selected" "$fixture/probe.c" "$fixture/probe.S" \
  "$selected/linked_call_dispatch.c" "$selected/tests/decoder/support.c" "$archive" \
  -Wl,-z,now,-z,relro,--no-undefined -ldl -lpthread -lm -o "$output"
