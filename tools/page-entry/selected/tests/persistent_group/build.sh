#!/bin/sh
# Pure two-member metadata only; no emitted instruction or guest execution.
set -eu
test "$#" -eq 2
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
selected=$(CDPATH= cd -- "$fixture/../.." && pwd)
archive=$1
output=$2
test -f "$archive"
test ! -e "$output"
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -fno-stack-protector -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -fstack-usage \
  -Wall -Wextra -Werror -Wno-misleading-indentation \
  -DLI2_PERSISTENT_GROUP=1 -DLI2_PERSISTENT_EPOCH=1 -DLI2_MOV_GUARD=1 \
  -I"$selected" "$fixture/metadata.c" "$selected/persistent_group_plan.c" "$selected/persistent_group_compact.c" \
  "$selected/tests/decoder/support.c" "$selected/linked_mov_guard.c" "$archive" \
  -Wl,--wrap=li2_decoder_span_describe,--wrap=li2_decoder_decode \
  -Wl,--wrap=li2_decoder_tf_classify,--wrap=li2_decoder_mov_store \
  -Wl,-z,now,-z,relro,--no-undefined -ldl -lpthread -lm -o "$output"
