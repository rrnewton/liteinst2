#!/bin/sh
# Additive LD-AUX model plus actual original/generated native pairs and TF recovery.
set -eu
test "$#" -eq 3
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
selected=$1
archive=$2
output=$3
test -d "$selected"
test -f "$archive"
test ! -e "$output"
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -fno-stack-protector -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -fstack-usage -no-pie \
  -Wall -Wextra -Werror -Wno-misleading-indentation \
  -DLI2_PERSISTENT_LOOP_PLAN=1 -DLI2_PERSISTENT_GROUP=1 -DLI2_PERSISTENT_EPOCH=1 -DLI2_MOV_GUARD=1 \
  -DLI2_PERSISTENT_DISPATCH=1 -DLI2_PERSISTENT_ACTIVE_DOMAIN=1 \
  -DLI2_PERSISTENT_CROSS_PAIR=1 -DLI2_PERSISTENT_DIRECT_FRONTIER=1 \
  -I"$selected" "$fixture/native.c" "$fixture/model.c" \
  "$selected/tests/loop_direct_far/direct_model.c" "$selected/tests/direct_call_native/probe.S" \
  "$selected/linked_direct_dispatch.c" "$selected/tests/decoder/support.c" "$archive" \
  -Wl,--wrap=li2_ld_recover,--wrap=li2_decoder_decode \
  -Wl,-z,now,-z,relro,--no-undefined -ldl -lpthread -lm -o "$output"
