#!/bin/sh
# Pure actual decoder/emitter plus unchanged independent models; no generated code runs.
set -eu
test "$#" -eq 6
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
selected=$1
overlay=$2
chooser=$3
scalar=$4
archive=$5
output=$6
test -d "$selected"
test -d "$overlay"
test -d "$chooser"
test -d "$scalar"
test -f "$archive"
test ! -e "$output"
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -fno-stack-protector -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -fstack-usage \
  -Wall -Wextra -Werror -Wno-misleading-indentation \
  -DLI2_PERSISTENT_LOOP_PLAN=1 -DLI2_PERSISTENT_FUSED_PLAN=1 -DLI2_PERSISTENT_BLOCK_PLAN=1 \
  -DLI2_PERSISTENT_GROUP=1 -DLI2_PERSISTENT_EPOCH=1 -DLI2_MOV_GUARD=1 \
  -DLI2_PERSISTENT_DISPATCH=1 -DLI2_PERSISTENT_ACTIVE_DOMAIN=1 \
  -DLI2_PERSISTENT_CROSS_PAIR=1 -DLI2_PERSISTENT_DIRECT_FRONTIER=1 \
  -I"$overlay" -I"$chooser" -I"$scalar" -I"$selected" \
  "$fixture/oracle.c" "$fixture/direct_model.c" "$fixture/mov_model.c" \
  "$overlay/persistent_group_plan.c" "$overlay/persistent_group_compact.c" \
  "$overlay/loop_read_bridge.c" "$chooser/loop_envelope.c" \
  "$selected/linked_direct_dispatch.c" "$selected/linked_jmp_dispatch.c" "$selected/linked_mov_guard.c" \
  "$selected/tests/decoder/support.c" "$archive" \
  -Wl,--wrap=li2_dd_recover,--wrap=li2_mg_recover,--wrap=li2_decoder_decode \
  -Wl,-z,now,-z,relro,--no-undefined -ldl -lpthread -lm -o "$output"
