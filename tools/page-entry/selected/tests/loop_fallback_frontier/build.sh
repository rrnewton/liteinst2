#!/bin/sh
# Whole old LPF oracle plus actual history destination regression; no generated execution.
set -eu
test "$#" -eq 3
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
selected=$1
archive=$2
output=$3
test -d "$selected"
test -f "$archive"
test ! -e "$output"
test ! -e "$output.c"
"${LI2_PYTHON:-python3}" -I -S -B "$fixture/prepare.py" "$selected" "$output.c"
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -fno-stack-protector -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -fstack-usage \
  -Wall -Wextra -Werror -Wno-misleading-indentation \
  -DLI2_PG_LOOP_ENCODING_VERSION=2 -DLI2_PERSISTENT_LOOP_PLAN=1 \
  -DLI2_PERSISTENT_FUSED_PLAN=1 -DLI2_PERSISTENT_BLOCK_PLAN=1 \
  -DLI2_PERSISTENT_GROUP=1 -DLI2_PERSISTENT_EPOCH=1 -DLI2_MOV_GUARD=1 \
  -DLI2_PERSISTENT_DISPATCH=1 -DLI2_PERSISTENT_ACTIVE_DOMAIN=1 \
  -DLI2_PERSISTENT_CROSS_PAIR=1 -DLI2_PERSISTENT_DIRECT_FRONTIER=1 \
  -I"$selected" "$output.c" \
  "$selected/tests/bounded_fusion_plan/direct_model.c" "$selected/tests/bounded_fusion_plan/mov_model.c" \
  "$selected/persistent_group_plan.c" "$selected/persistent_group_compact.c" \
  "$selected/loop_read_bridge.c" "$selected/loop_envelope.c" \
  "$selected/linked_direct_dispatch.c" "$selected/linked_jmp_dispatch.c" "$selected/linked_mov_guard.c" \
  "$selected/tests/decoder/support.c" "$archive" \
  -Wl,--wrap=li2_ld_recover,--wrap=li2_dd_recover,--wrap=li2_mg_recover,--wrap=li2_decoder_decode \
  -Wl,-z,now,-z,relro,--no-undefined -ldl -lpthread -lm -o "$output"
