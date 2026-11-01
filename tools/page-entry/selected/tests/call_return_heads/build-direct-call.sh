#!/bin/sh
# Pure register CALL return-head graph and unchanged byte models; no generated execution.
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
  -DLI2_PERSISTENT_CALL_RETURN_HEADS=1 \
  -DLI2_PERSISTENT_GROUP=1 -DLI2_PERSISTENT_EPOCH=1 -DLI2_MOV_GUARD=1 \
  -DLI2_PERSISTENT_DISPATCH=1 -DLI2_PERSISTENT_ACTIVE_DOMAIN=1 \
  -DLI2_PERSISTENT_CROSS_PAIR=1 -DLI2_PERSISTENT_DIRECT_FRONTIER=1 \
  -DLI2_PERSISTENT_CALL_DISPATCH=1 -DLI2_PERSISTENT_RET_DISPATCH=1 \
  -I"$selected" "$fixture/direct_call_oracle.c" "$selected/tests/ret_dispatch/model.c" "$selected/tests/call_dispatch/direct_model.c" \
  "$selected/persistent_group_plan.c" "$selected/persistent_group_compact.c" \
  "$selected/linked_ret_dispatch.c" "$selected/linked_call_dispatch.c" \
  "$selected/linked_jmp_dispatch.c" "$selected/linked_direct_dispatch.c" \
  "$selected/linked_mov_guard.c" "$selected/tests/decoder/support.c" "$archive" \
  -Wl,-z,now,-z,relro,--no-undefined -ldl -lpthread -lm -o "$output"
