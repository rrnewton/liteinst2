#!/bin/sh
# The baseline and additive profile use identical whole-page graph inputs.
set -eu
test "$#" -eq 3
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
selected=$(CDPATH= cd -- "$fixture/../.." && pwd)
archive=$(realpath "$1")
output=$(realpath -m "$2")
case "$3" in
  baseline) set -- ;;
  add) set -- -DLI2_ADD_GUARD=1 "$selected/linked_add_guard.c" ;;
  *) exit 2 ;;
esac
test ! -e "$output"
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -fno-stack-protector -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -fstack-usage \
  -Wall -Wextra -Werror -Wno-misleading-indentation \
  -DLI2_PERSISTENT_GROUP=1 -DLI2_PERSISTENT_EPOCH=1 -DLI2_MOV_GUARD=1 \
  -DLI2_PERSISTENT_DISPATCH=1 -DLI2_PERSISTENT_ACTIVE_DOMAIN=1 \
  -I"$selected" "$fixture/planner.c" "$@" \
  "$selected/persistent_group_plan.c" "$selected/persistent_group_compact.c" \
  "$selected/linked_jmp_dispatch.c" "$selected/linked_mov_guard.c" \
  "$selected/tests/decoder/support.c" "$archive" \
  -Wl,-z,now,-z,relro,--no-undefined -ldl -lpthread -lm -o "$output"
