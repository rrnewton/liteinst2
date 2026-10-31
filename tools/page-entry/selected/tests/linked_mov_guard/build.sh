#!/bin/sh
set -eu
test "$#" -eq 3
selected=$(realpath "$1")
archive=$(realpath "$2")
output=$(realpath -m "$3")
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cc_bin=${LI2_CC:-cc}
test ! -e "$output"
"$cc_bin" -std=gnu11 -O2 -g -fno-builtin -fno-stack-protector \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -fstack-usage \
  -Wall -Wextra -Werror -Wno-misleading-indentation -DLI2_MOV_GUARD=1 \
  -I"$selected" "$fixture/metadata.c" "$fixture/model.c" \
  "$selected/tests/decoder/support.c" "$selected/linked_mov_guard.c" "$archive" \
  -Wl,-z,now,-z,relro,--no-undefined -ldl -lpthread -lm -o "$output"
