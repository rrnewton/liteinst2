#!/bin/sh
# Actual source predicates/callers; scripted environment and initialization effects.
set -eu
test "$#" -eq 2
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
selected=$(CDPATH= cd -- "$1" && pwd)
output=$2
test ! -e "$output"
test ! -e "$output.c"
python_bin=${LI2_PYTHON:-python3}
cc_bin=${LI2_CC:-cc}
"$python_bin" -I -S -B "$fixture/prepare.py" "$selected" "$output.c"
"$cc_bin" -std=gnu11 -O2 -g -Wall -Wextra -Werror -fno-pie -no-pie \
  -fno-builtin -fno-tree-loop-distribute-patterns -fno-tree-vectorize \
  -fno-stack-protector -mgeneral-regs-only -DLI2_INITIAL_CODE_PROTECTION=1 \
  -I"$selected" -I"$selected/.." "$output.c" \
  -Wl,-z,now,-z,relro,-z,noexecstack,--no-undefined -o "$output"
