#!/bin/sh
set -eu
test "$#" -eq 4
selected=$1
donor=$2
archive=$3
output=$4
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cc_bin=${LI2_CC:-$(command -v cc)}
python_bin=${LI2_PYTHON:-$(command -v python3)}
# One generation and the original provider component compile/link options.
"$python_bin" -B "$here/prepare.py" --donor "$donor" --output "$output"
"$cc_bin" -std=c11 -O2 -Wall -Wextra -Werror -ffreestanding -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-stack-protector -fno-pie -mgeneral-regs-only \
  -ffunction-sections -fdata-sections -I"$donor" -I"$selected" -I"$donor/../.." \
  -c "$output/probe.c" -o "$output/probe.c.o"
"$cc_bin" -std=c11 -O2 -Wall -Wextra -Werror -ffreestanding -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-stack-protector -fno-pie -mgeneral-regs-only \
  -ffunction-sections -fdata-sections -I"$donor" -I"$selected" -I"$donor/../.." \
  -c "$donor/xstate.c" -o "$output/xstate.c.o"
"$cc_bin" -std=c11 -O2 -Wall -Wextra -Werror -ffreestanding -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-stack-protector -fno-pie -mgeneral-regs-only \
  -ffunction-sections -fdata-sections -I"$donor" -I"$selected" -I"$donor/../.." \
  -c "$donor/support.c" -o "$output/support.c.o"
"$cc_bin" -O2 -fno-pie -c "$donor/machine.S" -o "$output/machine.S.o"
"$cc_bin" -std=c11 -O2 -Wall -Wextra -Werror -ffreestanding -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-stack-protector -fno-pie -mgeneral-regs-only \
  -ffunction-sections -fdata-sections -I"$donor" -I"$selected" -I"$donor/../.." \
  -c "$selected/provider.c" -o "$output/provider.o"
"$cc_bin" -no-pie "$output/probe.c.o" "$output/xstate.c.o" "$output/support.c.o" \
  "$output/machine.S.o" "$output/provider.o" "$archive" \
  -Wl,--no-undefined,--gc-sections -o "$output/provider-callback-fixture"
