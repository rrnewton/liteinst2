#!/bin/sh
set -eu
test "$#" -eq 2
"${LI2_CC:?exact compiler required}" -std=gnu11 -O2 -g -mgeneral-regs-only -fno-tree-vectorize \
  -fno-tree-loop-distribute-patterns -fno-builtin -fno-pie -no-pie -Wall -Wextra -Werror \
  -Wl,-z,noexecstack,--build-id=none "$1/probe.c" -o "$2"
