#!/bin/sh
# One actual-header oracle; invocation/limits belong to the existing supervisor.
set -eu
test "$#" -eq 2
selected=$1
output=$2
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cc_bin=${LI2_CC:-cc}
mkdir -p "$output"
"$cc_bin" -std=gnu11 -O2 -g -fno-builtin -fno-stack-protector \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -Wall -Wextra -Werror \
  -DLI2_SCALAR_SPAN_TRACE=1 -DLI2_SPAN_FAST_BYTES=1 -I"$selected" \
  -Wl,-z,noexecstack,--build-id=none "$fixture/oracle.c" -o "$output/span-fast-bytes"
