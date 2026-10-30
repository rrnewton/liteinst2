#!/usr/bin/env bash
set -euo pipefail
test "$#" -eq 2
source_dir=$(realpath "$1")
output=$(realpath -m "$2")
test ! -e "$output"
mkdir -p "$output"
cc=${CC:-cc}
"$cc" -std=c11 -O2 -g -Wall -Wextra -Werror -fno-builtin -fno-strict-aliasing \
  -fno-tree-loop-distribute-patterns -mgeneral-regs-only -DLI2_FAST_EQUAL=1 -mcmodel=large -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-pie -no-pie \
  -Wl,-z,relro,-z,now,-z,noexecstack -Wl,-T,"$source_dir/pure.ld" -I"$source_dir" \
  "$source_dir/main.c" "$source_dir/pure.c" "$source_dir/machine.S" -o "$output/unrolled-hash-app"
