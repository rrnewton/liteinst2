#!/bin/sh
set -eu
test "$#" -eq 2
source_dir=$(realpath "$1")
output=$(realpath -m "$2")
common=$(realpath "$source_dir/../persistent_ret_owner_app")
test ! -e "$output"
mkdir -p "$output"
cc=${CC:-cc}
"$cc" -nostdlib -shared -Wl,-e,_start,-z,noexecstack,--build-id=none \
  "$common/fixture-interpreter.S" -o "$output/fixture-interpreter.so"
"$cc" -std=c11 -O2 -g -Wall -Wextra -Werror -fno-builtin -fno-strict-aliasing \
  -fno-stack-protector -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -DLI2_FAST_EQUAL=1 -mcmodel=large -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-pie -no-pie -nostdlib \
  "-DLI2_DIRECT_FRONTIER_INTERPRETER=\"$output/fixture-interpreter.so\"" \
  -Wl,-z,noexecstack,--build-id=none,--no-undefined -Wl,-T,"$common/app.ld" -I"$common" \
  "$source_dir/main.c" "$common/pure.c" "$source_dir/machine.S" "$common/entry.S" \
  -o "$output/persistent-direct-call-owner-app"
