#!/bin/sh
set -eu
test "$#" -eq 2
source_dir=$(realpath "$1")
output=$(realpath -m "$2")
test ! -e "$output"
mkdir -p "$output"
cc=${CC:-cc}
"$cc" -nostdlib -shared -Wl,-e,_start,-z,noexecstack,--build-id=none \
  "$source_dir/fixture-interpreter.S" -o "$output/fixture-interpreter.so"
"$cc" -std=c11 -O2 -g -Wall -Wextra -Werror -fno-builtin -fno-strict-aliasing \
  -fno-stack-protector -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -DLI2_FAST_EQUAL=1 -mcmodel=large -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-pie -no-pie -nostdlib \
  "-DLI2_SUBENTRY_INTERPRETER=\"$output/fixture-interpreter.so\"" \
  -Wl,-z,noexecstack,--build-id=none,--no-undefined -Wl,-T,"$source_dir/app.ld" -I"$source_dir" \
  "$source_dir/main.c" "$source_dir/pure.c" "$source_dir/machine.S" "$source_dir/entry.S" \
  -o "$output/persistent-subentry-app"
