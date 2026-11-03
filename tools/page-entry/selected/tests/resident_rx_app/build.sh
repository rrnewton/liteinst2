#!/bin/sh
set -eu
test "$#" -eq 3
case "$3" in 1|2|3|4|5|6|7) control=$3;; *) exit 2;; esac
source_dir=$(realpath "$1")
base_dir=$(realpath "$source_dir/../resident_generation_app")
output=$(realpath -m "$2")
test ! -e "$output"
mkdir -p "$output"
"${LI2_PYTHON:-python3}" -B "$source_dir/prepare.py" --donor "$base_dir/main.c" --output "$output/main.c"
cc=${CC:-cc}
"$cc" -nostdlib -shared -Wl,-e,_start,-z,noexecstack,--build-id=none \
  "$base_dir/fixture-interpreter.S" -o "$output/fixture-interpreter.so"
"$cc" -std=c11 -O2 -g -Wall -Wextra -Werror -fno-builtin -fno-strict-aliasing \
  -fno-stack-protector -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -DLI2_FAST_EQUAL=1 "-DLI2_RRX_CASE=$control" -mcmodel=large -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-pie -no-pie -nostdlib \
  "-DLI2_DIRECT_FRONTIER_INTERPRETER=\"$output/fixture-interpreter.so\"" \
  -Wl,-z,noexecstack,--build-id=none,--no-undefined -Wl,-T,"$base_dir/app.ld" -I"$base_dir" -I"$source_dir" \
  "$output/main.c" "$base_dir/pure.c" "$base_dir/machine.S" "$base_dir/entry.S" \
  -o "$output/resident-rx-app"
