#!/bin/sh
set -eu
test "$#" -eq 2
source_dir=$(realpath "$1")
output=$(realpath -m "$2")
test ! -e "$output"
cc=${CC:-cc}
"$cc" -std=gnu11 -O2 -g -Wall -Wextra -Werror -fno-pie -no-pie \
  -fno-stack-protector -fno-builtin -fno-tree-loop-distribute-patterns \
  -fno-tree-vectorize -mgeneral-regs-only -fno-omit-frame-pointer \
  -Wl,-z,noexecstack,--build-id=none "$source_dir/probe.c" "$source_dir/probe.S" -o "$output"
