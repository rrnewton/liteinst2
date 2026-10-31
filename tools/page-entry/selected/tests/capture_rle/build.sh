#!/bin/sh
set -eu
test "$#" -eq 2
selected=$1
output=$2
cc=${CC:-cc}
mkdir -p "$output"
"$cc" -std=gnu11 -O2 -g -Wall -Wextra -Werror -fno-builtin -fno-strict-aliasing -Wl,-z,noexecstack "$selected/tests/capture_rle/oracle.c" "$selected/capture_rle.c" -o "$output/capture-rle-oracle"
