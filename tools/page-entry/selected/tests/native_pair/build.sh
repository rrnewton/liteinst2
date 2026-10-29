#!/bin/sh
set -eu
test "$#" -eq 4
metadata=$1
output=$2
case_number=$3
control=$4
case "$case_number" in 0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20) ;; *) exit 2;; esac
case "$case_number:$control" in 16:0|16:1|*:0) ;; *) exit 2;; esac
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cc_bin=${LI2_CC:?exact compiler required}
"$cc_bin" -O2 -g -Wall -Wextra -Werror -fno-pie -no-pie -nostdlib \
 -ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables \
 -mgeneral-regs-only -mcmodel=large -DRN_CASE="$case_number" -DNP_CONTROL="$control" \
 "-Wl,-T,$fixture_dir/linker.ld,-z,max-page-size=4096,--build-id=none" \
 "$fixture_dir/fixture.S" "$fixture_dir/native_reference.c" "$metadata" -o "$output"
