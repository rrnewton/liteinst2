#!/bin/sh
set -eu
test "$#" -eq 3
metadata=$1
output=$2
operations=$3
case "$operations" in 1|256) ;; *) exit 2;; esac
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cc_bin=${LI2_CC:?exact compiler required}
"$cc_bin" -O2 -g -Wall -Wextra -Werror -fno-pie -no-pie -nostdlib \
 -ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables \
 -mgeneral-regs-only -mcmodel=large -DTFI_N="$operations" \
 "-Wl,-T,$fixture_dir/linker.ld,-z,max-page-size=4096,--build-id=none" \
 "$fixture_dir/fixture.S" "$fixture_dir/native_reference.c" "$metadata" -o "$output"
