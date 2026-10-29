#!/bin/sh
set -eu
test "$#" -eq 3
metadata=$1
output=$2
case_number=$3
case "$case_number" in 5) ;; *) exit 2;; esac
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
donor_dir=$fixture_dir/../tf_same_page
cc_bin=${LI2_CC:?exact compiler required}
"$cc_bin" -O2 -g -Wall -Wextra -Werror -fno-pie -no-pie -nostdlib \
 -ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables \
 -mgeneral-regs-only -mcmodel=large -DRN_CASE="$case_number" \
 "-Wl,-T,$donor_dir/linker.ld,-z,max-page-size=4096,--build-id=none" \
 "$fixture_dir/fixture.S" "$donor_dir/native_reference.c" "$metadata" -o "$output"
