#!/bin/sh
set -eu
test "$#" -eq 3
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
decoder_archive=$1
output_dir=$2
selected_dir=$(CDPATH= cd -- "$3" && pwd)
parent_dir=$(CDPATH= cd -- "$selected_dir/.." && pwd)
test -f "$decoder_archive"
test -f "$selected_dir/tests/generic/fixture.c"
mkdir -p "$output_dir"
cc_bin=${LI2_CC:-cc}
for group in 0 1 2 3 4 5 6 7; do
"$cc_bin" -DKMV_GROUP="$group" -std=gnu11 -O2 -g -nostdlib -static -no-pie -fno-pie \
  -fno-builtin -fno-stack-protector -fno-tree-loop-distribute-patterns \
  -fno-tree-vectorize -mgeneral-regs-only -fno-asynchronous-unwind-tables \
  -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
  -I"$selected_dir/tests/generic" -I"$selected_dir" -I"$parent_dir" \
  -Wl,-e,_start,-z,noexecstack,--gc-sections,--build-id=none \
  "$selected_dir/step_owner.c" "$selected_dir/lifecycle_loader.c" \
  "$selected_dir/tests/generic/tf_controls.c" "$source_dir/fixture.c" \
  "$source_dir/fixture.S" "$decoder_archive" -o "$output_dir/kmovq-register-$group"
done
