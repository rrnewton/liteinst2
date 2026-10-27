#!/bin/sh
set -eu
test "$#" -eq 2
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
selected_dir=$(CDPATH= cd -- "$source_dir/../.." && pwd)
parent_dir=$(CDPATH= cd -- "$selected_dir/.." && pwd)
decoder_archive=$1
output_dir=$2
test -f "$decoder_archive"
mkdir -p "$output_dir"
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -nostdlib -static -no-pie -fno-pie \
  -fno-builtin -fno-stack-protector -fno-tree-loop-distribute-patterns \
  -fno-tree-vectorize -mgeneral-regs-only -fno-asynchronous-unwind-tables \
  -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
  -I"$source_dir" -I"$selected_dir" -I"$parent_dir" -Wl,-e,_start,-z,noexecstack,--gc-sections,--build-id=none \
  "$selected_dir/step_owner.c" "$selected_dir/lifecycle_loader.c" \
  "$source_dir/tf_controls.c" "$source_dir/fixture.c" "$source_dir/fixture.S" \
  "$decoder_archive" -o "$output_dir/generic-tf-fixture"
