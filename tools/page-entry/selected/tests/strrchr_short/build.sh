#!/bin/sh
# Actual current selected source and one freshly authenticated decoder archive.
set -eu
test "$#" -eq 3
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
decoder_archive=$1
output_dir=$2
selected_dir=$(CDPATH= cd -- "$3" && pwd)
parent_dir=$(CDPATH= cd -- "$selected_dir/.." && pwd)
test -f "$decoder_archive"
mkdir -p "$output_dir"
python_bin=${LI2_PYTHON:-python3}
"$python_bin" "$source_dir/prepare.py" "$selected_dir" "$output_dir"
cc_bin=${LI2_CC:-cc}
for group in 0 1 2; do
"$cc_bin" -DSHORT_GROUP="$group" -std=gnu11 -O2 -g -nostdlib -static -no-pie -fno-pie \
  -fno-builtin -fno-stack-protector -fno-tree-loop-distribute-patterns \
  -fno-tree-vectorize -mgeneral-regs-only -fno-asynchronous-unwind-tables \
  -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
  -I"$selected_dir/tests/generic" -I"$selected_dir" -I"$parent_dir" \
  -Wl,-e,_start,-z,noexecstack,--gc-sections,--build-id=none,--no-undefined \
  "$selected_dir/step_owner.c" "$selected_dir/lifecycle_loader.c" \
  "$selected_dir/tests/generic/tf_controls.c" "$source_dir/fixture.c" \
  "$source_dir/fixture.S" "$decoder_archive" -o "$output_dir/short-leaf-$group"
done
"$cc_bin" -std=gnu11 -O2 -g -nostdlib -static -no-pie -fno-pie \
  -fno-builtin -fno-stack-protector -fno-tree-loop-distribute-patterns \
  -fno-tree-vectorize -mgeneral-regs-only -fno-asynchronous-unwind-tables \
  -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
  -DLI2_TF_HANDOFF=1 -DLI2_MAPS_PHASE_REUSE=1 \
  -I"$output_dir" -I"$source_dir" -I"$selected_dir/tests/generic" \
  -I"$selected_dir" -I"$parent_dir" \
  -Wl,-e,_start,-z,noexecstack,--gc-sections,--build-id=none,--no-undefined \
  "$selected_dir/tests/trace_chain/owner_wrapper.c" "$selected_dir/lifecycle_loader.c" \
  "$selected_dir/tests/generic/tf_controls.c" "$selected_dir/tests/trace_chain/route_controls.c" \
  "$source_dir/connected.c" "$source_dir/fixture.S" \
  "$decoder_archive" -o "$output_dir/short-connected"
