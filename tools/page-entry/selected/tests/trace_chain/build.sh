#!/bin/sh
# Parent supplies the authenticated composed selected directory and archive.
# prepare.py must have generated and pinned the only support include first.
set -eu
test "$#" -eq 3
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
decoder_archive=$1
output_dir=$2
selected_dir=$(CDPATH= cd -- "$3" && pwd)
parent_dir=$(CDPATH= cd -- "$selected_dir/.." && pwd)
test -f "$decoder_archive"
test -f "$output_dir/chain_support.inc"
test -f "$selected_dir/tf_chain.inc"
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -nostdlib -static -no-pie -fno-pie \
  -fno-builtin -fno-stack-protector -fno-tree-loop-distribute-patterns \
  -fno-tree-vectorize -mgeneral-regs-only -fno-asynchronous-unwind-tables \
  -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
  -DLI2_TF_HANDOFF=1 -DLI2_MAPS_PHASE_REUSE=1 \
  -I"$output_dir" -I"$fixture_dir" -I"$selected_dir/tests/generic" \
  -I"$selected_dir" -I"$parent_dir" \
  -Wl,-e,_start,-z,noexecstack,--gc-sections,--build-id=none,--no-undefined \
  "$fixture_dir/owner_wrapper.c" "$selected_dir/lifecycle_loader.c" \
  "$selected_dir/tests/generic/tf_controls.c" \
  "$selected_dir/tests/trace_chain/route_controls.c" \
  "$fixture_dir/fixture.c" "$selected_dir/tests/generic/fixture.S" \
  "$decoder_archive" -o "$output_dir/trace-chain-fixture"
