#!/bin/sh
set -eu
# The hosted component control refuses before raw rseq. It does not establish
# an initially unregistered task or qualify successful target registration.
test "$#" -eq 3
source_dir=$(CDPATH= cd -- "$1/tools/page-entry/selected" && pwd)
parent_dir=$(CDPATH= cd -- "$source_dir/.." && pwd)
archive=$2
output=$3
test -f "$archive"
cc_bin=${LI2_CC:-$(command -v cc)}
"$cc_bin" -std=gnu11 -O2 -g -fno-builtin -fno-stack-protector \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
  -DLI2_RSEQ_INACTIVE=1 -DLI2_MAPS_PHASE_REUSE=1 -I"$source_dir" -I"$parent_dir" \
  -Wl,--gc-sections,--exclude-libs,ALL,-z,noexecstack,--build-id=none \
  "$source_dir/lifecycle_loader.c" "$source_dir/step_owner.c" \
  "$source_dir/rseq_guard.c" "$source_dir/tests/rseq/preissue.c" \
  "$archive" -o "$output"
