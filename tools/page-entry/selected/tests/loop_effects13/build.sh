#!/bin/sh
# Exact caller-supplied loop-effects archive; no feature fallback or build here.
set -eu
[ "$#" -eq 4 ] || { echo 'usage: build.sh ROOT SELECTED_DIR LOOP_EFFECTS_ARCHIVE OUTPUT_DIR' >&2; exit 2; }
root=$(realpath "$1")
selected=$(realpath "$2")
archive=$(realpath "$3")
output=$(realpath -m "$4")
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cc_bin=${LI2_CC:-cc}
test ! -e "$output"
mkdir -p "$output"
"$cc_bin" -std=gnu11 -O2 -g -fno-builtin -fno-stack-protector \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -fstack-usage \
  -Wall -Wextra -Werror -Wno-misleading-indentation \
  -DLI2_MOV_GUARD=1 -DLI2_LOOP_EFFECTS=1 \
  -I"$selected" -I"$root/tools/page-entry/selected" \
  "$fixture/metadata.c" "$fixture/bmg_model.c" \
  "$root/tools/page-entry/selected/tests/linked_mov_guard/model.c" \
  "$root/tools/page-entry/selected/tests/decoder/support.c" \
  "$selected/linked_mov_guard.c" "$archive" \
  -Wl,-z,now,-z,relro,--no-undefined -ldl -lpthread -lm -o "$output/effects-metadata"
"$cc_bin" -std=gnu11 -O2 -g -fno-builtin -fno-stack-protector \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -fstack-usage \
  -Wall -Wextra -Werror -Wno-misleading-indentation \
  -DLI2_FAST_MEMSET=1 -DLI2_FAST_EQUAL=1 -DLI2_LOOP_EFFECTS=1 -DLI2_PERSISTENT_LOOP_EFFECTS=1 \
  -DLI2_PG_LOOP_ENCODING_VERSION=2 -DLI2_PERSISTENT_LOOP_PLAN=1 \
  -DLI2_PERSISTENT_FUSED_PLAN=1 -DLI2_PERSISTENT_BLOCK_PLAN=1 \
  -DLI2_PERSISTENT_GROUP=1 -DLI2_PERSISTENT_EPOCH=1 -DLI2_MOV_GUARD=1 \
  -DLI2_PERSISTENT_DISPATCH=1 -DLI2_PERSISTENT_ACTIVE_DOMAIN=1 \
  -DLI2_PERSISTENT_CROSS_PAIR=1 -DLI2_PERSISTENT_DIRECT_FRONTIER=1 \
  -I"$selected" -I"$root/tools/page-entry/selected" \
  -I"$root/tools/page-entry/selected/tests/region_cache" \
  "$fixture/native.c" "$root/tools/page-entry/selected/tests/region_cache/machine.S" \
  "$selected/persistent_group_plan.c" "$selected/persistent_group_compact.c" \
  "$selected/loop_read_bridge.c" "$selected/loop_envelope.c" \
  "$selected/loop_effects_bridge.c" "$selected/loop_effects_envelope.c" \
  "$selected/linked_direct_dispatch.c" "$selected/linked_jmp_dispatch.c" "$selected/linked_mov_guard.c" \
  "$archive" -Wl,-z,now,-z,relro,--no-undefined -ldl -lpthread -lm -o "$output/effects-native"
