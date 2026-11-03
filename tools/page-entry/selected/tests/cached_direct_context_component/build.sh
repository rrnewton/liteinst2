#!/bin/sh
# Pure component: actual source types/planners/emitter; emitted code never runs.
set -eu
test "$#" -eq 4
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
selected=$(realpath "$1")
archive=$(realpath "$2")
app=$(realpath "$3")
output=$(realpath -m "$4")
test -d "$selected"
test -f "$archive"
test -d "$app"
test ! -e "$output"
mkdir "$output"
"${LI2_PYTHON:-python3}" -B "$fixture/prepare.py" "$selected" "$app" "$output"
cc_bin=${LI2_CC:-cc}
# Fixed component image placement keeps real publication pointers disjoint from
# the modeled source/code regions and within the unchanged signed32 guard reach.
# This grants no runtime placement or executable-publication authority.
"$cc_bin" -std=gnu11 -O2 -g -fno-stack-protector -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -fstack-usage \
  -fno-pie -no-pie -D_GNU_SOURCE= \
  -Wall -Wextra -Werror -Wno-misleading-indentation \
  -DLI2_LOOP_RO_CERTIFICATE=1 -DLI2_SEALED_BYTE_CERTIFICATE=1 -DLI2_PERSISTENT_SEALED_GENERATION=1 \
  -DLI2_LOOP_RESIDENT_RX=1 -DLI2_LOOP_CACHE8=1 -DLI2_LOOP_GROUP_DESCRIPTOR=1 \
  -DLI2_LOOP_TRANSLATION_ARENA=1 -DLI2_LOOP_CACHED_DIRECT_CONTEXT=1 -DLI2_PERSISTENT_LOOP_EFFECTS=1 \
  -DLI2_LOOP_EFFECTS=1 -DLI2_PG_LOOP_ENCODING_VERSION=2 -DLI2_PERSISTENT_LOOP_PLAN=1 \
  -DLI2_PERSISTENT_LOOP_RUNTIME=1 -DLI2_PERSISTENT_FUSED_PLAN=1 -DLI2_PERSISTENT_FUSED_RUNTIME=1 \
  -DLI2_PERSISTENT_DIRECT_FRONTIER=1 -DLI2_PERSISTENT_CROSS_PAIR=1 -DLI2_PERSISTENT_SUBENTRY=1 \
  -DLI2_PERSISTENT_UNREGISTERED=1 -DLI2_MAPS_PARSE_MEMO=1 -DLI2_LINKED_NATIVE_PROBE=1 \
  -DLI2_PERSISTENT_ACTIVE_DOMAIN=1 -DLI2_RSEQ_CURRENT_DATA=1 -DLI2_PERSISTENT_RETAINED_TWO=1 \
  -DLI2_PERSISTENT_DISPATCH=1 -DLI2_PERSISTENT_GROUP=1 -DLI2_PERSISTENT_EPOCH=1 \
  -DLI2_MOV_GUARD=1 -DLI2_LINKED_EPOCH=1 -DLI2_SCALAR_SPAN=1 \
  -DLI2_SCALAR_SPAN_TRACE=1 -DLI2_SPAN_FAST_BYTES=1 -DLI2_MAPS_CURRENT_TF=1 \
  -DLI2_SCALAR_REGION=1 -DLI2_SCALAR_REGION_REUSE=1 -DLI2_INITIAL_CODE_PROTECTION=1 \
  -DLI2_UNROLLED_HASH=1 -DLI2_MAPS_MAINTAINED=1 -DLI2_NATIVE_PAIR=1 \
  -DLI2_REPEAT_RX_LEASE=1 -DLI2_RUN_CACHE_REUSE=1 -DLI2_EFFECT_PROVIDER=1 \
  -DLI2_ONESHOT_REUSABLE=1 -DLI2_ONESHOT_PUBLICATION=1 -DLI2_TF_SEALED_CUSTODY=1 \
  -DLI2_TF_SAME_PAGE_LEASE=1 -DLI2_TF_HANDOFF=1 -DLI2_REGISTER_RUN=1 \
  -DLI2_MAPS_PHASE_REUSE=1 -DLI2_RSEQ_INACTIVE=1 -DLI2_NATIVE_PAGES=1 \
  -DLI2_CPUID_NX_ONLY=1 -DLI2_RSEQ_NATIVE=1 -DLI2_RSEQ_NATIVE_BOUNDARY=1 \
  -DLI2_RSEQ_TCGETS_BTRFS=1 -DLI2_RSEQ_TIOCGWINSZ_BTRFS=1 -DLI2_FAST_MEMSET=1 \
  -DLI2_FAST_EQUAL=1 \
  -I"$output" -I"$selected" "$fixture/oracle.c" "$fixture/model.c" \
  "$selected/loop_cached_direct_context.c" \
  "$selected/persistent_group_plan.c" "$selected/persistent_group_compact.c" \
  "$selected/loop_read_bridge.c" "$selected/loop_envelope.c" \
  "$selected/loop_effects_bridge.c" "$selected/loop_effects_envelope.c" \
  "$selected/linked_direct_dispatch.c" "$selected/linked_jmp_dispatch.c" "$selected/linked_mov_guard.c" \
  "$selected/tests/decoder/support.c" "$archive" \
  -Wl,--wrap=li2_dd_recover,--wrap=li2_decoder_decode \
  -Wl,-Ttext-segment=0x60000000,-z,now,-z,relro,--no-undefined \
  -ldl -lpthread -lm -o "$output/context-component"
