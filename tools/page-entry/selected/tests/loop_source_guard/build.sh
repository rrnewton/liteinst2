#!/bin/sh
# Actual installed loader TU only; invoke under the retained bounded process owner.
set -eu
test "$#" -eq 3
selected_dir=$(CDPATH= cd -- "$1" && pwd)
output_dir=$2
mode=$3
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
parent_dir=$(CDPATH= cd -- "$selected_dir/.." && pwd)
cc_bin=${LI2_CC:-cc}
test -d "$output_dir"
set -- -std=gnu11 -O2 -g -fno-stack-protector -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
  -Wall -Wextra -Werror \
  -DLI2_PG_LOOP_ENCODING_VERSION=2 \
  -DLI2_PERSISTENT_LOOP_PLAN=1 -DLI2_PERSISTENT_LOOP_RUNTIME=1 -DLI2_PERSISTENT_FUSED_PLAN=1 \
  -DLI2_PERSISTENT_FUSED_RUNTIME=1 -DLI2_PERSISTENT_DIRECT_FRONTIER=1 -DLI2_PERSISTENT_CROSS_PAIR=1 \
  -DLI2_PERSISTENT_SUBENTRY=1 -DLI2_PERSISTENT_UNREGISTERED=1 -DLI2_MAPS_PARSE_MEMO=1 \
  -DLI2_LINKED_NATIVE_PROBE=1 -DLI2_PERSISTENT_ACTIVE_DOMAIN=1 -DLI2_RSEQ_CURRENT_DATA=1 \
  -DLI2_PERSISTENT_RETAINED_TWO=1 -DLI2_PERSISTENT_DISPATCH=1 -DLI2_PERSISTENT_GROUP=1 \
  -DLI2_PERSISTENT_EPOCH=1 -DLI2_MOV_GUARD=1 -DLI2_LINKED_EPOCH=1 \
  -DLI2_SCALAR_SPAN=1 -DLI2_SCALAR_SPAN_TRACE=1 -DLI2_SPAN_FAST_BYTES=1 \
  -DLI2_MAPS_CURRENT_TF=1 -DLI2_SCALAR_REGION=1 -DLI2_SCALAR_REGION_REUSE=1 \
  -DLI2_INITIAL_CODE_PROTECTION=1 -DLI2_UNROLLED_HASH=1 -DLI2_MAPS_MAINTAINED=1 \
  -DLI2_NATIVE_PAIR=1 -DLI2_REPEAT_RX_LEASE=1 -DLI2_RUN_CACHE_REUSE=1 \
  -DLI2_EFFECT_PROVIDER=1 -DLI2_ONESHOT_REUSABLE=1 -DLI2_ONESHOT_PUBLICATION=1 \
  -DLI2_TF_SEALED_CUSTODY=1 -DLI2_TF_SAME_PAGE_LEASE=1 -DLI2_TF_HANDOFF=1 \
  -DLI2_REGISTER_RUN=1 -DLI2_MAPS_PHASE_REUSE=1 -DLI2_RSEQ_INACTIVE=1 \
  -DLI2_NATIVE_PAGES=1 -DLI2_CPUID_NX_ONLY=1 -DLI2_RSEQ_NATIVE=1 \
  -DLI2_RSEQ_NATIVE_BOUNDARY=1 -DLI2_RSEQ_TCGETS_BTRFS=1 -DLI2_RSEQ_TIOCGWINSZ_BTRFS=1 \
  -DLI2_FAST_MEMSET=1 -DLI2_FAST_EQUAL=1 \
  -I"$selected_dir" -I"$parent_dir"
case "$mode" in
  headers) exec "$cc_bin" "$@" -M "$fixture_dir/oracle.c" ;;
  build) exec "$cc_bin" "$@" -Wl,--gc-sections,-z,now,-z,relro,-z,noexecstack,--build-id=none,--no-undefined \
    "$fixture_dir/oracle.c" -o "$output_dir/loop-source-guard" ;;
  *) exit 2 ;;
esac
