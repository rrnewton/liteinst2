#!/bin/sh
# Whole actual lifecycle TU; supplied observations, no target/native execution.
set -eu
test "$#" -eq 3
owner_context=$1
selected_context=$2
output_dir=$3
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
parent_context=$(CDPATH= cd -- "$selected_context/.." && pwd)
cc_bin=${LI2_CC:-cc}
mkdir -p "$output_dir"
"$cc_bin" -std=gnu11 -O2 -g -fno-stack-protector -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
  -Wall -Wextra -Werror -DLI2_LINKED_NATIVE_PROBE=1 \
  -DLI2_PERSISTENT_ACTIVE_DOMAIN=1 -DLI2_RSEQ_CURRENT_DATA=1 -DLI2_PERSISTENT_RETAINED_TWO=1 \
  -DLI2_PERSISTENT_DISPATCH=1 -DLI2_PERSISTENT_GROUP=1 -DLI2_PERSISTENT_EPOCH=1 \
  -DLI2_MOV_GUARD=1 -DLI2_LINKED_EPOCH=1 -DLI2_SCALAR_SPAN=1 -DLI2_SCALAR_SPAN_TRACE=1 \
  -DLI2_SPAN_FAST_BYTES=1 -DLI2_MAPS_CURRENT_TF=1 -DLI2_SCALAR_REGION=1 \
  -DLI2_SCALAR_REGION_REUSE=1 -DLI2_INITIAL_CODE_PROTECTION=1 -DLI2_UNROLLED_HASH=1 \
  -DLI2_MAPS_MAINTAINED=1 -DLI2_NATIVE_PAIR=1 -DLI2_REPEAT_RX_LEASE=1 \
  -DLI2_RUN_CACHE_REUSE=1 -DLI2_EFFECT_PROVIDER=1 -DLI2_ONESHOT_REUSABLE=1 \
  -DLI2_ONESHOT_PUBLICATION=1 -DLI2_TF_SEALED_CUSTODY=1 -DLI2_TF_SAME_PAGE_LEASE=1 \
  -DLI2_TF_HANDOFF=1 -DLI2_REGISTER_RUN=1 -DLI2_MAPS_PHASE_REUSE=1 \
  -DLI2_RSEQ_INACTIVE=1 -DLI2_NATIVE_PAGES=1 -DLI2_CPUID_NX_ONLY=1 -DLI2_RSEQ_NATIVE=1 \
  -DLI2_RSEQ_NATIVE_BOUNDARY=1 -DLI2_RSEQ_TCGETS_BTRFS=1 -DLI2_RSEQ_TIOCGWINSZ_BTRFS=1 \
  -DLI2_FAST_MEMSET=1 -DLI2_FAST_EQUAL=1 \
  -I"$owner_context" -I"$selected_context" -I"$parent_context" \
  -Wl,--gc-sections,-z,now,-z,relro,-z,noexecstack,--no-undefined \
  "$fixture_dir/oracle.c" "$selected_context/native_policy.c" -o "$output_dir/linked-native-probe-oracle"
