#!/bin/sh
# Actual-TU primitive controls only. No decoder archive, runtime setup or timing.
set -eu
test "$#" -eq 2
selected_context=$1
output_dir=$2
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
parent_context=$(CDPATH= cd -- "$selected_context/.." && pwd)
cc_bin=${LI2_CC:-cc}
mkdir -p "$output_dir"
# These are the same fixed REP profile macros as build-repeat-lease.sh,
# plus the two explicit test-only wrappers. Unreachable owners are discarded.
profile='-DLI2_REPEAT_RX_LEASE=1 -DLI2_RUN_CACHE_REUSE=1 -DLI2_EFFECT_PROVIDER=1 -DLI2_ONESHOT_REUSABLE=1 -DLI2_ONESHOT_PUBLICATION=1 -DLI2_TF_SEALED_CUSTODY=1 -DLI2_TF_SAME_PAGE_LEASE=1 -DLI2_TF_HANDOFF=1 -DLI2_REGISTER_RUN=1 -DLI2_MAPS_PHASE_REUSE=1 -DLI2_RSEQ_INACTIVE=1 -DLI2_NATIVE_PAGES=1 -DLI2_CPUID_NX_ONLY=1 -DLI2_RSEQ_NATIVE=1 -DLI2_RSEQ_NATIVE_BOUNDARY=1 -DLI2_RSEQ_TCGETS_BTRFS=1 -DLI2_RSEQ_TIOCGWINSZ_BTRFS=1 -DLI2_FAST_MEMSET=1 -DLI2_FAST_EQUAL=1 -DLI2_REPEAT_ZERO_ORACLE=1'
for source in step_owner lifecycle_loader; do
  "$cc_bin" -std=gnu11 -O2 -g -fPIC -fvisibility=hidden -fno-stack-protector \
    -fno-builtin -fno-tree-loop-distribute-patterns -fno-tree-vectorize \
    -mgeneral-regs-only -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
    -Wall -Wextra -Werror $profile -I"$selected_context" -I"$parent_context" \
    -c "$selected_context/$source.c" -o "$output_dir/$source.o"
done
"$cc_bin" -std=gnu11 -O2 -g -fno-builtin -fno-stack-protector -fno-pie -no-pie \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
  -Wall -Wextra -Werror $profile -I"$selected_context" -I"$parent_context" \
  -Wl,--gc-sections,-z,noexecstack,--build-id=none \
  "$fixture_dir/oracle.c" "$output_dir/step_owner.o" "$output_dir/lifecycle_loader.o" \
  -o "$output_dir/repeat-zero"
