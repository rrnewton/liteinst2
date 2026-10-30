#!/bin/sh
# Source-only recipe. The existing process owner imposes all original bounds.
# The CRT runs main; only the unused loader _start symbol is renamed. Its raw
# gateway and every production helper body remain the actual selected sources.
set -eu
test "$#" -eq 4
selected_dir=$(CDPATH= cd -- "$1" && pwd)
output=$2
archive=$3
config_dir=$(CDPATH= cd -- "$4" && pwd)
test -f "$archive"
test -f "$config_dir/scalar_reuse_certificate_config.h"
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
parent_dir=$(CDPATH= cd -- "$selected_dir/.." && pwd)
cc_bin=${LI2_CC:-cc}
mkdir -p "$output"
"$cc_bin" -std=gnu11 -O2 -g -fPIC -fvisibility=hidden \
  -fno-stack-protector -fno-builtin -fno-tree-loop-distribute-patterns -fno-tree-vectorize \
  -mgeneral-regs-only -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
  -Wall -Wextra -Werror -D_start=li2_certificate_component_unused_start -DLI2_SCALAR_REGION=1 -DLI2_SCALAR_REGION_REUSE=1 -DLI2_SCALAR_REGION_REUSE_CERTIFICATE=1 -DLI2_INITIAL_CODE_PROTECTION=1 -DLI2_UNROLLED_HASH=1 -DLI2_MAPS_MAINTAINED=1 -DLI2_NATIVE_PAIR=1 -DLI2_REPEAT_RX_LEASE=1 -DLI2_RUN_CACHE_REUSE=1 -DLI2_EFFECT_PROVIDER=1 -DLI2_ONESHOT_REUSABLE=1 -DLI2_ONESHOT_PUBLICATION=1 -DLI2_TF_SEALED_CUSTODY=1 -DLI2_TF_SAME_PAGE_LEASE=1 -DLI2_TF_HANDOFF=1 -DLI2_REGISTER_RUN=1 -DLI2_MAPS_PHASE_REUSE=1 -DLI2_RSEQ_INACTIVE=1 -DLI2_NATIVE_PAGES=1 -DLI2_CPUID_NX_ONLY=1 -DLI2_RSEQ_NATIVE=1 -DLI2_RSEQ_NATIVE_BOUNDARY=1 -DLI2_RSEQ_TCGETS_BTRFS=1 -DLI2_RSEQ_TIOCGWINSZ_BTRFS=1 -DLI2_FAST_MEMSET=1 -DLI2_FAST_EQUAL=1 -I"$config_dir" -I"$selected_dir" -I"$parent_dir" \
  -Wl,--gc-sections,-z,now,-z,relro,-z,noexecstack,--build-id=none,--no-undefined \
  "$parent_dir/bridge.c" "$fixture_dir/oracle.c" "$selected_dir/lifecycle_loader.c" \
  "$selected_dir/entry.S" "$selected_dir/selected_effect.c" "$selected_dir/selected_effect_native.c" "$selected_dir/oneshot.c" "$selected_dir/provider.c" "$selected_dir/step_owner.c" \
  "$selected_dir/selected_selftest.S" "$selected_dir/support.c" \
  "$selected_dir/register_run_plan.c" "$selected_dir/register_run_owner.c" \
  "$selected_dir/register_run_publish.c" "$selected_dir/register_run_reset.c" "$selected_dir/rseq_guard.c" "$selected_dir/native_policy.c" "$selected_dir/native_epoch.c" "$selected_dir/unrolled_hash_plan.c" "$selected_dir/region_plan.c" "$archive" -ldl -lpthread -lm \
  -o "$output/reuse-certificate"
