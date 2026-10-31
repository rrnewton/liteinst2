#!/bin/sh
# Distinct loop-only group observation; release authority/flags otherwise exact.
set -eu
test "$#" -eq 3
selected_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
parent_dir=$(CDPATH= cd -- "$selected_dir/.." && pwd)
archive=$1
image=$2
output=$3
test -f "$archive"
test -f "$image"
"${LI2_PYTHON:-python3}" "$selected_dir/persistent_group_binding.py" "$selected_dir" "$archive" "$image" "$output"
"${LI2_PYTHON:-python3}" "$selected_dir/persistent_group_capture_binding.py" "$image" "$output"
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -nostdlib -shared -fPIC -fvisibility=hidden \
  -fno-stack-protector -fno-builtin -fno-tree-loop-distribute-patterns -fno-tree-vectorize \
  -mgeneral-regs-only -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
  -Wall -Wextra -Werror -DLI2_PERSISTENT_GROUP_CAPTURE=1 -DLI2_PERSISTENT_GROUP=1 -DLI2_PERSISTENT_EPOCH=1 -DLI2_MOV_GUARD=1 -DLI2_LINKED_EPOCH=1 -DLI2_SCALAR_SPAN=1 -DLI2_SCALAR_SPAN_TRACE=1 -DLI2_SPAN_FAST_BYTES=1 -DLI2_MAPS_CURRENT_TF=1 -DLI2_SCALAR_REGION=1 -DLI2_SCALAR_REGION_REUSE=1 -DLI2_INITIAL_CODE_PROTECTION=1 -DLI2_UNROLLED_HASH=1 -DLI2_MAPS_MAINTAINED=1 -DLI2_NATIVE_PAIR=1 -DLI2_REPEAT_RX_LEASE=1 -DLI2_RUN_CACHE_REUSE=1 -DLI2_EFFECT_PROVIDER=1 -DLI2_ONESHOT_REUSABLE=1 -DLI2_ONESHOT_PUBLICATION=1 -DLI2_TF_SEALED_CUSTODY=1 -DLI2_TF_SAME_PAGE_LEASE=1 -DLI2_TF_HANDOFF=1 -DLI2_REGISTER_RUN=1 -DLI2_MAPS_PHASE_REUSE=1 -DLI2_RSEQ_INACTIVE=1 -DLI2_NATIVE_PAGES=1 -DLI2_CPUID_NX_ONLY=1 -DLI2_RSEQ_NATIVE=1 -DLI2_RSEQ_NATIVE_BOUNDARY=1 -DLI2_RSEQ_TCGETS_BTRFS=1 -DLI2_RSEQ_TIOCGWINSZ_BTRFS=1 -DLI2_FAST_MEMSET=1 -DLI2_FAST_EQUAL=1 -I"$output" -I"$selected_dir" -I"$parent_dir" \
  -Wl,--gc-sections,--exclude-libs,ALL,--undefined=li2_selected_observe_hardware,--undefined=li2_selected_complete_native,--undefined=li2_selected_complete_scripted,--undefined=li2_step_session_init,--undefined=li2_step_arm,--undefined=li2_step_begin,--undefined=li2_step_trace,--undefined=li2_step_abort,--undefined=li2_decoder_initialize,--undefined=li2_decoder_decode,--undefined=li2_decoder_scan_page,--undefined=li2_decoder_stats,--undefined=li2_decoder_tf_classify,--undefined=li2_tf_arm,--undefined=li2_tf_begin,--undefined=li2_tf_trace,--undefined=li2_tf_abort,--undefined=li2_tf_unexpected,--undefined=li2_lifecycle_tf_continuation,--undefined=li2_decoder_write_footprint,--undefined=li2_decoder_span_describe,--undefined=li2_span_plan_page,--undefined=li2_span_plan_validate,--undefined=li2_span_map_pc,--undefined=li2_decoder_link_none,--undefined=li2_link_plan_page,--undefined=li2_link_plan_validate,--undefined=li2_decoder_mov_store,--undefined=li2_pg_plan_pages,--undefined=li2_pg_miss_valid,--undefined=li2_pg_plan_pages,--undefined=li2_pg_plan_validate,--undefined=li2_pg_compact_build,--undefined=li2_pg_compact_validate,--undefined=li2_pg_compact_guard,--undefined=li2_pg_compact_recover,--undefined=li2_mg_emit,--undefined=li2_mg_recover \
  -Wl,-e,_start,-Bsymbolic,-z,now,-z,relro,-z,noexecstack,--build-id=none,--no-undefined \
  "$parent_dir/bridge.c" "$selected_dir/runtime_loader.c" "$selected_dir/lifecycle_loader.c" \
  "$selected_dir/entry.S" "$selected_dir/selected_effect.c" "$selected_dir/selected_effect_native.c" "$selected_dir/oneshot.c" "$selected_dir/provider.c" "$selected_dir/step_owner.c" \
  "$selected_dir/selected_selftest.S" "$selected_dir/support.c" \
  "$selected_dir/register_run_plan.c" "$selected_dir/register_run_owner.c" \
  "$selected_dir/register_run_publish.c" "$selected_dir/register_run_reset.c" "$selected_dir/rseq_guard.c" "$selected_dir/native_policy.c" "$selected_dir/native_epoch.c" "$selected_dir/unrolled_hash_plan.c" "$selected_dir/region_plan.c" "$selected_dir/linked_plan.c" "$selected_dir/persistent_group_plan.c" "$selected_dir/persistent_group_compact.c" "$selected_dir/linked_mov_guard.c" "$archive" \
  -o "$output/bridge-persistent-group-capture.so"
