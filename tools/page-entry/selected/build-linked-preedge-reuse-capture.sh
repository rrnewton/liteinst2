#!/bin/sh
# Distinct typed v2 pre-edge release profile; original NX cuts require separate qualification.
set -eu
test "$#" -eq 2
selected_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
parent_dir=$(CDPATH= cd -- "$selected_dir/.." && pwd)
archive=$1
output=$2
test -f "$archive"
python3 "$selected_dir/linked_epoch_binding.py" "$selected_dir" "$archive" "$output" native-hint-preedge
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -nostdlib -shared -fPIC -fvisibility=hidden \
  -fno-stack-protector -fno-builtin -fno-tree-loop-distribute-patterns -fno-tree-vectorize \
  -mgeneral-regs-only -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
  -Wall -Wextra -Werror -DLI2_LINKED_PREEDGE=1 -DLI2_LINKED_PREEDGE_REUSE_CAPTURE=1 -DLI2_LINKED_NATIVE_HINT=1 -DLI2_LINKED_EPOCH=1 -DLI2_SCALAR_SPAN=1 -DLI2_SCALAR_SPAN_TRACE=1 -DLI2_SPAN_FAST_BYTES=1 -DLI2_MAPS_CURRENT_TF=1 -DLI2_SCALAR_REGION=1 -DLI2_SCALAR_REGION_REUSE=1 -DLI2_INITIAL_CODE_PROTECTION=1 -DLI2_UNROLLED_HASH=1 -DLI2_MAPS_MAINTAINED=1 -DLI2_NATIVE_PAIR=1 -DLI2_REPEAT_RX_LEASE=1 -DLI2_RUN_CACHE_REUSE=1 -DLI2_EFFECT_PROVIDER=1 -DLI2_ONESHOT_REUSABLE=1 -DLI2_ONESHOT_PUBLICATION=1 -DLI2_TF_SEALED_CUSTODY=1 -DLI2_TF_SAME_PAGE_LEASE=1 -DLI2_TF_HANDOFF=1 -DLI2_REGISTER_RUN=1 -DLI2_MAPS_PHASE_REUSE=1 -DLI2_RSEQ_INACTIVE=1 -DLI2_NATIVE_PAGES=1 -DLI2_CPUID_NX_ONLY=1 -DLI2_RSEQ_NATIVE=1 -DLI2_RSEQ_NATIVE_BOUNDARY=1 -DLI2_RSEQ_TCGETS_BTRFS=1 -DLI2_RSEQ_TIOCGWINSZ_BTRFS=1 -DLI2_FAST_MEMSET=1 -DLI2_FAST_EQUAL=1 -I"$output" -I"$selected_dir" -I"$parent_dir" \
  -Wl,--gc-sections,--exclude-libs,ALL,--undefined=li2_selected_observe_hardware,--undefined=li2_selected_complete_native,--undefined=li2_selected_complete_scripted,--undefined=li2_step_session_init,--undefined=li2_step_arm,--undefined=li2_step_begin,--undefined=li2_step_trace,--undefined=li2_step_abort,--undefined=li2_decoder_initialize,--undefined=li2_decoder_decode,--undefined=li2_decoder_scan_page,--undefined=li2_decoder_stats,--undefined=li2_decoder_tf_classify,--undefined=li2_tf_arm,--undefined=li2_tf_begin,--undefined=li2_tf_trace,--undefined=li2_tf_abort,--undefined=li2_tf_unexpected,--undefined=li2_lifecycle_tf_continuation,--undefined=li2_decoder_write_footprint,--undefined=li2_decoder_span_describe,--undefined=li2_span_plan_page,--undefined=li2_span_plan_validate,--undefined=li2_span_map_pc,--undefined=li2_decoder_link_none,--undefined=li2_link_plan_page,--undefined=li2_link_plan_validate,--undefined=li2_preedge_plan_page,--undefined=li2_preedge_plan_validate \
  -Wl,-e,_start,-Bsymbolic,-z,now,-z,relro,-z,noexecstack,--build-id=none,--no-undefined \
  "$parent_dir/bridge.c" "$selected_dir/runtime_loader.c" "$selected_dir/lifecycle_loader.c" \
  "$selected_dir/entry.S" "$selected_dir/selected_effect.c" "$selected_dir/selected_effect_native.c" "$selected_dir/oneshot.c" "$selected_dir/provider.c" "$selected_dir/step_owner.c" \
  "$selected_dir/selected_selftest.S" "$selected_dir/support.c" \
  "$selected_dir/register_run_plan.c" "$selected_dir/register_run_owner.c" \
  "$selected_dir/register_run_publish.c" "$selected_dir/register_run_reset.c" "$selected_dir/rseq_guard.c" "$selected_dir/native_policy.c" "$selected_dir/native_epoch.c" "$selected_dir/unrolled_hash_plan.c" "$selected_dir/region_plan.c" "$selected_dir/linked_plan.c" "$selected_dir/linked_preedge_plan.c" "$archive" \
  -o "$output/bridge-linked-epoch.so"
