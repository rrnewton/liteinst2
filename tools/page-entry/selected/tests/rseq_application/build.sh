#!/bin/sh
set -eu
# Compile/link only, after separate review. TREE is compose.py's closed source
# tree; ARCHIVE is a separately authenticated footprint-enabled decoder archive.
test "$#" -eq 3
source_dir=$(CDPATH= cd -- "$1/tools/page-entry/selected" && pwd)
parent_dir=$(CDPATH= cd -- "$source_dir/.." && pwd)
archive=$2
output=$3
test -f "$archive"
cc_bin=${LI2_CC:-$(command -v cc)}
"$cc_bin" -std=gnu11 -O2 -g -nostdlib -shared -fPIC -fvisibility=hidden \
  -fno-stack-protector -fno-builtin -fno-tree-loop-distribute-patterns -fno-tree-vectorize \
  -mgeneral-regs-only -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
  -Wall -Wextra -Werror -DLI2_TF_HANDOFF=1 -DLI2_REGISTER_RUN=1 -DLI2_MAPS_PHASE_REUSE=1 \
  -DLI2_RSEQ_INACTIVE=1 -I"$source_dir" -I"$parent_dir" \
  -Wl,--gc-sections,--exclude-libs,ALL,--undefined=li2_selected_observe_hardware,--undefined=li2_selected_complete_native,--undefined=li2_selected_complete_scripted,--undefined=li2_step_session_init,--undefined=li2_step_arm,--undefined=li2_step_begin,--undefined=li2_step_trace,--undefined=li2_step_abort,--undefined=li2_decoder_initialize,--undefined=li2_decoder_decode,--undefined=li2_decoder_scan_page,--undefined=li2_decoder_stats,--undefined=li2_decoder_tf_classify,--undefined=li2_tf_arm,--undefined=li2_tf_begin,--undefined=li2_tf_trace,--undefined=li2_tf_abort,--undefined=li2_tf_unexpected,--undefined=li2_lifecycle_tf_continuation,--undefined=li2_decoder_write_footprint \
  -Wl,-e,_start,-Bsymbolic,-z,now,-z,relro,-z,noexecstack,--build-id=none,--no-undefined \
  "$parent_dir/bridge.c" "$source_dir/runtime_loader.c" "$source_dir/lifecycle_loader.c" \
  "$source_dir/entry.S" "$source_dir/provider.c" "$source_dir/step_owner.c" \
  "$source_dir/selected_selftest.S" "$source_dir/support.c" \
  "$source_dir/register_run_plan.c" "$source_dir/register_run_owner.c" \
  "$source_dir/register_run_publish.c" "$source_dir/register_run_reset.c" \
  "$source_dir/rseq_guard.c" "$source_dir/observe.c" "$archive" -o "$output"
