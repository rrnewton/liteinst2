#!/bin/sh
set -eu
test "$#" -eq 0
cd "$(dirname -- "$0")/../../.."
source_dir=tools/page-entry/selected
parent_dir=tools/page-entry
output_dir=target/page-entry/provider-configured
mkdir -p "$output_dir"
cc_bin=${LI2_CC:-$(command -v cc)}
cargo_bin=${LI2_CARGO:-$(command -v cargo)}
rustc_bin=${RUSTC:-$(command -v rustc)}
export RUSTC="$rustc_bin"

# The decoder is an isolated, locked package. Reuse the repository's only Cargo
# target directory; an explicit metadata identity distinguishes this source
# profile from older experimental archives with the same crate name.
export CARGO_TARGET_DIR="$PWD/target"
export CARGO_NET_OFFLINE=true
export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS=1
unset CARGO_ENCODED_RUSTFLAGS
export RUSTFLAGS='-C relocation-model=pic -C panic=abort -C force-unwind-tables=no'
"$cargo_bin" rustc --manifest-path "$source_dir/decoder/Cargo.toml" \
  --release --locked --offline -j 1 -- -C metadata=li2_page_entry_selected_product_configured_v1
cp target/release/libli2_page_selected_decoder.a "$output_dir/decoder.a"
cp target/release/libli2_page_selected_decoder.d "$output_dir/decoder.d"
# Keep the exact compiler identities and source dep-info beside the archive.
# This is build metadata only; no fixture or target program is executed.
"$rustc_bin" -vV > "$output_dir/decoder-rustc.txt"
"$cargo_bin" --version > "$output_dir/decoder-cargo.txt"
"$cc_bin" --version > "$output_dir/cc-version.txt"

"$cc_bin" -std=gnu11 -O2 -g -nostdlib -shared -fPIC -fvisibility=hidden \
  -fno-stack-protector -fno-builtin -fno-tree-loop-distribute-patterns -fno-tree-vectorize \
  -mgeneral-regs-only -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
  -Wall -Wextra -Werror -DLI2_TF_HANDOFF=1 -DLI2_REGISTER_RUN=1 -DLI2_MAPS_PHASE_REUSE=1 -DLI2_RSEQ_INACTIVE=1 -DLI2_NATIVE_PAGES=1 -DLI2_FAST_MEMSET=1 -DLI2_FAST_EQUAL=1 -DLI2_ONESHOT_PUBLICATION=1 -DLI2_SELECTED_PROVIDER=1 -I"$source_dir" -I"$parent_dir" \
  -Wl,--gc-sections,--exclude-libs,ALL,--undefined=li2_selected_observe_hardware,--undefined=li2_selected_complete_native,--undefined=li2_selected_complete_scripted,--undefined=li2_selected_complete_callback,--undefined=li2_step_session_init,--undefined=li2_step_arm,--undefined=li2_step_begin,--undefined=li2_step_trace,--undefined=li2_step_abort,--undefined=li2_decoder_initialize,--undefined=li2_decoder_decode,--undefined=li2_decoder_scan_page,--undefined=li2_decoder_stats,--undefined=li2_decoder_tf_classify,--undefined=li2_tf_arm,--undefined=li2_tf_begin,--undefined=li2_tf_trace,--undefined=li2_tf_abort,--undefined=li2_tf_unexpected,--undefined=li2_lifecycle_tf_continuation,--undefined=li2_decoder_write_footprint \
  -Wl,-e,_start,-Bsymbolic,-z,now,-z,relro,-z,noexecstack,--build-id=none,--no-undefined \
  "$parent_dir/bridge.c" "$source_dir/runtime_loader.c" "$source_dir/lifecycle_loader.c" \
  "$source_dir/entry.S" "$source_dir/provider.c" "$source_dir/step_owner.c" \
  "$source_dir/selected_selftest.S" "$source_dir/support.c" \
  "$source_dir/register_run_plan.c" "$source_dir/register_run_owner.c" \
  "$source_dir/register_run_publish.c" "$source_dir/register_run_reset.c" "$source_dir/rseq_guard.c" "$source_dir/native_policy.c" "$source_dir/native_epoch.c" "$source_dir/oneshot.c" "$output_dir/decoder.a" \
  -o "$output_dir/bridge-provider-configured.so"
"$cc_bin" -std=gnu11 -O2 -g -Wall -Wextra -Werror -I"$source_dir" \
  -Wl,--gc-sections,--exclude-libs,ALL,-z,noexecstack,--build-id=none \
  "$source_dir/fixture_observe.c" "$output_dir/decoder.a" -o "$output_dir/observe"
