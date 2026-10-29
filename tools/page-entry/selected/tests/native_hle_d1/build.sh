#!/bin/sh
set -eu
if [ "$#" -ne 1 ]; then echo "usage: $0 output-directory" >&2; exit 2; fi
out=$1
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../../../.." && pwd)
mkdir -p "$out"
out=$(CDPATH= cd -- "$out" && pwd)
cd "$root"
cc_bin=${LI2_CC:-cc}
cargo_bin=${LI2_CARGO:-cargo}
"$cc_bin" -O2 -g -std=gnu11 -Wall -Wextra -Werror -Itools/page-entry/selected \
  tools/page-entry/selected/tests/native_hle_d1/probe.c \
  tools/page-entry/selected/native_policy.c -o "$out/hle-d1-policy"
"$cargo_bin" build --offline --locked --release \
  --manifest-path tools/page-entry/selected/tests/native_hle_d1/Cargo.toml \
  --target-dir "$root/target"
cp "$root/target/release/hle-d1-modes" "$out/hle-d1-modes"
cp "$root/target/release/hle-d1-modes.d" "$out/hle-d1-modes.d"
