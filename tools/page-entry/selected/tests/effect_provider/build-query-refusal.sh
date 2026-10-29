#!/bin/sh
set -eu
test "$#" -eq 1
cd "$(dirname -- "$0")/../../../../.."
source_dir=tools/page-entry/selected/tests/effect_provider
output=$1
cc_bin=${LI2_CC:-$(command -v cc)}
# Build only. This negative fixture must never be executed without the gate.
"$cc_bin" -std=gnu11 -O2 -g -Wall -Wextra -Werror -fPIE -pie \
  -Wl,-z,relro,-z,now,-z,noexecstack \
  "$source_dir/query_refusal.c" -o "$output"
