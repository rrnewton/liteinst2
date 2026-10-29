#!/bin/sh
# Supplied-state span/encoding controls; no registration or native execution.
set -eu
test "$#" -eq 1
output_dir=$(realpath -m "$1")
test ! -e "$output_dir"
mkdir -p "$output_dir"
cd "$(dirname -- "$0")/../../../../.."
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -ffunction-sections -fdata-sections \
  -Wall -Wextra -Werror -Itools/page-entry/selected -Itools/page-entry \
  tools/page-entry/selected/tests/repeat_dword/rseq-controls.c \
  tools/page-entry/selected/step_owner.c -Wl,--gc-sections \
  -o "$output_dir/rseq-controls"
"$output_dir/rseq-controls"
