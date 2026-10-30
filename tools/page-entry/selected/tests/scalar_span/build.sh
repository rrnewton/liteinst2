#!/bin/sh
# The caller supplies the exact committed scalar-span archive and bounded owner.
set -eu
[ "$#" -eq 4 ] || { echo 'usage: build.sh ROOT SELECTED_DIR DECODER_ARCHIVE OUTPUT_DIR' >&2; exit 2; }
root=$(realpath "$1")
selected=$(realpath "$2")
archive=$(realpath "$3")
output=$(realpath -m "$4")
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cc_bin=${LI2_CC:-cc}
[ ! -e "$output" ]
mkdir -p "$output"
for kind in metadata native; do
  if [ "$kind" = native ]; then
    support="$root/tools/page-entry/selected/tests/region_cache/machine.S"
  else
    support="$root/tools/page-entry/selected/tests/decoder/support.c"
  fi
  "$cc_bin" -std=gnu11 -O2 -g -fno-builtin -fno-stack-protector \
    -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
    -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -fstack-usage \
    -Wall -Wextra -Werror -Wno-misleading-indentation \
    -DLI2_FAST_MEMSET=1 -DLI2_FAST_EQUAL=1 -DLI2_SCALAR_SPAN=1 \
    -I"$selected" -I"$root/tools/page-entry/selected" \
    -I"$root/tools/page-entry/selected/tests/region_cache" \
    "$fixture/$kind.c" "$support" "$selected/region_plan.c" "$archive" \
    -Wl,-z,now,-z,relro,--no-undefined -ldl -lpthread -lm -o "$output/span-$kind"
done
