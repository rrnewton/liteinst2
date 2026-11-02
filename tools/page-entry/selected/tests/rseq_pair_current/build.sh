#!/bin/sh
# Actual lifecycle kernel-map fixture; no instruction, registration or owner credit.
set -eu
test "$#" -eq 4
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
selected=$1
archive=$2
output=$3
case "$4" in
  projected) set -- ;;
  verified) set -- -DLI2_MAPS_DIFFERENTIAL=1 ;;
  *) exit 2 ;;
esac
test -d "$selected"
test -f "$archive"
test ! -e "$output"
test ! -e "$output.c"
"${LI2_PYTHON:-python3}" -I -S -B "$fixture/prepare.py" "$selected" "$output.c"
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -fno-stack-protector -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only \
  -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
  -Wall -Wextra -Werror -DLI2_MAPS_PHASE_REUSE=1 -DLI2_MAPS_MAINTAINED=1 \
  -DLI2_TF_HANDOFF=1 -DLI2_TF_SAME_PAGE_LEASE=1 -DLI2_TF_SEALED_CUSTODY=1 \
  -DLI2_RSEQ_INACTIVE=1 -DLI2_MAPS_CURRENT_TF=1 -DLI2_RSEQ_CURRENT_DATA=1 "$@" \
  -I"$selected" -I"$selected/.." "$output.c" "$archive" \
  -Wl,--gc-sections,-z,noexecstack,--build-id=none -ldl -lpthread -lm -o "$output"
