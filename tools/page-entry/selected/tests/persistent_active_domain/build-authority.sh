#!/bin/sh
# Actual active-domain authority predicates only; no archive, generated code or guest.
set -eu
test "$#" -eq 1
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
selected=$(CDPATH= cd -- "$fixture/../.." && pwd)
output=$1
test ! -e "$output"
test ! -e "$output.c"
python_bin=${LI2_PYTHON:-python3}
cc_bin=${LI2_CC:-cc}
"$python_bin" -I -S -B "$fixture/prepare.py" "$selected" "$output.c"
"$cc_bin" -std=gnu11 -O2 -g -fno-pie -no-pie -fno-stack-protector \
  -fno-builtin -fno-tree-loop-distribute-patterns -fno-tree-vectorize \
  -mgeneral-regs-only -fno-omit-frame-pointer -fstack-usage \
  -Wall -Wextra -Werror -DLI2_PERSISTENT_RETAINED_TWO=1 -DLI2_PERSISTENT_ACTIVE_DOMAIN=1 -DLI2_RSEQ_CURRENT_DATA=1 \
  -DLI2_PERSISTENT_DISPATCH=1 -DLI2_PERSISTENT_GROUP=1 -DLI2_PERSISTENT_EPOCH=1 \
  -DLI2_MOV_GUARD=1 -DLI2_LINKED_EPOCH=1 -DLI2_SCALAR_SPAN=1 -DLI2_SCALAR_SPAN_TRACE=1 \
  -DLI2_SPAN_FAST_BYTES=1 -DLI2_MAPS_CURRENT_TF=1 -DLI2_SCALAR_REGION=1 \
  -DLI2_SCALAR_REGION_REUSE=1 -DLI2_INITIAL_CODE_PROTECTION=1 -DLI2_UNROLLED_HASH=1 \
  -DLI2_MAPS_MAINTAINED=1 -DLI2_NATIVE_PAIR=1 -DLI2_REPEAT_RX_LEASE=1 \
  -DLI2_RUN_CACHE_REUSE=1 -DLI2_EFFECT_PROVIDER=1 -DLI2_ONESHOT_REUSABLE=1 \
  -DLI2_ONESHOT_PUBLICATION=1 -DLI2_TF_SEALED_CUSTODY=1 -DLI2_TF_SAME_PAGE_LEASE=1 \
  -DLI2_TF_HANDOFF=1 -DLI2_REGISTER_RUN=1 -DLI2_MAPS_PHASE_REUSE=1 \
  -DLI2_RSEQ_INACTIVE=1 -DLI2_NATIVE_PAGES=1 -DLI2_CPUID_NX_ONLY=1 -DLI2_RSEQ_NATIVE=1 \
  -DLI2_RSEQ_NATIVE_BOUNDARY=1 -DLI2_RSEQ_TCGETS_BTRFS=1 -DLI2_RSEQ_TIOCGWINSZ_BTRFS=1 \
  -I"$selected" "$output.c" -Wl,-z,now,-z,relro,-z,noexecstack,--no-undefined -o "$output"
