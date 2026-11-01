#!/bin/sh
# Pure policy puzzle only; no source or execution authority is modeled here.
set -eu
test "$#" -eq 1
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
selected_dir=$(CDPATH= cd -- "$fixture_dir/../.." && pwd)
output=$1
test -d "$output"
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -nostdlib -static -no-pie -fno-pie \
  -fno-builtin -fno-stack-protector -mgeneral-regs-only -Wall -Wextra -Werror \
  -DLI2_TF_NX_PAGE_BOUNDARY=1 -I"$selected_dir" \
  -Wl,-e,_start,--build-id=none,-z,noexecstack,--no-undefined \
  "$fixture_dir/oracle.c" -o "$output/tf-nx-page-boundary-oracle"
