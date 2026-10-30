#!/bin/sh
# Root supplies its existing bounded compiler/process owner; this script sets no limits.
set -eu
[ "$#" -eq 2 ] || { echo 'usage: build.sh SELECTED_DIR OUTPUT_DIR' >&2; exit 2; }
selected_dir=$(realpath "$1")
output_dir=$(realpath -m "$2")
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cc_bin=${LI2_CC:-cc}
[ ! -e "$output_dir" ]
mkdir -p "$output_dir"
"$cc_bin" -std=c11 -O2 -g -Wall -Wextra -Werror \
  -fno-builtin -fno-tree-loop-distribute-patterns -mgeneral-regs-only \
  -DLI2_INITIAL_CODE_PROTECTION=1 -I"$selected_dir" \
  "$fixture_dir/oracle.c" -Wl,-z,now,-z,relro,--no-undefined \
  -o "$output_dir/initial-code-protection"
