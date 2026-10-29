#!/usr/bin/env bash
set -euo pipefail
test "$#" -eq 2
source_dir=$(realpath "$1")
output=$(realpath -m "$2")
test ! -e "$output"
mkdir -p "$output"
cc=${CC:-cc}
common=(-std=c11 -O2 -g -Wall -Wextra -Werror -fno-builtin -fno-strict-aliasing -fno-tree-loop-distribute-patterns -mgeneral-regs-only)
"$cc" "${common[@]}" -fPIC -DPA_DSO=1 -shared -Wl,-z,relro,-z,now,-z,noexecstack \
  -Wl,-soname,libli2-provider-app.so "$source_dir/module.c" "$source_dir/machine.S" "$source_dir/sites.S" \
  -o "$output/libli2-provider-app.so"
"$cc" "${common[@]}" -fPIE -DPA_DSO=0 -pie -Wl,-z,relro,-z,now,-z,noexecstack \
  "$source_dir/app.c" "$source_dir/module.c" "$source_dir/machine.S" "$source_dir/sites.S" \
  -L"$output" -Wl,--no-as-needed -lli2-provider-app -ldl \
  -o "$output/provider-app"
