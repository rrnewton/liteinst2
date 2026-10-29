#!/usr/bin/env bash
set -euo pipefail
test "$#" -eq 3
source_dir=$(realpath "$1")
provider_dir=$(realpath "$2")
output=$(realpath -m "$3")
test ! -e "$output"
mkdir -p "$output"
cc=${CC:-cc}
common=(-std=c11 -O2 -g -Wall -Wextra -Werror -fno-builtin -fno-strict-aliasing -fno-tree-loop-distribute-patterns -mgeneral-regs-only -I"$source_dir" -I"$provider_dir")
"$cc" "${common[@]}" -fPIC -shared -Wl,-z,relro,-z,now,-z,noexecstack \
  -Wl,-soname,libli2-late-leaf.so "$source_dir/leaf.c" -o "$output/libli2-late-leaf.so"
"$cc" "${common[@]}" -fPIC -DPA_DSO=1 -shared -Wl,-z,relro,-z,now,-z,noexecstack \
  -Wl,-soname,libli2-late.so "$source_dir/late.c" "$provider_dir/module.c" \
  "$provider_dir/machine.S" "$provider_dir/sites.S" -L"$output" -Wl,--no-as-needed -lli2-late-leaf \
  -o "$output/libli2-late.so"
"$cc" "${common[@]}" -fPIE -DPA_DSO=0 -pie -Wl,-z,relro,-z,now,-z,noexecstack \
  -Wl,--export-dynamic-symbol=li2_late_note "$source_dir/main.c" "$provider_dir/module.c" \
  "$provider_dir/machine.S" "$provider_dir/sites.S" -ldl -o "$output/late-dso"
