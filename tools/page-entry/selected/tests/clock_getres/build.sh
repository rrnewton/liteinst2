#!/bin/sh
set -eu
test "$#" -eq 2
selected_dir=$(realpath "$1")
output_dir=$(realpath -m "$2")
test ! -e "$output_dir"
mkdir -p "$output_dir"
cc_bin=${LI2_CC:-cc}
fixture_dir=$selected_dir/tests/clock_getres
provider_dir=$selected_dir/tests/provider
"$cc_bin" -std=gnu11 -O2 -g -Wall -Wextra -Werror -fno-builtin -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only -ffunction-sections -fdata-sections -fno-pie -no-pie -Wl,--gc-sections,-z,noexecstack,--build-id=none "$fixture_dir/component.c" "$provider_dir/xstate.c" "$provider_dir/machine.S" -o "$output_dir/component"
"$cc_bin" -std=gnu11 -O2 -g -Wall -Wextra -Werror -fno-builtin -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only -ffunction-sections -fdata-sections -fno-pie -no-pie -Wl,--gc-sections,-z,noexecstack,--build-id=none "$fixture_dir/controls.c" -o "$output_dir/controls"
"$cc_bin" -std=gnu11 -O2 -g -Wall -Wextra -Werror -fPIE -pie -fno-builtin -fno-tree-loop-distribute-patterns -mgeneral-regs-only -Wl,-z,relro,-z,now,-z,noexecstack "$fixture_dir/subject.c" -o "$output_dir/subject"
