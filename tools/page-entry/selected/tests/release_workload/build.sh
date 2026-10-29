#!/usr/bin/env bash
set -euo pipefail
test "$#" -eq 1
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output=$(realpath -m "$1")
test ! -e "$output"
mkdir -p "$output"
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -Wall -Wextra -Werror -fPIE -pie \
  -fno-builtin-strrchr -fno-lto -Wl,-z,relro,-z,now,-z,noexecstack \
  "$source_dir/subject.c" -o "$output/strrchr-workload"
