#!/bin/sh
set -eu
test "$#" -eq 2
source_dir=$(CDPATH= cd -- "$1" && pwd)
output=$2
test ! -e "$output"
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -Wall -Wextra -Werror -I"$source_dir" \
  "$source_dir/trace.c" -o "$output"
