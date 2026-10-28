#!/bin/sh
set -eu
test "$#" -eq 4
variant=$1
metadata=$2
output=$3
negative=$4
case "$negative" in 0|1|2|3|4|5|6|7|8|9|10|11|12) ;; *) exit 2 ;; esac
case "$variant" in 1|2) ;; *) exit 2 ;; esac
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cc_bin=${LI2_CC:?exact compiler required}
# Both are actual linked images. Metadata only supplies the literal PT_INTERP
# pathname to main; no generated ELF or instruction patch substitutes for link.
"$cc_bin" -nostdlib -shared -fPIC -g -Wall -Wextra -Werror \
  "-DENTRY_KIND=$variant" "-DPB_NEGATIVE=$negative" -DIMAGE_ROLE=1 \
  "-Wl,-T,$fixture_dir/interpreter.ld,-Bsymbolic,-z,max-page-size=4096,--build-id=none,--no-undefined" \
  "$fixture_dir/fixture.S" -o "$output/li2-provider-builtins-entry.so"
"$cc_bin" -nostdlib -no-pie -g -Wall -Wextra -Werror \
  "-DENTRY_KIND=$variant" "-DPB_NEGATIVE=$negative" -DIMAGE_ROLE=2 \
  "-Wl,-T,$fixture_dir/main.ld,-z,max-page-size=4096,--build-id=none,--no-undefined" \
  "$fixture_dir/fixture.S" "$metadata" -o "$output/original"
