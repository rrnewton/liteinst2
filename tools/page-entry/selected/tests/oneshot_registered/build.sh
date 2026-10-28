#!/bin/sh
set -eu
test "$#" -eq 3
interpreter=$1
library_root=$2
output=$3
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cc_bin=${LI2_CC:?exact compiler required}
# Same genuine-interpreter ET_DYN convention as the existing boundary fixture.
"$cc_bin" -nostdlib -pie "-Wl,--dynamic-linker,$interpreter" \
  "-Wl,-T,$fixture_dir/linker.ld,-z,max-page-size=4096,--build-id=none,--no-as-needed" \
  "-L$library_root" "-l:$(basename -- "$interpreter")" \
  "$fixture_dir/fixture.S" -o "$output"
