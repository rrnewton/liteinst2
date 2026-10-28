#!/bin/sh
set -eu
test "$#" -eq 2
probe_cc=$1
probe_out=$2
test -x "$probe_cc"
test ! -e "$probe_out"
probe_src=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$probe_cc" -std=gnu11 -O2 -g -Wall -Wextra -Werror -Wstrict-prototypes \
    -mgeneral-regs-only -fno-builtin -fno-omit-frame-pointer -fPIE -pie \
    -Wl,-z,now,-z,relro,-z,noexecstack \
    "$probe_src/probe.c" "$probe_src/probe.S" -o "$probe_out"
