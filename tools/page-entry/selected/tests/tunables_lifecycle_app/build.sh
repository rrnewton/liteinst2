#!/bin/sh
# Source draft only: this recipe has not been invoked or source-qualified.
set -eu
test "$#" -eq 1
case "$1" in /*) ;; *) echo 'fresh absolute output directory required' >&2; exit 2;; esac
test ! -e "$1"
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
root=$(git -c index.threads=1 -c core.preloadIndex=false -C "$here" rev-parse --show-toplevel)
old=$root/tools/page-entry/selected/tests/persistent_direct_frontier_app
out=$1
mkdir -m 700 -- "$out"
cc -nostdlib -shared -Wl,-e,_start,-z,noexecstack,--build-id=none \
    "$old/fixture-interpreter.S" -o "$out/fixture-interpreter.so"
cc -std=c11 -O2 -g -Wall -Wextra -Werror -fno-builtin -fno-strict-aliasing \
    -fno-stack-protector -fno-tree-loop-distribute-patterns -fno-tree-vectorize \
    -mgeneral-regs-only -DLI2_FAST_EQUAL=1 -mcmodel=large \
    -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-pie -no-pie -nostdlib \
    "-DLI2_DIRECT_FRONTIER_INTERPRETER=\"$out/fixture-interpreter.so\"" \
    -Wl,-z,noexecstack,--build-id=none,--no-undefined "-Wl,-T,$old/app.ld" \
    -I"$old" -I"$here" "$here/main.c" "$here/reference.c" "$old/pure.c" \
    "$here/machine.S" "$old/entry.S" -o "$out/tunables-lifecycle"
