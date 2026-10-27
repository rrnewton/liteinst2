#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
mkdir -p target/page-mode
cc -std=gnu11 -O2 -g -shared -fPIC -fno-stack-protector -fno-builtin \
  -fno-tree-loop-distribute-patterns -fno-tree-vectorize -fvisibility=hidden \
  -Wall -Wextra -Werror -Wl,-Bsymbolic,-z,now,-z,relro \
  tools/page-mode/preload.c tools/page-mode/gateway.S -ldl -o target/page-mode/libli2_dynamic.so
exec cc -std=gnu11 -O2 -g -Wall -Wextra -Werror \
  tools/page-mode/probe.c -ldl -o target/page-mode/dynamic_probe
