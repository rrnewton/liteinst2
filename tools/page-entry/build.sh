#!/bin/sh
set -eu
cd "$(dirname -- "$0")/../.."
source_dir=tools/page-entry
output_dir=target/page-entry
mkdir -p "$output_dir"
absolute_output="$(pwd)/$output_dir"
export PYTHONDONTWRITEBYTECODE=1

cc -std=gnu11 -O2 -g -nostdlib -shared -fPIC -fvisibility=hidden \
  -fno-stack-protector -fno-builtin -fno-tree-loop-distribute-patterns \
  -fno-tree-vectorize -mgeneral-regs-only -fno-asynchronous-unwind-tables \
  -Wall -Wextra -Werror -Wl,-e,_start,-Bsymbolic,-z,now,-z,relro,-z,noexecstack,--build-id=none \
  "$source_dir/bridge.c" "$source_dir/runtime_loader.c" "$source_dir/lifecycle_loader.c" "$source_dir/entry.S" \
  -o "$output_dir/bridge-loader.so"
python3 "$source_dir/carrier.py" make /bin/ls "$output_dir/bridge-loader.so" "$output_dir/ls-carrier"

cc -std=gnu11 -O2 -g -Wall -Wextra -Werror -fPIE -pie -Wl,-z,noexecstack,-z,now \
  "$source_dir/refusal_probe.c" "$source_dir/refusal_thread.S" -o "$output_dir/refusal-probe"
python3 "$source_dir/carrier.py" make "$output_dir/refusal-probe" \
  "$output_dir/bridge-loader.so" "$output_dir/refusal-carrier"

cc -std=gnu11 -O2 -g -nostdlib -shared -fPIC -fvisibility=hidden \
  -fno-stack-protector -fno-builtin -fno-tree-loop-distribute-patterns \
  -fno-tree-vectorize -mgeneral-regs-only -fno-asynchronous-unwind-tables \
  -Wall -Wextra -Werror -Wl,-e,_start,-Bsymbolic,-z,now,-z,relro,-z,noexecstack,--build-id=none \
  "$source_dir/bridge.c" "$source_dir/fixture_runtime.c" "$source_dir/entry.S" \
  -o "$output_dir/bridge-fixture.so"
cc -nostdlib -shared -Wl,-e,_start,-z,noexecstack,--build-id=none \
  "$source_dir/fixture-interpreter.S" -o "$output_dir/fixture-interpreter.so"
cc -nostdlib -pie -Wl,-e,_start,-z,noexecstack,--build-id=none \
  -Wl,--dynamic-linker,"$absolute_output/fixture-interpreter.so" \
  "$source_dir/fixture-main.S" -o "$output_dir/fixture-main"
python3 "$source_dir/carrier.py" make "$output_dir/fixture-main" \
  "$output_dir/bridge-fixture.so" "$output_dir/fixture-carrier"

# Opt-in raw-fork fixtures. Existing loader/ABI/default-refusal products remain.
cc -std=gnu11 -O2 -g -fno-builtin -fno-stack-protector -fno-tree-vectorize \
  -Wall -Wextra -Werror -fPIE -pie -Wl,-z,noexecstack,-z,now \
  "$source_dir/fork_probe.c" -o "$output_dir/fork-probe"
python3 "$source_dir/carrier.py" make "$output_dir/fork-probe" \
  "$output_dir/bridge-loader.so" "$output_dir/fork-carrier"

cc -std=gnu11 -O2 -g -fno-builtin -fno-stack-protector -fno-tree-vectorize \
  -mgeneral-regs-only -Wall -Wextra -Werror -fPIE -pie -Wl,-z,noexecstack,-z,now \
  "$source_dir/continuation_probe.c" "$source_dir/continuation.S" -o "$output_dir/continuation-probe"
python3 "$source_dir/carrier.py" make "$output_dir/continuation-probe" \
  "$output_dir/bridge-loader.so" "$output_dir/continuation-carrier"
for kind in gpr redzone; do
  case "$kind" in gpr) variant=1 ;; redzone) variant=2 ;; esac
  cc -std=gnu11 -O2 -g -fno-builtin -fno-stack-protector -fno-tree-vectorize \
    -mgeneral-regs-only -Wall -Wextra -Werror -fPIE -pie -Wl,-z,noexecstack,-z,now \
    -DCONTINUATION_NEGATIVE="$variant" "$source_dir/continuation_probe.c" "$source_dir/continuation.S" \
    -o "$output_dir/continuation-$kind-probe"
  python3 "$source_dir/carrier.py" make "$output_dir/continuation-$kind-probe" \
    "$output_dir/bridge-loader.so" "$output_dir/continuation-$kind-carrier"
done
cc -std=gnu11 -O2 -g -Wall -Wextra -Werror \
  "$source_dir/supervisor_probe.c" -o "$output_dir/supervisor-probe"
