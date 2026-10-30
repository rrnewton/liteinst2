#!/bin/sh
# Explicit component build, never sourced by the default bridge recipe.
set -eu
[ "$#" -eq 4 ] || { echo 'usage: build.sh ROOT DECODER_ARCHIVE OUTPUT prepare|build' >&2; exit 2; }
root=$(realpath "$1")
decoder_archive=$(realpath "$2")
output_dir=$(realpath -m "$3")
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# The exact existing core is a path dependency, with no changed feature/policy.
python_bin=${LI2_PYTHON:-python3}
cargo_bin=${LI2_CARGO:-cargo}
if [ "$4" = prepare ]; then
[ ! -e "$output_dir" ]
mkdir -p "$output_dir/planner/src"
cp "$source_dir/planner/lib.rs" "$output_dir/planner/src/lib.rs"
"$python_bin" - "$root" "$output_dir/planner/Cargo.toml" <<'PY'
import json,sys
from pathlib import Path
root,out=sys.argv[1:]
Path(out).write_text('[workspace]\n[package]\nname="li2-region-plan"\nversion="0.0.0"\nedition="2024"\npublish=false\n[lib]\ncrate-type=["cdylib"]\n[dependencies]\nliteinst2={path='+json.dumps(root)+'}\n[profile.release]\nopt-level=2\ndebug=1\npanic="abort"\noverflow-checks=true\ncodegen-units=1\n')
PY
"$cargo_bin" generate-lockfile --offline --manifest-path "$output_dir/planner/Cargo.toml"
exit 0
fi
[ "$4" = build ]
[ -f "$output_dir/planner/Cargo.lock" ]
[ "${CARGO_TARGET_DIR:-}" = "$root/target" ]
"$cargo_bin" build --locked --offline --release --manifest-path "$output_dir/planner/Cargo.toml"
cp "$root/target/release/libli2_region_plan.so" "$output_dir/libli2_region_plan.so"
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -fno-builtin -fno-stack-protector -fno-tree-loop-distribute-patterns -fno-tree-vectorize -mgeneral-regs-only -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -Wall -Wextra -Werror -Wno-misleading-indentation -I"$source_dir" -I"$root/tools/page-entry/selected" -I"$root/tools/page-entry" "$source_dir/component.c" "$source_dir/machine.S" "$root/tools/page-entry/selected/step_owner.c" "$decoder_archive" -L"$output_dir" -lli2_region_plan -Wl,-z,now,-z,relro,--no-undefined -Wl,-rpath,'$ORIGIN' -ldl -lpthread -lm -o "$output_dir/region-component"
