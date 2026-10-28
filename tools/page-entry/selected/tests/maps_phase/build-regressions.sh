#!/bin/sh
# Source-only recipe. The caller supplies a fresh unique output directory and
# an independently authenticated current decoder archive; no Cargo invocation.
set -eu
test "$#" -eq 3
decoder_archive=$1
output_dir=$(CDPATH= cd -- "$2" && pwd)
selected_dir=$(CDPATH= cd -- "$3" && pwd)
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cc_bin=${LI2_CC:-$(command -v cc)}
python_bin=${LI2_PYTHON:-$(command -v python3)}
mkdir "$output_dir/positive-base" "$output_dir/controls-base" "$output_dir/positive" "$output_dir/controls"
"$python_bin" "$selected_dir/tests/register_run/prepare.py" \
  "$selected_dir/tests/generic/fixture.c" "$output_dir/positive-base/run_support.inc"
"$python_bin" "$selected_dir/tests/register_run_controls/prepare.py" \
  "$selected_dir/tests/generic/fixture.c" "$selected_dir/tests/register_run/fixture.c" "$output_dir/controls-base"
"$python_bin" "$fixture_dir/adapt_support.py" "$output_dir/positive-base/run_support.inc" "$output_dir/positive/run_support.inc"
"$python_bin" "$fixture_dir/adapt_support.py" "$output_dir/controls-base/run_support.inc" "$output_dir/controls/run_support.inc"
cp "$output_dir/controls-base/control_support.inc" "$output_dir/controls/control_support.inc"
# Quoted environment value, not generated shell interpolation. Pin the wrapper
# and actual compiler in the supervising receipt, including its added argument.
cat > "$output_dir/cc-maps" <<'WRAPPER'
#!/bin/sh
exec "$LI2_MAPS_CC" -DLI2_MAPS_PHASE_REUSE=1 "$@"
WRAPPER
chmod 700 "$output_dir/cc-maps"
export LI2_MAPS_CC="$cc_bin"
export LI2_CC="$output_dir/cc-maps"
sh "$selected_dir/tests/register_run/build.sh" "$decoder_archive" "$output_dir/positive" "$selected_dir"
sh "$selected_dir/tests/register_run_controls/build.sh" "$decoder_archive" "$output_dir/controls" "$selected_dir"
