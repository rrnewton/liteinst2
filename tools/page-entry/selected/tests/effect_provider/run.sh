#!/bin/sh
# Supplied-input controls only. Build build-effect-provider.sh from the same
# source first; this runner consumes that archive and does not establish build
# provenance or invoke selected backends, mappings or application subjects.
set -eu
test "$#" -eq 0
cd "$(dirname -- "$0")/../../../../.."
source_dir=tools/page-entry/selected
fixture_dir="$source_dir/tests/effect_provider"
decoder_archive=target/page-entry/effect-provider/decoder.a
output_dir=target/page-entry/effect-provider/controls
test -f "$decoder_archive"
mkdir -p "$output_dir"
cc_bin=${LI2_CC:-cc}
"$cc_bin" -std=gnu11 -O2 -g -Wall -Wextra -Werror -I"$source_dir" \
  "$fixture_dir/api.c" "$source_dir/selected_effect.c" "$decoder_archive" \
  -o "$output_dir/api"
"$cc_bin" -std=gnu11 -O2 -g -Wall -Wextra -Werror -I"$source_dir" \
  "$fixture_dir/plan.c" "$decoder_archive" -o "$output_dir/plan"
"$cc_bin" -std=gnu11 -O2 -g -Wall -Wextra -Werror -I"$source_dir" \
  "$fixture_dir/query.c" -o "$output_dir/query"
timeout --kill-after=2s 10s "$output_dir/api"
timeout --kill-after=2s 10s "$output_dir/plan"
timeout --kill-after=2s 10s "$output_dir/query"
