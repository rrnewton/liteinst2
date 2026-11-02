# LOOP source guard component

This oracle includes the actual `lifecycle_loader.c` under all 47 LOOP release
macros. It checks typed source classes, canonical anonymous backing (including
padding), sealed backing and alias checks, geometry, both source advisories, and
full page admission. Metadata is supplied; no application instructions or owner
lifetimes run. Success is exactly 1,110 C assertions, 176-byte backing and zero
raw calls. It grants no native, owner, qualification or performance credit.

The recorded run used base `7c37ef6c69bbff0542e69906d0298a423be9db0b` with exactly
three dirty production files. Their whole hashes and both fixture hashes appear
in `evaluation/inprocess/results/20261102-loop-anonymous-source-guards-7c37ef6c69bb.json`.
Commit `dbee73a820ae7909d256849a2c7dbf2f7014ff3e` publishes those exact five files;
it is a source reproduction checkout, not the revision claimed by the earlier
execution. The run used GCC 11.5.0 on Linux/x86-64, reserved CPU 3. No CPU model
was captured. All nine wrapper commands, 18 captures and 244 compiler dependencies
closed successfully. Durations describe validation only.

From that source checkout, first reserve one CPU externally. The following
portable manual recipe runs the same C oracle; it is not the historical private
wrapper argv. Use a fresh output path and verify the five hashes against the JSON.
Required tools are GCC, a POSIX shell, GNU `timeout` and `prlimit`.

```sh
set -eu
repo=$(pwd -P)
fixture="$repo/tools/page-entry/selected/tests/loop_source_guard"
selected="$repo/tools/page-entry/selected"
out="$repo/target/evaluation/inprocess/loop-source-guard-manual-FRESH"
mkdir "$out"
export PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC PYTHONDONTWRITEBYTECODE=1 LI2_CC=/usr/bin/gcc
bounded() {
    cpu=$1 wall=$2 file_bytes=$3
    shift 3
    timeout --signal=KILL "${wall}s" prlimit --cpu="$cpu:$cpu" \
        --as=536870912:536870912 --fsize="$file_bytes:$file_bytes" --core=0:0 -- "$@"
}
bounded 10 20 16777216 /bin/sh "$fixture/build.sh" "$selected" "$out" headers >"$out/headers-before.stdout" 2>"$out/headers-before.stderr"
bounded 30 60 67108864 /bin/sh "$fixture/build.sh" "$selected" "$out" build >"$out/build.stdout" 2>"$out/build.stderr"
bounded 5 15 16777216 "$out/loop-source-guard" >"$out/component.stdout" 2>"$out/component.stderr"
bounded 10 20 16777216 /bin/sh "$fixture/build.sh" "$selected" "$out" headers >"$out/headers-after.stdout" 2>"$out/headers-after.stderr"
cmp "$out/headers-before.stdout" "$out/headers-after.stdout"
test ! -s "$out/build.stdout"
for capture in "$out"/*.stderr; do test ! -s "$capture"; done
for capture in "$out"/*.stdout "$out"/*.stderr; do test "$(wc -c < "$capture")" -le 8388608; done
printf '%s\n' '{"status":"component_passed","checks":1110,"backing_bytes":176,"raw_calls":0,"native_executed":false,"qualification":false}' >"$out/expected.json"
cmp "$out/expected.json" "$out/component.stdout"
```

Every command must exit zero; a failure remains a failure. The first recorded
wrapper attempt failed before any child because it pinned absent `/usr/bin/dash`.
Only that pin changed to resolve the `/bin/sh` actually used by the recipe. Its
failed receipt is preserved and identified in the JSON; no test or production
predicate changed between the two attempts.
