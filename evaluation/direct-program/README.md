# Direct GNU cat comparison

**FAILED** at `25c9d0adb596642e11663e3ff90083be04ac02f4`. LiteInst kept all 751 selected sites: 741 local plans and ten refusals (six `NoPatchWindow`, four `AllocationUnavailable`). Atomic emission produced no candidate; its three native cases are **UNOBSERVED**. Local plans are not emitted sites or application passes.

E9Patch patched all 751 sites. Original and E9Patch cat each passed empty input, all byte values repeated to 65,536 bytes, and a fixed `cat -n` case: exact stdout, exit 0, empty stderr. [results.csv](results.csv) preserves all nine rows. [summary.json](summary.json) pins source, artifacts, tools, commands, limits, CPU/load/storage and reviewed authorities; full diagnostics remain private.

GNU coreutils 9.5 was built as non-PIE ET_EXEC. The first configure build remains FAILED after two descendant rescues. Three subreaper controls then passed, including the expected live-orphan timeout; corrected configure joined leader 0 and two adopted exits 0. The old descendants' exit statuses were not recorded. The corrected cat and Rust release builds succeeded before this functional comparison.

The catalog has 4,347 ledger heads, 4,239 RPC instruction contexts and 751 selected jump sites. Complete-code/no-overlap/no-code-as-data/private-image declarations are caller-supplied, not proved CFG completeness. All 2,253 policy records use fixed arena `[0x01000000,0x20000000)`, no preferences and the packed-entry-veneer route. No misses were filtered or larger arena retried. Hardware: AMD EPYC Zen 5 dev host. All comparison owners cleaned up without rescues; memory peak 434,229,248 bytes, no OOM. Recorded storage remained below the original ceilings. These observations grant no performance or page-exemption credit; prior strict N/N failures remain.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.

## Reproduction

Use a clean checkout of the exact revision, Python 3.9 `-I -B`, recorded compiler tools and offline Cargo cache. Stage the summary-pinned coreutils archive as `$ARCHIVE`, E9Tool at `target/evaluation/e9-full-address-provider-v1/source/e9tool`, and E9 backend at `ignored/a3/upstream/e9patch-pldi2020/e9patch`. These external inputs are prerequisites; no signature-verification claim is made. Set `$ROOT`, one externally reserved `$CPU`, `$TOOLCHAIN`, `$CARGO_HOME`, `$USER_HOME`, and fresh `$RUN` beneath `$ROOT/ignored`. Child outputs and derived owner-log namespaces must be absent. Run sequentially:

```bash
cd "$ROOT"
REV=25c9d0adb596642e11663e3ff90083be04ac02f4
mkdir -p "$RUN"
taskset -c "$CPU" /usr/bin/python3.9 -I -B evaluation/direct-program/build_cat.py \
  --revision "$REV" --archive "$ARCHIVE" --work "$RUN/cat"
taskset -c "$CPU" /usr/bin/python3.9 -I -B evaluation/direct-program/reproduce.py build \
  --revision "$REV" --work "$RUN/release" --toolchain "$TOOLCHAIN" \
  --cargo-home "$CARGO_HOME" --user-home "$USER_HOME"
CAT_SHA=$(sha256sum "$RUN/cat/closed.json" | cut -d' ' -f1)
BUILD_SHA=$(sha256sum "$RUN/release/closed.json" | cut -d' ' -f1)
UNIT=li2core-direct-cat-reproduction
/usr/bin/systemd-run --user --scope --collect --quiet --unit="$UNIT" \
  -p AllowedCPUs="$CPU" -p CPUQuota=100% -p MemoryMax=1073741824 \
  -p MemorySwapMax=0 -p TasksMax=64 -- \
  /usr/bin/python3.9 -I -B evaluation/direct-program/reproduce.py functional \
  --revision "$REV" --work "$RUN/functional" \
  --cat-receipt "$RUN/cat/closed.json" --cat-receipt-sha256 "$CAT_SHA" \
  --build-receipt "$RUN/release/closed.json" --build-receipt-sha256 "$BUILD_SHA" \
  --trusted-complete-code --unit "$UNIT"
```

The final command retains the recorded FAILED outcome. Scripts enforce bounded children, durable owners before payloads, postflight status guards and unchanged storage ceilings. The historical coordinator additionally owned this invocation with a 2,400-second wall backstop. Parent address-space limits must permit E9's 36 GiB virtual reservation; the cgroup still caps physical memory at 1 GiB. Reproduction cannot prove the caller-supplied completeness premise or correctness beyond these three cases.
