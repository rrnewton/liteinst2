# Fixed-address GNU cat result

**PASS: nine native cases** at `0076fced9793c7b1b8459b76020616791dafafbf`, profile `fixed-exec-overlapping-v2`. Original, LiteInst and E9Patch each produced exact stdout, exit zero and empty stderr for empty input, all byte values repeated to 65,536 bytes, and fixed `cat -n` input. [results.csv](results.csv) retains all nine rows and output hashes.

LiteInst emitted **751/751 imported jump sites**, without refusal or trap fallback: B1=683, B2=44, T1=3, T3=21. This denominator is the imported jump-site set, not all nondeterministic instructions or proved CFG coverage. E9 patched all 751 and retained its previous output bytes. The original is the same 55,056-byte GNU coreutils 9.5 non-PIE ET_EXEC build.

The [first comparison](../README.md) remains **FAILED**: 741 local plans, ten refusals, no candidate and three LI2 cases UNOBSERVED. The successor adds explicit fixed ET_EXEC/zero-bias binding and uses the existing overlapping-neighbor planner. All sites, 2,253 policy rows, arena `[0x01000000,0x20000000)`, permits, search bounds and case definitions remain. Historical 1,035 misses/action pairs remain unresolved.

Writer readback passed and compatibility metadata retains the fixed-source/zero-bias obligation. `qualification_complete` remains false. Caller-supplied completeness/ownership premises and the runtime loader obligation are not proved by these cases. No throughput, universal soundness, complete CFG, runtime admission or page exemption is claimed. Full test results and their first failure are [separate](../fixed-exec-correctness/README.md).

Hardware: AMD EPYC Zen 5 dev host. One root-reserved CPU 85; cgroup 1 GiB/swap0/tasks64/CPUQuota100%; peak 627,965,952 bytes/no OOM. All 25 inner owners plus outer ended normally, cleanup complete/zero rescues. [summary.json](summary.json) pins authorities, artifacts, source, limits and operational observations; timings are not performance comparisons.

Use a clean checkout of the exact revision, Python 3.9, recorded offline tools/cache, one externally reserved `$CPU`, and fresh `$RUN` below `$ROOT/ignored`. Set `$TOOLCHAIN`, `$CARGO_HOME`, `$USER_HOME`. `$CAT_RECEIPT` names the bound successful source-build receipt with its artifact resident. To build a new input, use `build_cat.py` and the pinned archive via the [original protocol](../README.md), then its new receipt; future builds are not assumed byte-identical. Stage the summary-pinned E9Tool/backend at that protocol's required paths. Run sequentially:

```bash
set -euo pipefail
cd "$ROOT"
REV=0076fced9793c7b1b8459b76020616791dafafbf
mkdir -p "$RUN"
taskset -c "$CPU" /usr/bin/python3.9 -I -B evaluation/direct-program/reproduce.py build \
  --revision "$REV" --work "$RUN/release" --toolchain "$TOOLCHAIN" \
  --cargo-home "$CARGO_HOME" --user-home "$USER_HOME"
CAT_SHA=$(sha256sum "$CAT_RECEIPT" | cut -d' ' -f1)
BUILD_SHA=$(sha256sum "$RUN/release/closed.json" | cut -d' ' -f1)
UNIT=li2core-direct-cat-fixed-exec-reproduce
/usr/bin/systemd-run --user --scope --collect --quiet --unit="$UNIT" \
  -p AllowedCPUs="$CPU" -p CPUQuota=100% -p MemoryMax=1073741824 \
  -p MemorySwapMax=0 -p TasksMax=64 -- \
  /usr/bin/python3.9 -I -B evaluation/direct-program/reproduce.py functional \
  --revision "$REV" --work "$RUN/functional" \
  --cat-receipt "$CAT_RECEIPT" --cat-receipt-sha256 "$CAT_SHA" \
  --build-receipt "$RUN/release/closed.json" --build-receipt-sha256 "$BUILD_SHA" \
  --rewrite-profile fixed-exec-overlapping-v2 --trusted-complete-code --unit "$UNIT"
```

Scripts enforce fixed child bounds, durable owners before captures, cleanup stops and original storage ceilings. Recorded outer backstops were 1200s/release and 2400s/functional; this snippet relies on bounded stages. Parent AS must permit E9's 36 GiB reservation; native cat retains 2 GiB AS and physical cgroup 1 GiB. No automatic retry/fallback.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
