# GNU cat/head/wc corpus protocol

`cat-head-wc-v1` is an opt-in source extension. The [completed comparison](corpus-result/README.md) at `f4a561a8c29fa0298c24215d5f2027df79cbbf77` passes all **27 rows**: three programs, three cases each, and original/LI2/E9 arms. Future invocations start with unobserved outcomes. Each invocation selects one program and plans nine rows; there is no aggregate dispatcher, automatic retry or inherited success. The [0076 fixed-cat PASS](fixed-exec-result/README.md) and [earlier cat FAILED](README.md) remain separate.

The hash-pinned [catalog](program_catalog.json) defines exact stdin, argv and stdout: cat empty/all-byte/numbered; head empty/three-lines/4,097-byte prefix; wc empty-word/newline/whitespace-word counts. Default `cat-only-v1`, old cat receipt selectors and cases remain. The new route requires `fixed-exec-overlapping-v2` and the complete three-product build receipt; mixing old/new selectors refuses.

Use a clean checkout of the **new committed corpus revision** as `$REV`, not the earlier cat result revision. Set `$ROOT`, one externally reserved `$CPU`, pinned coreutils 9.5 `$ARCHIVE`, `$TOOLCHAIN`, `$CARGO_HOME`, `$USER_HOME`, and fresh `$RUN` below `$ROOT/ignored`. Stage the existing E9 tools/backend using [the original protocol](README.md). Run sequentially; child basenames must be fresh in both work and target/evaluation. Select `PROGRAM` explicitly; do not turn this into a retry loop.

```bash
set -euo pipefail
cd "$ROOT"
: "${REV:?set the new committed corpus revision}"
mkdir -p "$RUN"
taskset -c "$CPU" /usr/bin/python3.9 -I -B evaluation/direct-program/build_cat.py \
  --revision "$REV" --archive "$ARCHIVE" --work "$RUN/corpus-build-v1" \
  --build-profile cat-head-wc-v1
taskset -c "$CPU" /usr/bin/python3.9 -I -B evaluation/direct-program/reproduce.py build \
  --revision "$REV" --work "$RUN/corpus-release-v1" --toolchain "$TOOLCHAIN" \
  --cargo-home "$CARGO_HOME" --user-home "$USER_HOME"
PROGRAM=head # choose cat, head or wc for this invocation
PROGRAM_SHA=$(sha256sum "$RUN/corpus-build-v1/closed.json" | cut -d' ' -f1)
BUILD_SHA=$(sha256sum "$RUN/corpus-release-v1/closed.json" | cut -d' ' -f1)
UNIT="li2core-direct-cat-corpus-$PROGRAM"
/usr/bin/systemd-run --user --scope --collect --quiet --unit="$UNIT" \
  -p AllowedCPUs="$CPU" -p CPUQuota=100% -p MemoryMax=1073741824 \
  -p MemorySwapMax=0 -p TasksMax=64 -- \
  /usr/bin/python3.9 -I -B evaluation/direct-program/reproduce.py functional \
  --revision "$REV" --work "$RUN/corpus-$PROGRAM-v1" \
  --corpus-profile cat-head-wc-v1 --program "$PROGRAM" \
  --program-receipt "$RUN/corpus-build-v1/closed.json" --program-receipt-sha256 "$PROGRAM_SHA" \
  --build-receipt "$RUN/corpus-release-v1/closed.json" --build-receipt-sha256 "$BUILD_SHA" \
  --rewrite-profile fixed-exec-overlapping-v2 --trusted-complete-code --unit "$UNIT"
```

The builder retains `-O2 -g0 -fno-pie`, `-no-pie`, configure joining and `make -j1` after `BUILT_SOURCES`. READY_BUILT_UNEXECUTED is not execution. All three ET_EXEC headers and hashes rejoin before selection. Every imported jump site must pass the unchanged full N/N gates, arena/permit/search policy and output checks; refusal leaves dependent cases UNOBSERVED. Native cases require exact stdout, exit zero and empty stderr.

Bounds remain fixed: source scratch admission/postcheck 250,000,000 bytes, release reserve 128 MiB, each functional reserve 160 MiB; slot ceilings 19,994,091,520 allocated/19,061,190,371 apparent bytes. These reserves are not live quotas. Source-build/native AS stays 2 GiB; native CPU/wall 20/30s. Parent AS must permit E9's 36 GiB reservation within the 1 GiB physical scope. Scripts retain child limits, durable owner-before-capture checks and stop after incomplete cleanup; no cap expansion or automatic retirement.

Caller completeness/ownership and zero-bias loader obligations remain unproved. This protocol claims no throughput, complete CFG, runtime admission or page exemption.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
