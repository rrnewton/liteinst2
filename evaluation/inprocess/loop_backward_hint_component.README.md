# Backward-refusal hint component

The retained run passed the original actual-loader hint oracle first:
26 controlled hits, 87 misses and two storage checks. The additive oracle then
passed 24 refusal classifications, six controlled hits and 16 invalidations.
Both use the real loader translation unit and hint helpers. Controlled insertion
does not establish actual owner cancellation/remember behavior or a runtime
cache hit. No guest subject or performance comparison ran.

The observation used CPU35 at HEAD
`4f3e28e7e1d434bc6d51c95bab828557a6d37442` with eight modified tracked files.
The result records that dirty status. Among the 142 repository files actually
authenticated by this component, only the runtime header and controller differed
from that HEAD; both exact hashes are in the result. All 142 bytes/hashes match
the later clean commit `567a27bfdb0a43b49b12ffdb5284d435d724aff9`.
That commit supplies a fresh reproduction; it does not change the historical
observation into a clean-revision run. Compiler paths, process IDs and generated
ELF debug paths can differ in a fresh run.

The driver below is byte-identical to the executed private driver
(`597bad8112ef9abb004b42029206d7aaed525fb57efcb19cf1c8f8dd21b9abb7`).
It uses the existing bounded process owner, the complete 47-macro LOOP profile,
compiler-M before/after, actual input hashes, unchanged HEAD/status and exact
stdout comparisons. It keeps the original nine-command schedule and all child
limits: metadata 10 CPU/20 wall seconds, build 30/60, component 5/15; 512 MiB
address space; 16 MiB metadata/component file limits, 64 MiB build file limit;
8 MiB captures. The driver also sets 180 CPU seconds and the command below adds
the recorded 180-second outer wall limit with a five-second termination grace.

Prerequisites are Linux x86-64, Python 3.12, the system C compiler, Git, GNU
timeout, and a configured `cpuset-alloc`. Start in a clean clone containing this
driver and the two tracked fixture files. Stage them before checking out the
source commit, because the result and driver are published later. The fixed
staging directory must be fresh. No old private receipt or output is needed.

```sh
mkdir -p target/reproduce-loop-backward-hint/files/tools/page-entry/selected/tests/loop_backward_hint
cp evaluation/inprocess/loop_backward_hint_component.py target/reproduce-loop-backward-hint/run.py
cp tools/page-entry/selected/tests/loop_backward_hint/oracle.c target/reproduce-loop-backward-hint/files/tools/page-entry/selected/tests/loop_backward_hint/oracle.c
cp tools/page-entry/selected/tests/loop_backward_hint/build.sh target/reproduce-loop-backward-hint/files/tools/page-entry/selected/tests/loop_backward_hint/build.sh
git checkout 567a27bfdb0a43b49b12ffdb5284d435d724aff9
timeout --signal=TERM --kill-after=5 180 env AGENT_UTILS_ENGINE=python cpuset-alloc run --cores 1 --tag loop-backward-hint-component -- python3.12 -B target/reproduce-loop-backward-hint/run.py --expect-revision 567a27bfdb0a43b49b12ffdb5284d435d724aff9 --output target/evaluation/inprocess/loop-backward-hint-fresh
```

Use a new output directory for each run. The allocator selects a disjoint CPU;
the driver requires and records singleton affinity. A successful receipt has
`status=component_passed`, all nine commands closed, and these exact two lines:

```text
loop_negative_hint hits=26 misses=87 storage=2 entries=8 owner_entries=0
loop_backward_hint classifications=24 lookup_hits=6 lookup_misses=16 entries=8 owner_entries=0
```

The private observed receipt is 88,212 bytes,
SHA256 `bf26a914ebb184b2ca2fb181863416f468691b4180ca60f40264b2fe72cf2b7f`.
The outer receipt is 1,312 bytes,
SHA256 `240d5df88c616a7ba72719b83775d51c84b31be2aa2e45c97dd67199621e7039`.
The public result retains command durations as validation-only observations,
original bounds, kernel identity hashes and CPU35. The component runner did not
record the CPU model; no model or microcode is inferred from another run.
All native, owner, lifecycle, original392/522 qualification and release
performance requirements remain outstanding independently of this component.
