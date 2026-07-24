# rapid-profiler

This tool profiles a deliberately narrow easy mode: a linked, self-contained
Linux x86-64 ELF image whose functions were compiled by Clang with:

```console
clang -O2 -fpatchable-function-entry=5,0 -falign-functions=4096 ...
```

Clang emits a single five-byte NOP at each function entry. The profiler copies
the linked `.text` into memfd-backed RW and RX aliases, discovers every marked
function symbol, and converts each NOP into a liteinst2 `RapidProbe`. The hot
toggle is therefore one opcode-byte store; the text mapping is never W+X.

## Entry-to-exit sampling

An armed entry callback reads the original return address from the application
stack, pushes a thread-local sample frame, and replaces that return address with
an assembly exit shim. The function body runs normally. `RET` enters the shim,
which preserves `RAX`, `RDX`, `XMM0`, and `XMM1`, finishes the sample, restores
the original return value, and jumps to the real caller address. A LIFO frame
stack handles ordinary nesting, recursion, and tail calls.

Each completed sample increments its function's count up to `K` (1000 by
default). The completion that reaches `K` disables that entry probe. Counts and
all distributions use fixed-size atomic summaries rather than retaining raw
samples. Multiple epochs reset summaries and rearm probes; `--epoch-ms` sets the
minimum interval between epoch starts.

A sample is `LEAF` when no other instrumented function completes during its
dynamic extent. Otherwise it is `non-leaf`, and its summary includes the number
of other completed samples. This makes the intended progression observable:
hot inner functions reach `K` first, then later outer-function samples become
leaf samples after their callees' probes have switched off.

For each leaf/non-leaf class the output reports `n/min/avg/max` for:

- retired instructions;
- retired branches;
- AMD L2 instruction/data request misses;
- elapsed TSC ticks;
- other samples completed during the interval.

It also reports the last sampled low 64-bit return value. Linux generic perf
events provide instructions and branches. The L2 event on the verified AMD family 26 host is named
`l2_cache_req_stat.ic_dc_miss_in_l2` by `perf`, encoded as raw event `0x64`,
umask `0x09`. Unsupported or permission-denied events are printed as
`unavailable`. Multiplexed counters are scaled with their
`time_enabled/time_running` deltas; an event that did not run during an interval
is omitted from that distribution. Counts include the profiler's exit-path
measurement overhead.

## Example

Build the included fixture and run two epochs:

```console
clang -O2 -fpatchable-function-entry=5,0 -falign-functions=4096 \
  -fno-pie -no-pie -fno-asynchronous-unwind-tables -nostdlib \
  -Wl,-e,workload -Wl,--build-id=none -Wl,-z,noexecstack \
  fixtures/simple.c -o /tmp/rapid-profiler-simple
cargo run --release -- /tmp/rapid-profiler-simple \
  --iterations 2500 --epochs 2 --epoch-ms 10
```

The fixture calls each leaf twice per `branch` invocation. Both leaf probes
therefore reach 1000 completions after 500 branch calls. The expected branch
classification is 500 non-leaf samples followed by 500 leaf samples.

## XRay exploration

Clang `-fxray-instrument -fxray-instruction-threshold=1` emits an 11-byte entry
sled (`jmp +9` over a NOP) and records it in `xray_instr_map`. Normal returns are
emitted as `RET` followed by a nine-byte NOP sled, also described by the map;
tail-call exits get a separate jump-over-NOP sled. These explicit exit sites
could support a later XRay-native backend and cover multiple return statements.
They do not directly fit liteinst2's current one-byte rapid plan: the inactive
`RET`/jump bytes imply fixed trampoline destinations, and XRay normally patches
whole sleds using its own runtime protocol. Phase 2 therefore uses one entry
probe plus return-address hijacking instead of mutating every XRay exit sled.

## Phase 2 limits

The input must have relocation-free, self-contained `.text`; the named workload
and fixture functions use the System V `extern "C" fn(u64) -> u64` contract. It
is not a general ELF loader or external-process profiler. The return shim
preserves integer/pointer and up-to-128-bit SSE return channels, but not x87 or
AVX-width returns. Exceptions, stack unwinding, `setjmp`/`longjmp`, CET shadow
stacks, and workloads that leave instrumented calls running on other threads
are unsupported because they can bypass or outlive the hijacked return slot.

GCC's five separate one-byte entry NOPs are rejected because the current
liteinst2 trampoline requires one displaced instruction of at least five bytes.
Functions must be spaced so their implied rapid-trampoline pages do not collide;
`-falign-functions=4096` provides that property for the fixture. The known rapid
install weakness still validates only opcode byte zero; this loader owns the
complete copied code image and exposes no competing tail-byte writer.
