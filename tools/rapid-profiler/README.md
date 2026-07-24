# rapid-profiler Phase 1

This tool profiles a deliberately narrow easy mode: a linked, self-contained
Linux x86-64 ELF image whose functions were compiled by Clang with:

```console
clang -O2 -fpatchable-function-entry=5,0 -falign-functions=4096 ...
```

Clang emits a single five-byte NOP at each function entry. The profiler copies
the linked `.text` into memfd-backed RW and RX aliases, discovers every marked
function symbol, and converts each NOP into a liteinst2 `RapidProbe`. The hot
toggle is therefore one opcode-byte store; the text mapping is never W+X.

Each callback atomically increments its function's count up to `K` (1000 by
default). The callback that reaches `K` disables that function's probe, so later
calls do not intentionally enter the instrumentation trampoline. Counts never
exceed `K`. Multiple epochs reset all counters and rearm every probe; `--epoch-ms`
sets the minimum interval between epoch starts.

Build the included fixture and run two epochs:

```console
clang -O2 -fpatchable-function-entry=5,0 -falign-functions=4096 \
  -fno-pie -no-pie -fno-asynchronous-unwind-tables -nostdlib \
  -Wl,-e,workload -Wl,--build-id=none -Wl,-z,noexecstack \
  fixtures/simple.c -o /tmp/rapid-profiler-simple
cargo run --release -- /tmp/rapid-profiler-simple \
  --iterations 2500 --epochs 2 --epoch-ms 10
```

Phase 1 accepts only relocation-free `.text` and invokes one named workload as
`extern "C" fn(u64) -> u64`. It is not a general ELF loader or an external
process profiler. GCC's five separate one-byte entry NOPs are rejected because
the current liteinst2 trampoline requires one displaced instruction of at least
five bytes. Functions must be spaced so their implied rapid-trampoline pages do
not collide; `-falign-functions=4096` provides that property for the fixture.
