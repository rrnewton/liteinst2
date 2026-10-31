# Native unwinding through a compiled indexed DSO

The closed C fixture now executes its rewritten work through an ordinary
compiled caller and unwinds through the generated frame using the system GNU
consumer. The witness checks the exact instruction pointers, CFAs, six preserved
registers, return-stack samples, return-slot/context bytes and function outputs.
Expected frames come from the authenticated code and CFI, independently of the
observed trace. This supports claim 4 for this synchronous fixture; general DSO
rewriting, exceptions, LSDA and asynchronous unwinding remain open.

The implementation is committed as
`a306d916315a9bb9acc112fe306e1371d929ea1a`, including main
`f353e4e5e5c1b2f404d10ea3faa5f3711ac69522`. The native campaign ran on the
exact source overlay before that commit; its executable inputs are byte-identical
to the committed files. The receipt distinguishes that history from subsequent
checks at the exact commit.

The second prospectively fixed campaign ran each mode once:

| Mode | C calls | Exact frame comparisons | FDE lookups | Result |
| --- | ---: | ---: | ---: | --- |
| Original | 4 | 8 | 38 | Pass |
| Intact rewrite | 4 | 16 | 44 | Pass |
| Original-index-only negative | 0 | 0 | 44 | Pass: generated lookups absent |

Each positive mode makes two reference and two work calls. Original work does
not invoke the trace hook. The negative restores the original
`PT_GNU_EH_FRAME` program-header row, making generated FDEs undiscoverable
without changing code, CFI or index bytes. It performs no rewritten call.
Every original subject/caller FDE boundary and
the generated points are checked. The consumer identity is revalidated 11 times
per positive mode and twice for the negative. All three processes and their
owners closed normally, without timeout or rescued descendants. The single
reserved CPU was 1; the load average was 40.86/57.55/68.85. These are debug
correctness results on an AMD EPYC Zen 5 dev host, not performance measurements.

The first fixed campaign remains failed: intact passed four calls, sixteen
frame comparisons and 44 lookups; original and negative refused stack admission
before loading a DSO. Their old diagnostic does not identify the failed stack
predicate. Five separate fixed diagnostic processes then all exposed the same
invalid assumption: glibc's main-thread allocation excludes 4–8 KiB of upper
argument/environment pages still present in the stack VMA. Those processes had
258,080–261,520 bytes of usable reserve against 137,664 required.

The repair uses the intersection for call-stack access and reserve accounting.
It retains both raw extent identities and excludes external objects from both
ranges. The 128 KiB + actual xstate + 4 KiB reserve, fixed pre-touch and all ABI
and frame comparisons are unchanged. All seven prior runtime controls remain;
three additional controls cover legitimate upper pages, clipped reserve,
out-of-range samples, raw identity drift and object aliases. The focused suite
passes 87 tests with no failures or ignores, and targeted strict Clippy passes.

`results.csv` retains every native cell from both development campaigns and
the subsequent exact-revision reproduction;
`stack-diagnostics.csv` retains all five diagnostic outcomes. Raw output,
addresses, manifests and source-review captures stay under ignored directories.
The qualification relies on the reviewed fixture and GNU compiler, CRT, loader,
libc and libgcc contracts; hashes bind those inputs but do not prove their
semantics. No larger platform or timing claim follows from these results.

The published reproduction also passed one complete attempt at the exact
revision above: all 13 C build stages, an offline Rust build, actual compiled
inspection and all three native modes. Its fresh subject/caller hashes differ
from the development build because build paths appear in debug information;
each product is checked against its own manifest. It reproduced the table's
8 calls, 24 frame comparisons and 126 lookups. All owners closed normally with
zero rescues, and the external CPU lease was released. CPU 1 was reserved;
load was 56.86/55.40/57.81 before and 57.37/55.56/57.83 after the run.

The same revision passed formatting, strict workspace/all-target/all-feature
Clippy, all-target/all-feature check, the full parallel workspace test and
separate serial launch. Workspace: **4,218 passed, 0 failed, 37 unchanged
ignored**; serial launch: **1,039 passed, 0 failed**. The raw 4,221 workspace
total includes three controlled-child summaries; their enclosing tests count
once. The 58 new tests are additive. All previously flaky RapidProbe,
observing-control, prefixed-pun and 21 short-neighbor cases passed. Sixteen CPUs
were reserved while retaining 316 harness threads, except the explicit serial
command. Original limits were unchanged. These correctness durations and exact
commands are retained in `receipt.json`.

To reproduce, use a clean Linux x86-64 checkout of `a306d916` and keep this
directory's [adapter](reproduce.py) and the published
[native recipe](../../../tools/unwind-oracle/indexed_dso/native_recipe.py)
outside the checkout or under its ignored directory. They were published after
the source commit and are byte-identical to the scripts actually executed.
The checkout must have its locked Cargo dependencies cached; there is no
network fetch or retry. The sole untracked exception is the coordinator's
`BRIEF-li2core.md`, which must remain absent from Git.

Copy `profile-template.json` privately and fill its explicit input pins:

- Use the supplied 79-file C inventory with the predecessor's
  [toolchain configuration](../indexed-5f5caa0/toolchain.json). It describes the
  recorded GNU host, not every distribution. Different tools require their own
  reviewed profile. The builder checks all emitted dependency and linker inputs.
- Supply canonical paths, byte lengths and SHA-256 hashes for Cargo, rustc,
  rustdoc, Python 3.9, timeout and Git; put these and the external execution
  dependencies in `execution_tools`. Rust tools share one directory. Set the
  private Cargo cache path and the actual recipe/toolchain pins. `receipt.json`
  records the executed tool identities without private installation paths.
- Supply current source/runtime premise documents covering this revision and
  the fixed fresh-build/compiler/CRT/loader/consumer contracts described above.
  Pin historical supporting reviews separately. A hash is provenance; the
  script does not create semantic approval.
- Set the actual external allocator ledger and tag. One CPU remains reserved
  through build, inspection and all native cells. The recipe checks the live
  ancestor PID/start time, ledger CPU and matching cgroup CPU; it has no bypass.

With those explicit local paths and the completed profile hash:

```sh
cpuset-alloc run --cores 1 --tag "$TAG" -- \
  "$PYTHON" -B "$ADAPTER" --recipe "$RECIPE" \
  --out ignored/indexed-native-reproduction --toolchain "$TOOLCHAIN" \
  --profile "$PROFILE" --profile-sha256 "$PROFILE_SHA256"
```

Every output path must be fresh. The aggregate owner has a 1,200-second bound
and 8 MiB log cap; C/native children retain 60 CPU seconds, 90 wall seconds and
128 MiB per output file. The Rust build retains its 180-second timeout and
three-second kill grace. Unknown custody stops continuation; normal failures
and untouched cells remain explicit. The caller checks lease release after
return. Keep complete raw manifests, logs and profiles ignored, and publish
only the compact result projection. `PASS_FINITE_CHECKS` still requires the
stated semantic premises and is not general native-unwind qualification.
