# Reproduce the compiled DSO build and structural inspection

This recipe builds the annotated C subject and ordinary C caller, then runs the
existing ELF/CFG/CFI inspector. It does **not** load a DSO, execute rewritten
code, qualify caller CFI or establish native unwinding. The reproduction adapter passed one complete attempt at the exact revision
below. The compact `receipt.json` retains that result and every earlier attempt.

Use a clean Linux x86-64 checkout of
`5f5caa0af44ee8a56e99b2351cac8ed27bd8e3d7`. Keep this recipe and your source-review
record outside that checkout, or under its ignored directory. The script refuses
tracked changes and nonignored untracked files. Provide an existing writable
Cargo cache with the locked dependencies already available and the Rust toolchain
used for the campaign; the inspector uses `--offline --locked` and four build
jobs. Set `RUST_TOOLCHAIN_BIN` to that toolchain's absolute `bin` directory and
`CARGO_HOME` explicitly. The adapter records the actual Cargo/rustc/rustdoc file
hashes; it does not infer their identity from a selector.

The supplied `toolchain.json` is the exact 79-file GNU input inventory used by
the recorded C build, SHA-256
`2c2c941e57d73821ae3f8022b0316c86890eb6d4a9c11de983017a199b9bcb73`.
Its `/usr` paths describe that host's layout, not every Linux distribution.
Another host needs a separately reviewed, exact inventory of its compiler,
subtools, CRTs, headers, linker inputs and shared libgcc. The builder captures
each actual file hash and requires every emitted dependency, verbose subprocess,
plugin/spec input and link-map input to join that inventory. Do not broaden it
after a failed attempt and call the original attempt successful.

`--source-review` names a caller-reviewed local document or summary receipt.
The adapter binds its hash and the eight committed build inputs into the existing
source-admission schema. This is provenance only: neither that JSON nor a review
document grants source/CFI/hook/loader semantic authority.

From the checkout root, reserve four disjoint CPUs using the local reservation
tool, then run this one attempt (replace the three recipe/input paths):

```sh
cpuset-alloc run --cores 4 --tag indexed-dso-reproduction -- \
  /usr/bin/python3.9 -B /path/to/reproduce.py \
  --out ignored/indexed-dso-reproduction \
  --toolchain /path/to/toolchain.json \
  --source-review /path/to/review-record.json
```

The caller owns the reservation; recorded affinity is not a separate lease-ledger
proof. Every output path must be fresh. The adapter calls the unchanged process
owner for two fixed actions, each with its original 1,200-second/8-MiB outer bound.
The C builder retains all 13 fixed inner stages and their 60 CPU-second,
90-second wall and 128-MiB file limits, plus the separate 16-MiB reader cap.
The inspector retains its 180-second timeout and three-second kill grace:

```text
/usr/bin/timeout --signal=TERM --kill-after=3s 180s cargo run --offline --locked -p liteinst-rewrite --example indexed_dso_inspect -- SUBJECT SUBJECT_SHA256 CALLER CALLER_SHA256
```

Closed owner results are saved before output reads; unknown custody stops the
sequence. A failed build leaves inspection unrun. All first failures, unresolved
dispatches and untouched actions remain in the private reproduction record;
there is no retry. Keep the raw files under `ignored/`. An incomplete record or
an individual command's successful exit is not final structural success.

The recorded build/inspection ran on the reviewed source overlay at `5b985091`,
subsequently committed and included in the checkout above. This recipe is a new
reproduction, not a claim those historical commands ran after the commit. The
historical first invocation refused a mistyped toolchain hash before any of the
13 stages; the next build completed but inspection refused nonzero ELF entries.
The retained zero-entry linker correction satisfied the unchanged inspector.

On an AMD EPYC Zen 5 dev host (AMD EPYC 9D85 158-Core Processor), the
recorded GNU tools produced a structural report with 17 work heads,
selected/continuation coordinates 4467/4472, 12 subject and 7 caller original
FDEs, work CALL/return coordinates 5767/5770 and reference CALL/return coordinates
6616/6619. These are ELF coordinates. Compare the actual structural report and
its source/tool provenance; altered build/output paths change debug bytes, so
historical whole-ELF hashes are not a portable equality oracle. The script uses
fresh whole-file hashes for both actual inspector inputs. Every result retains
`caller_cfi_qualified=false` and `native_qualification=false`.

The same merged revision passed fmt, strict workspace Clippy, all-target/all-feature
check, the required parallel workspace run and separate serial launch. The workspace
had **4,160 passed / 0 failed / 37 unchanged ignored**; serial launch had
**1,039 passed / 0 failed**. The raw workspace summaries include three nested
controlled-child passes; the reported 4,160 counts the enclosing tests once.
These debug correctness durations are not performance measurements. The full gate
uses the unchanged `evaluation/short-neighbor-parallel/validate.py` with the exact
revision above, a fresh ignored output directory, 16 reserved CPUs, and
`RUST_TEST_THREADS=316` (the explicit serial command excepted). Its five command
limits remain 180/180/180/900/180 seconds, with 8 MiB output and three-second cleanup.
Raw captures and complete manifests stay in ignored directories.
