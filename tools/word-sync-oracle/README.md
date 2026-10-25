# Synchronized Word publication witnesses

These standalone Linux x86-64 fixtures test the bounded synchronized Word API.
They are separate from Cargo's ordinary integration-test discovery: each native
mode must start on a fresh process main thread. They require the host facilities
they test; unavailable sync-core, ptrace, signal, or cache geometry fails the
required case. There is no capability skip or substitute smoke subset.

The baseline has four modes. Its positive mode requires 35 install/revert cycles,
263 calls, 68 owned guard deliveries, three signal returns and ten prewrite
refusals. Its three barrier-denial modes require terminal retained ownership and
zero poisoned-source execution. The strict fixture retains all thirteen modes,
838 ordered case IDs, twenty-six pure calibrations and the exact name listing.
The separate output-auditor calibration retains three accepted and twelve
rejected vectors. These inventories are separate; they are not added together
as a new architectural denominator.

`bounded_command.py` is the existing owned-descendant helper, copied unchanged.
The adapter launches it with the existing timeout backstop; it adds no process
supervisor. This helper is not a sandbox and does not establish cgroup memory or
PID limits. SIGKILL of the helper cannot run its cleanup. A missing helper
receipt provides no cleanup proof. Failure never advances to another case or
reuses an output directory.

## Build and run phases

All evidence goes into a fresh directory below the repository's `ignored/`.
Keep one build lane and the repository's shared `target/`; do not build or
modify admitted source/tool files concurrently. Before any Cargo build, archive
older evidence that refers to files under that target. This adapter freezes
current sources and archives the freshly selected Cargo artifacts; it does not
silently repair historical manifests after their files have been overwritten.

Supply a local toolchain JSON with exactly two fields:

* `tools`: absolute paths keyed by `cargo`, `rustc`, `gcc`, `linker`, `assembler`,
  `helper_python`, and `timeout`. Use actual toolchain Cargo/rustc binaries, not
  rustup shims. `linker` is the qualified BFD linker.
* `files`: the exact reviewed toolchain/linker input path inventory. Include the
  resolved tools, Rust sysroot libraries, GCC support programs/runtime/CRT files
  and loader libraries used by that toolchain. This adapter binds every listed
  identity before/after commands; the list itself must be reviewed for coverage.

Do not publish that local JSON, binaries or raw host receipts as source. The
tool identities and generated requests are outputs of the current attempt,
not hard-coded developer-machine pins in this tool.

From the repository root, the sequence is:

```text
python3 -B tools/word-sync-oracle/adapter.py freeze --output ignored/WORD-ATTEMPT --toolchain LOCAL-TOOLCHAIN.json
python3 -B tools/word-sync-oracle/adapter.py build --output ignored/WORD-ATTEMPT --freeze-sha256 PRINTED-FREEZE-SHA
```

Review the frozen source/tool identity before the build. `build` performs one
offline/locked Cargo library build with four jobs and incremental compilation
disabled. It selects the actual root `liteinst2` and dependency records from
Cargo JSON, requires the current fixed nine-library graph and default features,
and preserves all records/features. Cargo configuration files (including absent
ones), explicit Cargo home and disabled compiler wrappers are frozen as well.
A permission-denied `exists` observation is a separate record containing the
exact operation and errno (EPERM or EACCES); it is never recorded as absent or
as known file bytes. The same observation must hold again before the freeze
manifest is written and before/after every build and runtime command. A change
to readable, absent, or a different errno fails admission. Other I/O errors
propagate. Readable configuration still requires its exact identity, copied
bytes and all existing checks. This records stable inability to inspect a
configuration path; it does not certify inaccessible contents or prove that
Cargo could not read them through another authority. Exact Cargo invocation,
reported features/artifacts and dependency ownership remain separate evidence.
Each full Cargo package ID must match the name, version and registry source in
the frozen Cargo.lock root dependency closure. Duplicate package names,
ambiguous dependency spellings and unsupported lockfile syntax fail binding.
This initial adapter accepts the current unambiguous Cargo-v4 lockfile subset;
it does not provide a general TOML parser or admit another registry implicitly.
It archives rlib/rmeta files with their
original basenames, Cargo depfiles and the referenced dependency source bytes.
Each record must name its package's canonical Cargo.toml and src/lib.rs; registry
owners must be beneath the frozen Cargo home and have the exact locked package
name/version. The depfile must name exactly the associated .d, hashed .rlib and
.rmeta targets, with identical prerequisite lists, the actual crate root and
exact source phony rules. Every source must belong to that package owner; root
sources must also match the frozen repository hashes. Cargo's un-hashed root
rlib must equal the associated hashed rlib byte for byte. Package manifest
identities, complete lock records, source identities and artifact associations
are retained for the build review. These checks bind Cargo's reported ownership;
they do not independently reconstruct a downloaded registry archive checksum.
It then compiles the unchanged baseline once and strict fixture twice (ordinary
and `--test`) with warnings denied, one codegen unit, explicit debug/overflow
settings, and fresh output paths. The rustc depfiles must name the exact expected
source set. Unexpected Make syntax fails binding rather than being partially
parsed. Workspaces with paths requiring Make escaping are not admitted by this
initial adapter.

Cargo keeps CPU60/wall90/file128MiB; each fixture compiler keeps
CPU60/wall90/file128MiB. The copy/binding work is finite over frozen file
inventories. Run the outer phase under the existing helper as well when the
coordinator requires an outer command bound; do not invent a different
supervisor. Compiler success does not authorize executing the resulting binary.
Review `build/build-audit.json`, actual Cargo records, complete files,
`binary-binding.json`, depfiles and the actual tool/receipt identities first.

After that review:

```text
python3 -B tools/word-sync-oracle/adapter.py runtime --output ignored/WORD-ATTEMPT --freeze-sha256 PRINTED-FREEZE-SHA --review ACTUAL-BUILD-REVIEW --review-sha256 REVIEW-SHA
```

This creates twenty requests but executes none: four baseline commands, fifteen
strict fixture commands (listing, full calibrations, thirteen native modes),
and one pure auditor command. Review the generated manifest and every actual
binary/request identity before invoking the final entry point:

```text
python3 -B ignored/WORD-ATTEMPT/runtime/entry.py run PRINTED-SOURCE-SHA --manifest-sha256 PRINTED-RUNTIME-SHA
```

All twenty commands keep CPU20/wall30/file1MiB. All native state comparisons,
fifteen-second/20,000-step trace bounds, two-second rendezvous/cleanup limits,
exact stdout/stderr, panic annotations, case order, ECHILD and zero-descendant
receipt requirements remain. The final tree is admitted only when all required
commands complete; partial results remain incomplete. The copied strict
auditor has only an additive exact-output branch for the four baseline modes
and the corresponding complete-order extension. Its old comparisons are intact.

The runtime entry loads authenticated local Python source bytes with explicit
module names and `optimize=0`. It does not execute a cache selected by an import
loader. There is no helper-package import from a different build directory.

## Evidence limits

This tool is not a whole-library validation replacement. Run the eight model
tests, ordinary publisher/router regression suites, old/new ordinary planner
parity, advertised Rust baseline, full workspace gates and package/source
privacy checks separately against the active source identity. Do not borrow
private or previous-build results as active success.

The finite host evidence does not qualify all in-flight instructions, every
saved midpoint, all-thread signal mask/router admission, callback drain,
reclamation, active CET, cross-vendor CPUs or full A4. Late strict guard delivery
occurs after completed writer synchronization. Held-frame publication uses the
closed handwritten fixture; its COW RWX mappings are not a general W^X policy.
The baseline's dual aliases and the strict fixture's mapping policy remain
distinct. Post-mutation barrier failure retains ownership; final redirects may
already be reachable. No rollback, retry or safe reentry is inferred.

Compiler inputs are pinned, but this adapter does not record a per-binary linker
trace or certify arbitrary runtime-loader admission. The toolchain input list
must be audited separately. File identity and source equivalence are not an
architectural comparator and do not expand its masks or permitted outcomes.
