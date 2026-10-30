# Offline router native validation

This opt-in native path has an explicit unsafe caller boundary. The safe Rust
`admit` and legacy N01 `run` entry points still refuse unknown authority. The
pinned `native_launch.py` first reconstructs the independent final package and
accepts the exact externally pinned platform contract through
`final_admission.open_session`. Receipt booleans and startup completion never
substitute for that checker. The complete native source inventory and actual
observer build are frozen in a separate final profile; the earlier artifact
source profile is not rewritten.

The root-owned build sequence is concrete and acyclic:

1. Integrate/review the native sources, including the separate final-platform
   proposal and unchanged package resolver v2. Commit them. Freeze a private
   `LI2NATIVE-OBSERVER-BUILD-PLAN-1` with exact keys `schema`, `root`,
   `native_sources`, `artifact_source_profile`, `capture`, `output`, `destination`.
   `native_sources` is the complete committed native source map; the artifact
   profile is a `{path,sha256}` reference and capture a `{directory,sha256}`
   reference to the accepted original-facts closure for the selected profile. Both output and
   destination are new private paths. Destination is outside the new output
   directory, with an already existing owned parent.
2. Invoke `python3 -B evaluation/offline-router-native/native_launch.py
   build-observer --root ROOT --build-plan PLAN --build-plan-sha256 SHA`.
   This authenticates original facts/configuration and performs exactly one
   release/locked/offline standalone observer build, from `/`, using the existing
   single target and lock. Limits remain 120 CPU/180 wall seconds, 128 MiB files,
   190-second timeout, 205-second parent and 10-second cleanup. The actual compiler
   artifact is copied to an owned mode0500 inode with before/after identity and
   complete byte equality. Failure stays failure; there is no retry.
3. Freeze `LI2STARTUP-FINAL-PROFILE-1` after the actual build and final whole-facts
   review. Its observer field is exactly `{binary: FILE_PIN,
   build: {directory: BUILD_OUTPUT, sha256: CLOSED_SHA}}`. The independent launch
   reader reconstructs every raw build request/command/helper/Cargo/copy join.
   It does not promote a BUILT label. The native revision and source map must
   remain exact; the immutable observer copy can survive later target reuse.
4. Invoke the same launcher with `observe` or `n01`, plus `--root ROOT`,
   `--final-profile PROFILE`, `--final-profile-sha256 SHA`,
   `--accept-contract-sha256 CONTRACT_SHA`, and a new `--output DIRECTORY`.
   Those are separate populations, with no automatic retries or performance
   qualification. The final platform contract's acceptance is explicit and
   unsafe; no ordinary receipt supplies that acceptance for the caller.

The observer population has exactly one pre-entry control per full program.
Its bounded helper invokes the checked `observer-child` wrapper, which reopens
final admission, binds the exact owned candidate copy and dataset, reconstructs
all Request bytes, verifies the observer build, then creates a sealed memfd and
execs the pinned observer with an empty environment. Parent custody survives
through helper cleanup and is checked before and after each child. All four
WRITE/GROW/SHRINK/SEAL seals, the owned anonymous regular FD, exact bounded schema
and whole SHA256 are checked by Rust. They prove immutable transport, not caller
authentication or platform safety. The CLI's call to
`unsafe admit_from_checked_launcher` documents that trust boundary explicitly.

The observer retains the original absolute 15-second deadline before file
allocation/fork and separate five-second cleanup bound. It enforces controlled
signals, owned initial SIGSTOP, exact TRACEEXEC, actual AT_SECURE=0 and disabled
kernel SHSTK at both stops, arms DR0 at unchanged AT_ENTRY before the first loader
continuation, and checks the exact owned hardware event, entry bytes, argc/argv,
mapping/page identities and completion=1. The complete original immutable page
image is checked at both stops: the committed runtime only registers already
rewritten kernel-loaded images, so no changed-page exemption is needed. Xstate
is read into the full16384-byte buffer, then its actual returned size must equal
the reviewed576..16384-byte length. Raw GPR/xstate, siginfo, auxv, maps and status
are retained without normalization. Only typed DR0/DR6/DR7 writes exist; no memory,
RIP or general-register repair is added. The receipt retains primary refusal,
restoration and cleanup outcomes independently. Original entry is never
continued; the observer kills/reaps its child and requires ECHILD. A successful
pre-entry stop proves no route coverage or native semantics.

The N01 population preserves both programs, all ten fixed datasets per program,
twenty pairs and forty ordinary original/candidate invocations. Each executes
once under the unchanged20 CPU/30 wall-second,16 MiB-stream bounded helper,
40-second timeout,55-second parent and10-second cleanup limits. One cumulative
64 MiB output reader per program retains all complete streams and raw closures.
Every result requires independent expected-byte equality, empty stderr and
exit0; candidates additionally require an independently successful original and
exact complete output equality. The final checker authorizes each distinct owned
mode0700 candidate copy before dispatch. Environment is exactly empty and
inherited signal state is controlled. All40 rows remain, including FAILED and
UNRUN rows. No ptrace, producer, build or performance loop runs in N01. Route
coverage, overall qualification and performance eligibility remain false.

Run these source controls separately from native qualification:

    python3 -B evaluation/offline-router-native/package_controls.py
    python3 -B evaluation/offline-router-native/final_controls.py
    python3 -B evaluation/offline-router-native/n01_controls.py
    python3 -B evaluation/offline-router-native/native_launch_controls.py
    cargo test --locked --offline --release --manifest-path evaluation/offline-router-native/observer/Cargo.toml --lib
    cargo clippy --locked --offline --manifest-path evaluation/offline-router-native/observer/Cargo.toml --all-targets -- -D warnings

Use the existing target and pinned Cargo configuration. The original12 Rust and12 N01 Python controls are unchanged;
new boundary controls are additive. A causal delivered-SIGILL/rt_sigreturn/route
tracer remains separate work and is not implied by this executable path.

Final Session stability and all owned cleanup run before either population writes
its terminal result. A close failure keeps every row and prevents completion.
