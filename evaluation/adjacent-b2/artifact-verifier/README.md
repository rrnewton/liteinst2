This standalone validation crate checks saved, complete checksum and RLE producer
artifacts without rerunning the producer or executing a candidate. It checks the
full 187 original instruction heads and 42 selected sites, metadata, source edits,
image ownership, declared fixups, generated instruction boundaries, and the whole
candidate ELF. Its synthetic controls are separate from corpus results.

Run `./evaluation/adjacent-b2/artifact-verifier/check.sh` from the repository root
with Rust 1.97.1 and Python 3.9 or later. The script uses the existing Cargo cache
offline and the repository's target directory. This binary crate has a separate
checked-in lockfile; the producer's workspace lock is unchanged. On a shared
host, run it inside a four-CPU `cpuset-alloc` reservation.

`rooted_build.py` builds the release verifier from an authenticated D01 capture.
It invokes the exact captured Cargo/compiler binaries with an absolute manifest
and Cargo working directory `/`. It records and rechecks the actual root and
Cargo-home configuration scope, admitting only absent configuration and the
explicit `net.git-fetch-with-cli` / `http.proxy` subset. It refuses includes,
wrappers and other settings. Build outputs and command logs belong under
`ignored/`; the build receipt binds sources, lockfile, launcher and binary.

`verify_saved.py --help` describes the immutable capture, diagnostic and build
receipts it consumes. It dispatches only the verifier, once per complete program.
It preserves prior failures and requires complete capture configuration and file
custody before reporting W01. A separately complete verifier build does not
promote an earlier configuration-incomplete producer capture.

Structural acceptance does not establish full instruction semantics, exhaustive
fixup discovery, loader/runtime admission or native correctness. The output
retains every image's unresolved runtime requirement and alternate-entry route.
N01, qualification, corpus success and performance eligibility remain separate.
