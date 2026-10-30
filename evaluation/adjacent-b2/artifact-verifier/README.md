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
wrappers and other settings. Build schema 3 additionally admits ordinary TOML
line comments, including after values; schema 2 retains its stricter grammar.
Quoted `#` characters remain part of the value. Build outputs and command logs belong under
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

The additive startup profile accepts `--startup TRANSPORT SHA256` at the Rust
verifier and `--startup-binding` at the saved-artifact consumer. It independently
checks the same complete 187/42 corpus, the embedded catalog, actual startup ELF
layout and dependency bytes. Generalized puns and both images of short-neighbor
plans are checked against original instruction ownership and current overlays.
The startup result reports main joins only; package admission and execution are
separate.

For a fresh startup capture, freeze a private `LI2STARTUP-SOURCE-PROFILE-1` after
committing the reviewed sources. Supply its SHA explicitly to `startup_produce.py`,
which captures original facts, builds the release producer, and dispatches one
paired whole-program attempt. `startup_verifier_build.py` makes the separate
release verifier build; `verify_saved.py` consumes those saved outputs without
rerunning the producer. Each script's `--help` lists its concrete inputs. Preserve
prior failed receipts and use a new output directory for each declared attempt.

`startup_bootstrap.py` consumes completed main joins and builds one constructor
DSO per actual catalog. It preserves each DSO before the common target output is
replaced by the next build. The linked-file checker requires actual constructor
relocations, disjoint page ownership, immutable catalog storage and writable
completion storage after RELRO. Its output remains pending final package review.
The control script covers these additive Python helpers and the package resolver;
no control executes a candidate ELF.
