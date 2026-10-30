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
The opt-in original-capture profile
`startup-original-facts-readonly-headerpad-v1` keeps the authored checksum/RLE
assembly, all 187 heads, all 42 selected sites and U2/L1/J2 planning limits. Its
startup-specific linker takes the header padding from a one-byte, readonly
metadata seed object. This works without the newer linker `READONLY` directive.
The existing `layout.ld`, `corpus.py`, disassembly adapters and their pins remain
unchanged. The default `startup-original-facts-rooted-v1` remains the original
twelve-command capture; the opt-in profile has thirteen commands, adding exactly
one shared metadata assembler invocation. Both original link commands record the
new linker and seed object explicitly. No original program or candidate executes
during capture, and there is no fallback to a different source profile.

After committing the reviewed integration, the freeze helper writes a new private
source profile. Its output parent must already exist; retain its printed SHA256
and pass it explicitly to the producer and consumers:

```sh
python3 -B evaluation/adjacent-b2/artifact-verifier/freeze_startup_sources.py \
  --output "$STARTUP_SOURCE_PROFILE"
python3 -B evaluation/adjacent-b2/artifact-verifier/startup_produce.py \
  --output "$STARTUP_CAPTURE" \
  --original-profile startup-original-facts-readonly-headerpad-v1 \
  --source-profile "$STARTUP_SOURCE_PROFILE" \
  --source-profile-sha256 "$STARTUP_SOURCE_SHA256" \
  --toolchain "$STARTUP_TOOLCHAIN" --cargo-home "$STARTUP_CARGO_HOME" \
  --user-home "$STARTUP_USER_HOME" \
  --host-inventory "$STARTUP_HOST_INVENTORY" \
  --host-inventory-sha256 "$STARTUP_HOST_INVENTORY_SHA256" \
  --contract-record "$STARTUP_CONTRACT" --contract-sha256 "$STARTUP_CONTRACT_SHA256" \
  --failure-history "$PRIOR_STARTUP_RUN_CLOSED" \
  --failure-history "$PRIOR_STARTUP_SOURCE_PROFILE"
```

These paths and hashes are explicit owner inputs, not defaults or generated
success claims. Use canonical absolute private paths and a new capture directory.
Keep the earlier refusal, its source profile and every raw command unchanged.
The producer, saved W01 consumer and completed-main reader all derive materials
through the same source-pinned `startup_material.py` entry point, selected from
the authenticated original-capture profile. The new material result has its own
profile label and the actual linker/seed/original hashes. No consumer substitutes
legacy linker bytes or accepts a claimed receipt boolean in their place.

Before accepting the new capture, compare both real linked originals with the
retained old originals: all program headers, readonly note/padding payload,
executable text, writable data/stack, instruction bytes and complete head rows
must remain exact. Bind each head transport to its own actual original hash.
Retain the section/symbol/string metadata differences explicitly; changing the
metadata object may move the section table and update `e_shoff`, so do not claim
whole-file one-bit equivalence. The new `.header_pad` must have exactly ALLOC (2)
flags under its unchanged R-only LOAD. The carrier and independent verifier still
reject WRITE|ALLOC (3) under that owner.

The focused pure controls are included by `check.sh` discovery and can also run
alone. They preserve the old material route, compare the full new/old synthetic
material and wrapper bytes, exercise both programs with near/short branch forms,
and coherently rebind the writable-padding mutant to reach the new strict check:

```sh
python3 -B evaluation/adjacent-b2/artifact-verifier/startup_material_controls.py -v
```

These controls and a successful original link do not establish complete startup
artifacts, W01 package acceptance, native correctness or performance eligibility.
