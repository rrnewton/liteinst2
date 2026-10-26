# Exact-commit consumer MSRV and package listing

Both commands passed at source commit `be782c88f9f30581d67aa43aa20aa0a49062cd69`. All 290 tracked source hashes matched before and after, independently matched Git blobs, and the tracked diff was empty. These are compile-check and package-list results only. They are not a native unwind run, a created/inspected package archive, a full dependency-closure proof or a complete paper claim. Elapsed time is operational, not performance evidence.

Use a separate checkout of that exact commit and verify every entry in the linked result's `source-files.json`. Keep this report's request templates outside the source tree or under its ignored directory; adding reporting files must not silently change the tested 290-file snapshot. The existing `evaluation/prepare-msrv.py` illustrates the unchanged MSRV command profile but its fixed 165-file mode does not admit this new source. Do not alter or bypass its source assertions; use the exact declarative request templates supplied here. No new request program or supervisor is introduced.

Create a fresh absolute `${RAW}` directory strictly beneath `${REPO}/ignored`, excluding `${REPO}/ignored` itself, and create `${RAW}/tmp`. Store all materialized request JSONs, receipts, stdout/stderr and helper captures beneath that same ignored root. Substitute placeholders as literal JSON strings: `${REPO}` is the exact checkout; `${MSRV_TOOLCHAIN}` the pinned Rust 1.85.0 installation; `${TOOLCHAIN}` the pinned 1.97.1 installation; `${USER_HOME}` and `${CARGO_HOME}` the independently observed configuration roots. Reject any unresolved placeholder. Preserve the exact argv/environment, four jobs, offline/locked flags, RUSTFLAGS and limits; do not set `CARGO_ENCODED_RUSTFLAGS` or inherit wrappers/LD variables.

Before and after each command, independently authenticate the 290 sources, selected tool bytes/resolutions/full stats and current Cargo-configuration observations. The historical selected byte map is included, while host-specific inode rows remain private. Record a new explicit identity epoch for a new attempt rather than claiming historical inodes are current. Permission-denied exists checks remain exact operation/errno observations, never absence or hidden-content claims. Do not refresh an epoch during a command. The old helper source must equal `c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44`.

Run the two materialized requests serially through the existing helper, retaining its two streams and outer result. For MSRV use this exact wrapper and a finite parent timeout of 115 seconds:

```sh
/usr/bin/timeout --signal=TERM --kill-after=10s 100s /usr/bin/python3.9 -B "${REPO}/tools/unwind-oracle/bounded_command.py" --request "${RAW}/msrv.request.json" --receipt "${RAW}/msrv.receipt.json"
```

For package-list use the same wrapper with `40s`, `package.request.json`, `package.receipt.json` and a finite parent timeout of 55 seconds. Inner bounds remain MSRV 60 CPU/90 wall seconds/128 MiB file limit and package 20/30/16 MiB. The outer timeout supplies a wall backstop only; no cgroup/full-runtime containment is claimed. No extra supervisor, automatic retry or cap increase is permitted by this recipe.

Require integer child exit zero, exact request/helper/output hashes, ECHILD, no unexpected descendants, cleanup events/errors, abort or timeout, and unchanged inputs. The helper stdout must be its exact success-summary JSON, with empty helper stderr. Keep every failed/incomplete attempt immutable.

MSRV must check liteinst2 with all targets and all features using the exact Rust 1.85 request, with a successful final Cargo record and no compiler messages/warnings. The historical stream contains 61 records: 58 artifacts (48 fresh=false compiled, ten fresh=true reused), two build-script records and one terminal success. Reproduction must record its actual cache state; it must not manufacture those freshness values or claim metadata artifacts were archived when they were not. `actual-cargo-records.sanitized.json` is historical diagnostic evidence, not a replacement for the new stream.

Package stdout must equal `expected-package-list.txt` byte-for-byte: 148 unique names, all 26 public unwind-tool files, no BRIEF/private/target entries, and empty stderr. `.cargo_vcs_info.json` and `Cargo.toml.orig` are generated list entries. The command uses `--allow-dirty` as in the old profile, but the independent exact-source gate remains mandatory. This command lists contents; it neither builds a package archive nor executes native tests.

The summary and CSV tables keep the two commands and their distinct case units separate. Hardware is the recorded AMD EPYC Zen 5 host observation with its raw CPU digest and kernel label, not a current observation. New attempts must produce their own identities, hashes and operational times.
