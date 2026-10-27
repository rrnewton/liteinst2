# Native interval ownership bridge

The bridge retains the loaded installation and original entry receipt across epoch changes. Eighteen new metadata tests cover mixed sampled/unsampled nesting, old-owner returns, journal bounds and failure retention. The native interval modes and rendezvous remain unimplemented.

At `c66ea0607e38db67dd5b7cfbc7ab7f0ac7f7afdd`: **2,293 workspace tests passed, four unchanged ignores**; all 2,279 previous case identities/statuses were retained. Formatting, strict Clippy, workspace check, serial launch and all three parallel regression targets passed. `checks.csv` contains overlapping command observations; `receipt.json` records the revision, hardware, exact commands, profile and raw-log hashes. Durations are operational validation times, not performance measurements. Raw logs remain ignored.

To repeat, copy this recipe directory outside the tracked tree, then check out the exact revision above. For each phase in `targeted-profiler required serial parallel-library parallel-prefixed parallel-neighbor`, run:

```sh
python3.9 /path/to/copied-recipe/reproduce.py --repo "$PWD" \
  --toolchain "$(rustup which rustc | xargs dirname | xargs dirname)" \
  --user-home "$HOME" --cargo-home "${CARGO_HOME:-$HOME/.cargo}" --phase required
```

Use Rust 1.97.1 and replace `required` with the selected phase. This materializes the exact historical driver plus a parent with only its three host directories substituted; it retains all commands, affinity and time limits. Each output directory must be fresh. The portability wrapper is source-reviewed and has not itself been executed; the historical driver and parent produced the recorded results. This is partial claim-4 evidence, with no native interval or overall qualification claim.
