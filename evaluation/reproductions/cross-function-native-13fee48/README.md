# Reproducing the focused synthetic fixture

The two exported drivers are byte-identical to the actual callers. Preserve the selected export outside the tested checkout before checking out its exact revision; later reporting commits are not the tested source.

| Revision | Driver | SHA-256 |
| --- | --- | --- |
| b11870928d88cfcb63499e24bfba6268ee15712d | validate-b118709.py | 5764a764df2f7b17ea8a251a006c7410a033107dc9cab99b68690607711025e5 |
| 13fee48dad74409e401dce4943de7dc6dc416625 | validate-13fee48.py | 97b2a631467e665549e481d2a816f65f48d4ca53efb75dd4dddb8faf5814a5e1 |

Use a clean checkout at the chosen revision and the exact saved Rust 1.97.1 toolchain hashes/offline dependencies in the data. Pass canonical absolute paths and a fresh output directory beneath the checkout's ignored directory:

```sh
/usr/bin/python3.9 -B <saved-driver> --repo <checkout> --output <checkout>/ignored/<fresh-output> --toolchain <toolchain> --user-home <user-home> --cargo-home <cargo-home> --phase targeted
```

The driver authenticates the whole tracked source and selected tools/configurations before and after, sets CPU affinity to 0–3 and runs exactly:

```sh
cargo test -p liteinst2 --test neighbor_eviction_oracle cross_function_native::native_foreign_neighbor_two_owners_all_heads_both_seeds -- --exact
```

Its minimal environment, offline four-job settings, zero debug-information settings, empty Rust flags/wrappers, 180-second bound and 8-MiB log bound remain literal. It does not set RUST_TEST_THREADS or the staged-drop child variable. The saved actual parent had a separate 240-second wait bound. Both complete parent and child command contexts are in commands.json; path roles are injective placeholders with exact private inverses. Choose local paths explicitly rather than interpreting the placeholders as existing paths.

The first revision is expected to reproduce the retained compilation lint under the same compiler. The corrected revision's observed result is one passed case and 70 filtered cases. It is a finite synthetic fixture using real emitted images, not a complete common-corpus campaign. Child counts and trace dimensions are attested by the exact executed source assertions, without separate per-child capture evidence. No new result or environment qualification is inferred by this reproduction recipe.
