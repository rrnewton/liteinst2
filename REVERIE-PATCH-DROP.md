# Dropping Reverie integration's `[patch.crates-io]` liteinst override

Status: preparation note for the liteinst 0.3.0 release branch. Nothing in
this note has been published or applied to Reverie main yet.

## Why the patch exists

`integration/literoot-sprint` carries a root override equivalent to:

```toml
[patch.crates-io]
liteinst = { git = "https://github.com/rrnewton/liteinst2", rev = "34901a29a0070f30398f237839a567720c739af5" }
```

Its stated reason is that crates.io `liteinst` 0.2.0 does not compile its
root library for AArch64 (x86-gated `encoding_error` / saved-state
`detect` items), while liteinst2 main does (commit `f5fd865e`, "compile
the root library off x86-64"). Reverie main at the sprint base has no
such patch section; the patch must not be carried into main when the
integration content is promoted.

## What must happen, in order

1. **Publish `liteinst` 0.3.0 from this preparation branch** (root crate
   only). The branch bumps the root package to 0.3.0, repoints the
   in-workspace consumers (`liteinst-admission`, `liteinst-inprocess`,
   `liteinst-launch`) at `^0.3.0` so the workspace resolves, and adds
   `CHANGELOG.md`. It does not bump `liteinst-x86` or
   `liteinst-artifact`: the packaged root crate intentionally depends
   only on their already-published 0.2.0 features. Verify the exact
   publication candidate with `cargo package --locked -p liteinst`
   (archive build included) before publishing. Do not publish any other
   workspace crate from this branch without its own version bump.
2. **In Reverie, update the dependency and delete the patch.** Change
   `reverie-liteinst`'s dependency from `liteinst = "0.2.0"` to
   `liteinst = "0.3.0"`, remove the whole `[patch.crates-io]` section
   from the workspace root `Cargo.toml`, and refresh `Cargo.lock` so the
   `liteinst` package source is the crates.io registry (no `git+https`
   source, no pinned rev). Check with:
   - `cargo tree -p reverie-liteinst -i liteinst` (registry 0.3.0);
   - `cargo metadata --locked --format-version 1` (single `liteinst`
     package, registry source);
   - `grep -n '^\\[patch' Cargo.toml` (no match).
3. **Re-run the two build shapes the patch was protecting:**
   - `cargo check -p reverie-liteinst --no-default-features --target aarch64-unknown-linux-gnu` (trap-only build);
   - the usual x86-64 targeted checks/tests for `reverie-liteinst`
     (default features), so the registry 0.3.0 root crate — not a git
     checkout — is what the patching build links.
   Ask coord7 before any full `validate.sh` run, per sprint protocol.
4. **Internal (fbcode/BUCK) parity is a separate, later step.** The
   internal `hermetic_infra/reverie` export regenerates the OSS
   manifests (including the `@generated` `reverie-examples/Cargo.toml`);
   its liteinst dependency version and any autocargo inputs must be
   synchronized by the export owner before the next export. Nothing in
   this repository can regenerate that internal target.

## Rollback

If the registry build fails in step 3, restore the patch section
verbatim at the last known-good rev (`34901a29...`, or the then-current
liteinst2 main) and keep the dependency at `0.2.0`; the patch is the
only thing standing between Reverie and the AArch64 root-lib fix until
0.3.0 is actually on crates.io.
