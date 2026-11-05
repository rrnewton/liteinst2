# Getting started

Let's get LiteInst building and run the smallest hook in the repository.
By the end of this chapter you will have installed a hook over a
two-byte instruction, watched it change a function's result, and toggled
it off again.

## Installation

LiteInst is a library. Add it to a Cargo project like any other crate:

```console
$ cargo new my-instrument
$ cd my-instrument
$ cargo add liteinst
```

Or work from a checkout of the repository, which is what this book's
listings do:

```console
$ git clone https://github.com/rrnewton/liteinst2
$ cd liteinst2
```

You need a Linux x86-64 machine and Rust 1.94 or later. Check:

```console
$ rustc --version
$ uname -sm
Linux x86_64
```

## A first hook in one command

The `replace_first` example installs a hook over a two-byte instruction
(`xor eax, eax`), mutates the saved register context so the function
returns a different value, and toggles the hook off again:

```console
$ cargo run --example replace_first
```

The example builds its target function in a dual-mapped page (one
writable alias, one executable alias), so it needs no other program to
instrument. It prints the function's result with the hook installed
but inactive, then active, then deactivated
(`inactive=1 active=41 restored=1`). The next chapter takes this
example apart line by line.

Two more examples show the shapes real clients take:

```console
$ cargo build --example preload_consumer   # an LD_PRELOAD cdylib client
$ cargo run --example owned_loop_clock     # a stop/resume clock client
```

`preload_consumer` shows how a consumer can own `LD_PRELOAD` delivery
while depending only on the policy-free core. `owned_loop_clock` is a
standalone stop/resume client with an owned buffer; run it without
arguments.

## What you just linked

The workspace publishes six crates. Most programs need only the first:

* `liteinst` — the patching core: punning, WordPatch++, trampolines,
  rapid toggles, offline emission.
* `liteinst-x86` — shared decode facts (fact-only; no execution
  authority).
* `liteinst-artifact` — content identity, metadata, sparse overlays for
  offline rewriting.
* `liteinst-admission` — conservative admission facts and a mock
  publication model.
* `liteinst-inprocess` — a caller-owned in-process NX first-touch gate.
* `liteinst-launch` — stopped first-instruction launch checkpoints.

[Appendix A](appendix-crates.md) maps each crate to the chapter that
covers it. API documentation is published to
[docs.rs](https://docs.rs/liteinst) per release (if that page 404s for
a brand-new release, docs.rs has not built it yet — `cargo doc`
locally covers the default surface; add `--features offline-router`
for the module docs.rs also builds).

> 🚧 **Under construction — expected output transcripts.** TODO: paste
> the exact stdout of `replace_first`, `preload_consumer`, and
> `owned_loop_clock` from a clean run on this release, so readers can
> diff their output against the book's. <!-- UC: gs-transcripts -->
> Tracking: [liteinst2#38](https://github.com/rrnewton/liteinst2/issues/38) (`gs-transcripts`).
