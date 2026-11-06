# Introduction

Welcome to *The LiteInst Guide*, a book about hooking machine code in a
running program with the [`liteinst`](https://crates.io/crates/liteinst)
crate. LiteInst lets you intercept a chosen point in already-loaded x86-64
code — redirecting execution into your own function and then back — by
rewriting instructions in place while the program keeps running, with no
recompilation and no need to stop every thread.

This is a form of *dynamic binary instrumentation*. You would reach for it
to trace, profile, intercept, or modify a program's behaviour at runtime.
A common use is hooking a `syscall` instruction to observe or redirect the
call.

> **Under-construction regions in this guide: 9.** This guide was started
> early, on purpose: writing it is how we check that our own concepts are
> clear. Every unfinished or unimplemented part is marked with an
> *Under construction* box carrying a TODO. The count above is the number
> of those boxes; the work of this project includes driving it to zero.
> If you find a claim in this guide that the code does not back up, that
> is a bug — in the guide or in the code — and we want to hear about it.

## Who this book is for

This book assumes you can read Rust and that you know, at least roughly,
what a Linux process, a system call, and a machine-code instruction are.
It does not assume you have written instrumentation before. Concept
chapters alternate with project chapters: the project chapters build real,
runnable hooks, and the concept chapters explain why they work.

LiteInst is a standalone library and a deliberately policy-free one. You
link it into your own program (or into an `LD_PRELOAD` shim) and drive it
yourself. It makes no decisions about processes, signals, or syscalls —
those belong to the program that embeds it. If you want a complete
framework for building interception *tools* — process trees, typed
syscalls, backends — that is [Reverie](https://github.com/rrnewton/reverie),
which uses LiteInst as one of its building blocks. The
[Reverie guide](https://rrnewton.github.io/reverie/) covers that layer.

## The layer model

Three layers, each making sense on its own:

| Layer | Role | Guide |
|---|---|---|
| **liteinst** | Building blocks: in-place patching, page gates, offline rewriting, decode facts. No process or syscall policy. | This book |
| **Reverie** | Complete solutions: the `Tool` API, backends (ptrace, in-guest, KVM, …), loaders, conformance tests. | The Reverie guide |
| **Hermit** | One Reverie tool: deterministic execution. A consumer of the layers above, not a part of them. | Hermit's own docs |

This book never reaches up into Reverie or Hermit concepts. Where a
chapter needs a client to make sense, the client is a small example in
this repository that you can run.

## How to read this book

Read it front to back the first time. Later chapters build on earlier
ones: [your first hook](first-hook.md) previews the whole API at a high
level, and the concept chapters then take each piece apart. Reference
material — the crate map and the glossary — lives in the appendices.

Three kinds of boxes appear throughout:

* **Under construction** — this part of the guide (or the feature it
  describes) is unfinished. The box says what is missing.
* **Refusal** — LiteInst *refuses* here rather than approximating. A
  refusal is a feature: the library fails closed outside its envelope
  instead of corrupting the program it instruments.
* **Listing** — numbered code taken from a real file in this repository.
  Listings name their source file, and project chapters show the
  command to run; where the exact output is not yet quoted, an Under
  construction box says so.


## Platform envelope, up front

This guide opens with a platform warning, because getting this wrong
wastes the most time:

* **Linux, x86-64 only.** Instruction punning relies on x86's
  variable-length encoding and atomic word stores. There is no aarch64
  port, and one would be a new design, not a port.
* **Caller-certified code.** You supply trustworthy code regions and
  entry evidence. LiteInst does not discover arbitrary code in an
  arbitrary binary, and it refuses what it cannot prove safe.
* **Rust 1.94 or later** for the 0.2.x releases.

[The safety contract and refusals](safety.md) states the full envelope.
Everything in this book is written inside it.
