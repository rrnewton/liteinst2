# Project: your first hook

In this chapter we build a complete hook and then break it down. The
program is `examples/replace_first.rs` in the liteinst2 repository. Run
it first:

```console
$ cargo run --example replace_first
```

You should see the target function return one value with the hook
installed but inactive, a different value while it is active, and the
original value again after it is deactivated. Everything below
explains how that happened.

## The shape of every LiteInst program

Every client, from this example to a full syscall interceptor, follows
the same five steps:

1. **Obtain code you may patch** — a region whose bytes, entries, and
   mapping lifecycle you can vouch for.
2. **Scan it** — decode the region and classify each candidate site.
3. **Plan** — choose a tactic (direct pun, relocation, guarded split,
   or an explicit trap fallback) without touching executable memory.
4. **Publish** — write the patch with the protocol that tactic demands,
   and receive a receipt. An `InstalledHook` is published **inactive**:
   nothing detours yet.
5. **Activate, run, deactivate** — call `activate()` to arm the hook,
   execute through it, and `deactivate()` to restore the original
   behaviour. There is no remove/retire API on `InstalledHook` today;
   deactivation is the end of its lifecycle.

Steps 1–3 never modify the program. Only publication writes, and it
re-checks everything before it does. That split — *plan purely, publish
carefully* — is the library's central design decision, and
[Plans, leases, and receipts](contracts.md) is devoted to it.

## Breaking it down

Listing FH-1 is the heart of the example (the full file also creates
the dual-mapped page that holds the target code):

<span class="filename">Listing FH-1: examples/replace_first.rs (excerpt)</span>

```rust,ignore
// xor eax,eax; inc eax; nop; ret; padding
let code = [0x31, 0xC0, 0xFF, 0xC0, 0x90, 0xC3, 0x90, 0x90];
let address = executable as usize as u64;
let scanner = InstructionScanner::default();
let scan = scanner.scan(&code, address)?;
let arena = TrampolineArena::allocate_near(address, 1)?;
let hook = unsafe {
    InstalledHook::install_replacing_first_in_arena(/* … */)
};
```

* The target is eight hand-written bytes: a function that returns 1.
  The first instruction is two bytes long — smaller than the five-byte
  jump a hook needs. *Replacing first* is the tactic for exactly this
  situation: the short first instruction is replaced, the rest of the
  five-byte window is relocated into a trampoline, and execution
  continues there.
* `InstructionScanner::scan` decodes the bytes and records instruction
  boundaries and cache-line geometry. Scanning is fail-closed: bytes
  that do not decode cleanly are refused, not guessed at.
* `TrampolineArena::allocate_near` reserves dual-mapped memory (separate
  RW and RX aliases — never one RWX mapping) close enough for a
  five-byte relative jump to reach.
* `install_replacing_first_in_arena` plans and publishes — **inactive**
  (`src/trampoline.rs`: hooks bind in the inactive state). It is
  `unsafe` because *you* assert the envelope: the aliases stay live,
  no other writer touches the region, and no control-flow entry targets
  the interior of the relocated window. The example then calls the
  target (still returns 1), `hook.activate()?` (now returns 41: the
  callback's 40 plus the relocated `inc eax`), and
  `hook.deactivate()?` (back to 1) — `examples/replace_first.rs:87-92`.
  The full run prints exactly:

  ```console
  inactive=1 active=41 restored=1
  ```

The hook callback receives the saved register context and may mutate
it — here it sets `rax`, which is why the function's return value
changes:

<span class="filename">Listing FH-2: examples/replace_first.rs — the callback</span>

```rust,ignore
unsafe extern "C" fn replace_zero(context: *mut HookContext) {
    unsafe {
        (*context).rax = 40;
    }
}
```

## What could have gone wrong

Three failure classes matter, and this book marks them distinctly,
because in instrumentation they are *different* bugs:

* **Does not compile / does not install** — the planner refused the
  site, or allocation failed. You find out immediately, before any
  byte changes.
* **Installs but corrupts** — the class LiteInst exists to prevent. A
  torn patch (half old instruction, half new) is impossible by
  construction for sites the planner accepts: see
  [How instruction punning works](punning.md).
* **Installs but silently misses** — the hook is fine, but some path
  into the code was never hooked (an undiscovered entry, code created
  later). LiteInst cannot detect this for you in general; it is why
  [Scanning and admission](admission.md) and
  [Page gates](page-gates.md) exist, and why the
  [safety contract](safety.md) puts entry evidence on the caller.

## Growing this project

This target is the book's running project; later chapters return
to it and change one thing at a time:

| Stage | What changes | Full code at this step |
|---|---|---|
| 1. Replace-first hook | this chapter | `examples/replace_first.rs` |
| 2. Rapid toggle | the target is reshaped so its first instruction can pun; toggling becomes one atomic byte store | [Tactics](tactics.md#project-stage-the-first-hook-target-at-rapid-speed), Listings FH-3/FH-4 plus this chapter's dual-mapped page |
| 3. One bundle, two sites | two copies of the target, planned independently and published/retired as one install-once transaction | [Contracts](contracts.md#project-stage-two-sites-one-bundle), Listings FH-5/FH-6 plus this chapter's dual-mapped page |
| 4. Page-gated variant | one private page; eager core publication, then first-touch admission | [Page gates](page-gates.md#project-stage-the-first-hook-target-behind-a-page-gate), Listing FH-7 with the FH-5/FH-6 planning and lease patterns |

The stages carry one lesson in widening forms. The planner — not
the author — decides whether the rapid step is available, and when
it refuses, the honest move is to reshape the program; the bundle
then changes publication from one hook to one transaction; and
the gate changes the source-ownership model itself. Growth is
never just “the same code with more flags.”

## Summary

You installed a replace-first hook: scan, plan, publish (inactive),
activate, run, deactivate.
The next chapter explains why publishing a patch into live code is safe
at all — the instruction-punning idea the whole library rests on.

