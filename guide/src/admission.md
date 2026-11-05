# Scanning and admission

Patching safely starts before any patch: you must know what the bytes
*are*. Two components share that work. The core `scanner` decodes a
region and classifies sites for the planner. The
`liteinst-admission` crate goes further: it produces standalone
*admission facts* — what may be admitted for execution, under what
evidence — without changing memory at all.

## All-start scanning

A linear disassembly trusts one entry point. Real code has many:
function entries, resume points after syscalls and signals, computed
jumps. Worse, on x86 a byte sequence inside one instruction can decode
as a different, dangerous instruction from another entry.

`RuntimeScan` therefore decodes at *every* byte offset, including
starts up to 14 bytes before the requested range and the trailing
bytes needed to complete straddling instructions. By default it selects
CPUID, RDRAND, RDSEED, RDPID, RDTSC, RDTSCP, and SYSCALL; SYSENTER and
INT 0x80 require explicit selection. No candidate is discarded because
it appears inside another instruction or lacks a kernel trap — a
candidate-free page can be cleared without inventing a control-flow
graph, and pages with candidates need complete entry evidence.

Ambiguity is reported, not resolved by fiat. For example, RDPID's
suffix can decode as RDSEED; the scanner reports and refuses that
alternate candidate until a later proof resolves it.

## Entry evidence

A `LegalEntrySet` records identity, scope, provenance, completeness,
instruction entries, and dynamic resume obligations. Symbols, ENDBR
markers, unwind data, and loader discoveries are *positive* evidence
only. The strong claim, `AllInstructionHeads`, is a caller assertion
that no overlapping stream is enterable — constructing the type does
not prove it. `Incomplete` cannot authorize publication.

A mapping owner must also account for the entries nobody lists in a
symbol table: signal frames, syscall returns, parked threads, and
non-local continuations. New facts invalidate dependent plans, and the
identity generation must advance on every entry, policy, or alias
change — not just on byte writes.

## The mock gate: admission without execution

`liteinst-admission`'s `ModelGate` is deliberately a *model*: it
serializes first-fault requests, validates page and halo dependencies,
deduplicates successes, and binds receipts to a unique transaction and
generation set — while changing no permissions and executing nothing.
It rejects missing site coverage, stale plans and receipts, and
snapshot disagreements. A possibly-written failure poisons the whole
dependency bundle, mirroring the live publisher's discipline.

Why ship a mock? Because admission logic — dependency closure,
staleness, poisoning — is where subtle soundness bugs live, and a model
lets clients (and our own gates) validate that logic exhaustively
before any byte is at risk. The live gates in the next chapter consume
the same facts through the `liteinst::contracts` boundary.

> 🚧 **Under construction — scanner listing.** TODO: a listing based on
> `crates/liteinst-admission/examples/scan_metrics.rs` showing a scan
> of a real function, its selected candidates, and one refused
> ambiguity, with the exact output. <!-- UC: admission-listing -->
> Tracking: [liteinst2#38](https://github.com/rrnewton/liteinst2/issues/38) (`admission-listing`).
