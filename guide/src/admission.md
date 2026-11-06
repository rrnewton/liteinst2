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
not prove it. Two similarly-named types live at two layers and must
not be conflated: the admission crate's `Completeness::Partial`
(facts are still being gathered) and the core contracts'
`EntryCompleteness::Incomplete` (a plan-level state that cannot
authorize publication). The exporter maps between them explicitly.

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

## Worked example: four pages through the scanner

Listing ADM-1 adapts `crates/liteinst-admission/examples/scan_metrics.rs`
(drop its timing loop; keep its page shape) and prints verdicts instead
of metrics. The second case is a real function prologue —
`endbr64; push rbp; mov rbp,rsp; cpuid; pop rbp; ret` — with every
instruction head supplied as verified entry evidence. That evidence is
what upgrades its `cpuid` from *Unresolved* to *KnownInstruction*:
with only the function entry proven, the same bytes refuse, because
all-start decoding also reaches the site from entries nobody proved.

<span class="filename">Listing ADM-1: src/main.rs (`liteinst-admission` only)</span>

```rust,ignore
use liteinst_admission::entries::{Completeness, EntryProvenance, LegalEntrySet};
use liteinst_admission::scan::*;
use liteinst_admission::{Generation, MappingId};

fn scan_page(name: &str, prefix: &[u8], heads: &[u64]) {
    let mut bytes = vec![0xCC; 4096];
    bytes[..prefix.len()].copy_from_slice(prefix);
    let snapshot = Snapshot::new(
        MappingId(1),
        Generation(1),
        0x1000,
        bytes,
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap();
    let entries = LegalEntrySet::new(
        snapshot.mapping,
        snapshot.generation,
        1,
        snapshot.range(),
        Completeness::AllInstructionHeads,
        heads
            .iter()
            .map(|&pc| (pc, EntryProvenance::VerifiedInstruction)),
        [],
    )
    .unwrap();
    let report = RuntimeScan.inspect(&snapshot, snapshot.range(), &entries, &Policy::default());
    println!("{name}: verdict={:?}", report.verdict());
    for c in report.candidates() {
        println!(
            "  candidate {:#x} len={} class={:?} kind={:?}",
            c.address, c.len, c.class, c.kind
        );
    }
    for obligation in report.obligations() {
        println!("  obligation {obligation:?}");
    }
}

fn main() {
    // A page of int3 padding: nothing selected anywhere.
    scan_page("clean", &[0x90], &[]);
    // endbr64; push rbp; mov rbp,rsp; cpuid; pop rbp; ret — a real
    // function shape whose only selected site is the cpuid at +8.
    scan_page(
        "function_cpuid",
        &[
            0xF3, 0x0F, 0x1E, 0xFA, 0x55, 0x48, 0x89, 0xE5, 0x0F, 0xA2, 0x5D, 0xC3,
        ],
        &[0x1000, 0x1004, 0x1005, 0x1008, 0x100A, 0x100B],
    );
    // mov eax, 0xa20f — the cpuid bytes live inside the immediate.
    scan_page("embedded_cpuid", &[0xB8, 0x0F, 0xA2, 0, 0], &[0x1000]);
    // rdseed eax — its suffix also decodes as rdpid: unresolved.
    scan_page("unresolved_rdseed", &[0x0F, 0xC7, 0xF8], &[]);
}
```

Exact output:

```text
clean: verdict=Clean
function_cpuid: verdict=Sites
  candidate 0x1008 len=2 class=Cpuid kind=KnownInstruction
embedded_cpuid: verdict=Refused
  candidate 0x1001 len=2 class=Cpuid kind=Embedded
  obligation EmbeddedCandidate(4097)
unresolved_rdseed: verdict=Refused
  candidate 0x1000 len=3 class=Rdseed kind=Unresolved
  obligation UnresolvedCandidate(4096)
```

Read the four verdicts as the admission contract in miniature. A
page with nothing selected is `Clean` with no control-flow recovery
at all. A proven instruction stream yields `Sites` — facts a planner
may consume, still not permission to execute. And both ambiguity
shapes *refuse*: a candidate embedded inside another instruction's
immediate, and an encoding (`rdseed`/`rdpid`) that two decodes claim.
Neither is resolved by guessing which stream the author meant.
