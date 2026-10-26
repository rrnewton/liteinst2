# liteinst-admission

Standalone x86-64 admission **facts and a mock publication model**. This B0
crate does not change memory permissions, emit patches or execute callbacks.
It adds no runtime framework dependency. Its fact exporter consumes the A0
`liteinst2::contracts` boundary; the model publisher remains deliberately separate
from the unsafe live publisher.

`RuntimeScan` decodes at every byte offset with iced-x86 1.21, including starts
up to 14 bytes before the requested range and up to 14 trailing bytes needed
for complete instructions. It selects CPUID, RDRAND, RDSEED, RDPID, RDTSC,
RDTSCP and SYSCALL by default; SYSENTER and INT 0x80 require explicit selection.
Hardware CPUID feature masks do not suppress the scan. No candidate is discarded
because it appears inside another instruction or because it lacks a kernel trap.

A snapshot owns its original bytes and carries mapping incarnation, generation,
boundary protection assertions and writer ownership. Unknown adjacent mappings
need actual halo bytes. A non-executable boundary is an assertion by the mapping
owner, not something inferred from a short byte slice. The all-start scan can
clear a candidate-free page without inventing a CFG. Selected pages need complete
entry evidence. Unsupported, embedded, overlapping, unresolved, stale or
uncontrolled-writer cases return explicit obligations and remain refused. In
particular, RDPID's suffix can decode as RDSEED: B0 reports and refuses that
alternate candidate until a later implementation proves its resolution.

`LegalEntrySet` retains mapping, generation, scope, version, per-head provenance
and typed dynamic resumes. Symbols/ENDBR/unwind/loader discoveries are positive
facts. `AllInstructionHeads` requires caller-certified exhaustive instruction
locations for the claimed executable paths; constructing the type does not prove
that assertion. It is stronger than listing only function entries. New facts
invalidate dependent plans. The core exporter preserves exact expected bytes,
policy, entry version and sites. It requires an explicit exhaustive resume census
to export `NoneExist`; an empty list alone exports `Unresolved`. Core identity's
generation must advance on every entry/policy/alias change as well as byte writes.

`ModelGate` serializes model first-fault requests, validates all declared page
and halo dependencies, deduplicates successful requests and binds receipts to a
unique gate/transaction and generation set. It rejects missing site coverage,
stale plans/receipts and snapshot disagreements. A possibly-written failure
poisons the entire dependency bundle. Invalidation revokes transitive dependents
before replacing their facts. Previously admitted dependencies are conservatively
refused: revoking execute permission cannot erase saved contexts. A model lease
is scoped and cannot cross threads, but **is not a live quiescence proof**.
No API converts it or a mock receipt to an executable capability. Mapping
registration refuses neighbors that contradict a snapshot's non-executable
boundary claims; such a change requires renewed boundary facts and revocation.

Portable validation uses explicit byte puzzles and injected mock failures:

```console
cargo test -p liteinst-admission
cargo run -p liteinst-admission --example scan_metrics
```

Metrics count decoded starts, selected classes, known sites, embedded/unresolved
candidates, verdicts and scan duration. The example reports an informational
synthetic scan distribution; it is not admission performance or a release score.
No patch tactic is added, so there is no architectural rewrite-equivalence claim.
B1 additionally needs the first-instruction launch adapter, real OS page revocation,
all-thread/data-reader/writer rendezvous, saved-PC routing/refusal, explicit
instruction-stream synchronization and core publication. Later cache oracles must
fall back to this runtime scan on every miss/stale/corrupt entry.

`oracle_chain::OracleChain` adds bounded in-memory reuse of immutable scan reports.
A hit requires exact snapshot bytes, identity, generation, boundaries, writer
facts, complete entry facts, target and policy. Refused reports stay refused.
Disabled, missing, stale or poisoned cache entries use the mandatory RuntimeScan
terminal. Range invalidation includes adjacent boundary dependencies, and
serialization prevents an older scan from being inserted after invalidation.
Metrics separate actual scan work from cached historical report metrics. This
is an optional oracle seam; it is not wired into the live gate and does not parse
offline metadata or authorize sparse overlays.
# Potential CALL returns

`returns::CallReturnLedger` records verified direct and indirect CALL
fallthroughs before admitting their source page, including instructions that
start in the preceding page. A CALL ending at a page boundary can push a return
address on the next page while that page is still NX and has never executed.
Its execution history therefore cannot establish that no saved resumes exist.

The ledger checks source identity, bytes, generation and complete verified-head
facts. It retains potential returns across generation changes and unmapping;
there is no release API without a separately qualified drain proof. These are
conservative source facts, not a dynamic stack census or publication authority.
A live gate must authenticate them while execution is excluded and preserve,
route or refuse affected resumes before granting execution. Signal frames,
syscall returns and other saved contexts remain separate obligations.

The separate independent-stream census retains overlapping CALL heads for the
explicit trap-coverage backend. It grants no publication authority; the backend
must separately prove preservation of every admitted decode and saved return.
The original strict ledger method continues to refuse overlapping heads.
