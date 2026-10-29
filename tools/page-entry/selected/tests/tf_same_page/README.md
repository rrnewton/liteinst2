The opt-in same-page TF lease preserves the original permission owner while a
qualified PLAIN fallthrough instruction retires and the next qualified PLAIN
fallthrough instruction stays within that exact page. This finite oracle checks
that candidate mechanism. It does not establish general application completion,
B2/B3 completion, or a performance result.

The fixed corpus has 17 subjects:

- Five same-original-ELF native/observed pairs: three consecutive transfers then
  a real close; branch fallback; selected CPUID fallback; an instruction ending
  at the page boundary; and a clipped two-byte successor that needs the unchanged
  real release/reprepare path before a two-page instruction can execute.
- The first ELF also runs through the old owner with the lease macro absent and
  through the unobserved production lease bridge.
- Five gated operations must fail with exit 125: a real write overlapping the
  registered rseq publication word; an explicitly supplied stale ref; a real
  retained-backing-FD close; and real nested SIGTRAP delivery after staging or
  after singleton replacement but before chain-ref publication.

All 16 GPRs, flags, 32 ZMM registers, eight mask registers, initialized FP bytes,
source bytes, data, stack, rseq page, and genuine signal frames are retained.
Every locally unchanged frame remains byte-exact. A lease before-frame actually
has TF set. The old owner before-frame has its actual NX/TRACE meaning; no bit
is cleared to make those observations look identical. The CPUID case joins the
same literal input to actual native output and the actual raw/committed sample.

The observation adapters copy the original chain, fetch, rseq and permission
owner structures. On a transfer they require unchanged opening pages, hooks,
session and actual permission-call fields, a fresh RX map/backing/source check,
one new actual per-instruction rseq check, and a continuously held fetch ref.
On fallback they require the real original-page close/release and a strictly new
borrow. The clipped case retains both the first truncated borrow/release and the
new two-page borrow. No transfer fabricates CLOSED, a release, or a syscall.

The five failed operations remain failures. The original permission owner must
actually attempt the original-page revoke. A successful mprotect sets the old
`revoked` bit before authentication; it is not by itself verified-close evidence.
FAILED state, occupied/stale fetch prefix, and absent continuation/release remain
visible. The observer separately reads actual R permissions after cleanup; that
read cannot upgrade a failed owner to a verified close. The two nested controls
retain the genuine SI_TKILL frame and require the injected tgkill not to return.
The supplied stale-ref mutation is labelled as such and is not a native fault.

After committing the reviewed runtime and this additive oracle, reserve one CPU
and run the unchanged positive six, full negative 49, and fast inactive-rseq 17
cohorts at that exact revision. Pass their full private receipts to:

```
python3 evaluation/inprocess/page_selected_tf_same_page_run.py \
  --expect-revision "$REVISION" \
  --positive-receipt "$POSITIVE_PRIVATE_RECEIPT" \
  --negative-receipt "$NEGATIVE_PRIVATE_RECEIPT" \
  --rseq-receipt "$RSEQ_PRIVATE_RECEIPT"
```

The driver replays those exact prerequisites and runs unchanged registered16+4,
TCGETS20pairs+16supplied controls, and TIOCGWINSZ17pairs+1supplied control before
these17 subjects. It imports the corrected gate helper; it does not replace it.
The original chain, generic, maps, alias and write-footprint regression evaluators
remain required at the same committed source. New subject bounds are5 CPU seconds,
15 wall seconds,512MiB address space and16MiB capture; bridge/fixture link bounds
remain30 CPU/60 wall with the same memory/capture limits. All failed prefixes and
primary/cleanup errors are retained by the existing Build/invoke owner.

The build uses the fixed three-argument recipe `build.sh metadata.S output case`
for cases0..9. Native and gated members use the same emitted ELF per case. The
actual ELF reader requires the original all-start helper+halo policy and exact
instruction bytes; there are no opcode-policy exemptions. The enclosing driver
records actual compiler-M closure, archive/tool/header/ELF identities, DWARF,
argv/environment, namespace seals and FD3 identities privately. Public output is
a bounded numeric summary. No subjects or compiler have run for this candidate.
