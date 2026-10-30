# Actual application and independent x87 seed prerequisite

The owner qualifier requires all 25 application subjects: nine native
references, nine gated counterparts and seven required owner refusals. Their
30 CPU second, 60 wall second, 512 MiB address-space and 16 MiB file-size limits,
441 owner-record controls and complete architectural comparisons remain fixed.

Before those subjects, it builds and runs the unchanged
[provider seed probe](../provider_app/seed_probe/README.md) once on the same
reserved CPU, under that probe's original 5 CPU second / 15 wall second limits
and the same memory/file limits. This separate prerequisite earns no owner,
application-completion or performance credit. Its complete record, executable,
compiler include closure and resolved libraries are retained with the receipt.

The unchanged probe reader authenticates two distinct emitted
`FNINIT; FLD1; FLDPI` sequences, each observed before and after `FNSTCW/FNSTSW`:
four complete equal FXSAVE buffers, nonempty PI/one payloads and exact zero
FIP/FDP. Both probe machine observations include all 67 CPUID rows, XCR0 and
actual supported/permitted XCOMP masks. Each application's corresponding actual
observations must equal this complete profile. Prefix words 26/27 and 28/29
now retain the return/value pairs from `ARCH_GET_XCOMP_SUPP/PERM`; words 30/31
remain zero. Record sizes and the FNINIT/FLD1/FLDPI seed sequence are unchanged.

This corrects the former unsupported prediction that FLDPI must leave its ELF
address in FIP. The earlier provider run at revision `5110f2d80b8c` already
retained a successful seed observation with zero pointers; that enclosing run
remains failed. The owner run at `7dfedabf3c1c` also remains failed: all 19 native
frames had FIP zero, and its old reader required the FLDPI address. Historical
observations motivate this expected-state correction; they do not replace the
new run's independent prerequisite.

The new finite expectation is strictly `(FIP, FDP) == (0, 0)`. It accepts no
alternate pointer value, ignores no byte and edits no captured frame. The
whole 65,536-byte native conservation and native/gated FP comparisons, every
GPR, actual AF, stack and data comparison remain intact. Different seed
behavior, an unqualified probe, a changed format or any nonzero pointer refuses
qualification. A fresh complete committed run is required for new evidence.

The seed/capture assembly now occupies a separate high RX page, surrounded by
complete CC pages; its state and constants have distinct nearby RW and R-only
loads. This meets the unchanged native admission address bound without asking
the generic TF path to execute PUSHFQ/POPFQ, x87 or memory KMOV forms. The
ordinary CRT and focal loop remain low. An exact original-PC FF25 return stub
and a bound R-only entry pointer transfer between them without changing any
GPR, flag or stack byte. The reader checks every transfer/literal and complete
load extent, and still requires the actual whole helper plus 14-byte halos to
pass the unchanged all-offset native policy. An emitted layout or policy
failure refuses before application launches; no new admission is inferred.

The three complete struct observations use the existing high pure copy
helper, avoiding compiler-generated REP MOVSL while retaining every byte. The
failed `8e6497ae0fec` run remains failed; its nine native references and fresh
seed passed, while all sixteen gated subjects refused before the prefix. The
new geometry requires a fresh complete 25-subject qualification, with the same
limits and all 441/234/528 owner/application/terminal controls.
