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
remain zero. Record sizes and the assembly producer are unchanged.

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
