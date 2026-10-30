The finite scalar-span TRACE experiment passed all nine cases at `2c6ce7f9025193c86222f1f5ddbb69fea4aa2578` on CPU 228 (AMD EPYC 9D85, Linux 7.1.3). This qualifies the tested finite transfer paths; it does not establish whole-program eligibility or a performance result.

The [JSON receipt](20261030T163009.016195Z-scalar-span-trace-2c6ce7f90251.json) and [nine-row CSV](20261030T163009.016195Z-scalar-span-trace-2c6ce7f90251.csv) retain all 63 commands and outcomes:

- Four native references and four complete native/owner pairs: two generated completions, one ordinary successor resumed and closed by its actual next TRACE, and one real generated read fault with exact original-PC association.
- One additional real nested-signal refusal. Both required failure paths exited 125 and retained their cleanup observations; they are not application completions.
- All 112 application, 164 owner-record and 1,489 terminal supplied-evidence refusals passed. These are reader controls, separate from native failure injections.

The pair comparisons retain all 23 general-register fields, actual flags including AF, the complete 65,536-byte FP buffers, 224 stack bytes, 8,192 data bytes and the original source page. The nested case additionally binds the actual gateway signal and independently observed XSAVE bytes and destination-stack preimage. The emitted gateway/shim, actual DWARF layouts, runtime protected ranges, full terminal projections, source, archive, ELF and process cleanup bindings closed. The independent audit verified all 131 command captures, 1,784 input facts and 233 artifacts without rerunning a reader or native subject.

The mandatory actual-header byte-helper oracle also passed: 23 lengths, 993 placements, 2,766 unequal comparisons, 64 overlaps, 368 zero-access cases, 98 prefix mismatches and three FP checkpoints. Its original bounds remained 5 CPU seconds, 15 seconds wall time, 512 MiB address space and 16 MiB output. The native subjects retained their original 30 CPU seconds, 60 seconds wall time, 512 MiB address space and 16 MiB output bounds.

The prior e376, 4443 and 5f766 failed cohorts remain failed. The immediately preceding [wrong-revision preflight JSON](20261030T162955.469112Z-scalar-span-trace-2c6ce7ff3eeb.json) and [CSV](20261030T162955.469112Z-scalar-span-trace-2c6ce7ff3eeb.csv) also remain failed: the expected-revision argument was mistyped, the actual HEAD was unchanged, and zero commands or application children launched.

The prior register-run cache in the three successful gated cases had 19 resident publications, nine hits and 28 completions, with zero retirements; this gives no retirement coverage. Full 43-case owner qualification, broader transfer/stale/repeat/rollback/close/release/permission/retirement/late-fault native controls, whole-LS eligibility and performance remain separate obligations. This receipt makes no repository-check or speedup claim.

The receipt’s portable reproduction command is:

```sh
python3 -B evaluation/inprocess/scalar_span_trace.py --expect-revision 2c6ce7f9025193c86222f1f5ddbb69fea4aa2578
```
