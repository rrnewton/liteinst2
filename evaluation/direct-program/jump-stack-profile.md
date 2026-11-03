# Complete jumps and register PUSH/POP profile

`jumps-gpr-stack64-v1` selects the existing `j*` mnemonic population plus exact
`Push_r64` and `Pop_r64` instructions. It includes all sixteen registers, RSP,
prefixes and unreachable selected heads. Selection is descriptive: refused
instructions remain in the denominator. Memory/immediate/16-bit PUSH/POP,
PUSHF/POPF, CALL, RET and LOOP are outside this separately named profile.

Both profiles use the shared x86 decoder/classifier, ledger validation, CFG
cuts, geometry, policy parser, patch planner and encoder. The new typed selection
binds its class census into the manifest. The legacy jump-only profile and its
results remain unchanged. The E9 request uses exactly the same selected
PC/offset/length rows; no backend-specific subset is permitted.

Use `reproduce.py functional --rewrite-profile jumps-gpr-stack64-v1` with the same
release-build and program receipts documented in [corpus-result](corpus-result/README.md).
The CLI maps this to input `et-exec-jumps-gpr-stack64-v1`, policy
`et-exec-jumps-gpr-stack64-bounded-512m-v1`, and the corresponding
`disassembly_sites --whole-program-fixed-exec-packed-overlapping-jump-stack64-4096`
route. Material, policy and LI2 inventories must agree byte for byte, including
the complete head count and jump/PUSH/POP counts. The existing 4,096-site,
16,384-head, image/output, arena and execution bounds apply without change.
An over-limit inventory is retained whole and then refused, never truncated.

`validate_stack.py` runs the required workspace checks, prior CFG/clock controls,
14 new Rust selection/policy/CLI controls, four native stack state/fault controls
and four Python inventory controls.
The native controls cover all sixteen register forms, explicit PUSH/POP RSP
values and four original-operand faults with valid observer scratch. These
finite checks do not establish arbitrary-stack transparency or full-program
correctness. Actual corpus outcomes belong in a separate exact-revision result.
The observer needs valid save/restore stack space before the original operation;
PUSH RSP stores the incoming RSP, and POP RSP ends at the loaded value. Complete
code/entry ownership, zero-bias loading and helper-stack premises remain caller
obligations. Runtime page exemptions and performance are not established here.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
