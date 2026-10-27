# Interleaved ET_EXEC carrier at 6abee75

All four normally loaded fixtures passed at
`6abee75266792d2977e48da8a05ac683e08665cc` on an **AMD EPYC Zen 5 dev host**:
the original ELF and rewritten variants with an RX image below, between, or
above its original LOAD segments. Every fixture produced exactly `42\n` and
exited zero. All six bounded build/emit/execute commands closed with ECHILD;
the enclosing supervisor completed cleanup with no rescued descendants.

`cases.csv` and `stages.csv` preserve every numeric row and result hash.
`receipt.json` records the exact revision, hardware and tool/product hashes;
`commands.json` records commands and environments with private paths replaced
by roles. Raw logs and generated ELFs remain ignored. Development opt-level 0,
debug-info 0, assertions and overflow checks were explicit; elapsed times are
validation diagnostics, not performance measurements.

Repeat with the [tracked reproducer](../interleaved-carrier/README.md) at the
exact revision, a new ignored output directory, cached dependencies and
Rust 1.97.1. Preserve its fixed child and supervisor bounds. This is a finite
freestanding ET_EXEC loading/output check, not general dynamic-loader or
architectural equivalence evidence.

The change addresses a real common-corpus failure: at predecessor
`77c4d6c67f434ab833667ed418488556072462a6`, all 74 production stages ran,
with 62 passing and 12 failing. Four core jump-selection cells refused lower
RX images (`InvalidImage { index: 6 }`); their eight E9 comparisons each
reported nine lost sites. Those failures remain unchanged. This small native
cohort does not turn the predecessor campaign into a pass or satisfy its
704 core-null and 2,112 recording-pair obligations.

Independent saved-result review also reconstructed every byte of all four
ELFs from the finite fixture model and checked all six receipts and contexts.
Its binding is SHA256 `edc3571ffaa2b78a01578b8883a7074513d512328fab0b45de71d339f6a94173`;
`closure.json` preserves the enclosing supervisor result.
