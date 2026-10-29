# Ordinary CSV: retained mapping-class refusal

At `c81a1be4c5003db4a64c1a530d46839638224ca9`, the single corrected-build
release qualification **FAILED**. The eager-binding recipe now satisfies the
loader, but the consumer required private `r-xp` mappings for both original
source and generated images. LiteInst creates its executable trampoline images
as shared `r-xs` memfd mappings. The exact mapping check therefore aborted.

The child exited by SIGABRT (-6), with ECHILD, unchanged inputs and no timeout
or rescued descendants. Stdout was empty: there is no completed 16-row case
table. Source control flow places this generated-image check before the first
installed call; no per-call counts were independently exported. This is not a
functional pass or a native-state comparison result.

The new ELF has the required NOW metadata. Its complete 126-byte CSV body is
byte-identical to the prior failed build; the independently inspected Rust
caller remains 20 bytes with CALL continuation/result-store offset 15. CPU92
was reserved with hard AllowedCPUs92. One-minute load was60.76→61.26, with no
quiet-host claim. Release optimization3, assertions and overflow checks enabled.

All seven exact-source checks passed: default workspace3,140passed/0failed/36ignored
in336.375s within the unchanged360s guard; serial launch1,039passed; staged
allocation3; prefixed-pun36; fmt, strict Clippy and check. Both historical
allocation-contention cases passed. The new CSV state-oracle source also passed
149 active calibration controls, with the existing hardware control ignored;
its32-pair native qualification is a separate, still-unrun experiment.

`receipt.json` records every command and outcome, exact revision, tools, hardware,
reservation, bounds and artifact hashes. `outcomes.csv` contains the complete
one-attempt population. Raw logs and captures remain ignored. Reproduce using
the receipt command at the recorded revision with fresh local output. Durations
are operational wall times, not performance measurements.

The prospective fix distinguishes private loaded source from shared generated
images using their typed plan owners. Each retains one exact expected mapping
class and complete byte checks. It will receive its own reviewed-source
qualification. The [3bfd505 loader refusal](../ordinary-csv-3bfd505/README.md) and
[4395e90 source timeout](../ordinary-csv-4395e90/README.md) remain unchanged.
