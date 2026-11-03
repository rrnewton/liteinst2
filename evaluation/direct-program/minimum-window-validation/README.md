# Minimum-window correctness

Revision `26cc9b7fc1760e1e63f38c3b4079dd9a76f19656` passed full validation on an AMD EPYC Zen 5 dev host: **4,704 top-level + 11 nested = 4,715 raw workspace passes**, zero failures, 43 unchanged ignores; **1,039 serial passes**, zero failures/ignores. All old rows remain with 17 Rust additions. All **163 focused controls (146 Rust, 17 Python)** passed in this full run.

Current freestanding facts passed **15 subjects and 138 reader controls**. Five expected child-125/helper-1 fatal paths remain explicit. All 34 full owners and 116 facts owners plus its outer closed normally, with complete cleanup and zero rescues. [receipt.json](receipt.json) retains all numeric subject results. Walltimes are validation costs, not benchmarks.

Three earlier campaigns remain **FAILED**: focused-v1 (one fixture); focused-v2 (incomplete router census despite 159 test passes); full checks-v1 (strict Clippy, later stages unobserved). The corrected roster includes 35 inherited calibrations/22 should-panic markers. [Older facts outcomes](../../shared-x86/freestanding-facts/README.md), including the reserve failure, remain separate.

Use the receipt's exact argv and pinned committed recipes from a clean exact checkout. Externally reserve 12 CPUs for full validation and one for facts; select distinct fresh outputs/log basenames and the recorded toolchain. Full uses Python 3.9; facts requires 3.11+ and its 1200-second/64KiB outer envelope. Path placeholders are normalized. `--focused` does not replace full validation.

Scope is finite immutable-source min5 seals, shared planner/consumer, production-router state/event/fault and decoder/descriptor controls. Marked test exports stay separate; span/MOV/ADD execute no generated instructions. The [corpus receipt](../minimum-window-result/receipt.json) is separate; no complete-CFG, runtime exemption, broad native or performance qualification. [Prior corpus failures](../ledger-chunks-result/README.md) remain unchanged.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
