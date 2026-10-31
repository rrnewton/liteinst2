# Owned module batch: three closed native runs

The fixed integration control passed once at `5b90ed28c1145bb721edb2da58cf052e21feb260` on an AMD EPYC Zen 5 dev host. Earlier failures remain failures. This is no A5, performance, accuracy, hardware single-step-oracle or complete-workspace qualification.

| Run | Executed source | Native result | Child seconds |
|---|---|---|---:|
| v1 | `a3a181f7a12f2f9c07f64b3437ef70416aa751d8` | 0 passed, 1 failed: caller load returned `Err(Format)` | 0.1355386460 |
| v2 | `c8799225a5b30458e4c1c10d4dc8c4ad252e6218` | SIGABRT (-6); only test-start output, empty stderr | 0.6084196500 |
| v3 | `5b90ed28c1145bb721edb2da58cf052e21feb260` | Exact named test: 1 passed, 0 failed, 0 ignored | 0.3024791330 |

Each campaign dispatched that test once, after twenty successful prerequisite stages. There was no retry within a campaign. Times include scheduler/observer costs and support no speedup or CPU-time inference. The unchanged 20 CPU-second/30 wall-second/1 MiB native limits and test's absolute 15-second deadline applied throughout.

The v1 caller-format blocker was `DT_SYMBOLIC=0`, emitted by the unchanged `-Bsymbolic` recipe. The caller-specific correction requires exactly one such tag and preserves the default parser and every other ELF/body/ownership check. Empty LOAD segments were already accepted. Focused validation at c879 passed strict Clippy, 16 pure tests (the native test remained ignored) and two compile-fail doctests.

V2's first abort cause was not established. A separate bounded GDB attempt timed out after 45 seconds, obtained no backtrace and printed `Function "abort" not defined.` Its helper killed and reaped two processes; this is distinct from the outer owner's complete cleanup with zero rescue reaps. The subsequent test-setup correction excludes reserved SIGILL from its newly blocked set, refuses an inherited blocked SIGILL mask and prints publication failure before the same abort. Production router checks remain unchanged. That necessary contract correction is not proof of v2's first abort cause. Fmt and strict Clippy passed at 5b90 before v3.

The passing test enforces three genuine four-call C batches and their stores/ordinary returns: totals entered/return-observed/confirmed are 12/12/12, with eight sampled and four removed observations. It checks actual epoch A/B ownership, semantic function IDs, exact continuation words, reports of four records per epoch, four history actions, final `Closed`, and refusal of later batch/finish calls. These are executed source assertions, not a separately exported per-call trace. The complete caller has 123 bytes, 40 instruction heads, four CALLs, four stores and an outer RET.

[receipt.json](receipt.json) records exact commands, environments, CPUs/load, tool/product/log pins, limits and closure outcomes. Its command groups expand in listed order; `${TOOLS[role]}` selects the tool row, `${TEST}` the exact named test, and each run supplies `${REV}` and a fresh `${RAW}`. The [canonical adapter instructions](../README.md) reproduce the fixed sequence with [reproduce.py](../reproduce.py). All raw captures remain private.

All native helpers established ECHILD, no timeout or unexpected descendants, and unchanged inputs. All three native campaign outer owners completed cleanup, reported unchanged source and zero rescue reaps. Original process/scope/reservation-tag absence was checked; the shared ledger remains. V3's absence check joins retained live metadata; no independent contemporaneous live observation or allocator start-time capture is claimed. Parent exit zero is root-reported. Historical v1/v2 binary hashes are archived artifact/retention evidence: their reused target path was subsequently overwritten, so no current-byte reread of those binaries is claimed. The original failed adapter stage labels remain `DISPATCHED_UNKNOWN`; separate authenticated receipts establish their failures.

Sealed copies provide backing immutability. The finite safe-input semantics, ABI, actual mapping ownership, rendezvous, inactive CET, no foreign entry/writer/unload/reentry and ordinary-return premises remain required. Kernel-advertised CPU flags do not establish physical CPUID/MSR state. No assertion, bound or failure was discarded to obtain this result; no evidence from a separate full gate is included here.
