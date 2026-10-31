# Native custody-map observations

**Aggregate FAILED.** At `1c37c74619a924b0aad39890da432dad2a8993c1` on an AMD EPYC Zen 5 dev host, locked emitted 1,014 observed returned-call rows of 2,048 planned; random completed all 2,048 with structural PASS. Each ran once. Missing final drain means the locked rows are not an exhaustive physical-return count.

Locked hit the original clock Deadline at 599,287,159 ns. Its recorded wait/context switch do not establish an exclusive cause. Normal OS reap does not supply missing SDK drain or PMU shutdown. [receipt.json](receipt.json) retains the failure, raw outcomes, every limit, seven durations/loads and tool/source/owner hashes; [rows.csv](rows.csv) retains exact observed/planned counts and clock endpoints. Callback PMU windows and CALLTIME enclosures do not establish body-only counts or exact native entry.

Reproduce with the [seven existing owner commands](../prepared-27e/README.md#reproduction-with-the-existing-owners), this revision and fresh output/name/tag; all other switches remain exact. Preserve the single three-CPU lease, independent geometry reviews and every custody/source/retention gate. Safe closed locked FAILED permits one random attempt while retaining aggregate FAILED; unknown closure stops. No retries or renewed bounds.

Fresh native prerequisites passed 130 Rust/104 Python. [Workspace-1c37](../workspace-1c37/README.md) supplies separate fresh SDK45; [22 prepared Python controls](../prepared-focused-27e/README.md) remain historical with unchanged source, not rerun here.

Phase/hardware remain **UNRESOLVED**; no accuracy, full-state, throughput or causal speedup claim. The denominator stays 43,200. Original strict-clock **one PASS/four FAIL**, [phase-071](../phase-071/README.md) and [prepared-27e](../prepared-27e/README.md) remain unchanged. Raw logs stay private.
