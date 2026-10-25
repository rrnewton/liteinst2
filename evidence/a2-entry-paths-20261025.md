# A2 entry paths and signed rel32 boundaries

These additive Linux/x86-64 fixtures run on an **AMD EPYC Zen 5 dev host**.
They use the existing native state comparator, flags and extended-state rules,
15-second child deadline and 20,000-step limit. No earlier case or assertion is
removed. Raw receipts, addresses and captures remain in ignored private evidence.

`tests/entry_paths_oracle.rs` forces B1 over five one-byte NOPs followed by
MOV EAX,42 and RET. All seven original heads remain legal. The four interior
heads of the E9 displacement must route; a simpler instruction layout cannot
substitute. Every target executes with both original state seeds through direct
entry, an actual incoming E9 branch, and every case of one indexed indirect jump
table. The table and adjacent bytes remain covered by the complete source-page
check. Exact native itineraries establish that each incoming edge executes.

The second cycle supplies `ResumeObligation::Enumerated` for all seven heads.
Every original, installed and retired trace receives a real SIGUSR1 on a private
64-KiB alternate stack. The test authenticates the kernel-created ucontext and
witnesses the handler return and actual rt_sigreturn entry/exit. It compares full
state before and after restoration, including orig_rax, with no register or
extended-state reset between frame capture and comparison. It then executes the
restored entry, including normal SIGILL routing where required.

| Entry cycle | Original | Installed | Retired | Required hook events |
|---|---:|---:|---:|---:|
| Direct and every jump-table case | 42 | 42 | 42 | 6 |
| Actual signal-frame restoration | 14 | 14 | 14 | 2 |
| Total | 56 | 56 | 56 | 8 |

All 42 signal round trips are required. Four separate planner negatives reject
an entry or resume in the middle of MOV, unresolved resumes, and incomplete
entries, with exact refusal values and unchanged original bytes. The two isolated
exec modes each have 20 CPU seconds, 30 wall seconds and bounded output; a child
failure or timeout fails the parent.

`tests/rel32_endpoint_oracle.rs` separately requires B1 at displacements
-2,147,483,648 and +2,147,483,647. The preferred address must be used exactly,
with one candidate, no upstream search and no tactic fallback. The two targets
one byte outside these limits must return `AllocationUnavailable`. Four original
entry/seed traces supply eight refusal-preservation, eight installed and eight
retired full-state comparisons. Source E9 bytes, actual image addresses and the
complete generated image are checked; retirement restores exact original bytes.

The shared oracle additions preserve the complete earlier implementation and
comparators. Removing only the additive signal helpers recovers the earlier
source byte for byte. Existing helper calibrations are retained; their duplicate
compilation into new test binaries does not create new semantic coverage.

These results qualify entry behavior, not a context parked across publication:
the installed signal frame is captured after the patch is installed. They also
do not supply CALL-return or exception landing-pad evidence, arbitrary signal
interruption/unwind support, generated unwind registration, active CET, Intel,
mandatory-prefix qualification or eviction-chain coverage. Those gates remain
open; the full A2 milestone is not complete.
