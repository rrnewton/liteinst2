These source components define two fixed parent-clocked lease workloads,
N=1 and N=256. It supplies the subject, native reference, observation adapters,
actual-DWARF layout and fixed pipe process seam. The strict consumer fixes four explicit reference/observed/timing profiles;
the enclosing qualifier and separate performance driver bind their source,
artifacts and commands. No current invocation or receipt is qualified by these
source files alone.

The unchanged release profile and its full 17-case qualification remain
prerequisites. There is no production source, policy, descriptor or mapping
change. `build.sh METADATA.S OUTPUT N` builds the fixed high-address ELF. The
existing CPUID-first custom interpreter/metadata construction is reused by the
enclosing helper. No main entry, helper, complete source page or halo
receives an admission exemption; actual emitted bytes must pass the existing
policy/identity checks before subjects run.

The original clean seed/capture page stays at 0x200402000. WAIT is 0x200403000:
READY is followed by an old NOP at +4093 and canonical two-byte read at +4094.
Only one candidate NOP precedes the selected instruction, below the copied-run
minimum. Its old-step TRACE closes before the read. The authenticated two-byte
borrow excludes BODY; owned-syscall dispatch releases it, performs the real
read, and returns without TF to BODY=0x200404000. BODY contains exactly N
`49 83 c0 01` instructions (ADD $1,%r8), then an old NOP and branch to GUARD.
Unreachable CPUID bytes keep BODY/GUARD dirty under the original scanner.

Required future qualification: real gated read NX ingress, exact decoded
successor/arguments/result, actual read-return BODY permission NX, no pending
owner/borrow, then genuine first-byte BODY SIGSEGV/ACCERR/trap14/error21 with
RIP=si_addr=CR2 and original flags/mask. Native has no read-ingress ucontext:
its genuine BODY NX supplies native read-return evidence. Modes `reference`
and `native` differ explicitly: reference installs the existing kind of native
handler and makes BODY/GUARD NX before registration; native timing does neither
but sets the same application signal mask. Gated mode installs no target
handler. Every target uses the same subject ELF and normal registered setup.

The `tfi_record` has full real read/endpoint/opening/final frames, complete
opening/closing owners, the genuine pre-BODY lease state and a terminal chain. The N compact rows have the actual
SIGTRAP/signo/TRAP_TRACE/errno/si_addr tuple, raw 128-byte siginfo, 23 GPR slots
(including full flags/trap/error/CR2), mask, actual FS/GS, FP pointer/extent,
zero-word observation, complete instruction request, actual opaque fetch ref,
full fetch progress, permission/open/revoke fields, transfer receipt and rseq
state. Before/after rows must join the same real handler and permission owner.
Full FP is retained at endpoints/open/final close, not at every compact step.
N=256 requires 255 ADD-segment transfers and one lease close; N=1 requires zero
transfers and no established lease, with its ordinary owner fully closed.
Later NOP/branch owners remain separately counted. No repeated full large
event records are used; a C static16 MiB bound is present, but actual emitted
layout remains unverified.

Header words are zero unless explicitly written. Full frames retain the
unchanged `rn_frame` protocol. Endpoint h[0:6] is present/index/PC/address/
returned/native-fetch-result (native uses result0); h[24:28] binds actual
siginfo entry/return pointers, size and address offset. The gated read uses
h[5] for the actual returned RAX, h[6] decoded capture, h[8:15] map-query start,
result/protection, lifecycle query result, pending step/route/interlock.
TRACE frame h[0:15] is present/sig/signo/code/errno/address/SI pointer/UC pointer/
FP pointer/extent/SI size/address offset/FS/GS/zero-word. Compact event h[0:7]
is present/index/slot/generation/returned/result/next active slot. The source
names and actual DWARF own every other field and padding; no consumer may ignore
unclaimed bytes or infer a missing observation from a later counter.

`pipe_run.command(...)` builds only this launcher's fixed argv. `invoke(row,
directory,cpu,terminal_check)` preserves FD1 as genuine parent normal-open
Btrfs capture, FD2 stderr and fresh regular FD3. Only two extra child pipe ends
are inherited: GO-read and READY/DONE-write, distinct and >3. Parent and launcher
retain actual FIFO identity/access/blocking/inheritance and normal stdout
dup/exec identity. Launcher records signal reset, FD3 and actual single-CPU
affinity before native/carrier exec. There are no new target syscalls for pipe
creation, descriptor import, threads or shared mappings.

All IPC uses one absolute 15-second deadline from invocation start; the target
retains 5 CPU seconds, 512 MiB address space and16 MiB file bounds. Parent sends
one GO byte after exact READY. Its DONE timestamp remains provisional until
exact transcript plus EOF, complete successful reap, all captures/descriptors
and the required strict terminal/report reader pass. The bounded post-DONE
collector retains up to nine extra bytes, including a complete duplicate DONE;
any extra byte still rejects the protocol. No default accepting
reader, retry, sample filtering or deadline reset exists. Post-timeout kill/reap
has the existing separate bounded cleanup allowance and cannot rescue a sample.

Normal control0 produces READY/DONE. Subject controls1/2/3 produce wrong READY,
duplicate DONE or no DONE. Parent controls wrong-go/eof-go test the unchanged
post-body GO/result check: the benign ADD body can execute before rejection,
so these are not pre-effect refusals. All controls remain failed rows in this
seam; a future fixed negative-case reader must inspect their actual prefixes.
Launcher-only controls must additionally exercise FD3 alias, regular-file
instead of FIFO, wrong endpoint direction and opposite ends of the same FIFO. They
must fail before target exec; argv assertions cannot establish provenance.

The future timing population is five alternating native/gated pairs per N.
GO-to-DONE includes IPC/scheduling, remaining READY/read ingress, read return,
first fault/kernel/handler/sigreturn, body, real closure and finish/DONE work.
Bulk stdout/FD3 records follow DONE but remain mandatory before acceptance.
Call N=1 a first-entry workload round-trip and N=256 an eligible-operation
batch. Batch/256 includes first/last costs. Neither is isolated retirement or
pure interior steady-state latency; first execution is not cache/TLB cold.
Real-program process times and existing admission-work timers remain separate.

The gated record is version2. A fresh read borrow retains zero last-validation
bytes until the actual release; the observer conditionally copies only a real
last_backing pointer. The consumer authenticates complete retained stat/VMA
identity against the separately source-bound carrier extent, preserves every
N=1 prior-lease byte except the literal miss/cancel writes, and joins N=256
opening and predecessor frames to genuine body observations. Superseded setup
payloads are not a claim of independently replayed setup history.

Run the supplied-record projection suite separately, alongside the unchanged
350-test recorder, using Python 3.12:

```sh
python3 -B evaluation/inprocess/test_tf_interval_samples.py
```

This mandatory standalone suite contains exactly two tests and retains all
projection assertions and malformed-record controls. It runs with limits of
3 CPU seconds, 10 wall seconds and 128 MiB address space. Its separate location
preserves the recorder's exact historical 350-test inventory; the combined
validation does not claim a 352-test recorder run. These supplied-data tests
grant no native qualification or performance credit.

The explicit `--sealed-custody` interval mode adds no production changes. It
requires three passed receipts at the same current revision and reserved CPU:
the original full lease cohort (148 subjects plus 6/49/17 prerequisites), the
separate 69-command/17-subject custody cohort including its exact stale-proof
and nested-cleanup refusals, and the original 40-command/17-subject interval
cohort. All source files must be committed before those prerequisites run.

The new mode builds an unobserved bridge with the fixed
`build-tf-sealed-custody.sh` recipe: the same 15 translation units and release
flags, with its exact 14 macros. Five additional header/link/import/symbol/reset
commands make the custody interval inventory 45 commands. The unchanged 17
subjects remain eight normal lanes, five protocol failures and four pre-exec
descriptor refusals. The two observed lanes use an explicit custody appendage
and actual emitted DWARF; native reference lanes and timing lanes keep their
original record contracts. A retained origin never satisfies a current fresh
maps receipt predicate.

Within the actual BODY, N=1 requires one fresh cancelled stage, no custody seed,
retained stage/check or commit, and one original permission-owner close. N=256
requires one fresh stage/seed, 255 retained stages, 509 fresh backing checks on
the retained route and 255 committed transfers. The final retained stage is the
old-NOP miss, with no commit. Each stage uses exactly the predecessor RX serial
plus one; only genuine handler-end changes RETURN to READY. Full original
frame/source/rseq/owner predicates remain, with complete FP at the original
endpoints and final close rather than an invented per-TRACE FP claim.

```sh
python3 -B evaluation/inprocess/page_selected_tf_interval.py \
  --expect-revision REV --qualification-receipt LEASE_RECEIPT \
  --qualification-sha256 LEASE_SHA --sealed-custody \
  --custody-receipt CUSTODY_RECEIPT --custody-sha256 CUSTODY_SHA \
  --baseline-interval-receipt BASELINE_INTERVAL_RECEIPT \
  --baseline-interval-sha256 BASELINE_INTERVAL_SHA --output FRESH_FINITE_DIR
python3 -B evaluation/inprocess/page_tf_interval_performance.py \
  --expect-revision REV --qualification-receipt CUSTODY_INTERVAL_RECEIPT \
  --qualification-sha256 CUSTODY_INTERVAL_SHA --sealed-custody \
  --output FRESH_PERFORMANCE_DIR
```

Performance still records all 20 fixed alternating native/gated samples and the
complete CSV under the original per-child limits and protocol. It reuses the
exact authenticated unobserved artifact; empty FD3 carries no BODY-local
custody claim. Original complete report predicates and the fixed global lease
and six loader counter joins remain mandatory. The raw observed custody proof
and separate required stale refusals precede timing; output equality alone
does not qualify the optimization. Run the original mode separately at the
same source/revision for a baseline comparison. Historical measurements are
not a controlled speedup comparison, and GO-to-DONE retains its full workload
round-trip meaning described above.
