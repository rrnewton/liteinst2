# Two ordinary calling workers

`ordinary-interval normal-session-two CANDIDATE FINAL ELF_VA LENGTH K EPOCHS`
adds a finite two-caller application route. The original `normal-session` route,
worker, ledger, protocol, I/O and tests are unchanged. This new route requires the
independently qualified unchanged FreeBSD strnlen final ELF, 41-byte selected
extent and its RET offsets34/40. File/source/selection authentication and native
prerequisites belong to the qualification recipe; this CLI is not discovery or
an arbitrary-function semantic certificate.

One direct typed C ABI call processes each accepted external CALL. The controller
selects three distinct already-permitted CPUs, creates both workers before
narrowing its affinity, and waits for both actual-thread attachment Ready events
under one original two-second setup deadline. It dispatches no subject work
before both observations. The sealed TwoCaller owner, global publication
quiescence, D1 per worker, immutable inputs/source/images, process-lived owners
and no signals/reentry/unwind/cancellation/fork/CET remain unsafe application
obligations. No per-call profiler wrapper or alternate engine is introduced.

E4/T2/D1, M2 and A4096 preserve E*A=16384. Each worker owns a capacity2 FIFO and
one reply slot; one additional logical pending command remains controller-owned.
CALL acceptance alternates workers, independently of FLUSH. The unchanged grammar
and ID set admit at most4096 CALL+FLUSH commands, with globally unique canonical
u64 IDs, at most4096 input bytes and bound<=input length. The controller never
reroutes a Full queue or drops an accepted command.

FLUSH holds its ID, each assigned-call prefix and per-worker sent/ack bits until
both exact acknowledgements arrive. Later input acceptance pauses, while timer,
retirement, reply and nonblocking output work continue. STOP cannot overtake this
barrier. Each worker checks all retained input bytes and guards, independent
scalar results and complete source/generated spans before its own unsafe
checkpoint, after at most four calls or idle. Its final Stop adds an empty
checkpoint and detach. Success requires both actual joins and complete final
population/history/Report checks; fail-stop is never successful cancellation or
code reclamation.

The controller uses the unchanged Schedule/10ms period, inclusive2ms arm limit,
strict shutdown and active idle-wait policy. It processes at most one reply per
iteration, rotating preference, with two nonblocking probes. Concurrent metadata
waiting has no fairness or latency guarantee. This route consumes a controller
CPU during timed operation; it makes no low-overhead, throughput, accuracy or
all-interleaving claim.

Two independent ledger cursors verify actual registration/TID, local ordinal,
batch, full512-word journal, totals, sampled completion sequence and monotone
absolute history prefix. The shared ledger joins real generation/invocation
slots to every final Report payload. Report slots and retained ranks are separate
contiguous sets; a rank is not a slot or arrival order. Completed counts all
admitted confirmations, including DroppedAfterBudget. Each Report requires
retained=min(K,admitted), dropped=admitted-retained and no cancelled/unfinished
records. FunctionClosed is checked against K retained outcomes in its final
Report. No timestamp or request ordering selects an owner. Prompt retirement
copies data and drops each Report; data-only batches/history retain no epoch
permit. Two old pending owners plus current and fresh fit E4 under that rule.

The prospective stdout grammar is LF-only CSV with these fields after each tag:

- READY: normal-two-session-v1,K,epochs,10,2,4096,4096,2,1,2,1,4,2,4096
- WORKER: worker,registration,TID (exactly1/1 then2/2)
- RESULT: ID,worker,registration,ordinal,bound,input_len,FNV,value,owner,generation,invocation_plus1,prefix,RET_offset,ack,start,end,start_AUX,end_AUX,batch
- FLUSHED: ID,confirmed1,confirmed2,batch1,batch2,completed1,completed2
- HISTORY: chunk,prefix,published_or_removed,generation
- REPORT: generation,admitted,retained,dropped,cancelled,unfinished
- SAMPLE: ID,worker,registration,generation,invocation,entry_value,start_sequence,retained_or_dropped,rank_plus1,terminal_value,end_kind,end_value
- WORKER_DONE: worker,batches,entered,ret_observed,confirmed,completed,unsampled,1,1 (ordered1 then2, after actual joins)
- IO: actual write-EAGAIN snapshot
- DONE: reason,arms,actions,accepted,calls,admitted,retained,dropped,unsampled,batches,flushes,0,0,2,2

RESULT owner sampled means admitted, including a later dropped disposition;
unsampled owners are closed/removed/initial with invocation_plus1=0. SAMPLE rank
is encoded+1, zero only for dropped. Terminal value is the invocation slot; end
value is the raw endpoint or unavailable reason (AUX mismatch1 takes precedence
over counter reversal2). No cross-worker clock ordering is asserted. Results
and intermediate metadata before DONE do not establish successful completion;
normal exit, empty stderr and whole transcript qualification remain necessary.

The unchanged350-byte row and4MiB total I/O guards remain authoritative. For
C+F<=4096, S<=C and arms<=4096, all arbitrary20-digit IDs/generations/ticks/TIDs,
10-digit AUX and every row fit
`195C+59F+136S+49*(arms+1)+47*arms+328 <= 1,749,369` bytes. No input strings or
duplicate journal pages are serialized. Six pure controls exercise real
validators/dispatchers without native credit. Fresh two-worker SDK/native and
external producer qualification remain separate prerequisites; prior failures,
old populations, comparators and limits are not rewritten.
