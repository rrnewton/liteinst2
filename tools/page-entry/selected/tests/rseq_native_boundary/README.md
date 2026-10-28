# Registered native boundary retry

This explicit profile extends the registered native-page owner with a bounded
two-signal boundary retry. It does not change the original registered-native
profile or its sixteen-case qualification, including its straddler refusal.
The page bytes remain unchanged, and all ordinary decoded-instruction and rseq
write-footprint guards still apply.

The first actual NX frame must place the current kernel RIP within fourteen
bytes before the next page boundary, with CR2 and siginfo naming that boundary.
Its RIP page must be the one actual admitted page. The owner verifies closure,
fresh registration-page identity, the zero publication word and actual FS/GS
bases before returning the original frame. A retained WAIT_REFAULT token keeps
the pure zero/pin guard active before any returning runtime syscall at the next
handler entry.

The second actual NX must name that same RIP as its first-byte fault. The old
native owner compares all saved registers, selectors, flags, signal mask and
complete FP bytes, excluding only CR2. A separate zero-page close observation
and fresh matching TLS/pin observations must succeed before the token is
consumed and execution passes to the existing decoded owner. No instruction
completion or second page revocation is inferred from the retry.

RIP is the kernel's current architectural PC. It may already be an rseq abort
target; this protocol does not reconstruct an earlier PC or claim an absence
of publication during the preceding native epoch. Far, backward, same-page,
changed-frame and unbound pending retries remain refusals. The unsafe-entry
path still terminates without repairing the application word or claiming a
verified close.

Build the explicit profile with:

```sh
sh tools/page-entry/selected/build-rseq-native-boundary.sh
```

Run the unchanged five-case release matrix on one reserved CPU with:

```sh
python3 evaluation/inprocess/native_pages.py \
  --expect-revision "$(git rev-parse HEAD)" \
  --output evaluation/inprocess/results/native-pages-rseq-boundary.json \
  --cpuid-nx --rseq-native --rseq-native-boundary
```

The original 30 CPU-second, 60 wall-second, memory and output limits apply.
Every exit/output/completion/source predicate remains mandatory. The separate
`LI2_RSEQ_BOUNDARY` row records attempted and completed retries; a partial prefix
does not confer completion. Private observations retain both complete close
records and both genuine frames. Public summaries omit their addresses.

Qualification requires the original sixteen-case profile plus genuine split
MOV, split CALL, CALL-ending-at-boundary and bounded abort-target cases. The
CALL-ending case must not retry the CALL. Execution results are reported
separately at the tested revision; this profile alone does not establish B2 or
B3 completion, application completion, or performance improvement.
