# Bounded generated hash-loop experiment

`build-unrolled-hash.sh` builds a separate release profile. It recognizes one
24-byte, eight-instruction loader hash loop and emits 64 copies. Each copy keeps
the original data load; a direct conditional branch returns to the original
stop on NUL, and the final direct jump returns to the original head. One entry
therefore executes at most 512 original instructions without TF. This is a
specific retained-code experiment, not a general code cache.

The original source remains NX. A source borrow authenticates the same sealed
page, backing identity, generation, source bytes and complete guard used to
construct the plan. All 65 direct branch displacements must fit at the actual
allocated entry. Reuse requires the same source identity. The existing rseq,
native-page, REP, effect, fetch and generated-run ownership checks remain
required.

The actual runtime publisher uses protected private anonymous mappings. This
is a distinct publication contract from the sealed-slot proposal in the pure
planner header: generated pages are **not memfd-sealed**. Existing syscall and
mapping guards exclude application mutations of the protected metadata and
arenas. An unused page is written once, checked over all 4096 bytes, and changed
to read-only. It becomes RX only for its active owner and returns to read-only
at the original head or stop. The profile reserves two fixed 64-page arenas,
one ordinary and one `MAP_32BIT`; at most 64 immutable slots total are published.
There is no eviction, rewrite, allocation retry or enlarged slot count.

A genuine first-byte NX fault supplies each entry and normal exit. The hardware
executes original loads under the restored application state, including PKRU;
the handler does not read strings to predict loop results. Full saved FP state,
TLS and unaffected registers are conserved. Actual logical flags, including
undefined AF, are imported from the exit frame. Unexpected generated faults
retain their real frame and generated-to-original instruction mapping, then
terminate. They do not resume or earn completion credit.

`LI2_UNROLLED_HASH_OBSERVE_ONLY=1` retains the same arenas and signal counters
but never attempts this tactic. `LI2_MAPS_DIFFERENTIAL=1` additionally compares
the maintained address-space view with fresh complete maps observations.
These are distinct build profiles; default runtime builds are unchanged.

Qualification has three separate stages:

1. `evaluation/inprocess/unrolled_hash_component.py`: nine hardware-original
   versus generated cases, including two required inaccessible-load faults.
   Full flags, GPRs, FP, source, data and stack comparisons remain mandatory.
2. `evaluation/inprocess/unrolled_hash_owner.py`: nine native references, nine
   real page-gate application cases and seven required owner refusals. A
   qualification-only capture build binds its focal source to the actual ELF
   symbol and retains protected owner records through an exclusive descriptor.
   Its narrower descriptor policy does not qualify arbitrary applications.
3. `evaluation/inprocess/unrolled_hash_performance.py`: after both preceding
   stages pass at the same revision, six finite maps cases followed by 42 fixed
   release launches of `/bin/ls -d .` and `/bin/true`. Forty observation-only and
   generated samples measure whole-process time; two differential runs provide
   separate qualification. Failed attempts stay in the cohort. Medians and IQR
   require the complete cohort to pass.

The performance report counts actual signal entries and maps acquisitions.
Existing route counters overlap and must not be summed into a trap total.
Component process duration includes setup and capture and is not throughput.
Results do not establish a general translated-fault continuation, complete
selected-instruction coverage, or the target of ten times DynamoRIO unless the
corresponding application measurements demonstrate it.
