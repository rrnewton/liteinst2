# Fast reset and canonical atomic base registers

This increment adds an optional full-byte reset and canonical `LOCK CMPXCHG
r/m32, EDX` addressing for all 16 base registers. It does not complete the
selected runtime's real-program envelope: all four real-program/environment
pairs below still fail, and source patches and page admissions remain zero.

The optimized reset preserves the complete 200,896-byte chain slot. At
`af08160895fb9af7ab06d6245c75d06027e08329`, GCC 11.5.0 `-O2` on an AMD EPYC
9D85 produced a 15-byte `CLD; REP STOSB` helper. Six native processes each
passed all 273 functional cases. Across 16 measured intervals per lane,
with 256 fills per interval, mean scalar and fast costs were 67.756487 and
1.664589 microseconds per fill (40.704638 times). These are warm helper-call
batch measurements including loop/call overhead, not runtime speedups.
[The primitive receipt](results/20261028T035139.737337Z-page-selected-fast-memset-af08160895fb.json)
contains every interval, hardware, exact revision and command.

The actual fast function then passed all 47 native full-state fixture
processes at `a6b970fbbed6f1cbf7d40cb00ef8dbe282d163ce`: generic, TRACE,
register semantic/capacity, failure controls and REP. All 29 required failed
operations retained exit 125. The unchanged comparators cover registers,
flags, FP/XSAVE, stack/data, unused storage and cleanup.
[Qualification receipt](results/20261028T040416.091596Z-page-selected-fast-zero-a6b970fbbed6.json).

At `7e8f902eb56597eba42d94335a46588cbaf385d0`, the canonical atomic extension
passed 152 new native/stepped pairs (76 matching and 76 mismatching), 24
paired genuine memory faults, 352 actual-before write-footprint queries and
2,656 refusal checks. Every footprint includes the full four-byte RMW range,
including comparison mismatch. Width, source-register, prefix and addressing
aliases outside the explicit family remain refused. The prior RIP atomic,
R13 atomic, write-footprint, generic and TRACE regressions also passed.
[Atomic receipt](results/20261028T035418.431658Z-page-selected-lock-cmpxchg-base-7e8f902eb565.json).

The explicit `--fast-memset` inactive-rseq profile at
`c57dff0d36e4837d1719871698aa7104106cd9a8` passed its 17-case application
oracle: two complete applications and 15 required refusals. The default
scalar profile is unchanged.
[Application receipt](results/20261028T040541.889428Z-page-selected-rseq-application-fast-memset-c57dff0d36e4.json).
The four unchanged real-program pairs completed **0/4**: default `true`
refused classifier policy 0 (error 1207), rseq-disabled `true` refused
`f0440fb12f` (`LOCK CMPXCHG [RDI], R13D`), and both `ls -d .` processes were
killed at the existing 30-CPU-second bound. No first-touch or steady-state
numbers are claimed.
[Real-program receipt](results/20261028T040610.071553Z-page-selected-rseq-real-fast-memset-c57dff0d36e4.json).

All six required checks passed at that same revision: formatting, clippy,
workspace check, 2,571 workspace tests (8 ignored), recorder tests, and
1,039 serial-launch tests. Source/configuration closure and cleanup passed.
[Checks receipt](results/20261028T040830.511161Z-checks-c57dff0d36e4.json).

For reproduction, check out the exact revision in the corresponding JSON
and run its `reproduce` argument vector. Native scripts require one reserved
CPU; the checks use four. Set `CARGO_INCREMENTAL=0` and use the same single
Cargo target directory. JSON records include tool versions, hardware,
resource bounds, outcomes and hashes; raw process output remains private.
