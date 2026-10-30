# Current-custody component

This is a source-only qualification candidate. It includes the actual complete
`lifecycle_loader.c`, links the actual default eight-source decoder archive, and
uses real sealed memfd mappings, permission changes, source reads, descriptor
observations and `/proc/self/maps` open/read/EOF/close operations. It executes no
application instruction and installs no signal handler. The step owner, session
and handler boundary are explicitly supplied component inputs. It provides no
actual TF, full-frame, rseq runtime-entry or bridge protected-range credit.

The recipe is `build.sh SELECTED OUTPUT ARCHIVE projected|verified`; it produces
`OUTPUT/maps-current-custody`. The native interface is `maps-current-custody MODE`,
with modes 0 through 13, once each in both profiles: 28 fixed processes. Each uses
the original 5 CPU-second, 15 wall-second, 512 MiB address-space and 16 MiB output
limits. There are no retries or substitute modes. Modes 0–2 must exit 0; modes
3–13 must reach the specified actual API refusal and exit 125. Unexpected fixture
failure exits 124 and cannot qualify. All 28 and every reader control are mandatory.

| Mode | Actual API sequence / required result |
| --- | --- |
| 0 | Cold current stage/commit/publish/return, event boundary, retained current lifetime. Also 29 ticket refusals: wrong serial/owner/view, 22 named descriptive-field corruptions, double release, and actual wrapped RAW/query/phase invalidations. |
| 1 | Current lifetime, discard, old physical lifetime, boundary and exact current UNAVAILABLE followed by physical retention, discard, new current lifetime. Stale `bound` never becomes physical ownership. |
| 2 | Old physical lifetime and physical ENTRY fallback/retention without any current payload. |
| 3 | Actual current ENTRY plus supplied stale epoch: current stage refuses STATE (303), never UNAVAILABLE. |
| 4 | Supplied ENTRY without either origin: current stage refuses STATE. |
| 5–7 | Actual current stage passed to old commit/cancel/publish: exact foreign-pointer STALE (302). |
| 8–10 | Actual physical stage passed to current commit/cancel/publish: exact foreign-pointer STALE. |
| 11 | Actual physical RETURN passed to current return: STATE. |
| 12 | Actual current RETURN passed to old return: STATE. |
| 13 | Actual current READY plus supplied maximum epoch: actual discard poisons without wrapping; current stage refuses STATE. |

`check.py` exports `check(stdout, stderr, exit_status, mode, differential)` and
`controls` with the same arguments. The canonical single JSON line is bounded by
32 KiB; stderr must be empty. `FIELDS` names all 80 event columns. The reader binds
the exact operation sequence, both distinct private stages, shared phase/epoch,
held borrow sequence, first error, historical typed origins, separate producer
counters and maintained-view/physical-I/O equations. The original physical seed
remains strictly FRESH with real I/O. Current query provenance is strictly
PROJECTED/no-I/O or VERIFIED/real-I/O and retains its separately observed physical
baseline; retained stages do not fabricate new maps receipts.

The fixture initializes/seals the real decoder once, decodes each supplied NOP
request, and requires its complete 48-byte statistics unchanged afterward. No
descriptor is mocked. The summary retains all eight statistics fields. Every
accepted native record must reject 25 copied-record/protocol mutations (700
total); these perform no native operations and grant no additional native credit.

Before terminal output, the source page is actually changed to R, synchronized,
and compared over all 4096 bytes with its original sealed ELF bytes. Successful
cases perform the real borrow release; refused cases retain their failed/held
prefix rather than inventing a release. All cases then unmap the source and close
both original and retained descriptors. The old cancel case honestly retains
STAGED/current-owned with no fetch error until this terminal revocation: that old
API only refuses its foreign stage pointer. Actual maps I/O through cleanup is
included in the final census.

The existing old physical fixtures, production APIs and all their checks remain
unchanged. Launch's separate integration helper must authenticate the actual
default archive, compiler `-M` closure, executable/library/tool/source closure,
both recipes and all 28 supervised outcomes. It must also bind all nine new static
state objects to the actual compiled production bridge's complete protected
RW/NX PT_LOAD extents using ELF/DWARF, not these component addresses. Genuine
bridge cold-TF full-state comparison, nested/fault cleanup and the rest of
`integration/QUALIFICATION.md` remain required before production/performance
credit. No build, native execution or reader/control replay occurred here.
