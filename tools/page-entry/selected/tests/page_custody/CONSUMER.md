# Sealed-page custody proof consumer

This fixed leaf consumes the actual `cso_stream` emitted by the custody observer. It does not launch subjects, select policies, issue validation queries, or manufacture records. Source review and supplied negative controls are not native qualification.

The public calls are:

- `gated(record, layout, image, pid, exit_status, cpu, *, fault_event=0, stack_context=None, overlap=False)`
- `pair(nrec, grec, nout, gout, layouts, image, npid, gpid, cpu)` for ordinary cases 0–4, using the original native reference
- `stack_pair(nrec, grec, nout, gout, layouts, image, npid, gpid, cpu)` for the genuine stack-growth pair
- `reports_join(stderr, record, layout, image, pid, result)`

`layouts` has the exact `native` and `gated` emitted layouts. The enclosing qualifier must bind each layout to its actual ELF/DWARF and retain the complete record. The stream is below the unchanged 16 MiB cap; truncation, extra bytes, unknown types, and nonzero retained C padding fail.

`image` is the fixed ELF reader's authenticated original image, enriched with `backing={bytes, sha256}` from that gated launch's complete carrier. Original source bytes and retained backing size are distinct authorities. No parent execution descriptor is claimed as the runtime's retained descriptor. Process IDs and the reserved CPU are independent launch inputs. `stack_context` comes only from the fixed stack leaf's complete output/proof reader, including real maps, stack limit, target, growth, PID, and retained bytes; it is not an arbitrary comparator callback.

FRESH requires the original successful stage's current maps acquisition and complete source/backing/page/opening-owner proof. RETAINED requires the exact earlier origin, an uninterrupted READY → ENTRY → STAGED → COMMITTED → RETURN → READY sequence, and each actual backing check. Current maps/preparation/validation fields remain zero wherever the producer performed no corresponding query. The original origin is never relabelled as current. Every instruction still joins its actual rseq check and full genuine TRACE frame. Old revoke/release/closure and full endpoint FP comparisons remain required.

The embedded base retains the original finite assertions. The new `_core` has an exact source inverse to the original `tf_same_page/check.py::gated`; only fixed custody receipt semantics, explicit warm/stack/overlap source models, and the new profile's exact close-invalidation error differ. Original cold cases 0–9 remain mandatory. Warm cases 6–9 require one completed transfer before the second event's failure. Overlap uses `fault_event=0, overlap=True`, two completed ADDs, and the original 1205 refusal before MOV. In this new profile only, case 7's actual raw close discards custody before commit, yielding exactly STALE 302 and exit 125. The untouched baseline retains its original 307 comparator. No either-code acceptance is used.

The stack pair requires four genuine endpoints and two episodes. A real MOV grows the actual fresh-exec stack, then a retained code-page stage occurs before any fresh maps query. A real close and syscall precede the second cold episode. All source, full endpoint state/FP, literal memory, page identity, and actual stack proof remain mandatory; typed differences between independently created process addresses are validated before cross-lane comparison.

`gated` returns `accepted`, `case`, `exit_status`, `operation_status`, `events`, `transfers`, `real_closes`, `observed_cpus`, `cpuid`, `nested_sender_uid`, selectors, and the separately counted custody events. Acceptance means the required outcome was verified: exit-125 operations remain `failed`. Pair results retain `successful_pair=1` only after both complete readers and full endpoint joins. Reports use only the new literal loader-scope adapter before the unchanged report parser, completion predicates, and binary terminal joins. Raw records and stderr are never rewritten.
