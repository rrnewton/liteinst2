Timing and all six required checks passed at `78cf2fcafc25b6a0fd8aaf1442e5c3ed60bd4a1d`. Saved audits verified capture/log hashes, arithmetic, outcomes and cleanup; they did not repeat full-state/semantic readers. The [actual receipt](20261029T134410.388448Z-page-selected-effect-time-78cf2fcafc25.json) retains all 11 raw samples, 11 origins and two entry stamps.

| Observed interval | First ns | Ten hits: min / median / max ns |
| --- | ---: | ---: |
| Entry to first closed unit | 138,388 | Not repeated |
| Two-MOV block round trip | 201,703 | 156,685 / 161,773 / 170,536 |
| Publication API | 37,356 | 7,251 / 10,396 / 13,951 |

[Checks](20261029T134632.993973Z-checks-78cf2fcafc25.json): recorder 350; fmt; strict Clippy; workspace 3,260 passed/36 ignored across 103 harnesses; all-target check; serial 1,039 passed across 27 harnesses. Zero failures, all cleanup complete, source/configuration unchanged.

Entry starts **after li2_boot**, before original state restoration, and ends after the first MOV RSP→RDI completes through genuine STEP/revoke/release, before CALL. Block timing excludes source fetch/plan and ends after generated exit/reset before guard; publication ends before arm. Discovery froze the lowest eligible interpreter offset, 46,332. No sample was discarded. These are neither full first-touch nor whole-app steady throughput or speedup measurements.

The original three clock fixtures exited 0/125/125. Four actual seam modes exited 0/125/125/125, with 78 supplied-record refusals. Native/gated discovery and measurement each completed with identical dot/newline output; both gated runs retained default application rseq.

Separate regressions passed at `4818594540c6b756ca126d4d11c018d26c7fc6de`: SLOW preflight skipped fresh borrowing; full-capacity SLOW consumed/released once after 64 immutable publications. Both reached natural NX without executing generated code. TRACE7 retained two completed runs and six required failures. Normal unobserved LS recorded 1,115 TRACE completions, 148 restored publications and 147 completed effects plus the nonreturning exit. Its whole-process durations remain separate functionality evidence in the summary.

Both 9fae SLOW failures remain failed: missing-path setup after one metadata command and zero native subjects, then an unsupported-ADD guard mismatch in the separate attempt. The e23bc66 timing attempt remains failed overall: private validation passed, but its 12,154-byte projection exceeded the unchanged 10 KiB guard. The fresh pass does not rewrite history.

Timing used reserved CPU 45; regressions used CPU 1, on AMD EPYC 9D85/Linux 7.1.3. [The summary](2026-10-29-entry-run-timing-78cf2fcafc25.json) binds exact versions, bounds and receipt hashes. Finite subjects retain 5 CPU/15 wall seconds; real programs 30 CPU/60 wall seconds, 512 MiB/16 MiB. On one externally reserved CPU:

```sh
python3 -B evaluation/inprocess/page_selected_effect_time.py --expect-revision 78cf2fcafc25b6a0fd8aaf1442e5c3ed60bd4a1d
```

Runtime bytes are unchanged from e23 through 78; only the SLOW guard reader and public projection changed. Full B2, general entry routes and 9,216-effect app stress remain outside this milestone.
