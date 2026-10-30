Private source-only actual-TU component; no execution or runtime-entry credit.
Build: build.sh SELECTED_DIR OUTPUT_DIR; output maps-view. Run all six modes
once with the existing owner: 5 CPU/15 wall seconds, 512 MiB, 16 MiB capture.
check.check(stdout_bytes, stderr_bytes, exit_status, mode) requires one exact
JSON line. Modes0/5 exit0;1/2/3/4 require125. No retry/split or cap increase.

Mode0: real mappings, partial-ENOMEM mprotect, sealed-file writable aliases,
nested gateway, user and same-handler pread64 stack growth, stale-bottom split
retirement. Later stack-mprotect remains fresh; it is not a second independent
retirement-trigger claim.
1/2: actual untracked mutation, mismatch303 then persistent poison303.
3: missing anchor;4: explicitly supplied READ_IMPLIES_EXEC refusal.
5: real shared anonymous anchor requires permanent fresh fallback.
All fixture-owned mappings/fds close even on refusal. Event boundaries are
supplied API calls. Stats end before cleanup/printing; all counters are exact, including
invalidations [21,2,2,0,0,2]. Old sources/tests/limits remain unchanged.
