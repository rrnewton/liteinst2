# Page-runtime event budget

`page_event_budget.py` measures the release page runtime's event counts and
handler time on `/bin/ls -d .` and `/bin/true`. Run it from a clean committed
checkout with one reserved CPU:

```sh
python3 -B evaluation/inprocess/page_event_budget.py --expect-revision REVISION
```

Replace `REVISION` with the full commit ID. The script retains the exact source,
compiler inputs, commands, hardware, executable identities and process outcomes.
It writes compact numeric JSON and CSV under `evaluation/inprocess/results/`;
full command captures stay under `target/`.

The fixed cohort interleaves three observed and three unobserved launches of
each program. Both variants retain the original page-runtime qualification.
Each launch has the original 30 CPU-second, 60-second wall, 512 MiB address-space
and 16 MiB file limits. Failed attempts remain failures.

The observer counts actual handler entries, ordinary C syscall-gateway calls,
fresh maps acquisitions and their physical I/O, decoding calls, admission
operations and TF-chain fallback sites. A bounded nested timer assigns each
measured interval to exactly one leaf. Count times mean duration therefore
reconstructs the measured handler total without adding overlapping intervals.
Signal and route durations are separate inclusive views of that same total.

Timing starts after the original ingress guards and stops before return or
reporting. Startup, ingress guards, execution and signal transitions between
handlers, reporting and reaping remain an explicit process-time residual.
Handler-body means are not complete trap latencies. Observer overhead is
reported from the paired cohort; it is not subtracted from another benchmark.

The fallback histogram retains up to 16,384 distinct sealed-source tuples and
reports the top 32, a full-table digest and explicit overflow. A nonsealed
fallback invalidates the diagnostic. Object IDs describe captured lifecycle
objects; the summary does not independently attribute them to public DSO names.
Internal gateway counts do not establish the number of external ptrace stops.
