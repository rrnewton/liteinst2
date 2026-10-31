# Complete-request E9 backend generation

One bounded backend attempt at `8d3d1be` emitted a 282,324-byte candidate. Debug records match all 2,053 patch addresses (1,210 B1 / 841 B2 / 2 T3). **The candidate was not executed or independently qualified.** [Exact results](receipt.json) retain commands, timings, bounds, hashes and released ownership; memory peak is charged-scope memory, not RSS or target performance.

The [AS 1 GiB failure](../full-program-whole-result-v1/) and zero-dispatch wrong-interpreter help refusal remain. This separate AS 36 GiB / memory 1 GiB profile accommodates the backend's fixed 32 GiB VMA reservation.

The later [portable script](../offline-corpus/run_e9_backend.py) verifies the pinned original and complete RPC using a filename-token digest, then changes only `binary.params.filename`; every other wire line remains exact. Its current clean `REV` is separate from the measured revision. This port has not run a backend.

Retain one disjoint HARD CPU (lane<=12/1200%). Set `CPU`, fresh `UNIT` beginning `li2core-e9-backend-36g-`, inputs and fresh `OUT`. Run this argv via `evaluation/admission/processes.py::run_command`, with a fresh target/evaluation log and 110 s / 8 MiB; retain an owned 120 s / 8 MiB lease parent whose hard AS permits 36 GiB:

```sh
systemd-run --user --scope --collect --quiet --unit="$UNIT" \
 -p AllowedCPUs="$CPU" -p CPUQuota=100% -p MemoryMax=1073741824 \
 -p MemorySwapMax=0 -p TasksMax=64 -- /usr/bin/python3.9 -I -B \
 evaluation/offline-corpus/run_e9_backend.py --revision "$REV" \
 --cpu "$CPU" --unit "$UNIT" --original "$ORIGINAL" --rpc "$RPC" --out "$OUT"
```

Actual scope settings are checked; failures are retained without retries. If OOM prevents an inner receipt, the outer owner must retain failure and close custody. No whole-program parity claim follows.
