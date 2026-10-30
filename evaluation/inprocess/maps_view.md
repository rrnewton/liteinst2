The maintained maps experiment removes repeated maps acquisitions from the
singleton page runtime. `LI2_MAPS_MAINTAINED=1` enables a separate address-space
view after bootstrap and self-test. The default maps-phase profile is unchanged.
`LI2_MAPS_DIFFERENTIAL=1` compares every reused view with a fresh acquisition;
any difference poisons the view and refuses the operation. Neither option
changes the source, backing, allocation, generation, alias or entry predicates.

Successful intercepted `mprotect` updates the view's permission intervals.
Other mapping operations invalidate before execution. Failed or partial
operations require a fresh acquisition. Nested adapters apply each update once.
The runtime still refuses unsupported guest operations, including `mremap` and
`exec`; invalidating their raw gateways does not add support for them.

The view represents maximal contiguous intervals with identical permissions,
sharing and backing identity, and continuous file offsets. Differential mode
compares every field of every canonical interval, including unmapped gaps.
Bootstrap checks that require actual VMA boundaries run before this mode is
enabled. Existing owners that demand physical fresh acquisitions retain those
demands and receipt checks. Projected and differentially verified observations
have separate receipt kinds; they are never labelled as fresh acquisitions.

Kernel stack expansion needs separate treatment. The bridge registers the real
initial stack pointer. Before reuse after a handler boundary or a kernel access
that could grow that stack, a private `mincore` probe checks the page below the
last raw stack extent. A mapped predecessor requires a fresh view. Before a
mapping operation could split an unobserved grown stack, growth retires reuse.
Operations touching the tracked stack also retire reuse. All later queries then
use fresh maps. The runtime already refuses additional grow-down mappings and
shared-mm threads. `READ_IMPLIES_EXEC` is refused before enabling the updater.

Reproduce the finite native oracles and release comparison with a reserved CPU:

```
python3 evaluation/inprocess/maps_view.py --expect-revision FULL_COMMIT_SHA
```

The evaluator records the exact revision, hardware, compiler/input identities,
commands, numerical outcomes and raw timing samples under `evaluation/`. It
requires the native positive and refusal controls before the 42 fixed real
launches: ten baseline and maintained samples each for `ls -d .` and `true`,
plus one differential run of each. Existing CPU, wall, memory, output and
application-result bounds remain unchanged. Differential timing is diagnostic;
it receives no performance credit. The baseline reports wall time and existing
route counts, not a newly measured physical maps-open count. On a successful
maintained run, miss refreshes plus differential comparisons count its physical
fresh acquisitions. No result or ten-times-DynamoRIO claim is implied by the
implementation alone.
