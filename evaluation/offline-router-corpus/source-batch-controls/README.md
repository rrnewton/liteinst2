# Fresh source-batch controls

The native admission path now uses one fresh Git blob batch and the unchanged
inventory check at every existing stability boundary. Exact retained lengths,
ordered content hashes, Git object framing, live bytes and inode identities
remain checked. The 15-second Git and 30-second observer limits are unchanged.

Final focused results: 159 artifact controls, 207 native controls and 21 E9
executor controls passed. The first native run had five errors in the added
test recorder: a string pathname was treated as a `Path`. Normalizing that
argument fixed the recorder without changing any assertion. That failed run is
retained in `results.json`; the 159 unaffected artifact results come from it.

Reproduce from the checked source with Python 3.9:

```sh
python3 -B evaluation/offline-router-corpus/reproduce_preparation.py controls-inner
python3 -I -B evaluation/offline-corpus/full_startup_e9_execute_controls.py "$PWD"
```

The receipt records the exact base plus source overlays used, commands, raw-log
hashes, disjoint CPU reservations and load averages. No native application was
dispatched and no performance improvement is inferred from these controls.
The earlier observer timeout and E9 membership refusal remain failures. The E9
runner now records actual versus expected membership and preserves the closed
command exit before that check; its acceptance predicate remains exact.
