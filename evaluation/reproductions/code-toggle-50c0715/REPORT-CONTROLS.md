# Saved-report refusal checks

Two synthetic omissions were checked after the real validation records closed at `50c0715e015107c92a8ecee03735645a83734220`. A missing successful command log and a missing reviewed case inventory each reached its exact assertion and created no report output. The actual log, caller and collector remained unchanged. These are reporting checks, not additional workload tests.

`report-controls.py` is the exact executed source (SHA256 `6bde22bb9e3e1fe1a1610c71db65eea64c41bff421daef00387b3c169ec09fec`). It requires the exact `evaluation/collect-code-toggle.py` source and a complete, authenticated caller following that collector's schema. The caller contains local raw-evidence coordinates and remains private. The validation reproduction recipe explains how to obtain fresh records; copying published PASS rows cannot supply missing logs or inventories.

The control command has this form, with absolute paths and the SHA256 of the supplied caller:

```text
/usr/bin/python3.9 -B report-controls.py --collector COLLECTOR --inputs INPUTS --inputs-sha256 SHA256 --out NEW_OUTPUT
```

Run it through `tools/unwind-oracle/bounded_command.py` with the historical request limits: 60 CPU seconds, 90 wall seconds and 64 MiB per output file, CPUs 0–3, outer timeout 100 seconds with a 10-second kill delay, and a parent wait of 115 seconds. It requires assertions enabled and fresh output under the checkout's `ignored/` directory. The script replaces a read predicate in memory for one control and supplies a copied caller for the other; it never removes or renames an actual input.

[reporting-controls.json](../../data/code-toggle-50c0715/reporting-controls.json) preserves the exact normalized requests, parent commands, environment, bounds, successful waits, strict helper receipts, source hashes, hardware and both assertion outcomes. `${REPO}` and the other path roles replace private absolute coordinates reversibly; raw helper streams and tracebacks remain ignored, with hashes recorded. Historical collection and control timings are operational observations, not benchmarks.
