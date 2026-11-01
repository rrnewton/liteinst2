# Installed direct-CALL campaign

Revision `651269c6fc111c1f5f2b957be2e251818d6c0f5b`: all twelve finite recipes and the 41-instruction native oracle passed. The campaign **failed** because both whole-program subjects (`/bin/ls -d .` and `/bin/true`) were killed at the unchanged 30-second CPU limit. These observations grant no original392/cross-pair522 qualification or performance credit.

`summary.json` records all fourteen stage outcomes, exact receipt and command digests, hardware, bounds, source identity, populations and reproduction commands. `programme.csv` contains the measured times and event-count prefixes for every programme case. Prefixes from killed runs are incomplete; they are not completed-run throughput or counts of every kernel trap.

The summary uses named columns and shared metadata to keep the record compact. Expand it from the repository root with:

```sh
python3 -B evaluation/inprocess/expand_campaign_summary.py evaluation/inprocess/results/20261101T045315.195046Z-installed-direct-call-651269c6fc11/summary.json
```

Expansion verifies the canonical decoded digest. Presentation omits 24 successful finite per-case detail rows and repeated stage descriptors; their exact source receipts and the unabridged summary are digest-bound. All stage outcomes, errors, command counts, bounds, aggregate populations and failed or incomplete cases remain visible. No acceptance gate is changed. Reproduction uses the public scripts listed in `reproduce.commands`, in order, on a reserved CPU; substitute the newly produced receipt paths and their SHA-256 digests for the placeholders.
