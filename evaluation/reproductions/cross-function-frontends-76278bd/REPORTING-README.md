# Saved reporting reproduction

The tested source is `76278bdfd19db60a0734ed1195d0f96d9da1a680` on the saved **AMD EPYC Zen 5 dev host**. These scripts project existing validation records; they do not run Cargo, native cases, or benchmarks. The separate 822c history preserves its targeted success and strict Clippy failure.

The first collector failed with `invalid_harness_binary_path` before creating its output. The exact failed source is `collect-cross-function-v1-failed.py` (SHA256 `6d4f077822e94b05f33bd1f48b6ef21d67e51a345bd6b818241514bd78125d5c`). The corrected collector at `evaluation/collect-cross-function.py` is SHA256 `a917b61f00df9c6aeaa32dc9b543ef9f500d48ef6e01b7e5472ca104f4a274e7`; it joins only three exact zero-test Cargo examples. All original assertions, counts and workload outcomes remain. The unchanged shared parser still reports its actual limitations in `parser-results.json`.

With the exact private saved-record caller and its referenced files available, use fresh output paths:

```sh
python3.9 -B evaluation/collect-cross-function.py --inputs "$PRIVATE_INPUTS" --inputs-sha256 dbb15d256587db9936555e790330e2cd57d1f30b116cdd78a631528cf5f4c0a3 --new-output "$FRESH_REPORT"
python3.9 -B evaluation/reproductions/cross-function-frontends-76278bd/controls.py --collector "$REPO/evaluation/collect-cross-function.py" --inputs "$PRIVATE_INPUTS" --inputs-sha256 dbb15d256587db9936555e790330e2cd57d1f30b116cdd78a631528cf5f4c0a3 --out "$FRESH_CONTROLS"
```

The controls source SHA256 is `929087223cb6ef592a38c778f55b184e4743e378bd232a38f289532922ce8240`. Its five recorded outcomes comprise one full positive projection and four intended assertion refusals: missing successful log, missing successful inventory, mismatched example source/binary, and duplicate example identity. Synthetic callers and inventories are copied beneath the fresh controls output; actual inputs remain unchanged. The positive control's ten public files are byte-identical to the real collection.

Reproduce the saved request environments, affinity and limits in `reporting-history.json` through the unchanged `tools/unwind-oracle/bounded_command.py` helper. Real collection used 60 CPU seconds, 90 wall seconds and a 64 MiB per-file cap, with outer 100/10 and parent 115 second bounds. Controls used 10 CPU seconds, 15 wall seconds and 1 MiB per file, with outer 25/10 and parent 40 second bounds. Each used four CPUs. The failed collector uses the same real-collection profile and exact caller, with a fresh absent output. The normalized command contexts preserve the exact original private script coordinates; these public script paths are byte-identical exports, not claims that the historical argv used the public locations.

The complete private caller, raw logs and role-to-path inverse are not published. Therefore the public sources alone cannot replay these exact saved records. Expanding the public path-role tokens requires the corresponding caller authority; restoring bytes does not recreate historical owner continuity. Timings are operational observations. Repeated test counts and nested terminals are not additive qualification, and neither reporting success nor these controls establishes full A3 or a new native result.
