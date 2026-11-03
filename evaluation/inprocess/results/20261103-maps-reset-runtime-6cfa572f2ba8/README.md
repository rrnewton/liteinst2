# Maps reset runtime observations at 6cfa572f2ba8

The JSON and nine-row CSV project four closed receipts from the same source and CPU. The paired native and causal checks passed their stated scopes. Both plain RO programs and both ABI6 programs failed with exit -9 under the original 30 CPU-second limit. No program terminal, completed measurement, performance comparison, full owner/lifecycle qualification or full19 pass is claimed. Earlier failed attempts remain unchanged.

The ABI6 data are sealed per-cell observations after reap, not a transaction snapshot. Both executions stopped with one observer operation in flight. No completed-prefix equations were applied. The signal vector counts linked preentry SIGSEGV/SIGTRAP/SIGILL/SIGSYS/other; it does not classify NX versus TRACE faults. The 16-entry retired-root ring observes prior exact source/context matches; it grants no admission authority and predicts no larger-cache hit rate. Rank and offer-age bins describe only that bounded ring. The four failed prefixes do not establish matched application progress.

The CSV records actual command elapsed nanoseconds and, when recorded, process elapsed and CPU nanoseconds. Missing values are blank. A blank hash beside zero capture bytes denotes the standard empty SHA256; a blank byte count means that capture is absent. Native/causal record captures are empty. These are validation or failed-prefix measurements, not performance results.

Run the existing tracked drivers from the repository root at the JSON revision, with the recorded Python binary identity and an allocator-owned singleton matching historical CPU148. Choose fresh output directories. These commands preserve the scripts' source, dependency, namespace, resource, comparator and cleanup checks:

The recorded historical native provider is an ignored private output, not a shipped prerequisite. To regenerate it, use the existing complete 82-command / 28-case producer at its recorded revision. Run the following sequentially in the **same dedicated checkout path** on the reserved singleton, with no concurrent source work. The provider embeds absolute artifact/source paths: moving its receipt to another checkout or copying the receipt alone is not supported.

```sh
REV=6cfa572f2ba8d2cad10077f3674e0cca5de4a084
NREV=4ed9d1ca1ee6c73ac7a23e3ba714d93f5783dc4d
N=target/evaluation/inprocess/FRESH-native-provider/receipt.json
git switch --detach "$NREV"
python3.12 -B evaluation/inprocess/persistent_loop_effects_native.py --expect-revision "$NREV" --cpu 148 --output "${N%/receipt.json}"
# Continue only after this complete native82 producer passes and closes.
git switch --detach "$REV"
N_SHA=$(sha256sum "$N" | cut -d ' ' -f1)
B=target/evaluation/inprocess/FRESH-standard/receipt.json
P=target/evaluation/inprocess/FRESH-positive/receipt.json
python3.12 -B evaluation/inprocess/loop_ro_program_release.py --expect-revision "$REV" --output "${B%/receipt.json}"
# Set B_SHA to the whole SHA256 of the newly closed B receipt.
python3.12 -B evaluation/inprocess/loop_ro_native_positive.py --expect-revision "$REV" --native-receipt "$N" --native-receipt-sha256 "$N_SHA" --current-build-receipt "$B" --current-build-sha256 "$B_SHA" --output "${P%/receipt.json}"
# Set P_SHA to the whole SHA256 of the newly closed P receipt.
python3.12 -B evaluation/inprocess/loop_ro_native_controls.py --expect-revision "$REV" --native-receipt "$N" --native-receipt-sha256 "$N_SHA" --positive-receipt "$P" --positive-receipt-sha256 "$P_SHA" --current-build-receipt "$B" --current-build-sha256 "$B_SHA" --output target/evaluation/inprocess/FRESH-causal
python3.12 -B evaluation/inprocess/loop_ro_retired_program.py --expect-revision "$REV" --output target/evaluation/inprocess/FRESH-retired
```

The fixed programs are `/bin/ls -d .` and `/bin/true` (resolved to the recorded `/usr/bin` images). Each program driver builds a fresh archive. Native14/causal13 retain the historical fixture, seed and compiler recipe separately from the current 14-source Rust archive. A closed standard-program failure can supply only its completely validated build prefix, as the existing provider explicitly checks; it grants no program qualification. The native comparison uses a fresh 107-frame/106-instruction execution. The two causal subjects intentionally exit 125 after 22/35 mutations and 23/36 restorations, with literal failure 3303 and details 8801/8802.

Whole private receipt hashes bind every original command, capture and custody ledger. The public files contain selected measurements, not raw receipts or logs. No recorded outcome has been reclassified and no bound, case, assertion or comparator was changed for this projection.

The recorded provider was `tunables-effects-full19-r3-loop-native/receipt.json` at NREV, whole SHA256 `784fe75f566ea134a65464010823430d2b6dcadf2036bc99c47629418d39f983`. A fresh provider has its own whole hash, paths, process identities and measurements; those do not rewrite the recorded observation. The current native-positive and causal drivers accept the explicit fresh `N`/`N_SHA` only if the original 82-command schedule, 13-source historical archive, all compiler/fixture/header/tool identities, CPU/hardware, capture custody and closure still match their strict retained-support contract. They authenticate its historical Rust/config/recipe from Git separately from the current 14-source archive. They do not accept a newly built current 14-source native provider in that historical slot. Changed tools, fixture bytes, incompatible host hardware, missing history or missing artifacts remain failures; no identity normalization is permitted.

This gives the complete provider → fresh current standard build → fresh native-positive → causal chain through existing tracked scripts. The fourth ABI6 program driver builds independently. Generating the historical provider is not a substitute for the still-required full19 qualification. The fixed native82 schedule and every original bound/control remain unchanged.
