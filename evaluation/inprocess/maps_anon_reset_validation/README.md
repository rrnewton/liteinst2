# Anonymous-reset and original maps component reproduction

The accompanying JSON and 13-command CSV record two completed component suites at `6cfa572f2ba8d2cad10077f3674e0cca5de4a084`: 31 cases in each maintained/maps-DIFF build, and the unchanged six-mode maps fixture with 19 subcases. The four required exit 125 results remain refusals. These observations provide no guest-program, owner/lifecycle, maps42/full19 qualification, or performance credit.

`original_six.py` is byte-identical to the executed private wrapper: 8008 bytes, SHA256 `e42a54df8df83aea605aa2d8f5ec02b6802dba4456d085e9fb19205223c342e9`. Its published location has not been executed. It invokes the existing `maps_view.finite` callback once; it contains no copied fixture or comparator. The publication path retains its exact `parents[3]` checkout-root calculation.

Use Python 3.12 with assertions enabled, the repository's Linux x86-64 toolchain, and an externally reserved singleton CPU. From a clean checkout, run:

```sh
python3.12 -B evaluation/inprocess/maps_anon_reset.py \
  --expect-revision REVISION --attempt maps-anon-reset-reproduce-1
python3.12 -B evaluation/inprocess/maps_anon_reset_validation/original_six.py \
  --expect-revision REVISION --attempt maps-original-finite-reproduce-1 \
  --provider target/evaluation/inprocess/maps-anon-reset-reproduce-1/receipt.json \
  --provider-sha256 FRESH_PROVIDER_SHA256
```

Replace `REVISION` with the exact clean checkout revision. The second command requires the first command's passed private receipt and its actual SHA256, not the historical receipt hash. Its compiler/tool/input proof must match the same revision; all six modes execute freshly. Output namespaces must not already exist. The original 5 CPU seconds / 15 wall seconds / 512 MiB address space / 16 MiB file size finite bounds and 30 CPU seconds / 60 wall seconds / 512 MiB address space / 64 MiB file size metadata bounds are enforced by the unchanged bounded invoker; all captures remain limited to 16 MiB.

For exact historical-source reproduction, save these published wrapper bytes, use an isolated clean checkout of `6cfa572f2ba8d2cad10077f3674e0cca5de4a084`, and copy them to `target/page-region-next/maps-anon-reset-r1/validate_original.py`. Run the same first command at that revision, then invoke the copied target path for the second command with its new passed provider receipt/hash. This ignored path is the actual historical wrapper location and retains the same root calculation. Do not add a tracked file to the historical checkout. The JSON preserves both actual normalized parent commands; only the Python executable path is normalized.

The public summary hashes the complete original command rows and capture ledger; the CSV retains each actual stdout size/hash and validation duration. Every stderr was empty with the SHA256 of empty bytes. Full tool/header/ELF/library and process/input closure remains in the identified private receipts. Durations include validation and build work and are not benchmark samples.
