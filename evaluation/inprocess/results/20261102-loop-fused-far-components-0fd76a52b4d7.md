The JSON/CSV report the actual 68-command LPF component run at clean `0fd76a52b4d733cfff24bd5d349dce1a0405543d` on CPU6 and two separate model attempts. All seven C components passed. The additive LPF row records 12 near/12 far plans, 24 descriptive histories, four partial failures with 24 controls, 4,608 DIRECT/1,280 MOV models, 300 corruptions, 96 literal refusals and the unchanged complete original PF row. No generated guest code or owner lifecycle was executed by these component interpreters.

Model attempt1 remains failed after its original 28/28/6/806 rseq checks. Python dictionary equality treated the actual `near_record=True` mutation as equal to `near_record=1`, so the nonidentity precheck stopped before that strict validator call. Attempt2 at clean `1a662abfdfc78591f2f113f974261c1bc2aec5c8` changed only that precheck to whole key-ordered JSON inequality. It passed the unchanged rseq checks and all eight positive/136 negative saved-history models. These dictionaries do not prove actual owner completions. The failed result's false closure flags are preserved, as are its exact receipt and error.

Use a clean checkout, the tracked offline toolchain, fresh ignored output directories and one reserved CPU. The JSON contains actual receipt hashes, revision, CPU, observed hardware, validation durations, bounds and normalized C argv. Model reproduction argv is explicitly reconstructed. CSV has seven component rows and two model rows; blank history counts in the failed row mean no complete history result was recorded.

The component reuses the actual decoder archive from the clean4f native receipt. It does not claim current-revision native qualification. If those retained inputs are unavailable, at clean `4f3e28e7e1d434bc6d51c95bab828557a6d37442` run:

```sh
python3.12 -B evaluation/inprocess/persistent_loop_native.py --expect-revision 4f3e28e7e1d434bc6d51c95bab828557a6d37442 --cpu "$CPU" --output "$NATIVE"
```

Require its successful actual receipt and compute `ARCHIVE_SHA` from `$NATIVE/artifacts/decoder.a` and `NATIVE_SHA` from `$NATIVE/receipt.json`. A new receipt has its own hash. Preserve these inputs across checkout, then at clean `0fd76a52b4d733cfff24bd5d349dce1a0405543d` run:

```sh
python3.12 -B evaluation/inprocess/loop_fused_far_components/run.py --expect-revision 0fd76a52b4d733cfff24bd5d349dce1a0405543d --cpu "$CPU" --archive "$NATIVE/artifacts/decoder.a" --archive-sha256 "$ARCHIVE_SHA" --archive-native-receipt "$NATIVE/receipt.json" --archive-native-receipt-sha256 "$NATIVE_SHA" --output "$FRESH_OUTPUT"
```

The collector retains the original 30 CPU/60 wall seconds per build, five CPU/15 wall seconds per component, 512 MiB address-space and 16 MiB file/capture bounds. There is no separate aggregate outer CPU/wall bound in the original component collector.

At clean `1a662abfdfc78591f2f113f974261c1bc2aec5c8`, run the model pair under the same singleton reservation:

```sh
python3.12 -B evaluation/inprocess/loop_fused_models.py --expect-revision 1a662abfdfc78591f2f113f974261c1bc2aec5c8 --output "$FRESH_MODEL_OUTPUT"
```

Both model groups share their original aggregate 30 CPU/60 wall seconds, 512 MiB address-space and 16 MiB output bounds. Using the prior clean0fd revision reproduces the precheck failure. Full native, owner, mixed lifecycle, original392-case/522-pair qualification and release performance measurements remain mandatory. None of these validation durations is an application benchmark.
