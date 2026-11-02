These JSON/CSV files report three additive C component attempts and two separate Python model attempts. The successful C run used clean `2e4832bb76ef4ce782ba2314dd99989fd8968dab`, CPU6, and the unchanged 64-command schedule. The original five components passed in every attempt. The first attempt stopped at its far dependency check; the second launched the far oracle and received SIGABRT. Both remain failed. The second receipt's component field remained `not_run` because invocation raised before its result update; the command record proves execution.

The C oracle interprets generated descriptions and checks full recovered state; it does not execute generated code. The successful Python run at clean `1970d82785b6ad34417465fde12937bee192b038` checks 28 root orders, 28 focal graphs, six lifecycle graphs and 806 whole descriptors with near banks. Its preceding wrong-revision preflight ran no models. None of these results establishes owner, native, lifecycle or performance qualification. Durations are validation time, not application benchmarks.

All C attempts reused the actual 12,007,764-byte decoder archive with SHA256 `d5ae6933ce1e905be557a9dac3ffd2341c7649c42f58f9594bba2365ea8ba399` from the clean4f native receipt `eb24445ff4f7a214fee6545e1e9ed58c51933ebc5eaac40779e6b076ed7ac8b2`. This is recorded reuse, not same-revision native evidence. The JSON preserves each exact receipt/result hash, revision, CPU, hardware, original bounds and normalized recorded C invocation. CSV blank values mean absent observations, including the unexecuted far oracle in attempt1.

To reproduce, use a clean checkout, an offline toolchain suitable for the tracked recipes, sufficient storage, fresh ignored output directories, and a reserved singleton CPU. Run the commands from the repository root within that CPU reservation. The tracked collectors own all per-command bounds, capture and cleanup. The original component collector has no additional aggregate CPU/wall limit.

For a fresh decoder prerequisite, check out `4f3e28e7e1d434bc6d51c95bab828557a6d37442` and run:

```sh
python3.12 -B evaluation/inprocess/persistent_loop_native.py --expect-revision 4f3e28e7e1d434bc6d51c95bab828557a6d37442 --cpu "$CPU" --output "$NATIVE"
```

Require its actual successful receipt, then compute `ARCHIVE_SHA` from `$NATIVE/artifacts/decoder.a` and `NATIVE_SHA` from `$NATIVE/receipt.json`. A fresh receipt has its own identity; do not copy a historical hash onto it. Preserve that directory across checkout. At clean `2e4832bb76ef4ce782ba2314dd99989fd8968dab`, run:

```sh
python3.12 -B evaluation/inprocess/loop_far_components/run.py --expect-revision 2e4832bb76ef4ce782ba2314dd99989fd8968dab --cpu "$CPU" --archive "$NATIVE/artifacts/decoder.a" --archive-sha256 "$ARCHIVE_SHA" --archive-native-receipt "$NATIVE/receipt.json" --archive-native-receipt-sha256 "$NATIVE_SHA" --output "$FRESH_OUTPUT"
```

The original failed C behavior is reproducible using the respective recorded revision and its tracked wrapper, with a fresh output each time. For the separate model result, check out `1970d82785b6ad34417465fde12937bee192b038` and run:

```sh
python3.12 -B evaluation/inprocess/loop_rseq_model.py --expect-revision 1970d82785b6ad34417465fde12937bee192b038 --output "$FRESH_MODEL_OUTPUT"
```

The JSON also retains the original erroneous expected revision. Supplying it must fail preflight. The full original native, component, lifecycle, 392-case and 522-pair qualification and release performance measurements remain separate mandatory work.
