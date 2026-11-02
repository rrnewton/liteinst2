# Additive LOOP far-DIRECT components

This entry point runs the original ordered five component populations, then the
far-DIRECT oracle. Its distinct `experimental-loop-far-components-v1` profile
cannot satisfy the production five-component prerequisite. It executes no
generated guest code and grants no native, owner, lifecycle, qualification or
performance credit. The existing five-case CLI remains unchanged.

From a clean installed revision on one externally reserved CPU:

```sh
python3 -B evaluation/inprocess/loop_far_components/run.py \
  --expect-revision <current-40-hex-revision> --cpu <reserved-cpu> \
  --archive target/evaluation/inprocess/loop-diagnostic-r4-native/artifacts/decoder.a \
  --archive-sha256 d5ae6933ce1e905be557a9dac3ffd2341c7649c42f58f9594bba2365ea8ba399 \
  --archive-native-receipt target/evaluation/inprocess/loop-diagnostic-r4-native/receipt.json \
  --archive-native-receipt-sha256 eb24445ff4f7a214fee6545e1e9ed58c51933ebc5eaac40779e6b076ed7ac8b2 \
  --output target/evaluation/inprocess/<fresh-far-component-attempt>
```

This example reuses the 12,007,764-byte decoder archive from the closed native
receipt at revision `4f3e28e7e1d434bc6d51c95bab828557a6d37442`, CPU23.
The receipt hash, original status/source, archive pathname and complete archive
bytes/mode join both recorded native inventories. The new attempt records that
provenance as reused. It does not revalidate the old native captures or claim
same-head native evidence; `archive_source_provenance_verified` stays false.
Reproduction needs that retained archive/receipt pair, or an explicitly supplied
new closed native pair. A clean checkout alone does not contain those outputs.

The exact schedule has64 commands:40 unchanged tool/link/archive commands and
four for each of six cases (headers, build, dependencies, component). All eleven
far translation units, included original oracle, new header/include and existing
header dependencies are mandatory. Compiler-M, every retained intermediate,
whole link trace, ELF/runtime dependency closure, actual recipe hash, input and
source equality, capture and cleanup checks use the original runner.

Each build retains30 CPU seconds/60 wall seconds,512MiB address space and16MiB
file/capture limits. Each component retains5 CPU seconds/15 wall seconds and
the same memory/output limits. No retry, skipped case or enlarged bound is added.

The far oracle first emits the original LOOP row, which is passed whole through
the unchanged original comparator. Its additive row requires exactly70 adapters
(12 near,58 far),13,440 models,464 literal refusals,870 direct corruptions,
4 plans,128 plan corruptions,6 relocations and102 relocation controls. `steps`
remains an integer observation; every model's exact steps/recoveries and full
machine-state assertions remain in the C oracle. Fixed expected populations are
source requirements until an actual attempt completes.

The compact `summary.json` and complete private receipt retain literal failures.
High mixed-policy lifecycle and all original392/522/native/program gates remain
mandatory and unfulfilled by this component diagnostic.
