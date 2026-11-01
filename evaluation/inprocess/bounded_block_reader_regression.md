# Offline bounded-block reader regression

The closed regression passed the unchanged 40 native-application, 204 owner checks in each of two lanes, and 36 pair checks in each lane: 520 supplied refusals. It also re-read both complete retained native/generated pairs. No new subject or child command ran. The original bounded-block attempt-2 receipt remains **failed**.

The 697,653,982,083 ns elapsed value measures this offline validation, including mutation checks. It is not application runtime or performance evidence. The original subjects ran at source `6a4095b40e5d41817e0c19eb3703cf1b8b4dae20` on CPU 218. The regression ran on CPU 1; its result records exact script/reader hashes, but no current Git revision or launch argv. Hardware and ISA identity in the summary come from the retained subjects, not a new hardware probe.

`evaluation/inprocess/replay_bounded_block_owner.py` is a byte-for-byte copy of the reviewed private script (`fc940e956a03d0e4efa368e63e1bebc075c4f5af51b2c704409dcd91979531c3`). Both locations resolve the repository root with the same `parents[2]` expression. No reader, capture, control, comparator, resource bound, or outcome is changed by this publication.

To reproduce, restore the original closed attempt-2 directory and all inputs identified by its receipt, including the same-CPU seed, real compiled bridge/layouts, application outputs, namespace descriptions, pure native-policy classifier, and exact reader/helper source versions. Preserve original metadata and recorded input locations; this is a fixed-data replay, not a rebuild or a relocatable dataset. The script authenticates consumed files before and after use and refuses different identities.

Under an externally reserved singleton CPU affinity, from the repository root:

```sh
python3 -I -S -B evaluation/inprocess/replay_bounded_block_owner.py --cpu "$RESERVED_CPU" --output "$FRESH_RESULT"
```

This is a reproducible installed command, not a claim that the closed result recorded that argv. Select a fresh output file with an existing parent directory, outside the historical cohort. The script imposes 900 CPU seconds, 1200 wall seconds and 512 MiB on the offline process. These bounds do not change the original subjects' 30 CPU / 60 wall / 512 MiB / 16 MiB limits.

The compact JSON and CSV bind the whole 41,848-byte regression result (`59328209e1b0f6a49085188f5aba100c8df2cc2b2560a1058880766911894f94`) and original 1,492,183-byte failed receipt (`b70d1294042cebd9fd7a0acaf531c1872827a28bb859d2ccee60e6997c493ef4`). Full raw captures, absolute host paths and the complete input inventory remain outside the public projection. Terminal reports were not replayed. No runtime qualification or speedup credit follows from this reader regression; the fresh runtime campaign is separate.
