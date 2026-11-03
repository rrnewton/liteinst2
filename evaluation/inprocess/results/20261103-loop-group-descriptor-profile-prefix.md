The historical descriptor LS observation retained 2,758 user samples from a target that
failed with exit -9 under the original 30 CPU-second / 60 wall-second limit. Its
30.428-second process duration describes this failed prefix. It is not a completed
program time, a speedup measurement, or qualification evidence.

[The compact result](20261103-loop-group-descriptor-profile-prefix.json) binds the
whole audited receipt, bridge, source context and hardware digest. It preserves all
sampled periods through explicit other/unknown totals. The full raw observation
was loss-free and covered the exec-to-exit envelope; unwound paths remain bounded
observations. These results are **provisional until the installed natural runner is
rerun**. No equality between that historical private overlay and later code is
claimed.

| Exclusive leaf | Samples | Share of sampled user period |
|---|---:|---:|
| pda_receipt | 871 | 31.58% |
| pgx_terminal_members | 411 | 14.90% |
| equal | 139 | 5.04% |
| li2_pg_epoch_bind | 119 | 4.31% |
| lpf_project | 108 | 3.92% |

DWARF places 1,193 samples (43.26%) in canonical zero checks over unused
completion/member/peer capacity. Source inspection also shows that issuing one
completion writes the shared certificate-root page, expiring other cells' saved
root epochs. This is a concrete invalidation mechanism, not a measured count of
misses attributed to that reason. The original failed target remains failed.

After the runner is installed, generate a **fresh natural 34-command descriptor
program receipt on the same clean revision**. Its required native prerequisite and
all existing qualification gates remain separate. Run both commands under an
externally reserved singleton CPU, with no concurrent runtime/build or unbounded
writer in the checkout:

```sh
python3.12 -B evaluation/inprocess/loop_group_descriptor_program.py \
  --expect-revision REVISION \
  --output target/evaluation/inprocess/descriptor-program-NEW

python3.12 -B evaluation/inprocess/loop_group_descriptor_program_profile.py \
  --expect-revision REVISION \
  --diagnostic-receipt target/evaluation/inprocess/descriptor-program-NEW/receipt.json \
  --diagnostic-sha256 WHOLE_RECEIPT_SHA256 \
  --output target/evaluation/inprocess/descriptor-profile-NEW
```

The profile runner accepts the complete source-closed two-program failed cohort
(32 successful setup commands and both subjects -9). It reuses its exact retained
LS bridge without building, recreates the original namespace, and records the
original versus currently reserved CPU separately. Every hardware field other
than that CPU number must agree; no matched-timing comparison is claimed.

The target keeps 30 CPU seconds, 60 wall seconds, 512 MiB memory and 16 MiB output.
Perf and DWARF children keep 30 CPU seconds, 80 wall seconds, 1 GiB memory and
128 MiB output. Sampling remains user-only 99 Hz with the original 4 KiB DWARF
stack and complete loss-free envelope checks. A 20,000,000,000-byte allocation
guard admits complete outputs or refuses before writing them; it never truncates,
filters or drops samples. At least the original 432 MiB pre-profile reservation
plus existing checkout allocation must fit. The original RO profiler CLI and its
checks are unchanged.
