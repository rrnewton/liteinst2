# Stable source generation across a nonmapping boundary

This opt-in finite experiment separates a retained source-content identity from
the execution lease that is revoked before each guest operation. It keeps the
three resident certificates and every live source, mapping, alias, seal, rseq and
full-byte check. The original one-activation three-region experiment remains a
mandatory baseline.

The positive case runs the same four-cycle graph twice. Between entries, nine
successful native getters revoke the execution lease while preserving the
authenticated content identity. Passing requires three actual publications, two
complete owner lifetimes, zero interior signals and complete native/generated
register, flags, floating-point, signal-context and 520-byte stack comparisons
for both activations. Counters alone do not pass the experiment.

Three separate cases must refuse the second entry: an equal-protection mapping
transaction, a protection change followed by restoration, and a failed getter.
Their gated subjects retain exit 125 and their audits retain
`observed_failed_prefix_unqualified`. Completing the reproduction means the
positive and all three declared refusal observations were checked; it does not
turn the refused subjects into successful executions.

From a clean checkout, reserve one CPU externally and place the entire process
tree on that CPU. Set `LI2_CPU` to its number, then run:

```sh
python3 -B evaluation/inprocess/reproduce_resident_generation.py \
  --expect-revision "$(git rev-parse HEAD)" --cpu "$LI2_CPU" \
  --output target/evaluation/inprocess/resident-generation
```

The entrypoint checks exact single-CPU affinity and the complete clean source
before and after every stage. It creates a fresh cohort directory and thirteen
fresh sibling stage directories. The fixed sequence is:

1. Build the decoder archive; run the complete flags and helper native cohorts,
   including the original write-footprint oracle.
2. Build/run and fully audit the unchanged one-activation baseline.
3. Build/run and audit getters, equal protection, protection ABA and failed
   getter, in that order, passing exact whole prerequisite receipt hashes.

There are no retries, case selections or replacement results. Every existing
child recipe and limit is retained: native subjects use 5 CPU seconds / 15 wall
seconds; gated subjects and full bridge builds use 30 CPU seconds / 60 wall
seconds, with 512 MiB memory and a 16 MiB capture bound. Existing inspection and
archive limits remain those of their source-owned collectors. Full byte oracles,
actual ELF/DWARF checks and all original/additive reader controls are mandatory.

`cohort.json` records the stage outcomes, timings, script/capture/receipt hashes,
source identity and hardware digest. Full captures and receipts stay in the
stage directories under `target/`. A failed stage is retained and stops the
schedule. Published summaries should remain compact and bind the whole receipts.

This establishes only the finite two-activation contract when its audit passes.
It does not qualify arbitrary programs, source restoration after mutation,
procfs aliases, larger resident sets or a speedup. Original qualification cohorts
and the matched native/page/DynamoRIO comparison remain separate requirements.
