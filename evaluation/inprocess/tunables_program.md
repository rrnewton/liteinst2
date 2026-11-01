# Mixed-policy program observation

This driver is pending its separately reviewed native, focal-owner and lifecycle
prerequisite modules. It fails inside a retained attempt when a mandatory module
or proof is absent. It grants no whole-profile or performance qualification.

Once every prerequisite is installed and has actually passed on one clean
revision, hardware identity and reserved CPU, run the following on that same
reserved CPU. Supply exact whole private receipt SHA-256 values; native41 keeps
its existing public receipt contract.

```sh
python3 -B evaluation/inprocess/tunables_program.py \
  --expect-revision "$revision" \
  --direct-receipt "$native41_public" \
  --block-receipt "$pb_receipt" --block-receipt-sha256 "$pb_sha256" \
  --fused-receipt "$pf_receipt" --fused-receipt-sha256 "$pf_sha256" \
  --loop-component-receipt "$component_receipt" --loop-component-receipt-sha256 "$component_sha256" \
  --loop-native-receipt "$native_receipt" --loop-native-receipt-sha256 "$native_sha256" \
  --loop-owner-receipt "$owner_receipt" --loop-owner-receipt-sha256 "$owner_sha256" \
  --loop-lifecycle-receipt "$lifecycle_receipt" --loop-lifecycle-receipt-sha256 "$lifecycle_sha256"
```

The exact four subjects are `/bin/ls -d .` native then counted, followed by
`/bin/true` native then counted. Each retains the original30 CPU seconds,
60 wall seconds, 512 MiB address-space and16 MiB file/output bounds. A unique
timestamped private directory retains every command, capture and outcome; a
compact JSON/CSV pair is written under `evaluation/inprocess/results`.

The old native41/PB/PF archive and new scalar-read archive remain distinct.
All nine loop counters are ABI3 cells at offsets752 through816. The collector
matches actual successful terminal cells before applying the unchanged PF
terminal checks. A killed prefix stays failed and has no completion equations.
Membership and redirect counts are reported under their actual source names;
neither supplies loop-iteration, internal-transfer or instruction counts.

Reported times are bounded observations of those actual subjects. The driver
does not establish throughput, speedup, phase costs or completed-program
performance. Original392/522 qualification and the ten-run native/DR comparison
remain separate requirements.
