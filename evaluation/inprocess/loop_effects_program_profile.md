# Reproduce the retained LOOP13 LS profile

The original four-subject diagnostic and this separate LS subject both failed. The profile successfully captured a failed prefix; it does not establish completion, a kill cause, event counts, speedup or qualification. The sampled period is user CPU only. The actual wait4 user/system totals and incomplete unwind states remain separate.

The public script is byte-identical to the executed private script (SHA256962d12d5916f33f192f2338e22801d30db4d7d0f8db7857131a4d991a1cfae83). The JSON retains the actual private argv; installation of the public copy did not precede this observation. No original result is relabelled.

To reproduce this historical experiment, use clean source de48400c25b67916098f6457fb8f171797ad3305. Copy the published profile script outside that checkout if necessary, and set PROFILE_SCRIPT to that file. First run the existing evaluation/inprocess/loop_effects_program_diagnostic.py at that revision with a fresh output directory and a reserved singleton. This produces the original four fixed subjects, real fresh archive/release builds, complete namespaces and literal outcomes under its existing bounds. It must close with the exact native-pass/release-minus9 shape before this profile can consume its receipt. Any different outcome is retained and is not normalized to fit this historical experiment.

From that same clean checkout, reserve the same actual CPU/hardware and use the retained receipt SHA:

```sh
python3.12 -B "$PROFILE_SCRIPT" \
  --expect-revision de48400c25b67916098f6457fb8f171797ad3305 \
  --diagnostic-receipt "$DIAGNOSTIC_RECEIPT" \
  --diagnostic-sha256 "$DIAGNOSTIC_SHA256" \
  --output target/evaluation/inprocess/loop-effects-program-profile-fresh
```

The actual observation used CPU1. Use the existing cpuset allocator; its hard-pin test needs a parent affinity with an additional CPU, while the adapter must receive exactly the original singleton. The original target30CPU/60wall/512MiB/16MiB and observer30CPU/80wall/1GiB/128MiB bounds remain unchanged. Do not apply a smaller global512MiB parent cap. The same-PID held-exec wrapper is included in the observed process envelope. The adapter uses the original bridge/carrier/working directory and changes only the namespace destination. All old input/artifact identities, current compiled input equality, loss/exec/exit/raw mappings and process/FD checks are mandatory. No build or guest replay occurs while preparing this publication packet.

The JSON is a compact projection of the closed observation. The CSV partitions all2,814 samples into the top four named leaf functions, unknowns and all others per second; no sample is discarded. Raw captures and complete function/path attribution remain in the private closed receipt. ISA flags are hashed as their recorded ordered list with json.dumps(flags,separators=(',',':')).encode().
