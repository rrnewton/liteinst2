# In-process selected effects

`build-effect-provider.sh` builds an optimized Linux x86-64 page gate that runs
inside the target process. The system interpreter enters through the gate;
execution does not require a ptrace supervisor. The profile supports trusted,
linked callbacks for CPUID, RDTSC, RDTSCP, RDRAND, RDSEED, RDPID and SYSCALL.
The default binding requests native effects. Unsupported instructions and
lifecycle operations stop with a structured refusal.

The callback ABI is in `selected_effect.h`. To supply a policy, replace
`selected_effect_native.c` in the link recipe with a translation unit defining
`li2_effect_runtime_binding`. Callbacks receive immutable original inputs and
choose Native or Scripted. A post-native callback can inspect the actual result.
Callbacks must obey the header's freestanding, nonreentrant ownership contract.
They cannot authorize source publication or modify a live signal frame.

CPUID, SYSCALL and RDTSC use temporary five-byte jumps when the source plan is
eligible. The gate restores original bytes before executing the selected effect
and retires ownership before reuse. The page generation advances on each
publication and restoration. Other selected encodings use the existing direct
NX path. Default inactive glibc rseq registration remains registered; publication
and syscall write spans must preserve the protected rseq word.

Build and run a small real-program example from the repository root, with an
unused namespace directory:

```sh
CARGO_INCREMENTAL=0 sh tools/page-entry/selected/build-effect-provider.sh
python3 tools/page-entry/carrier.py make /bin/ls \
  target/page-entry/effect-provider/bridge-effect-provider.so \
  target/page-entry/effect-provider/ls-carrier
python3 tools/page-entry/carrier.py exec-loader --library-root /usr/lib64 \
  --namespace target/page-entry/effect-provider/ls-namespace \
  target/page-entry/effect-provider/ls-carrier /bin/ls -- /bin/ls -d .
```

This remains a bounded single-thread profile with a closed instruction and
syscall envelope. The explicit sealed dependency namespace is part of the
launch contract. It does not establish unrestricted application, thread,
signal, JIT, browser or B3/B4 support.

The committed evaluators under `evaluation/inprocess/` produce exact-revision
receipts: `page_selected_effect_b2.py` checks both policies against fresh
full-state references; `page_selected_provider_app.py` checks a normal-loader
main/DSO before reuse stress; `page_selected_query_refusals.py` checks that
registered-word overlaps stop before an effect is issued. Each requires one
externally reserved CPU and `--expect-revision` with the full commit SHA.
An evaluator's presence is not a passing result; use its recorded outcome.
