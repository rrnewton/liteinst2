# Certificate qualification attempt, 2026-10-30

The first generation-bound reuse-certificate owner qualification **failed**. All 43 subjects ran; 42 qualified. All 13 native/gated pairs and 348 application-reader refusal controls passed. The required owner-control subject `subject-gated-0-1` returned exit 125 but its new reader rejected `scalar_certificate_store.terminal_matches`. All eight separate mapping subjects returned their required exit 125 and failure code, but their new reader rejected `li2_native_pair_progress.phase`. Those outcomes remain failed; no case was replaced.

The [owner JSON](20261030T140608.867548Z-scalar-region-reuse-certificate-owner-1fa3253820b4.json) and [CSV](20261030T140608.867548Z-scalar-region-reuse-certificate-owner-1fa3253820b4.csv) retain all outcomes. Actual supplied-refusal counts were 3,946 original owner, 1,899 original terminal, 964 certificate owner and 435 certificate terminal; the required totals were 4,102, 1,964, 998 and 450. Mapping certificate controls have no credit. Complete source and process cleanup checks passed: 161 commands, 360 captures, no final errors. This closure does not qualify the failed population.

The separate production transaction component passed all eight modes and 256 supplied-record refusal controls. Its boundaries/completion permits are explicitly supplied; it grants component evidence only. It includes successful publication, hit and retirement, and required stale-generation, payload-corruption, unconsumed-permit, partial-protection and writable-certificate failures. The real partial-protection failure remains an incomplete cleanup observation, not a successful transaction.

Five original prerequisites passed on the same revision and CPU:

| Prerequisite | Receipt |
|---|---|
| Decoder, 8 cases | [JSON](20261030T134709.182296Z-region-decoder-1fa3253820b4.json) |
| Scalar component, 11 cases | [JSON](20261030T134749.895606Z-scalar-region-component-1fa3253820b4.json) |
| Original reuse owner, 43 subjects and separate 8 mapping cases | [JSON](20261030T134834.602073Z-scalar-region-reuse-owner-1fa3253820b4.json) |
| Unrolled component, 9 cases | [JSON](20261030T140234.832614Z-unrolled-hash-component-1fa3253820b4.json) |
| Unrolled owner, 25 subjects | [JSON](20261030T140303.179031Z-unrolled-hash-owner-1fa3253820b4.json) |

Source revision: `1fa3253820b41d44e263181e09241358fe0aa1c2`. All runs used reserved CPU 1, unprivileged, on AMD EPYC 9D85, family 26/model 17/stepping 0, microcode `0xb101066`, Linux 7.1.3. The actual release builds, tool/source inventories and complete commands are bound by the receipts. Original program limits remained 30 CPU seconds, 60 wall seconds, 512 MiB and 16 MiB output; transaction components retained 3 CPU seconds, 10 wall seconds, 256 MiB and 1 MiB output. The mandatory 82-attempt performance comparison did not start. No certificate timing, speedup or 10× DynamoRIO claim is made, and repository checks were not rerun on this failed source.

Reproduce with CPU affinity 1 after the two referenced prerequisites:

```sh
python3 -B evaluation/inprocess/scalar_region_owner.py \
  --expect-revision 1fa3253820b41d44e263181e09241358fe0aa1c2 \
  --decoder-receipt evaluation/inprocess/results/20261030T134709.182296Z-region-decoder-1fa3253820b4.json \
  --component-receipt evaluation/inprocess/results/20261030T134749.895606Z-scalar-region-component-1fa3253820b4.json \
  --reuse --certificate
```
