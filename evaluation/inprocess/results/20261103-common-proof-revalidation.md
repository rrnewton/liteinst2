# Common-proof reuse: native pass, real programs still fail

At revision `c2edb0ee1c0ab9452f9702c13611e8d6c0e26a22`, the release and
differential implementations match the 255-instruction native oracle at all
12 complete state frames. The 79-command campaign includes six intentional
exposure failures. Every original control remains required; each exposure
subject additionally exercises 31 token mutations, six guards, three actual
writable exposures, 42 full-proof/reuse pairs, and failed-proof recovery.
The native JSON records their actual counts and the complete resource bounds.

Common full validations decrease from 10,209 in the separately recorded
`466858c` native baseline to 2,952, with 7,257 revalidation hits. Historical
fallbacks remain 9,831. These are finite-fixture counts, not real-program
performance. Both release programs still exit `-9` at the original 30-second
CPU bound: `ls -d .` at 30.165870315 seconds and `true` at 30.165550828 seconds.
Neither produces validated terminal counters.

The separate natural release profile captures 2,671 user samples at 99 Hz,
with zero loss or throttle records. The target still fails; its wall time is
30.426199457 seconds, with 26.778199 user and 3.221979 system CPU seconds.
The 26,979,797,710 ns sampled period is not an elapsed-time decomposition.

| Exclusive leaf | Samples | Share of all samples |
|---|---:|---:|
| `lgd_common_value` | 336 | 12.58% |
| `pgx_terminal_members` | 243 | 9.10% |
| `lpf_project` | 172 | 6.44% |
| `li2_pg_epoch_bind` | 153 | 5.73% |
| `equal` | 148 | 5.54% |
| `ptr_storage` | 135 | 5.05% |

The full top-20, explicit other/unknown totals and all 31 time bins are in the
profile JSON. Its mapping/reset rows are profiler metadata, not mapping
syscall or trap counts. Bounded DWARF paths do not prove complete unwinding.

The next structural experiment isolates certificate pages: normal completion
of cell j should no longer invalidate the immutable proof for cell i. It must
retain full first proofs, actual writable-exposure invalidation, differential
comparison, and fresh execution authority checks. This does not remove cold
publication, live source checks or permission calls. DynamoRIO-null parity
remains unmet; no speedup estimate follows from this failed prefix.

The three adjacent `20261103-loop-group-descriptor-*-c2edb0e.json` files retain
exact revision, receipt hashes, hardware and portable reproduction commands.
Use the native driver first, then `loop_group_descriptor_program.py`, then
`loop_group_descriptor_program_profile.py`, each on an externally reserved
singleton CPU. Original failures and the separate full qualification gates
remain unchanged.
