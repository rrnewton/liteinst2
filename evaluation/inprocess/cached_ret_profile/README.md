# Historical cached CALL/RET profile

This reproduces the failed whole-program experiment at
`9fb789544f604732d94fddccbda57993273bf765`. The sampler is byte-identical to
the executed 29,159-byte adapter, SHA256
`ae62687f8a42daec331eee7eda0af0d10f6720443b13e81a76526d4c5c220411`.
The public reservation wrapper takes the agent-utils installation as an explicit
argument; the sampling process and all original target/observer limits are
unchanged. Copy this directory into `target/cached-ret-profile-reproducer` of a
clean checkout of that revision. The source manifest requires that location
for the portable reservation helper. Do not run the historical source gate
against a later runtime tree.

From that clean checkout, with a Python 3.11+ executable and the same compiler,
CPU features and perf permissions required by the existing native oracles:

```sh
python3 -B target/cached-ret-profile-reproducer/reserve_cpu.py \
  --agent-utils /path/to/agent-utils -- \
  python3 -B target/cached-ret-profile-reproducer/reproduce.py \
  --output target/evaluation/inprocess/cached-ret-profile-reproduction
```

The allocator must start with broad parent affinity containing CPU3 and at
least one other CPU; its unchanged hard-pin escape probe establishes the
reserved child tree. There is no taskset wrapper, allocation fallback or retry.
Use one Python executable throughout. The nested build scripts retain their
existing toolchain checks and job limits.

The recipe runs the complete original nine-stage CALL/RET owner chain and
native41, then exactly native LS, counted LS, native true, counted true. It
profiles the same failed counted LS binary, without rebuilding it or replaying
readers. A successful application on a different machine is not this recorded
failure and the failure-specific sampler will refuse it. Failure is preserved
as failure; completing the observation grants no application or qualification
credit. Every new output directory must be fresh.

The observed LS target was killed at the unchanged 30 CPU-second bound after
30.397848868 seconds. Its 2,876 user samples at 99 Hz had no loss or throttle
records and covered the full same-PID EXEC-to-EXIT interval, including launcher
startup and unknown mappings. Sampled leaf shares were 24.24% planning/decode,
20.69% full publication-byte checks, 19.12% compact projection and 35.95% other.
These are user sample shares, not wall-time attribution or kernel-trap cost.

The post-reap counter prefix contains 19,263 linked ingress events, 1,395 fresh
maps acquisitions, 558,833 view queries, 5,444 cached entries, 1,913 hits, 3,458
publications and 3,457 retirements. Per-cell prefixes do not establish completed
transaction totals, throughput or speedup. The next structural experiment must
address translation retirement and publication work. The 263.060775 ms target
(ten times the historical DR-null median) remains unmet; original392/522 and
the matched ten-run comparison remain mandatory.

Compact numeric JSON/CSV are under `evaluation/inprocess/results`; complete
raw samples and process receipts stay in the private output directory. The
public packet's portability edits have source review only; the historical
observation is bound to its original receipt and driver hash, not relabelled
as execution of this packaging.
