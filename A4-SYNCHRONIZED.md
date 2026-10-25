# Experimental synchronized word publication

`patcher::synchronized` is a separate Linux x86-64 publication API for a
complete first instruction of five through eight bytes. It uses a prepared
`SyncCore` capability. Existing `LiveJumpPatch` publication remains unchanged.

An unsafe `SyncJumpPatch::bind` retains the mapping and route obligations for
process lifetime. `SynchronizedBatch::prepare` takes exclusive writer leases
and authenticates every complete write envelope before any store. Call
`advance` six times to publish all guards, synchronize, publish all back words,
synchronize, publish all final front words, then synchronize and release the
leases. A batch shares each of the three barriers across its members. It is
not an atomic switch of all members: an executor can observe one final member
before another.

The initial supported geometry is one entire decoded instruction, with an
eight-byte single-line store or two aligned words spanning a cache-line
boundary. Full padding bytes and canonical neighboring tails are authenticated.
Duplicate or overlapping member write envelopes, including writable aliases,
are refused. Sequential neighboring atomic registrations retain canonical
bytes for independently active sites.

Every error is terminal for that batch handle. A failure before mutation
releases its leases. A failure after mutation retains WRITING ownership and all
permanent routes/mappings, including after Drop. There is no automatic retry or
rollback. If the final barrier fails, final redirects may already be reachable;
retained ownership does not imply stopped execution. Receipts record the last
completed phase, completed barriers, mutation and ownership state, and the
first failure.

Callers must prove normal cacheable memory, the actual host cache-line geometry,
permanent source/writable/target mappings, exact aliases and exclusive writer
registration. All entries and saved resumes must be original instruction heads.
Every executing thread must retain the installed router and keep SIGTRAP
unblocked, including through signal return and late guard delivery. The writer
must not execute guarded code or run a handler that does. Runtime checks query
only the calling thread's mask and current disposition; they cannot establish
the all-thread or future-race obligations. Runtime fork during a transition,
shared cross-process aliases and unregistered physical aliases are excluded.

This API supplies neither callback drain nor safe reclamation. It does not
qualify arbitrary in-flight instruction decodes, arbitrary saved interior PCs,
code-as-data observers, active CET, or every processor vendor. These remain
separate requirements before broader concurrent instrumentation is admitted.

## Validation

The mandatory native gate is the complete `tools/word-sync-oracle` command,
whose README defines its fresh build and run procedure. A workspace test pass
alone does not qualify native synchronized publication. Missing host
prerequisites fail the command; they do not skip cases.

The fixed baseline checks 35 apply/revert cycles, 263 calls, 68 owned guard
deliveries, three signal returns and ten prewrite refusals. Three additional
processes independently deny each publication barrier and require retained
ownership, exact partial/final bytes and no execution of poisoned source.

The strict gate requires every one of 838 named cases: 576 completed-state
traces (192 each original/installed/reverted), 124 guard resumes, 128 held-frame
publications, and ten neighbor states covering 40 calls, eight operations and
two overlap refusals. It includes 252 separate schedule baseline traces and
252 actual signal returns. All 26 calibration tests and the separate three
positive/twelve negative receipt-auditor checks must pass. Repeated discovery
of shared calibration tests in other binaries does not add unique cases.

Each native command has CPU20/wall30 and a 1 MiB per-file cap. Strict traces
retain a fifteen-second/20,000-step bound and two-second rendezvous/cleanup.
CPU limits are per process and inherited; this command makes no aggregate
cgroup memory/PID containment claim. Raw generated requests, artifacts and
captures belong under ignored output directories.

The guard-resume schedule delivers a genuine pending guard after the writer
finishes synchronization; the baseline separately exercises real executors
that reach installed guard routes. The held-frame publisher runs in a closed
handwritten signal fixture. Its private COW RWX setup is not general W^X or
arbitrary async-signal-safety qualification. Evidence documents the tested
host and source/artifact identities separately.
