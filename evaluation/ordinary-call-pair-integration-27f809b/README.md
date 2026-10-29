The nested parent/child SDK and ordinary input adapter are implemented at
`27f809b323af79178e7e178a08cde657d9031040`. Their seven-check qualification
**failed**: the workspace command reached its unchanged 360-second deadline
while running the neighbor-eviction oracle. Completed test summaries account
for 1,978 passes, zero failures and one ignored test; these are an incomplete
prefix, not a workspace pass. Cleanup completed with eight rescued descendants.
Formatting, strict Clippy and workspace checking passed. Serial launch, staged
allocation and prefixed-pun checks were unrun after the timeout.

The implementation admits a bounded original parent E8 call to a selected child,
keeps separate parent and child receipts across generation changes, and routes
ordinary CSV inputs through the existing shared session loop. Its CallPair240
stack profile protects the complete admitted enclosing stack window. Report
invocation slots and payload child counts are checked independently. See
[the application contract](../../tools/rapid-profiler/normal-work/CALL_PAIR_SESSION.md).
This is claim-4 functional work; original-address native nested execution remains
unqualified, and A5 remains open.

`development.csv` retains all 17 development commands, including six failures:
a private-field fixture construction error, four incorrect Report-join controls,
a reference-iteration fixture error, two Clippy diagnostics and one mechanical
rename compilation error. The final targeted SDK controls passed 29 tests; the
full profiler library passed 497 with 31 ignored; the ordinary application passed
247. Those development runs used the recorded base plus dirty-source digests;
the separate seven-check attempt used the clean exact revision above. No result
is a throughput measurement or a hardware accuracy claim.

`checks.csv` and `receipt.json` summarize the exact clean-revision attempt on
AMD EPYC Zen 5 dev host, Rust 1.97.1. The hard reservation contained CPUs
23,33,40,113,139,156,175,181. Libtest used its default parallelism within that
mask, not a 316-thread campaign. Raw logs remain ignored and are authenticated
by the recorded hashes. Durations are operational wall times only.

To reproduce the seven checks, check out the exact revision, reserve eight
disjoint CPUs with `cpuset-alloc run --cores 8 --sample-s 1 --tag UNIQUE --`, and
run the tracked script (the receipt records the full command):

```sh
python3 -B evaluation/admission/check_exec_identity.py \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$REPO/ignored/UNIQUE" --checks-only
```

The script fixes compiler jobs at four, disables incremental/debug data, retains
assertions and overflow checks, and preserves every command deadline. The
single recorded attempt was not retried on unchanged source. The SDK and
application source reviews checked the actual Report producer, complete stack
geometry and ownership rules; source approval does not replace native execution.
