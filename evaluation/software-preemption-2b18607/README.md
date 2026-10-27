# Finite inline-clock preemption at 2b18607

All six commands passed at `2b18607cdae834496c4c97f1135d6e76685d91f2` on an AMD EPYC Zen 5 dev host. This covers four authored, call-free functions, each with one near backward JNZ, JG, JB or JMP. The gate counts taken edges and parks before the selected edge when its budget reaches zero. Matching synchronous resume permits that original edge to execute. This is not arbitrary-binary coverage or a general progress bound.

Median nanoseconds per loop iteration, using seven measured repetitions after two warmups:

| Function | Native | Counter only | Stop/resume, quantum 64 |
|---|---:|---:|---:|
| countdown-jnz | 0.708 | 2.074 | 162.978 |
| signed-jg | 0.585 | 1.845 | 173.896 |
| unsigned-jb | 0.593 | 3.191 | 184.058 |
| direct-jmp | 0.622 | 2.793 | 174.006 |

Each timing row runs 128 calls of 256 iterations: 32,768 work units. Compute each median from the seven measured `elapsed_ns` values, then divide by 32,768. Stop mode performs 510 synchronous handoffs per row, without deliberate sleeps. The timed worker loop excludes worker creation/join. Counter overhead is 2.93–5.39 times native; stop/resume is 230–311 times native. No cross-cohort causal speedup is claimed. This shared host used process affinity CPUs 0–3, without individual worker/controller pinning or exclusive CPU reservation. Minima/maxima and all 108 rows retain the observed variance.

The run completed 28 sibling pairs/56 children with full GPR, defined RFLAGS, XSAVE, application-page and 64 KiB stack comparisons at the fast original-body or zero pre-save boundary. It also completed 96 stop cells, 16 native and 16 counter baselines, 512 hardware SETcc checks, 256 parked checks and 48 repeated stop projections. Full architectural and parked-state comparisons ran live; their memory/register captures were not serialized. Saved CSV arithmetic and repeat projections were independently checked. No full-stack-after-callback claim is made.

The first attempt at `1345b10` remains FAILED: gate exit 101 at exact sibling image equality, with all five later commands UNRUN. The corrected fixture forks both siblings before parent readiness allocations. Equality, all 54 assertions, 28 pairs and limits remain intact; no address normalization was added.

To repeat in a clean checkout, select the exact revision above, supply an absolute resolved Rust toolchain directory, and choose a fresh ignored output:

```sh
python3 -B tools/software-preemption/evaluate.py --repo "$PWD" \
  --raw "$PWD/ignored/inline-new" --toolchain "$LI2_TOOLCHAIN" \
  --user-home "$HOME" --cargo-home "$CARGO_HOME" --profile inline-clock-v1
```

The committed evaluator builds release opt-level 3 with debug assertions and overflow checks enabled, then runs all six commands. Build limits are 120 CPU/180 wall seconds; each native command has 60 CPU/90 wall seconds and a 1 MiB file cap, with strict ECHILD closure. The receipt retains exact normalized commands, environment, source/tool hashes, outer bounds, both attempts and CSV hashes. Role substitutions invert privately; logs and detailed records remain ignored.

[Validation](validation.json) records the same code revision: all four required gates passed, with 2,306 workspace tests passed and four ignored. All 2,299 predecessor case identities and statuses remain present. Serial launch tests (995), successor (34), prefixed pun (30), neighbor eviction (74), and the five-case exec-admission repeat passed. The parallel library process reports 226 passed and one ignored; its log lacks one named terminal, which receives no independent named-case credit. Earlier compilation failures, the workspace timeout, and the intermittent exec-source-maps failure remain recorded as failed attempts; the maps failure has no established cause or deterministic fix.
