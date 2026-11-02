# Retained PUSHFQ source-model diagnostic

These three scripts are byte-identical copies of the private scripts actually
executed for the accompanying 51-row diagnostic. They replay retained historical
inputs; they do not reconstruct a new native or owner run. The fresh end-to-end
reproduction remains `evaluation/inprocess/reproduce_effects_tunables.py`, with
every original stage, case, bound and qualification gate.

The original full19 owner run at
`1b2028e795bac3b308114d73681311b67cf2da1a` remains failed: 51 source-coverage
errors and five differential exit-9 outcomes. The latter have no readable-pair
pass or established kill cause. This diagnostic used clean observer revision
`d6a4dcf5bfc719f191a01259fdb4e828c1b124fa`, CPU25, and a private, uninstalled
source-model overlay. All 51 retained readable pairs passed the unchanged full
owner reader and native comparison. The full owner negative-control suite was
not rerun. Each read also required all 16 prefixed-9C inputs to remain
`CoverageError`, and the old source model to keep refusing bare9C.

The only candidate change describes bare9C PUSHFQ as Code317,
STEP_FLAGS_OBSERVED2, kind0/stop1, with no ready instruction. Its complete source
fact is 6181 bytes, SHA256
`5046f1286e180af2e5c3098c17206a2f5b5717914ebe85c926fda416511bc223`.
It adds no executable instruction authority.

## Historical inputs

Keep the original native and owner directories under
`target/evaluation/inprocess/tunables-effects-full19-r2-{loop-native,loop-owner}`.
The reader requires their exact receipts, recorded source inputs, artifacts,
captures, namespace aliases and original absolute custody paths. Their receipt
hashes are respectively
`63ffcec24921e93d9ef9682e04feb411a1684f21c1ed93939701a5a0e4f4fbf1` and
`02ed8e3106cb8add3f761dd4f7e9f80f745a5b8008694fc183a353635b3b849a`.
Historical native/subject CPU192 is separate from the replay's allocated CPU.
Neither moving artifacts to another root nor substituting a new receipt is
supported by these unchanged scripts.

## Exact replay setup

Before checking out the historical observer revision, copy these three scripts
into the ignored directory
`target/page-region-next/loop-effects-pushfq-model-r1/`. Copy the reviewed model
source into that directory's
`files/tools/page-entry/selected/tests/persistent_loop_effects_owner/source_decode.py`
and verify its hash above. Both locations retain the original directory depth
used by `ROOT = Path(__file__).resolve().parents[3]`. Execute the copied scripts
from the repository root, not directly from this tracked directory: the
historical input closure admits the ignored diagnostic code separately.

Use a clean checkout of `d6a4dcf5bfc719f191a01259fdb4e828c1b124fa` with those
retained historical inputs. Preserve all existing outputs. Each parent refuses
an existing output directory; its fixed names are
`target/evaluation/inprocess/effects-pushfq-reader-replay-attempt-1` and
`effects-pushfq-reader-replay-attempt-2`.

The initial parent reads maintained0/0 and5/0. The remaining parent reads the
other49 capturable cases and requires the **original** initial receipt
`bce507db08f1f1c211fcd4736514bd0e5d3670f20bdecbaf6f182172c1bb327d`
at the first output path. These are independent historical diagnostics: a new
initial run has new timings and does not produce that required receipt hash.
Run the parents in separate prepared historical states, preserving the original
initial receipt for the remaining-parent input. Never overwrite original results.

```sh
AGENT_UTILS_ENGINE=python cpuset-alloc run --cores 1 \
  --tag effects-pushfq-reader-initial -- python3.12 -B \
  target/page-region-next/loop-effects-pushfq-model-r1/execute_initial.py

AGENT_UTILS_ENGINE=python cpuset-alloc run --cores 1 \
  --tag effects-pushfq-reader-remaining -- python3.12 -B \
  target/page-region-next/loop-effects-pushfq-model-r1/execute_remaining.py
```

These are normalized forms of the actual allocator commands; the executable
locations depend on the host. Each parent calls the existing `invoke` owner
sequentially, preserving 30 CPU seconds, 60 wall seconds, 512MiB address space,
16MiB file/output limits, descriptor closure and source checks for every child.
No guest or build command runs. The scripts preserve diagnostic failures and
confer no new owner qualification or guest-performance credit. CSV times are
reader durations only. No additional portable wrapper was authored or executed.
