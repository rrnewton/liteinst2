Eight pure saved-data auditor tests passed in the recorded
`041bd4a933d050eee946d9b03ae9fd7082a72186` checkout context. The bounded child
returned 0 with strict ECHILD closure in 0.2676824638620019 seconds; its parent
returned 0 after a successful wait in 0.31616191007196903 seconds. These are
operational elapsed times, not a benchmark. Later publication commits do not
inherit a complete source-owner or runtime admission from this result.

The tests exercise the unchanged auditor's pure profile, route, ledger, code,
register, frame, FP and mapping checks using synthetic saved-data fixtures.
All eight named methods passed. Their source contains 99 expected-refusal
variants; `methods.csv` labels these counts as source-derived. The terminal
directly observes eight methods, not 99 separately reported test results.
The auditor main, compiler, verifier and native subject never run in this
suite. Both auditor activation pins remain None. Fresh canonical/build/product,
runtime and namespace authority remain unadmitted, with 704 core and 2112
recording obligations UNRUN. No common-corpus, normal-loader or full-A3
qualification is claimed. The separate twelve-control suite and all historical
failures remain unchanged.

`summary.json` records the result, exact revision, sources, selected tools,
bounds and evidence scope. `methods.csv` contains all eight results.
`contexts.json` contains all three complete saved command objects with private
absolute paths replaced by reversible roles. `closures.json` preserves the
strict helper receipt, helper-parent wait and separate root tool exit record.
`records.json` retains hashes and byte lengths for all twelve raw control files
and five root records. Raw stdout and stderr are not exported, even when they
contain no private paths. Full owner tuples and path inverses remain private.

Six selected source/helper files and two tool records match exactly before
and after the child. The helper receipt's `inputs_unchanged` concerns only
request/helper bytes; the caller's separate snapshots establish its selected
file/tool equality. This is not a complete repository or runtime census.
The root tool inherited an unrecorded environment; its PID and duration were
not saved, so they remain null. The caller's own source-review record still
says UNRUN as it did before execution; the actual result is recorded separately.

The execution-context label is AMD EPYC Zen 5 dev host. The root implementation agent explicitly
confirmed same-host continuity with the earlier A4 required hardware record,
SHA256 `7b8045a29f005210d4b6fc65d270ce4eccae560df23150cc471e8fb3ab1fbf80`.
This caller captured no new hardware model; `hardware_observation` stays null.
Tool hashes come from saved equal before/after observations, not a later refresh.

The five exports are byte-identical to the executed sources: `caller.py` and
the four files under `payload/evaluation/e9-common-app/`. The bounded helper
is the repository's `tools/unwind-oracle/bounded_command.py`, exact SHA256
`c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44`.
Use an isolated checkout at 041bd4a with Python3.9 and bring this frozen export
directory into it; the export was published later. Install the source files
at their original depths without changing their contents:

```python
from pathlib import Path
import hashlib, json

repo = Path.cwd().resolve()
export = repo / 'evaluation/reproductions/core-auditor-pure-041bd4a'
subject = repo / 'ignored/a3/common-core-auditor-proposal-v2'
caller = repo / 'ignored/a3/common-core-auditor-pure-caller-v1/payload/launch.py'
names = (
    'payload/evaluation/e9-common-app/test_core_pair_profiles.py',
    'payload/evaluation/e9-common-app/audit_core_pairs.py',
    'payload/evaluation/e9-common-app/core-pair-heads.json',
    'payload/evaluation/e9-common-app/core-pair-source-pins.json',
)
pairs = [(export / 'caller.py', caller)] + [
    (export / name, subject / name) for name in names]
pins = json.loads((export / 'summary.json').read_text())['sources']
assert all(not dest.exists() and not dest.is_symlink() for _, dest in pairs)
for source, dest in pairs:
    pin = pins[str(source.relative_to(export))]
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == pin['sha256']
    assert len(data) == pin['bytes']
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open('xb') as stream:
        stream.write(data)
```

Run the unchanged bounded caller from that repository root:

```text
/usr/bin/python3.9 -B ignored/a3/common-core-auditor-pure-caller-v1/payload/launch.py --run-controls
```

It requires CPUs 0–3 in the allowed affinity and a fresh
`ignored/a3/common-core-canonical-epoch-50c0715-v1/auditor-pure-controls-v1`
output. The historical 50c name is just the retained pure-control directory
coordinate; this cohort's recorded checkout revision is 041bd4a. The exact
limits are 10 CPU seconds, 15 wall seconds and 1 MiB per output file, outer
timeout 25 seconds with kill-after 10 seconds, parent wait 40 seconds and one bounded 10-second failure cleanup.
The child environment is exactly PATH=/usr/bin:/bin, LC_ALL=C and
PYTHONDONTWRITEBYTECODE=1. `-v` records names without filtering the suite.
Cleanup timeout or failed postchecks remain caller failure even if an earlier
child returned 0.

This installation recipe has not itself been executed. A fresh reproduction
must retain its own source/tool observations, complete receipt, parent closure
and result. Passing these pure controls does not execute or admit an actual
saved-capture audit, canonical product build or native campaign.
