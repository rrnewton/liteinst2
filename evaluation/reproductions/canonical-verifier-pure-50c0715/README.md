These twelve pure source controls passed in the recorded `50c0715e015107c92a8ecee03735645a83734220` context. All twelve named methods passed; the bounded child returned0/ECHILD in0.21344421221874654 seconds, and its parent waited successfully in0.2653883770108223 seconds. These are observed elapsed times, not a benchmark. The later publication revision does not inherit a full-source or runtime admission from this result.

The controls import only the frozen runner/producer definitions. They check the seven-member source map, five exact path transformations and their inverses/refusals, explicit reader dispatch, refusal while activation is unset, and the fresh-root boundaries. The compiler and producer mains do not run. No compiler, verifier, native workload, product, runtime or namespace is admitted.704 core and2112 recording obligations remain UNRUN. The seventeen historical PREPARED files are unchanged.

`summary.json` records the result, bounds, selected source/tool hashes and limits of the evidence. `methods.csv` retains all twelve method results. Raw logs remain ignored; `records.json` retains their hashes and byte lengths. `contexts.json` contains the three complete recorded command objects with reversible private paths replaced by roles. The root tool environment was inherited and not recorded; its PID and duration are also absent, so no values are inferred. `closures.json` keeps the actual helper receipt, helper-parent wait and separate root tool result. `records.json` gives hashes and byte lengths for every one of the12 control files and5 enclosing root records. The full owner tuples and path inverses remain private. The two tool identities come from saved equal before/after observations, not a later host refresh. No new hardware model was captured by this caller. The execution-context label is AMD EPYC Zen 5 dev host, from the earlier same-session A4 required hardware record (SHA256 `7b8045a29f005210d4b6fc65d270ce4eccae560df23150cc471e8fb3ab1fbf80`), with same-host continuity explicitly confirmed by the root coordinator. `hardware_observation` remains null; this attribution is not a fresh hardware census.

The four Python exports are exact executed source bytes: `caller.py`, `controls.py`, `payload/build.py` and `payload/evaluation/e9-common-app/run_core_pairs.py`. The two large modules remain unactivated. They are exported for these pure controls, not as a standalone compiler or native campaign recipe. The bounded helper is the repository's `tools/unwind-oracle/bounded_command.py`, exact SHA256 `c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44`.

Use an isolated checkout with that exact helper and Python3.9. To reproduce the original tracked context, use revision50c0715 and bring this frozen reproduction directory into it; the reproduction directory was published later. Install the exports at their exact original source depths. The following preparation refuses any existing destination before writing; do not overwrite retained evidence.

```python
from pathlib import Path
import hashlib, json

repo = Path.cwd()
export = repo / 'evaluation/reproductions/canonical-verifier-pure-50c0715'
proposal = repo / 'ignored/a3/common-core-canonical-verifier-proposal-v3'
caller = repo / 'ignored/a3/common-core-canonical-bytecheck-proposal-v1/controls-caller-v2/launch.py'
pairs = [(export / 'caller.py', caller)] + [
    (export / name, proposal / name) for name in (
        'controls.py', 'payload/build.py',
        'payload/evaluation/e9-common-app/run_core_pairs.py')]
pins = json.loads((export / 'summary.json').read_text())['sources']
assert all(not dest.exists() and not dest.is_symlink() for _, dest in pairs)
for source, dest in pairs:
    name = str(source.relative_to(export))
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == pins[name]['sha256']
    assert len(data) == pins[name]['bytes']
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open('xb') as stream:
        stream.write(data)
```

Then invoke the bounded caller:

```text
/usr/bin/python3.9 -B ignored/a3/common-core-canonical-bytecheck-proposal-v1/controls-caller-v2/launch.py --run-controls
```

It requires CPUs0–3 in the allowed affinity and a fresh `ignored/a3/common-core-canonical-epoch-50c0715-v1/canonical-pure-controls-v1` output. It retains10CPU/15wall/1MiB child limits, timeout25/kill-after10, normal parent wait40 and one bounded10-second failure cleanup. `-v` only records method names; it does not filter the suite. A cleanup timeout or failed postcheck remains a caller failure even if an earlier child returned0. The earlier caller had two unbounded post-kill waits; that source finding was corrected before any controls ran. Its status remains UNRUN, not a failed control result.

This public installation recipe has not itself been executed. A fresh reproduction must retain its own exact selected source/tool owners, complete receipt, parent closure and result. Creating the output directory is not a fresh runtime/source-owner admission, and a passing source-control result does not satisfy the outstanding compiler/product/native prerequisites.
