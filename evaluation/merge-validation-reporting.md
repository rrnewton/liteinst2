This collector projects one closed merged-validation run at
`41a236dff00295a70b5c4cf2982eb91359e5b2c1`. It retains twelve command rows:
four required gates, one serial launcher test command, and seven default-parallel
commands. It does not execute tests or infer test totals from nested output.

The required and parallel reproducers are `evaluation/required-gates.py` and
`evaluation/trampoline-parallel.py`. The serial caller is
`evaluation/serial-launch.py`, copied byte-identically from the reviewed caller
(SHA256 `dc3885bec8e3717ecd4122895f0f3646e98b2e08b0a1cc1bebfb0449a08620a4`).
Copy that caller into the fresh ignored raw directory before checking out the tested revision;
it is a reporting-era addition and is not present in that historical tree.
Run its documented `--repo`, `--output`, `--toolchain`, `--user-home`,
`--cargo-home`, and `--cpus 0,1,2,3` arguments. The actual command remains
`cargo test -p liteinst-launch --tests -- --test-threads=1 --nocapture`, with
offline Cargo environment, 180-second wall limit, 8 MiB output limit and the
existing three-second owned-descendant cleanup. It is one command, not the full
admission protocol. Required gates use four CPUs; the recorded default-parallel
sequence uses eight CPUs without overriding default test-thread count.

After all three enclosing callers are closed, run the committed collector:

```sh
python3 -B evaluation/collect-merge-validation.py --repo "$REPO" \
  --raw "$REPO/ignored/a3/merge-725f383-v1" --output "$NEW_REPORT"
```

The raw root must contain `required`, `serial`, and `parallel` records, and
their `-launch` siblings with actual command/started/closed records and streams.
The collector requires each caller's actual wait record and exact stream
hashes, source equality, closed serial/default input observations, and each
saved command outcome. Clean command failures and later UNRUN rows are retained.
Missing closure, early failures without the required saved schema, or source
drift cause collection to fail; they are not reclassified as successful runs.
The tested revision and actual committed reporter revision remain separate.

The new output contains `public/summary.json`, `commands.json`, `commands.csv`
and `files.json`. The JSON preserves full command argv/environment/cwd/affinity
contexts and outcomes; the CSV provides twelve concise rows. The three enclosing
launch contexts remain separate in the summary. Private input hashes/owners,
original contexts, and reversible path substitutions are retained in
`private-binding.json`. Raw logs, source maps, terminal observations and private
owners are not published. `$REPO`, `$RAW`, `$RAW_REL`, `$HOME`, `$CARGO_HOME` and
`$TOOLCHAIN` are explicit substitution roles, not shell-expanded script input.

CPU time was not measured and is reported as null; affinity is recorded.
Durations are operational diagnostics, not performance measurements. Independent
complete log accounting supplies test totals separately. Leader waits and serial
owned-descendant cleanup retain their distinct recorded scopes. The result grants
no full dependency/configuration/loader closure, architectural equivalence or
milestone qualification. Actual collector output and its enclosing wait still
require separate review.

To reconstruct the enclosing callers from a published summary, begin at the
reporting revision. Set `REPO`, `RAW`, `USER_HOME`, `CARGO_HOME`, `TOOLCHAIN` and
`SUMMARY_JSON` to absolute paths; `RAW` must be a new directory under the
checkout's `ignored/`. `TOOLCHAIN` names the Rust 1.97.1 toolchain directory.
The recorded CPU numbers must be available. The following setup only copies
scripts and reconstructs their saved commands; it does not run validation:

```python
import json, os, re, shutil
from pathlib import Path
repo = Path(os.environ['REPO']).resolve(strict=True)
raw = Path(os.environ['RAW'])
assert raw.is_absolute() and raw.is_relative_to(repo / 'ignored')
assert raw.parent.resolve(strict=True) == raw.parent and not raw.exists()
summary = json.loads(Path(os.environ['SUMMARY_JSON']).read_text())
roles = {'$REPO': str(repo), '$RAW': str(raw),
         '$RAW_REL': str(raw.relative_to(repo)),
         '$HOME': os.environ['USER_HOME'], '$CARGO_HOME': os.environ['CARGO_HOME'],
         '$TOOLCHAIN': os.environ['TOOLCHAIN']}
pattern = re.compile('|'.join(re.escape(k) for k in sorted(roles, key=len, reverse=True)))
def restore(value):
    if isinstance(value, str):
        return pattern.sub(lambda match: roles[match[0]], value)
    if isinstance(value, list):
        return [restore(item) for item in value]
    if isinstance(value, dict):
        return {key: restore(item) for key, item in value.items()}
    return value
raw.mkdir()
(raw / 'required-tmp').mkdir()
(raw / 'serial-proposal').mkdir()
shutil.copyfile(repo / 'evaluation/serial-launch.py',
                raw / 'serial-proposal/serial_launch.py')
for phase in ('required', 'serial', 'parallel'):
    directory = raw / (phase + '-launch')
    directory.mkdir()
    shutil.copyfile(repo / 'evaluation/record-merge-command.py', directory / 'launch.py')
    command = restore(summary['launches'][phase]['command'])
    (directory / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
```

Check out the tested revision in a clean worktree, then run the three copied
callers sequentially. Their output directories must remain fresh. The unchanged
recipes enforce their per-command deadlines; the copied caller records its
actual direct-child wait and hashes its streams.

```sh
git -C "$REPO" switch --detach 41a236dff00295a70b5c4cf2982eb91359e5b2c1
python3 -B "$RAW/required-launch/launch.py"
python3 -B "$RAW/serial-launch/launch.py"
python3 -B "$RAW/parallel-launch/launch.py"
```

Retain every failed run. Restore the reporting revision before using the
collector, which requires its own committed source and a clean tracked tree.
The literal parent source is `evaluation/record-merge-command.py` (SHA256
`d0e2e99e3a1e6024b417d379db471b7d7ac98ec2978d2c962c18e7586025267e`).
Python 3.9 supports these scripts; the saved command contexts retain the actual
interpreter path used for each recorded run.
