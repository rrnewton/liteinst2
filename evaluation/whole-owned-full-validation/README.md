# Whole-program and owned-batch correctness gate

At `002cf64b288735c185d1c3863d1dbdfd893373eb`, all five root-workspace commands passed on an AMD EPYC Zen 5 dev host: **4,260 passed / 0 failed / 39 ignored** in the workspace and **1,039 / 0 / 0** in serial launch. [receipt.json](receipt.json) records exact commands, environment, limits, source, load, durations and private log hashes.

The raw 4,263 passes include the same three controlled child summaries; every parent remains. Complete comparison with the [previous gate](../owned-batch-full-validation/) retains every old identity, context, status, ignore reason and custom harness. Eight new pure controls passed; one new ignored cost experiment receives no execution credit here. All 202 mandatory identities / 208 occurrences and historical contention/rejection groups pass.

The outer closure took 863.328614s: complete cleanup, zero rescues, unchanged source. Root-reported parent exit and owner/scope absence are recorded separately. This run uses 12 reserved CPUs, 12 Cargo jobs and 12 harness threads under the prospective CPUQuota=1200% policy; serial launch is single-threaded. The historical 16-job / 316-thread profile is not claimed here.

The earlier focused Clippy E0308 remains failed; its fixture now clones the complete entry vector. Earlier failed full gates, [native setup failures](../owned-module-batch/result-v1/) and the [strict 1,342/2,048 short failure](../ordinary-accuracy-results/coordinate-01ca/) retain their labels. The explicit 4,096-site profile preserves the old 1,024-site default and its actual 2,053-site refusal. This gate does not establish full-program backend execution, performance, accuracy or A5 qualification. These durations do not establish speedup.

Reproduce at the exact revision in a clean checkout with offline caches and stable Rust 1.97.1, inside a disjoint 12-CPU reservation. Keep the receipt outside checkout; set `RECEIPT` to its absolute path, plus `STABLE_TOOLCHAIN_BIN` and `CARGO_BIN`. Use fresh paths and Python 3.9 at the repository root. It invokes the tracked validator through the existing bounded owner: 180/180/180/900/180s, outer 1,200s, 8MiB combined log caps.

```python
import importlib.util, json, os
from pathlib import Path
root = Path.cwd()
r = json.loads(Path(os.environ["RECEIPT"]).read_text())
assert len(os.sched_getaffinity(0)) == 12
values = dict(ROOT=str(root), FRESH_OUTPUT="whole-owned-repro",
    STABLE_TOOLCHAIN_BIN=os.environ["STABLE_TOOLCHAIN_BIN"], CARGO_BIN=os.environ["CARGO_BIN"])
def expand(text):
    for key, value in values.items(): text = text.replace("${" + key + "}", value)
    return text
env = dict(os.environ, **{k: expand(v) for k, v in r["environment"]["overrides"].items()})
spec = importlib.util.spec_from_file_location("owner", root / r["reproduction"]["helper"])
owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
log = root / "target/evaluation/whole-owned-repro/outer.log"
log.parent.mkdir(parents=True, exist_ok=False)
p = r["reproduction"]
result = owner.run_command([expand(v) for v in p["argv"]], env, log,
    p["outer_wall_seconds"], p["combined_log_cap_bytes"])
print(json.dumps(result))
raise SystemExit(0 if result["exit_code"] == 0 and result["termination"] is None
    and result["cleanup_complete"] and result["reaped_descendants"] == 0 else 1)
```
