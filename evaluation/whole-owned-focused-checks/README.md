# Whole-program profile and owned-batch focused checks

V1 at `ba6417b8669c03553331bee860f7b80f4778dc40` **failed strict Clippy** (E0308, exit101): an integration fixture supplied `Arc<Vec<LegalEntry>>` instead of `Vec<LegalEntry>`. Formatting and five test groups passed: rewrite library168, bridge10, sites5, owned16 (two native controls ignored), doctests2.

The sole correction, `site.heads.as_ref().clone()`, copies the complete vector with all assertions unchanged. V2 at `002cf64b288735c185d1c3863d1dbdfd893373eb` **passed three corrective checks**: fmt, strict Clippy and the affected composition test (1pass,18filtered). The five v1 groups were not rerun; v1 remains failed.

[receipt.json](receipt.json) retains all ten outcomes, exact commands/revisions/trees, recorded CPU IDs/load, durations and log hashes, including the zero-test doctest harness. Every command closed normally with complete cleanup/zero rescue reaps and the unchanged180s/8MiB bound. Each controller recorded12CPU affinity/HARD cgroup; jobs/harness threads were12 under the owner's1200% quota policy. Quota and release are not independently certified here. Wall durations include scheduling/compilation, not CPU cost or speedup.

This is focused correctness, not full-workspace, native/performance, full-program planner/backend or A5 qualification. Earlier failures remain, including strict1342/2048 and the old1024-site refusal. The new larger profile is explicit; default bounds stay unchanged.

## Reproduce

Keep the receipt outside a clean checkout of the selected exact revision. Reserve12 disjoint CPUs within the1200% lane quota and select the stable Rust toolchain with offline dependencies. This portable wrapper uses the existing owner, runs every selected command and preserves failure; the original controllers remain private. No allocator operation is included.

```sh
export RECEIPT=/absolute/path/to/receipt.json RUN_ID=v2
export TOOLCHAIN_BIN=/absolute/path/to/stable/toolchain/bin
export CARGO_BIN=/absolute/path/to/cargo/bin
export LOG_DIR="$PWD/target/evaluation/whole-owned-reproduction-v2"
python3.9 -I -B - <<'PY'
import hashlib, importlib.util, json, os, pathlib, subprocess
root = pathlib.Path.cwd()
r = json.loads(pathlib.Path(os.environ['RECEIPT']).read_text())
run = next(x for x in r['runs'] if x['id'] == os.environ['RUN_ID'])
assert subprocess.check_output(['git','rev-parse','HEAD'], text=True).strip() == run['revision']
assert not subprocess.check_output(['git','diff','--binary','HEAD'])
assert len(os.sched_getaffinity(0)) == 12
h = root / r['reproduction']['helper']
assert hashlib.sha256(h.read_bytes()).hexdigest() == r['reproduction']['helper_pin']['sha256']
s = importlib.util.spec_from_file_location('owner', h)
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
logs = pathlib.Path(os.environ['LOG_DIR']).resolve()
assert logs.is_relative_to(root / 'target/evaluation')
logs.mkdir(parents=True, exist_ok=False)
env = dict(os.environ)
replace = {'${ROOT}':str(root), '${TOOLCHAIN_BIN}':os.environ['TOOLCHAIN_BIN'],
           '${CARGO_BIN}':os.environ['CARGO_BIN']}
for key, value in r['policy']['environment_overrides'].items():
    for a, b in replace.items(): value = value.replace(a, b)
    env[key] = value
failed = False
for row in run['records']:
    name = row['command']
    x = m.run_command(r['commands'][name], env, logs/(name+'.log'), 180, 8388608)
    print(json.dumps({'command':name,'result':x}), flush=True)
    failed |= (x['exit_code'] != 0 or x['termination'] is not None
               or not x['cleanup_complete'] or x['reaped_descendants'] != 0)
assert not subprocess.check_output(['git','diff','--binary','HEAD'])
raise SystemExit(int(failed))
PY
```

Use `RUN_ID=v1` with its exact revision/fresh log directory for the seven-command history. `evaluation/short-neighbor-parallel/validate.py` is the separate five-command full-workspace recipe at12jobs/12threads; no such broader run is claimed here.
