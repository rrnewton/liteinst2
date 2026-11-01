# Fresh reproduction

Use a clean checkout at `10a778d6415e51c66dfdc122d1e019e5c8c94c3c`. Stage the pinned original/LI2/E9/nop inputs, upstream source and tool/runtime libraries from the [first-generation recipe](../functional-corpus/README.md) and inputs.json. This is a recipe for those exact assets, not arbitrary installed tools. Copy scripts outside the tracked tree before checkout.

Set absolute `CORPUS_SCRIPTS` to a directory containing the four public corpus assets run.py, capture.py, definitions.json and first-case.json; capture.py must be mode 0500. Set absolute `SCRIPTS` to a second directory containing this publication's Python and JSON files. Keep each group together. The canonical public corpus receipt stays in the checkout. `first_generation.py` changes only the imported corpus helper's readiness revision; native children remain literal.

Set the checkout root explicitly:

```sh
export ROOT="$PWD"
```

Set fresh absolute `FIRST`, `SECOND`, `CLOSURE` directly under `$ROOT/ignored/a3`. FIRST/SECOND are new directories; CLOSURE is a new file. Set `FIRST_OWNER="${FIRST}-owner"`. Never fabricate old custody records. Each command needs one externally reserved CPU and a separately closing parent scope; `cpuset-alloc` supplies that dependency. Preserve failures and do not retry.

Save this exact source, including its final newline, as `$SCRIPTS/fresh-owner.py`. The closer pins its bytes. It makes one owned dispatch and retains actual source/live/closed records; it does not supply an independent live witness.

```python
import hashlib, importlib.util, json, os, resource, stat, sys
from pathlib import Path
if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit('Use assertions-enabled Python -I -B')
root = Path.cwd().resolve()
stage, scripts, corpus, out = sys.argv[1:5]
scripts, corpus, out = map(lambda p: Path(p).resolve(), (scripts, corpus, out))
assert stage in ('first', 'second') and out.parent == root/'ignored/a3'
cpus = sorted(os.sched_getaffinity(0)); assert len(cpus) == 1
cpu = 4800 if stage == 'first' else 2400
wall = 9000 if stage == 'first' else 2400
for key, value in ((resource.RLIMIT_CPU,cpu),(resource.RLIMIT_AS,38654705664),
                   (resource.RLIMIT_FSIZE,536870912),(resource.RLIMIT_CORE,0)):
    resource.setrlimit(key,(value,value))
meta = out.with_name(out.name+'-owner')
logs = root/'target/evaluation'/meta.name
assert not any(os.path.lexists(p) for p in (meta,logs,out))
meta.mkdir(mode=0o700); logs.mkdir(mode=0o700,parents=True)
helper = root/'evaluation/admission/processes.py'
def stamp(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def pin(path):
    fd = os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_size <= 1048576
        digest = hashlib.sha256(); size = 0
        while True:
            data = os.read(fd,65536)
            if not data: break
            size += len(data); assert size <= before.st_size
            digest.update(data)
        assert size == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat())
        return dict(bytes=size,sha256=digest.hexdigest(),stat=stamp(before))
    finally:
        os.close(fd)
source = Path(__file__).resolve(); assert source == scripts/'fresh-owner.py'
source_pins = {str(p):pin(p) for p in (source,helper)}
assert source_pins[str(helper)]['sha256'] == '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
unit = 'li2core-functional-repro-'+str(os.getpid())
subject = [str(scripts/'first_generation.py'),'--corpus-scripts',str(corpus)]
if stage == 'second':
    assert len(sys.argv) == 8
    first, closure, digest = sys.argv[5:8]
    subject = [str(scripts/'reproduce.py'),'--first-generation',str(Path(first).resolve()),
               '--closure',str(Path(closure).resolve()),'--closure-sha',digest]
else:
    assert len(sys.argv) == 5
subject += ['--cpu',str(cpus[0]),'--unit',unit,'--out',str(out)]
command = ['/usr/bin/systemd-run','--user','--scope','--collect','--quiet','--unit='+unit,
           '-p','AllowedCPUs='+str(cpus[0]),'-p','CPUQuota=100%','-p','MemoryMax=1073741824',
           '-p','MemorySwapMax=0','-p','TasksMax=64','--','/usr/bin/python3.9','-I','-B',*subject]
live = dict(pid=os.getpid(),stat=Path('/proc/self/stat').read_text(),
            cgroup=Path('/proc/self/cgroup').read_text(),cpus=cpus,command=command,
            load=os.getloadavg(),source_pins=source_pins,independent_witness=False)
with (meta/'live.json').open('x') as f:
    json.dump(live,f); f.flush(); os.fsync(f.fileno())
spec = importlib.util.spec_from_file_location('owner',helper)
owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
assert all(pin(Path(p)) == v for p,v in source_pins.items())
r = owner.run_command(command,dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),
                      logs/'outer.log',wall,8388608)
same = all(pin(Path(p)) == v for p,v in source_pins.items())
with (meta/'closed.json').open('x') as f:
    json.dump(dict(r,source_pins=source_pins,source_unchanged=same),f); f.flush(); os.fsync(f.fileno())
assert same and r['cleanup_complete'] and r['termination'] is None and r['reaped_descendants'] == 0
raw = (logs/'outer.log').read_bytes()
assert len(raw) <= 8388608 and hashlib.sha256(raw).hexdigest() == r['private_log_sha256']
with (meta/'outer.log').open('xb') as f:
    f.write(raw); f.flush(); os.fsync(f.fileno())
raise SystemExit(r['exit_code'] if r['exit_code'] in (0,1) else 125)
```

Run the first producer once with a fresh reservation tag:

```sh
cpuset-alloc run --cores 1 --tag fresh-selfhost-first -- \
  /usr/bin/python3.9 -I -B "$SCRIPTS/fresh-owner.py" first "$SCRIPTS" "$CORPUS_SCRIPTS" "$FIRST"
```

The canonical first-generation outcome is outer exit **1**, with all ten strict coverage results FAILED. Exit 1 alone is insufficient. After the entire command/scope closes, obtain `RECEIPT_SHA`, `LIVE_SHA`, `OWNER_SHA` from the new FIRST/receipt.json and FIRST_OWNER/{live,closed}.json using sha256sum. Authenticate that new CLOSED data once:

```sh
cpuset-alloc run --cores 1 --tag fresh-selfhost-close -- \
  /usr/bin/timeout --kill-after=5s 90s /usr/bin/python3.9 -I -B \
  "$SCRIPTS/close_first_generation.py" --first-generation "$FIRST" \
  --corpus-scripts "$CORPUS_SCRIPTS" --receipt-sha "$RECEIPT_SHA" \
  --owner-live-sha "$LIVE_SHA" --owner-closed-sha "$OWNER_SHA" --out "$CLOSURE"
```

The closer requires released parent/worker scopes, all 40 normal child closures and the canonical requests, products and complete ordered outcomes. It is metadata-only, CPU 60, AS 256MiB, file 1MiB and wall 90. If it exits 0, set `CLOSURE_SHA` to the new closure's SHA256 and run the fresh six-chain passthru stage once:

```sh
cpuset-alloc run --cores 1 --tag fresh-selfhost-second -- \
  /usr/bin/python3.9 -I -B "$SCRIPTS/fresh-owner.py" second "$SCRIPTS" "$CORPUS_SCRIPTS" "$SECOND" \
  "$FIRST" "$CLOSURE" "$CLOSURE_SHA"
```

The first stage uses generator CPU 30f/wall 45f/AS 1GiB, backend CPU 60f/wall 90f/AS 36GiB, and outer CPU 4800/wall 9000. The second uses per-process CPU 60f, chain wall 135f/AS 36GiB and outer CPU/wall 2400. f is 4 for e9tool and 1 for e9patch. Both use one CPU, physical 1GiB, swap 0, tasks 64, file 512MiB and logs 8MiB*f. Each independently admits 2GiB+64MiB below 20GB. Its actual completed run and the failed post-close external identity check are recorded separately in receipt.json; no historical failure is upgraded.

# Remaining four stock actions

The measured 24-row STOCK matrix closed with 21 accepted byte comparisons, one source-identity failure and two undispatched E9 print chains. The failed LI2/e9patch print chain exited 0, but its source guard stopped acceptance and later dispatch; diagnostic byte equality did not change that result. This recipe uses new public configurations and has not itself been executed. Their new profile follows stock e9test.sh: matching generated pairs, the same original inputs/actions, no added debug, FD1/FD2=/dev/null, normal exit and complete ELF byte equality. Ordered outcomes remain UNOBSERVED/null; first-generation strict failures stay FAILED. No passthru rerun is part of this stage.

Stage exact run_stock.py, stock_owner.py, matrix_disk.py, matrix_controls.py, binding.json, owner-binding.json and matrix-template.json beside inputs.json. The public configurations omit private review artifacts; all executable/runtime/canonical pins remain. They are new, unexecuted configurations, distinct from the private execution bindings. The direct guarded controls can be reproduced without native execution:

```sh
cpuset-alloc run --cores 1 --tag fresh-stock-disk-controls -- \
  /usr/bin/timeout --kill-after=3s 60s /usr/bin/python3.9 -I -B "$SCRIPTS/matrix_controls.py"
```

The measured private control launcher used an inner 45-second subprocess timeout and an outer 60-second timeout. Its actual single run exited 0; the prospective command above runs the guarded source directly. The pure control source enforces CPU 30/AS 256MiB/file 1MiB/core 0.

Create one fresh metadata directory and immutable matrix. The template fixes actions 1–4 and their sixteen absent run/log/owner roots. Use a fresh checkout/output set if any root already exists. Keep the original closer source at its authenticated path. Verified restored products are checked by content/current identity; consumed first-generation logs/requests need not remain expanded.

```sh
export ROOT SCRIPTS FIRST CLOSURE CLOSURE_SHA
export MATRIX="$ROOT/ignored/a3/functional-selfhost-stock-matrix-v2/matrix.json"
mkdir -m 700 "$(dirname "$MATRIX")"
/usr/bin/python3.9 -I -B - "$SCRIPTS" "$MATRIX" "$FIRST" "$CLOSURE" "$CLOSURE_SHA" <<'MATRIX_JSON'
import json, pathlib, sys
root = pathlib.Path.cwd().resolve()
scripts, target, first, closure = map(pathlib.Path, sys.argv[1:5])
m = json.loads((scripts/'matrix-template.json').read_text())
m.update(first_generation=str(first.relative_to(root)), closure=str(closure.relative_to(root)), closure_sha256=sys.argv[5])
with target.open('x') as f:
    json.dump(m, f); f.write('\n')
MATRIX_JSON
export MATRIX_SHA="$(sha256sum "$MATRIX" | cut -d' ' -f1)"
export OWNER_BINDING_SHA="$(sha256sum "$SCRIPTS/owner-binding.json" | cut -d' ' -f1)"
```

All four actions share **one** 2GiB data and 64MiB metadata envelope. Initial admission reserves the full sum. Later admission uses fresh allocated/apparent slot counts plus the unused reservation in the same dimension. Every prior output and both log copies stay charged. The unchanged 20GB ceiling, per-native limits and per-action CPU/wall 2400/log 8MiB remain. No concurrent owner or archival writer may touch the declared roots.

For one action at a time, set and export `I=1` (then 2, 3, 4), `STOCK_ACTION="$ROOT/ignored/a3/functional-selfhost-stock-$I-v2"`, and `PREVIOUS_SHA`. For action 1, PREVIOUS_SHA is empty. For later actions it is the authenticated SHA256 of the immediately preceding owner's CLOSED file, obtained only after its process/scope release check. Start the following independent observer in a second terminal with the same exported variables **before** launching that owner. It observes the actual process; it never manufactures a successful witness.

```sh
cpuset-alloc run --cores 1 --tag "fresh-stock-witness-$I" -- \
  /usr/bin/timeout --kill-after=3s 90s /usr/bin/prlimit --cpu=5 --as=268435456 --fsize=65536 --core=0 -- \
  /usr/bin/python3.9 -I -B - <<'LIVE_WITNESS'
import hashlib, json, os, pathlib, sys, time
if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit('Use assertions-enabled Python -I -B')
P = pathlib.Path
root, scripts, matrix, first, closure, run = map(lambda k:P(os.environ[k]).resolve(), ('ROOT','SCRIPTS','MATRIX','FIRST','CLOSURE','STOCK_ACTION'))
i = int(os.environ['I']); assert i in (1,2,3,4) and P.cwd().resolve() == root
expected = ['/usr/bin/python3.9','-I','-B',str(scripts/'stock_owner.py'),
 '--binding-sha',os.environ['OWNER_BINDING_SHA'],'--matrix',str(matrix),'--matrix-sha',os.environ['MATRIX_SHA'],
 '--action-index',str(i),'--first-generation',str(first),'--closure',str(closure),
 '--closure-sha',os.environ['CLOSURE_SHA'],'--out',str(run)]
if i > 1: expected += ['--previous-closed-sha',os.environ['PREVIOUS_SHA']]
else: assert not os.environ['PREVIOUS_SHA']
meta = run.with_name(run.name+'-owner'); path = meta/'live.json'; deadline = time.monotonic()+60
while not path.exists():
    assert time.monotonic() < deadline
    time.sleep(.1)
v = json.loads(path.read_text()); q = P('/proc')/str(v['pid'])
raw = (q/'stat').read_text(); start = raw.rsplit(')',1)[1].split()[19]
assert start == v['stat'].rsplit(')',1)[1].split()[19]
assert (q/'cgroup').read_text() == v['cgroup'] and sorted(os.sched_getaffinity(v['pid'])) == v['cpus'] and len(v['cpus']) == 1
assert (q/'cwd').resolve() == root
assert [x.decode() for x in (q/'cmdline').read_bytes().split(b'\0')[:-1]] == expected
assert v['action_index'] == i and v['dispatch_limit'] == 1 and v['wall_seconds'] == 2400 and v['log_bytes'] == 8388608
assert hashlib.sha256((scripts/'owner-binding.json').read_bytes()).hexdigest() == os.environ['OWNER_BINDING_SHA']
assert hashlib.sha256(matrix.read_bytes()).hexdigest() == os.environ['MATRIX_SHA']
cg = v['cgroup'].strip(); assert cg.startswith('0::/') and '..' not in P(cg[3:]).parts
assert (P('/sys/fs/cgroup')/cg[4:]/'cpuset.cpus.effective').read_text().strip() == str(v['cpus'][0])
assert (q/'stat').read_text().rsplit(')',1)[1].split()[19] == start
with (meta/'root-live.json').open('x') as f:
    json.dump(dict(authenticated=True,pid=v['pid'],starttime=start,cgroup=v['cgroup'],cpus=v['cpus'],raw_stat=raw,command=expected),f)
    f.write('\n'); f.flush(); os.fsync(f.fileno())
LIVE_WITNESS
```

Launch the corresponding owner in the first terminal (Bash):

```bash
extra=()
if [ "$I" != 1 ]; then extra=(--previous-closed-sha "$PREVIOUS_SHA"); fi
cpuset-alloc run --cores 1 --tag "fresh-stock-$I" -- \
  /usr/bin/python3.9 -I -B "$SCRIPTS/stock_owner.py" \
  --binding-sha "$OWNER_BINDING_SHA" --matrix "$MATRIX" --matrix-sha "$MATRIX_SHA" \
  --action-index "$I" --first-generation "$FIRST" --closure "$CLOSURE" \
  --closure-sha "$CLOSURE_SHA" --out "$STOCK_ACTION" "${extra[@]}"
```

The owner preserves all six rows and an exact dispatched prefix on failure. After it returns, retain its CLOSED file/hash, worker receipt and logs. Independently check that the parent and worker PID identities and scopes are gone. The next owner rechecks release and the complete pinned prior-closure chain; it refuses a partial/global source, capacity or lifecycle failure. For the final action, perform the same release check rather than relying on a later action. A normal byte mismatch remains FAILED. Do not execute output products outside these declared chains or infer full instrumentation from a stock byte pass.
