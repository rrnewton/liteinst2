The companion JSON records validation at revision `4f3e28e7e1d434bc6d51c95bab828557a6d37442`. The actual C component completed 26 hit, 87 miss and two storage assertions; its build took 3.772917956 s and execution 0.013264735 s. The separate runtime-loader compile took 5.464686878 s. These are validation durations, with no performance or qualification credit.

The component forces metadata keys into the cache. It does not demonstrate insertion after real cancellation, guest execution or owner completion. The compile uses two older generated configuration headers, reproduced byte-for-byte in the JSON, solely for syntax/type integration. It does not establish a current linked binding. Compile attempt 1 remains a zero-command harness failure: its inline Python module filename was `<stdin>`. Attempt 2 corrected that harness input selection and is a separate result.

Reproduction requires Linux x86-64, GCC, Python 3, and a clean checkout of the exact revision above. Reserve one available logical CPU, set `CPU` to it, and set `SUMMARY` to the absolute path of the companion JSON. Run from the checkout root. The script below reconstructs commands from the retained receipts; this combined manual recipe has not itself been run. The observed component used a private copy of `build.sh` and `oracle.c` whose bytes equal the tracked versions used here. The observed compile harness was inline, without a retained driver file.

```sh
export CPU SUMMARY
# Example SUMMARY="$PWD/target/.../loop-negative-hint-4f3e28e7e1d4.json"
taskset -c "$CPU" timeout 180s nice -n 10 python3 -B - <<'PY'
import hashlib, json, os, resource, shlex, sys
from pathlib import Path
root = Path.cwd().resolve()
s = json.loads(Path(os.environ['SUMMARY']).read_text())
affinity = sorted(os.sched_getaffinity(0)); assert len(affinity) == 1
for kind, value in ((resource.RLIMIT_CPU, 180), (resource.RLIMIT_AS, 512<<20),
                    (resource.RLIMIT_FSIZE, 64<<20), (resource.RLIMIT_CORE, 0)):
    resource.setrlimit(kind, (value, value))
sys.path.insert(0, str(root/'evaluation/inprocess'))
from page_selected_process import invoke
out = root/'target/evaluation/inprocess/loop-negative-hint-manual-reproduction-1'
out.mkdir(exist_ok=False)
selected = root/'tools/page-entry/selected'
fixture = selected/'tests/loop_negative_hint/build.sh'
env = dict(LANG='C', LC_ALL='C', PATH='/usr/bin:/bin',
           PYTHONDONTWRITEBYTECODE='1', TZ='UTC')
meta, build, component = [10,512<<20,16<<20,20], [30,512<<20,64<<20,60], [5,512<<20,16<<20,15]
def run(name, argv, bounds, extra=None):
    row = dict(name=name, argv=list(map(str, argv)), bounds=bounds,
               capture_limit=8<<20, environment=dict(env, **(extra or {})))
    stdout, stderr = invoke(row, out, affinity[0])
    assert row['exit'] == 0 and not stderr, name
    return stdout

def source_facts():
    for name, expected in s['sources'].items():
        raw = (root/name).read_bytes()
        assert len(raw) == expected['bytes']
        assert hashlib.sha256(raw).hexdigest() == expected['sha256']
source_facts()
git = ['/usr/bin/git','-C',root,'-c','index.threads=1','-c','core.preloadIndex=false']
head = run('head-before', git+['rev-parse','HEAD'], meta)
assert head == (s['revision']+'\n').encode()
assert not run('status-before', git+['status','--porcelain','--untracked-files=no'], meta)
cc = {'LI2_CC':'/usr/bin/gcc'}
run('cc-version', ['/usr/bin/gcc','--version'], meta, cc)
before = run('headers-before', ['/bin/sh',fixture,selected,out,'headers'], meta, cc)
assert not run('build', ['/bin/sh',fixture,selected,out,'build'], build, cc)
assert run('component', [out/'loop-negative-hint'], component, cc) == (
    b'loop_negative_hint hits=26 misses=87 storage=2 entries=8 owner_entries=0\n')
assert run('headers-after', ['/bin/sh',fixture,selected,out,'headers'], meta, cc) == before

# Reconstruct the two exact old headers; this grants no current binding authority.
config = out/'historical-config'; config.mkdir()
for h in s['compile_attempt_2']['config_headers']:
    raw = h['content'].encode()
    assert len(raw) == h['bytes'] and hashlib.sha256(raw).hexdigest() == h['sha256']
    (config/h['name']).write_bytes(raw)
recipe = (selected/'build-persistent-loop.sh').read_text()
flags = shlex.split(recipe.split('"$cc_bin"',1)[1].split('-I"$output"',1)[0].replace('\\\n',' '))
assert sum(x.startswith('-D') for x in flags) == 47
args = ['/usr/bin/gcc',*flags,'-I'+str(config),'-I'+str(selected),'-I'+str(selected.parent)]
run('controller-headers', args+['-M',selected/'runtime_loader.c'], meta)
assert not run('controller-compile', args+['-c',selected/'runtime_loader.c','-o',out/'runtime_loader.o'], build)
assert run('head-after', git+['rev-parse','HEAD'], meta) == head
assert not run('status-after', git+['status','--porcelain','--untracked-files=no'], meta)
source_facts()
PY
```

Each child uses the existing bounded process owner: metadata 10 CPU/20 wall seconds, build or compile 30/60, and component 5/15; all have 512 MiB address-space and 8 MiB per captured stream. The file-size limits are 16 MiB for metadata/component and 64 MiB for compilation. The prospective combined recipe has a 180-second outer bound. Actual component and compile attempts had separate outer wrappers; the JSON reports their measured child durations, not a time for this recipe. Private receipts retain raw commands and captures; none are copied into this public summary.
