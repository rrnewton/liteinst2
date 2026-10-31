# Coordinate focused controls

**102 PASS: 16 new + 86 legacy; no failures/skips/errors.** Eight suites ran once on AMD EPYC Zen 5 hardware at `23d6bad2f021ce361a24dbf0b2ef7df6931f131d` plus six files, later committed unchanged as `634480e25138203c92da30a96a5e57139739bc4e`. These were precommit tests. [receipt.json](receipt.json) retains exact commands, identities, source/closure/log pins, CPUs, loads and durations. Raw logs stay private. Tool binary/version and separate allocator-ledger custody were not captured.

To reproduce each `SUITE=0..7` once, use a clean source checkout and external `RECEIPT`; set the named environment variables, fresh relative `RUN` under `target/evaluation`, and private `RUN_TMP`. Reserve `CORES=4` for suite 0, 1 otherwise, through closure. No retries; unknown cleanup stops. Commands retain their 30 s/20 CPU or 60 s bounds and 3 s kill grace; owner 1200 s/8 MiB/3 s cleanup. This unexecuted snippet reuses the pinned owner and census:

```sh
export ROOT RECEIPT USER_HOME TOOLCHAIN CARGO_HOME RUN_TMP RUN SUITE CORES
cd "$ROOT"
cpuset-alloc run --cores "$CORES" --sample-s 1 --tag coordinate-focused-reproduce -- \
/usr/bin/python3.9 -B - <<'PY'
import hashlib,importlib.util,json,os,subprocess,sys
from pathlib import Path
from string import Template
assert not sys.flags.optimize
r=json.loads(Path(os.environ['RECEIPT']).read_text());i=int(os.environ['SUITE'])
assert 0<=i<8 and len(os.sched_getaffinity(0))==(4 if i==0 else 1)
s=dict(zip(r['columns'],r['suites'][i]));root=Path.cwd()
assert root==Path(os.environ['ROOT']).resolve()
def stable():
 return subprocess.check_output(['git','rev-parse','HEAD']).decode().strip()==r['source_commit'] and subprocess.check_output(['git','status','--porcelain=v1','--untracked-files=all']) in (b'',b'?? BRIEF-li2core.md\n')
assert stable()
def load(k):
 p=r['helpers'][k];raw=Path(p['path']).read_bytes()
 assert len(raw)==p['bytes'] and hashlib.sha256(raw).hexdigest()==p['sha256']
 spec=importlib.util.spec_from_file_location(k,p['path']);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
owner,census=load('owner'),load('census')
out=(root/os.environ['RUN']).resolve();assert out.is_relative_to(root/'target/evaluation')
out.mkdir(parents=True,exist_ok=False)
env={k:Template(v).substitute(os.environ) for k,v in r['environment'].items()}
Path(env['TMPDIR']).mkdir(parents=True,exist_ok=True)
(out/'planned.json').write_text(json.dumps(s))
c=owner.run_command(s['command'],env,out/'log',1200,8388608);same=stable()
(out/'closed.json').write_text(json.dumps(dict(owner=c,source_unchanged=same)))
assert same and census.normal(c,1200)
b=(out/'log').read_bytes();assert hashlib.sha256(b).hexdigest()==c['private_log_sha256']
census.census(b,'python_tests',{k:s[k] for k in ('count','identities_sha256')})
PY
```

Identity hashes bind sorted full names as compact UTF-8 JSON without newline. No native/phase/PMU/performance qualification: strict 2 ms, historical 1 PASS/4 FAIL and 43,200 cells remain unchanged. [Native failure](../native-1c37/README.md) stays separate. Native preparation retains 20 CPU/30 wall/1 MiB. Durations are validation metadata.
