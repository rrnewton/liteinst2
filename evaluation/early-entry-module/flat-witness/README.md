# Flat witness extraction

Source `5c580fdbe4ba37bac33432127abc1af5584d0a2f`, tree `4104d2c6d1931a38a701b2f2b8091d19d81bdcb5`; AMD EPYC Zen 5 dev host. The qualification-only adapter owns 128 header and 512 journal words and releases TLS borrows before publication. Typed reference, actual receipt summary and full 640-word comparator remain independent.

Focused first attempt FAILED: fmt passed; library 595 passed with 37 unchanged ignores. Calibration compilation timed out at 180 seconds with empty stdout; Clippy UNRUN. One authorized 12-CPU/jobs continuation passed calibration (242 passed, 1 ignored) and scoped Clippy, carrying the two prior successes. Harness 1, wall and file limits remained; 120 CPU seconds is per process, so aggregate exposure changed. The first failure stays FAILED. Native 4 PASS is default-feature correctness only, not encoded/AVX state credit.

Static: setup Box 5,152 B / init 5,129 B; runtime local frames 88/8/8/8 B; full 1,024 B header reset and 4,096 B journal copy; separate publication and existing witness allocation retained. These facts establish no executed savings; caveats below.

Strict 20,000-step attempt FAILED: 1 cohort failed, 11 unobserved and 0 completed pairs; its plan retains 1 failed and 31 unobserved rows.

Separate 80,000-step qualification PASS: 288 pairs / 576 children / 139,872 exact comparisons, no mismatch. All 288 matched candidate counts decreased (total −400,242); originals, other fields, plans and coverage were unchanged. Enabled counts remain 33,973–35,321; 144 of all 288 rows exceed 20,000. All 33 produced CSVs are retained.

The first full gate FAILED at its 900-second workspace timeout: fmt/Clippy/check PASS, cleanup complete with 3 rescued descendants, serial UNOBSERVED. The partial census records 2,812 top-level passes, 1 ignore, two unfinished neighbor cases and 38 later contexts not started; no complete workspace or serial result is inferred.

The separately declared 1,800-second full correctness attempt PASSed all five commands: 4,570 top-level passes plus 11 nested passes (4,581 raw), 43 ignored; profiler 595 passed/37 ignored, default calibration 237 passed/1 ignored, ordinary interval 522 passed/1 ignored and serial 1,039 passed. All 27 critical cases, 5 required serial cases and 21 short-neighbor cases passed. Workspace elapsed 870.4284 seconds and serial 132.2486 seconds are operational records under that declared profile; the first 900-second failure remains FAILED. The root retains this candidate after the reviewed fixed outcomes; strict A4 remains open. The [row-prefix baseline](../row-prefix/receipt.json) retains earlier failures:

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.

Candidate strict status is separate. Matched arithmetic preserves increases/originals; no causal, throughput or quiet-host claim.

Check out the exact clean source; export ROOT, TOOLCHAIN, USER_HOME and CARGO_HOME. Reserve one CPU externally and run once per MODE=native, strict, wide with fresh paths. The wrapper uses the public recipes and original 1,800/11,000-second, 8MiB whole-driver bounds. It is reproduction syntax, not the original launcher.

```bash
cd "$ROOT"
export MODE=native  # repeat once with strict, then wide; retain every outcome
python3.9 -I -B - <<'PY'
import importlib.util, json, os
from pathlib import Path
root=Path(os.environ['ROOT']).resolve(); mode=os.environ['MODE']
assert len(os.sched_getaffinity(0))==1
script,wall={'native':('reproduce.py',1800),'strict':('state.py',11000),'wide':('state_wide_80k.py',11000)}[mode]
out=root/'ignored/flat-witness-reproduction'/mode
logs=root/'target/evaluation/flat-witness-reproduction'/mode
out.mkdir(parents=True,exist_ok=False); logs.mkdir(parents=True,exist_ok=False)
spec=importlib.util.spec_from_file_location('owner',root/'evaluation/admission/processes.py')
owner=importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
argv=['/usr/bin/python3.9','-I','-B',str(root/'evaluation/early-entry-module'/script),'--root',str(root),'--revision','5c580fdbe4ba37bac33432127abc1af5584d0a2f','--toolchain',os.environ['TOOLCHAIN'],'--user-home',os.environ['USER_HOME'],'--cargo-home',os.environ['CARGO_HOME'],'--output',str(out/'result')]
r=owner.run_command(argv,dict(PATH='/usr/bin:/bin',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1'),logs/'driver.log',wall,8<<20)
with (out/'owner.json').open('x') as f:
    json.dump(r,f,sort_keys=True); f.write('\n'); f.flush(); os.fsync(f.fileno())
assert r['cleanup_complete'] and r['reaped_descendants']==0
assert r['termination'] is None
raise SystemExit(r['exit_code'])
PY
```

Measure allocated/apparent ROOT, ignored and target before and after each attempt; root ceilings remain 19,994,091,520 / 19,061,190,371 bytes. Those external inventories are not implemented by the wrapper above. Scientific limits remain 20,000 / 80,000 steps, 15 seconds per pair and 2 seconds cleanup, with all 640 witness words compared. Native permissions and hardware prerequisites still apply.

Save RECEIPT outside ROOT or under ignored. MODE=first/remaining/full-first/full requires 1/12/12/12 reserved disjoint CPUs. Run once per selected phase, after earlier owners close; no automatic retry. First runs fmt/library/calibration; remaining runs calibration/Clippy with jobs 12, harness 1. A historical timeout is not guaranteed to repeat. Full-first/full use the same five commands with workspace walls 900/1,800 seconds respectively; all other walls are 180 seconds, captures 8 MiB and harness threads 12 except serial 1. This is reproduction syntax, not the original launcher.

```bash
cd "$ROOT"
python3.9 -I -B - <<'PY'
import hashlib, importlib.util, json, os, subprocess
from pathlib import Path
R=Path(os.environ['ROOT']).resolve(); m=os.environ['MODE']
j=json.loads(Path(os.environ['RECEIPT']).read_bytes()); full=m in ('full-first','full')
g=j['full_first' if m=='full-first' else 'full'] if full else None
assert m in ('first','remaining','full-first','full') and j['revision']=='5c580fdbe4ba37bac33432127abc1af5584d0a2f'
assert len(os.sched_getaffinity(0))==(1 if m=='first' else 12)
def clean():
    def git(*a): return subprocess.check_output(['/usr/bin/git','-C',str(R),*a],timeout=15)
    assert git('rev-parse','HEAD','HEAD^{tree}').decode().split()==[j['revision'],j['tree']]
    assert not git('status','--porcelain','--untracked-files=no')
clean()
D=R/'ignored/flat-witness-validation'/m; L=R/'target/evaluation/flat-witness-validation'/m
for p in (D,L): p.mkdir(parents=True,exist_ok=False)
s=importlib.util.spec_from_file_location('owner',R/'evaluation/admission/processes.py')
o=importlib.util.module_from_spec(s); s.loader.exec_module(o)
def save(p,b):
    with p.open('xb') as f: f.write(b); f.flush(); os.fsync(f.fileno())
def sha(b): return hashlib.sha256(b).hexdigest()
safe=True
def run(n,a,e,w,c,check=True):
    global safe
    safe=False
    r=o.run_command(a,e,L/n,w,c)
    save(D/(n+'.owner'),json.dumps(r).encode())
    safe=r['cleanup_complete']
    assert safe and not r['reaped_descendants']
    b=(L/n).read_bytes(); assert len(b)<=c and sha(b)==r['private_log_sha256']
    save(D/(n+'.log'),b)
    if check: assert r['termination'] is None and r['exit_code']==0
    return b if check else r
def cap(tag):
    for apparent,limit in [(False,19994091520),(True,19061190371)]:
        a='/usr/bin/prlimit --cpu=30 --as=268435456 --fsize=65536 --core=0 -- /usr/bin/du --block-size=1 --count-links --max-depth=1'.split()
        b=run(tag+str(apparent),a+(['--apparent-size'] if apparent else [])+[str(R)],{'PATH':'/usr/bin:/bin','LC_ALL':'C'},180,65536)
        rows=dict(x.split('\t',1)[::-1] for x in b.decode().splitlines())
        v=[int(rows[str(p)]) for p in (R,R/'ignored',R/'target')]
        assert min(v)>0 and v[0]<limit
def expand(v):
    for k in ('ROOT','TOOLCHAIN','USER_HOME','CARGO_HOME'): v=v.replace('${'+k+'}',os.environ[k])
    assert '${' not in v
    return v
def env(v): return {k:expand(x) for k,x in v.items()}
def compose(base,d): return {k:v for k,v in base.items() if k not in d['remove']}|d['set']
phase=None if full else next(p for p in j['focused']['phases'] if p['name']==m)
F=compose(j['environment'],g['environment_delta'] if full else phase['environment_delta'])
e=env(F)
assert e['CARGO_INCREMENTAL']=='0' and e['CARGO_BUILD_JOBS']==('1' if m=='first' else '12')
assert e['CARGO_PROFILE_DEV_DEBUG']==e['CARGO_PROFILE_TEST_DEBUG']=='0'
assert full or e['RUST_TEST_THREADS']=='1'
cap('before')
try:
    commands=g.get('commands') if full else phase['commands']
    if full and commands is None:
        assert g['commands_ref']=='full.commands'
        commands=[[n,a,g['wall_seconds_set'].get(n,w)] for n,a,w in j['full']['commands']]
    assert len(commands)==(5 if full else 3 if m=='first' else 2)
    for i,c in enumerate(commands):
        clean(); n=str(i)
        if full:
            name,a,w=c; assert w==[180,180,180,900 if m=='full-first' else 1800,180][i]
            if i==4: e=env(compose(F,g['serial_environment_delta']))
            assert e['RUST_TEST_THREADS']==('1' if i==4 else '12')
            run(n,a,e,w,8<<20)
        else:
            name,a=c; bounds=j['focused']['bounds']
            assert (bounds['cpu_seconds'],bounds['wall_seconds'],bounds['file_bytes'])==(120,180,128<<20)
            q=dict(bounds,argv=list(map(expand,a)),cwd=str(R),env=e,stdout=str(D/(n+'.out')),stderr=str(D/(n+'.err')))
            req=D/(n+'.request'); res=D/(n+'.receipt'); save(req,json.dumps(q).encode())
            owned=run(n,['/usr/bin/python3.9','-I','-B',str(R/'tools/unwind-oracle/bounded_command.py'),'--request',str(req),'--receipt',str(res)],e,205,1<<20,check=False)
            z=json.loads(res.read_bytes())
            assert owned['termination'] is None and owned['exit_code']==0
            assert z['request_sha256']==sha(req.read_bytes()) and z['inputs_unchanged'] and z['absence_proof']=='ECHILD'
            assert z['exit']==0 and not (z['wall_timeout'] or z['unexpected_descendants'] or z['cleanup_events'] or z['aborted'] or z['cleanup_error'])
            if name in ('library-tests','calibration-tests'):
                b=Path(q['stdout']).read_bytes(); assert sha(b)==z['stdout_sha256']
                assert (b'595 passed; 0 failed; 37 ignored;' if name=='library-tests' else b'242 passed; 0 failed; 1 ignored;') in b
        clean()
finally:
    if safe: cap('after')
PY
```

Receipt tables are lossless: files.groups[profile][case_index] rows [name_index,bytes,SHA] name csv/profile/case_names.state[case_index]/files.names[name_index]. Campaign case indices use case_names; recipe_command_set replaces cells in recipe_command_base. Full outcome names index full.commands. Full-first commands_ref plus wall_seconds_set reconstruct its original five commands; the failed attempt retains its own outcomes, partial census, owners, source and capacity results. Environment deltas remove keys then apply set: each full attempt and focused phase composes against environment; serial composes against that attempt. Null means unrecorded. Tools/statistics declare columns; binary refs use build.binary. Static function columns distinguish instruction rows from executed counts. Source/review references do not claim independent knowledge of uninspected callees.

## Evidence scope

Presentation limits are 32 KiB for the receipt and 128 KiB for the packet, expanded from 20/100 KiB to retain both failed full-gate history and focused continuation. This changes no scientific, test, CPU, capture or capacity limit; no evidence is omitted. Earlier reporting refusals remain in the linked baseline history.

The workspace wall budget expands from 900 to 1,800 seconds for one separately named full correctness attempt. The original 900-second attempt remains FAILED; no scientific limit or comparator changes and no quiet-host or timing comparability claim.
Pinned CLOSED records and independent review hashes; review applicability, source/static interpretation and external CPU reservations are root-attested. No raw log or executable payload is projected.

Focused phases: Three pre-run source pins and current readback only; no whole-tree revision freeze or recorded workload postflight guard is invented.

Focused attempts: Both attempts record fixed-ceiling preflight only; no postflight or quiet-host result is invented.

Same-identity step arithmetic only; includes all increases and unchanged originals. No timing, causal function attribution, production throughput or strict-pass inference.

Every243 name/22panic bits/exact ignore reason equal v27; required179 preserved through identical recipe and complete roster.

Strict preparation: All37 complete preparation requests equal v27 after output namespace only; full caller4/Python18/reader6 rosters equal. Native argv/env/stream paths also unchanged after namespace.

Root-attested source applicability, reservation, policy and history (not an independent allocator witness):

Source 5c580fdbe4ba37bac33432127abc1af5584d0a2f, tree 4104d2c6d1931a38a701b2f2b8091d19d81bdcb5, adds only the three reviewed, formatted flat-witness files beyond 4261826. Focused checks, static inspection and fixed campaigns bind those bytes; both full attempts retain source postflight checks. Fresh main 4261826 is an ancestor. No scientific recipe changed.

Root invoked cpuset-alloc: native, strict, wide and first focused attempts each reserved one CPU; the focused continuation and both full attempts each reserved twelve disjoint CPUs. Cargo jobs and harness threads were bounded at 12. Actual affinities and loads are retained; no independent allocator-live witness or quiet-host claim.

The original full-v27 remains FAILED at its 900-second workspace timeout, with serial UNOBSERVED. Exactly one separate full-correctness-1800 rerun was declared before dispatch and passed. Its aggregate wall budget expanded; tests, case deadlines, captures, CPU and capacity guards stayed unchanged. This does not qualify the original 900-second gate, a quiet host or performance.

Retain the first focused compilation timeout at 180 seconds and its declared 12-CPU continuation; the failed 900-second full attempt and separate 1,800-second success; strict20k FAILED and wide80k PASS. Earlier row-prefix/AVX failures and the rejected, reverted capsule remain in baseline records. Only presentation caps expanded to 32 KiB receipt/128 KiB packet before projection; no scientific limit changed.

Prepare/matches GOT and observer-vtable association are source-assisted; slot contents were not independently resolved. A GOT call is not automatically another dynamic observer dispatch.

External shape/drained/IntervalEntry::summary,libc/TLS/thread/panic implementations were not recaptured. Calls/order/source obligations remain; no whole-path cost or internal implementation claim.

Complete inline SSE2 publication and ordered actual AVX calls are observed. AVX helper/selector/marker bodies and XSTATE restoration are outside this selection; earlier490 evidence is not reused for the new ELF. Runtime ISA/restoration/full640 agreement still require scientific qualification.

All six extents authenticated; complete runtime bodies and child guard/allocation/install/refusal sites interpreted. The4798-row child mostly covers unrelated setup; its external callees are not re-proved.

No applicable prior complete extraction/callback was compared. Rows/calls/frames are not executed counts,timings or savings. No strict20k,wide80k,full,A4/A5 or performance credit.
