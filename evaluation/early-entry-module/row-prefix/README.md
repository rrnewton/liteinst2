# Row-prefix validation

Source `662888ff343722e01e7f58b3c26c1f08e055863e`, tree `e1644683fc0f8936f62e99ea0fbeb6b283d4a251`; AMD EPYC Zen 5 dev host. The physical-shape loop visits the completed prefix and checks the current ordinal separately, after the unchanged occupancy guards prove the remaining suffix empty. Fresh shared/normal, geometry, record and Pending checks remain. There is no persistent validity flag or cross-callback proof cache.

Focused release library checks passed 592 tests with 37 unchanged ignores, plus fmt and scoped strict Clippy. Native passed all four fixed cases (4,136 calls, 4,072 observed, 4,056 sampled, 64 bypass). Strict20k FAILED on its first attempt: one failed cohort, 11 UNOBSERVED, zero completed pairs; its literal plan retains one FAILED and 31 UNOBSERVED rows. Return boundaries were 8,645/17,322 steps, −212/−334 versus AVX v26. These partial-boundary differences do not establish a completed strict pair or causal speedup.

The separate 80,000-step profile passed all 12 cohorts: 288 pairs, 576 children and 139,872 comparisons, with zero mismatches. All 288 matched candidate counts decreased versus AVX v26; every original count and non-step CSV field is unchanged. Enabled cases saved 343 steps each (36,032–37,380); bypass cases saved 39 (12,753–14,128). The four scheduled scenarios saved 39/162/343/244 respectively (loaded-true-disarm/loaded-false-arm/admitted-rearm/returned-disarm), spanning 14,082–37,413. There were 144 broader-profile pairs at or below 20,000 steps and 144 above; this does not change the strict failure.

All five full-v26 correctness commands passed at this source revision: fmt, strict workspace Clippy, all-feature/all-target check, workspace tests and serial launch. The audited workspace census is 4,567 top-level plus 11 nested passes (4,578 raw), with 43 unchanged ignores; serial launch passed 1,039. The source change is retained. These instruction counts and correctness results do not establish production throughput. The v4 and v5 metadata projections both stopped at the unchanged size guard before writing packet files. V5 measured a 26,461-byte receipt, 9,675-byte README and 69,720 CSV bytes, totaling 105,856 bytes. Both failures are retained; this presentation correction reruns no scientific work and preserves every CSV and validation outcome.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.

The receipt records actual execution metadata and review hashes; its evidence limits are stated below. The [prior AVX receipt](../avx2-publisher/receipt.json) preserves earlier failures and gate outcomes. Every new CSV is retained verbatim; size limits never justify dropping a result.

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
out=root/'ignored/row-prefix-reproduction'/mode
logs=root/'target/evaluation/row-prefix-reproduction'/mode
out.mkdir(parents=True,exist_ok=False); logs.mkdir(parents=True,exist_ok=False)
spec=importlib.util.spec_from_file_location('owner',root/'evaluation/admission/processes.py')
owner=importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
argv=['/usr/bin/python3.9','-I','-B',str(root/'evaluation/early-entry-module'/script),'--root',str(root),'--revision','662888ff343722e01e7f58b3c26c1f08e055863e','--toolchain',os.environ['TOOLCHAIN'],'--user-home',os.environ['USER_HOME'],'--cargo-home',os.environ['CARGO_HOME'],'--output',str(out/'result')]
r=owner.run_command(argv,dict(PATH='/usr/bin:/bin',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1'),logs/'driver.log',wall,8<<20)
with (out/'owner.json').open('x') as f:
    json.dump(r,f,sort_keys=True); f.write('\n'); f.flush(); os.fsync(f.fileno())
assert r['cleanup_complete'] and r['reaped_descendants']==0
assert r['termination'] is None
raise SystemExit(r['exit_code'])
PY
```

Measure allocated/apparent ROOT, ignored and target before and after each attempt; root ceilings remain 19,994,091,520 / 19,061,190,371 bytes. Those external inventories are not implemented by the wrapper above. Scientific limits remain 20,000 / 80,000 steps, 15 seconds per pair and 2 seconds cleanup, with all 640 witness words compared. Native permissions and hardware prerequisites still apply.

For full correctness, reserve 12 disjoint CPUs after one-CPU work ends. The next wrapper reconstructs the recorded environments and five commands, with 180/180/180/900/180-second walls and 8MiB captures. Bare Cargo commands alone do not provide this containment; no quiet or performance qualification follows.

Save receipt outside ROOT or under ignored; export RECEIPT and MODE=focused/full. Reserve 1/12 CPUs. Reproduction syntax, not the original launcher; run once.

```bash
cd "$ROOT"
python3.9 -I -B - <<'PY'
import hashlib, importlib.util, json, os, subprocess
from pathlib import Path
R=Path(os.environ['ROOT']).resolve(); m=os.environ['MODE']
j=json.loads(Path(os.environ['RECEIPT']).read_bytes()); full=m=='full'
assert m in ('focused','full') and j['revision']=='662888ff343722e01e7f58b3c26c1f08e055863e'
assert len(os.sched_getaffinity(0))==(12 if full else 1)
def clean():
    def git(*a): return subprocess.check_output(['/usr/bin/git','-C',str(R),*a],timeout=15)
    assert git('rev-parse','HEAD','HEAD^{tree}').decode().split()==[j['revision'],j['tree']]
    assert not git('status','--porcelain','--untracked-files=no')
clean()
D=R/'ignored/row-prefix-validation'/m; L=R/'target/evaluation/row-prefix-validation'/m
for p in (D,L): p.mkdir(parents=True,exist_ok=False)
s=importlib.util.spec_from_file_location('owner',R/'evaluation/admission/processes.py')
o=importlib.util.module_from_spec(s); s.loader.exec_module(o)
def save(p,b):
    with p.open('xb') as f: f.write(b); f.flush(); os.fsync(f.fileno())
def sha(b): return hashlib.sha256(b).hexdigest()
safe=True
def run(n,a,e,w,c):
    global safe
    safe=False
    r=o.run_command(a,e,L/n,w,c)
    save(D/(n+'.owner'),json.dumps(r).encode())
    safe=r['cleanup_complete']
    assert safe and not r['reaped_descendants']
    b=(L/n).read_bytes(); assert len(b)<=c and sha(b)==r['private_log_sha256']
    save(D/(n+'.log'),b)
    assert r['termination'] is None and r['exit_code']==0
    return b
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
F=compose(j['environment'],j['full']['environment_delta']) if full else j['environment']
e=env(F)
assert e['CARGO_INCREMENTAL']=='0' and e['CARGO_BUILD_JOBS']==('12' if full else '1')
assert e['CARGO_PROFILE_DEV_DEBUG']==e['CARGO_PROFILE_TEST_DEBUG']=='0'
assert full or e['RUST_TEST_THREADS']=='1'
cap('before')
try:
    commands=j['full' if full else 'focused']['commands']; assert len(commands)==(5 if full else 3)
    for i,c in enumerate(commands):
        clean(); n=str(i)
        if full:
            name,a,w=c; assert w==[180,180,180,900,180][i]
            if i==4: e=env(compose(F,j['full']['serial_environment_delta']))
            assert e['RUST_TEST_THREADS']==('1' if i==4 else '12')
            run(n,a,e,w,8<<20)
        else:
            assert (c['cpu_seconds'],c['wall_seconds'],c['file_bytes'])==(120,180,128<<20)
            q=dict(c,argv=list(map(expand,c['argv'])),cwd=str(R),env=e,stdout=str(D/(n+'.out')),stderr=str(D/(n+'.err')))
            req=D/(n+'.request'); res=D/(n+'.receipt'); save(req,json.dumps(q).encode())
            run(n,['/usr/bin/python3.9','-I','-B',str(R/'tools/unwind-oracle/bounded_command.py'),'--request',str(req),'--receipt',str(res)],e,205,1<<20)
            z=json.loads(res.read_bytes())
            assert z['request_sha256']==sha(req.read_bytes()) and z['inputs_unchanged'] and z['absence_proof']=='ECHILD'
            assert z['exit']==0 and not (z['wall_timeout'] or z['unexpected_descendants'] or z['cleanup_events'] or z['aborted'] or z['cleanup_error'])
            if i==1:
                b=Path(q['stdout']).read_bytes(); assert sha(b)==z['stdout_sha256']
                assert b'592 passed; 0 failed; 37 ignored;' in b
        clean()
finally:
    if safe: cap('after')
PY
```

Receipt tables are lossless: a files.groups[profile][case_index] row [name_index,bytes,SHA] names csv/profile/case_names.state[case_index]/files.names[name_index]. Campaign cases use their case_names table; recipe_command_set replaces indexed recipe_command_base cells. Full outcomes index full.commands by name. Environment deltas remove keys then apply set; compose full against environment, serial against full (null means unrecorded). Tools/statistics declare columns/fields; binary refs use build.binary. Original scope statements follow verbatim.

## Evidence scope
Pinned CLOSED records and independent review hashes; review applicability, source/static interpretation and external CPU reservations are root-attested. No raw log or executable payload is projected.

Both recorded pre-run hashes equal the approved formatted manifest and the files rehashed by reviewer after closure. No recorded revision, whole-tree freeze, or workload postflight source guard is invented.

Exactly three unique positive totals per allocated/apparent capture; unchanged --count-links and fixed root ceilings. These focused runs record preflight only, not an invented after-capacity measurement.

Complete242 pass names/panic bits plus one exact ignore reason equal CLOSEDv26; all243 listed names match. Required179 inherited controls remain included; no current roster additions or removals.

All37 preparation argv/env/CPU/wall/file requests equal CLOSEDv26 after only output namespace substitution. Complete caller/Python/reader rosters match.

Same-identity step arithmetic only; includes all increases and unchanged originals. No timing, causal function attribution, production throughput or strict-pass inference.

One fixed full-v26 correctness attempt on 12 disjoint reserved CPUs after single-CPU campaigns ended; all five commands and 180/180/180/900/180-second limits unchanged. Actual loads are recorded. No quiet-host or performance qualification is claimed; earlier quiet refusal remains in the prior AVX receipt.

The published prior AVX receipt retains its earlier failed checks and NOT_ADMITTED/NOT_RUN quiet gate. No prior outcome is relabeled by this packet.

Recorded affinities and sampled loads are actual; disjoint external CPU reservation is root-attested, not independently proved by an allocator ledger.

Focused evidence records only the two pre-run source hashes, not a whole-tree revision freeze. Independent carry/source reviews bind them to the exact662 source; native/strict/build have their own exact revision evidence.

No source/emitted correctness blocker found for the fixed qualification attempt. Adoption requires actual unchanged native/strict/wide/full evidence; this static review is not a benefit finding.

No separately authenticated immediately comparable pre-row-prefix full body was established in this review; no baseline rows/frame/dynamic-cost delta is claimed.

430 static rows and5 static call sites are descriptive only, not executed counts. No timing, production-throughput, full640 execution, strict20000 fit or wider-profile completion credit.
