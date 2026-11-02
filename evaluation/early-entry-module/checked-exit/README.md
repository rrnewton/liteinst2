# CheckedExit: checked completion across one exclusive borrow

Candidate `2bdad58364327ea832cc599de55838def35e38b2` (tree `a21911398e95355f114ecf6fdeb84d2530cbd416`) adds a consuming completion proof and an ordinary inline hint on its check. Hardware: AMD EPYC Zen 5 dev host. The hint is compiler guidance; static review does not establish net savings.

Focused validation passed: 597 library tests with 37 unchanged ignores, and 242 qualification calibration tests with one unchanged ignore and all 22 panic controls. Fmt and scoped strict Clippy passed. All four default-feature native cases passed, preserving 4,136 calls, 4,072 observed entries, 4,056 sampled entries and 64 bypasses. Filtered tests are not credited as executed.

Strict `qualification-feature-v1` failed at its original 20,000-step limit on the first case: zero completed pairs, one failed cohort and eleven unobserved cohorts; the plan retains one FAILED and 31 UNOBSERVED rows. Partial return boundaries were 8,087 and 16,235 steps, versus 8,089 and 16,248 for the flat-witness baseline. These partial arithmetic differences are not completed-path or causal performance claims.

The separate `qualification-feature-optional-entry-80k-v1` campaign passed all 12 cohorts: 288 pairs, 576 children and 139,872 exact comparisons with no mismatch. Against the flat-witness baseline, 152 candidate rows used fewer steps, 136 were unchanged and none increased; the signed total is −4,968. All original step counts, other pair fields, plans and coverage were unchanged. Enabled cases fell by 35 steps each (33,938–35,286); bypass cases were unchanged (12,055–13,425); scheduled cases ranged from unchanged to 35 fewer steps (13,399–35,308). Exactly 144 candidate rows were at or below 20,000 and 144 above. These are matched step-count arithmetic, not a timing or throughput result.

The current full correctness run passed all five commands under the separately declared 1,800-second workspace profile. The workspace completed in 913.708 seconds, exceeding 900 seconds; this does not pass or replace the historical 900-second FAILED attempt. Its observed census was 4,572 top-level passes plus 11 nested child passes, or 4,583 raw passes, with 43 unchanged ignores. All 27 critical and 21 short-neighbor controls passed. The serial-launch command passed in 137.100 seconds under its unchanged 180-second limit. These durations are operational observations, with no quiet-host or timing qualification.

Root selected RETAINED for the small matched step reduction: 152 of 288 rows decreased, 136 were equal and none increased, with all original counts and other pair fields unchanged. The independent full correctness and fixed scientific results support this decision; the strict 20,000-step claim remains open. The receipt preserves the exact root-attested source applicability, CPU reservations, fixed-attempt history and selection rationale separately from independently reviewed measurements.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.

The four public files are this README, `receipt.json`, `case-comparison.csv` and `attempts.csv`. The attempts table’s `wall_limit` consistently names the recorded outer owner: 205 seconds for focused commands and 55 for native cases; their child walls remain 180 and 30 seconds. The comparison is derived from every authenticated pair CSV: it preserves all current fields and values, both signed step deltas, increases, non-PASS and unmatched rows. `side=baseline_only` identifies baseline values with no current observation. Plans reconstruct from the fixed cohort/seed/scenario roster and stored status arrays; every coverage cell remains in the receipt. The complete raw CSV inventory is authenticated before consolidation and identified by count, bytes and manifest hash. No measurements are filtered to meet a presentation size target.

The exact independent comparison includes all 640 witness words (128 header and 512 journal), plus architectural state; its actual comparison census is recorded, never estimated as 640 times a marker count. Strict 20,000 and separate 80,000 profiles, 15-second pair and 2-second cleanup limits remain distinct. Affinity/load and durations are operational observations, not proof of a quiet host or throughput.

History remains explicit. The unhinted `b2fc5575485b80f8809a86bcd3240b440141fd30` had a failed headers-only ticket-alias capture, followed by a separately authorized corrected capture. Its lowering was rejected as an optimization candidate; all four runtime profiles remained UNRUN. This was not a correctness failure or a measured regression. The hinted path still has the final 32-byte argument, caller frame and outlined completion costs; uncaptured GOT/OnceLock/drop/equality/panic/unwind bodies and the old source-associated GOT edge remain limits.

The [flat-witness receipt](../flat-witness/receipt.json) supplies separately labeled historical checks: a first focused compilation timeout and its 12-CPU continuation, the original 900-second whole-workspace FAILED attempt with partial census and serial UNOBSERVED, and a later declared 1,800-second full PASS. Those facts and abnormal owners are retained here; no historical PASS qualifies this candidate. The 900-to-1,800 expansion was an operational whole-suite budget change, not a scientific threshold change. Current CPU120 is per process, not an aggregate twelve-core CPU budget. No automatic rerun, quiet-host claim, A5 claim or strict-fit claim is made.

## Reproduction

Save this receipt outside the checkout or under `ignored`. Export `ROOT`,
`TOOLCHAIN`, `USER_HOME`, `CARGO_HOME` and `RECEIPT`. Check out the exact revision
and tree recorded for the selected attempt, with no tracked changes. Reserve its
recorded number of disjoint CPUs externally: one for build/static/native/strict/
wide, twelve for current focused/full checks. Affinity alone is not proof of an
exclusive reservation or a quiet host.

Select **one** receipt key with `ATTEMPT` (`focused`, `build`, `static`,
`native`, `strict`, `wide`, or `full`). Use a fresh `RUN_ID` for its output. This
does not schedule another phase or retry. Historical keys require the additional
explicit `HISTORY=1`; do not rerun old failed attempts as prerequisites. Historical
timeouts are recorded outcomes, not outcomes a reproduction is guaranteed to
repeat. Undispatched attempts have no executable command list.

The receipt's `reproduction.environment` is the base environment. Each
`reproduction.attempts[ATTEMPT]` contains `revision`, `tree`, `cpus`, `historical`,
`environment_delta` and `commands`. A delta removes named keys, then sets values.
Each command records `name`, `kind` (`direct` or `bounded`), complete `argv`, outer
`wall_seconds`/`capture_bytes`, and an optional environment delta. Bounded commands
also record `request_bounds`; library/calibration commands retain their exact
`stdout_contains` summary assertion. Static objdump commands require `artifact_before`
with `path`, `bytes` and `sha256`. Only the six placeholders below are expanded;
no shell evaluates command arrays.

```bash
cd "$ROOT"
export ATTEMPT=focused RUN_ID=checked-exit-focused-1
python3.9 -I -B - <<'PY'
import hashlib, importlib.util, json, os, re, subprocess
from pathlib import Path
assert __debug__ and __import__('sys').flags.isolated and __import__('sys').dont_write_bytecode
R=Path(os.environ['ROOT']).resolve(); ident=os.environ['ATTEMPT']
j=json.loads(Path(os.environ['RECEIPT']).read_bytes())['reproduction']
a=j['attempts'][ident]; assert a['commands']
assert not a['historical'] or os.environ.get('HISTORY')=='1'
run_id=os.environ['RUN_ID']; assert re.fullmatch('[A-Za-z0-9_-]+',run_id)
cpus=sorted(os.sched_getaffinity(0)); assert len(cpus)==a['cpus']
D=R/'ignored/checked-exit-reproduction'/run_id
L=R/'target/evaluation/checked-exit-reproduction'/run_id
values={k:os.environ[k] for k in ('TOOLCHAIN','USER_HOME','CARGO_HOME')}
values.update(ROOT=str(R),OUT=str(D),LOGS=str(L))
def expand(s):
    for k,v in values.items(): s=s.replace('${'+k+'}',v)
    assert '${' not in s
    return s
def compose(base,d): return {k:v for k,v in base.items() if k not in d['remove']}|d['set']
empty={'remove':[],'set':{}}
base=compose(j['environment'],a['environment_delta'])
def env(d): return {k:expand(v) for k,v in compose(base,d).items()}
def sha(b): return hashlib.sha256(b).hexdigest()
def save(p,b):
    with p.open('xb') as f: f.write(b); f.flush(); os.fsync(f.fileno())
def clean():
    def git(*args): return subprocess.check_output(['/usr/bin/git','-C',str(R),*args],timeout=15)
    assert git('rev-parse','HEAD','HEAD^{tree}').decode().split()==[a['revision'],a['tree']]
    assert not git('status','--porcelain','--untracked-files=no')
    assert sorted(os.sched_getaffinity(0))==cpus
clean()
for p in (D,L): p.mkdir(parents=True,exist_ok=False)
owner=R/'evaluation/admission/processes.py'; helper=R/'tools/unwind-oracle/bounded_command.py'
assert sha(owner.read_bytes())=='0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
helper_sha='c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
assert sha(helper.read_bytes())==helper_sha
s=importlib.util.spec_from_file_location('owner',owner)
o=importlib.util.module_from_spec(s); s.loader.exec_module(o)
safe=True
def run(n,argv,e,w,cap):
    global safe
    safe=False
    z=o.run_command(argv,e,L/n,w,cap)
    save(D/(n+'.owner.json'),json.dumps(z).encode())
    safe=z['cleanup_complete'] is True
    assert safe, 'incomplete cleanup: stop; no payload or follow-up process'
    b=(L/n).read_bytes(); assert len(b)<=cap and sha(b)==z['private_log_sha256']
    save(D/(n+'.log'),b)
    return z
def normal(z):
    assert z['exit_code']==0 and z['termination'] is None and z['reaped_descendants']==0
def capacity(tag):
    for apparent,limit in ((False,19994091520),(True,19061190371)):
        n=tag+('-apparent' if apparent else '-allocated')
        cmd='/usr/bin/prlimit --cpu=30 --as=268435456 --fsize=65536 --core=0 -- /usr/bin/du --block-size=1 --count-links --max-depth=1'.split()
        z=run(n,cmd+(['--apparent-size'] if apparent else [])+[str(R)],{'PATH':'/usr/bin:/bin','LC_ALL':'C'},180,65536)
        normal(z); rows=[x.split('\t') for x in (D/(n+'.log')).read_text().splitlines()]
        assert rows and all(len(x)==2 and x[0].isdigit() for x in rows)
        t={p:int(v) for v,p in rows}; assert len(t)==len(rows)
        assert all(p==str(R) or Path(p).parent==R for p in t)
        assert all(t[str(p)]>0 for p in (R,R/'ignored',R/'target')) and t[str(R)]<limit
capacity('before')
try:
    for i,c in enumerate(a['commands']):
        clean(); n='command-'+str(i); e=env(c.get('environment_delta',empty))
        argv=list(map(expand,c['argv']))
        if c['kind']=='bounded':
            assert a['cpus'] in (1,12) and e['CARGO_BUILD_JOBS']==str(a['cpus'])
            assert e['RUST_TEST_THREADS']=='1'
        if ident in ('full','baseline-900','baseline-1800'):
            assert a['cpus']==12 and e['CARGO_BUILD_JOBS']=='12'
            assert [x['name'] for x in a['commands']]==['fmt','clippy','check','workspace','serial-launch']
            assert e['RUST_TEST_THREADS']==('1' if c['name']=='serial-launch' else '12')
        if any(Path(x).name=='objdump' for x in argv):
            p=c['artifact_before']; b=Path(expand(p['path'])).read_bytes()
            assert len(b)==p['bytes'] and sha(b)==p['sha256'], 'different ELF: stop; archived extents do not apply'
        assert c['kind'] in ('direct','bounded')
        if c['kind']=='bounded':
            bounds=c['request_bounds']; assert bounds==dict(cpu_seconds=120,wall_seconds=180,file_bytes=128<<20)
            assert (c['wall_seconds'],c['capture_bytes'])==(205,1<<20)
            q=dict(bounds,argv=argv,cwd=str(R),env=e,stdout=str(D/(n+'.out')),stderr=str(D/(n+'.err')))
            req=D/(n+'.request.json'); res=D/(n+'.receipt.json'); save(req,json.dumps(q).encode())
            argv=['/usr/bin/python3.9','-I','-B',str(helper),'--request',str(req),'--receipt',str(res)]
        z=run(n,argv,e,c['wall_seconds'],c['capture_bytes'])
        if c['kind']=='bounded':
            t=json.loads(res.read_bytes())
            safe=safe and t['absence_proof']=='ECHILD' and t['cleanup_error'] is None
            assert safe, 'incomplete helper cleanup: no follow-up process'
            assert t['request_sha256']==sha(req.read_bytes()) and t['helper_sha256']==helper_sha
            for stream in ('stdout','stderr'):
                b=Path(q[stream]).read_bytes(); assert len(b)<=bounds['file_bytes'] and sha(b)==t[stream+'_sha256']
            assert t['inputs_unchanged'] and t['exit']==0
            assert not (t['wall_timeout'] or t['unexpected_descendants'] or t['cleanup_events'] or t['aborted'])
            if c['name'] in ('library-tests','calibration-tests'):
                assert c['stdout_contains'].encode() in Path(q['stdout']).read_bytes()
        normal(z); clean()
finally:
    if safe: clean(); capacity('after')
PY
```

Focused commands are the recorded fmt, library, qualification calibration and
scoped all-target/all-feature Clippy arrays, with offline/debug-zero/incremental-
zero settings, Cargo jobs 12 and harness 1. Full runs the five recorded commands;
its serial command's environment delta sets harness threads to 1. Current full
walls are 180/180/180/1,800/180 seconds, each with 8 MiB capture. The historical
900-second profile remains separate and FAILED; selecting it uses its recorded
900-second wall, never the current full limit. The 120-second focused CPU limit
is per process, not an aggregate twelve-CPU budget. These pre/post inventories
are reproduction safeguards, not invented postflight evidence for old attempts.

Native/strict/wide command arrays invoke the existing tracked
`evaluation/early-entry-module/{reproduce.py,state.py,state_wide_80k.py}` with
`/usr/bin/python3.9 -I -B` and all six required arguments: `--root`, `--revision`,
`--toolchain`, `--user-home`, `--cargo-home`, `--output`. Use the fresh, absent
`${OUT}/result` child path; whole-driver walls remain 1,800/11,000/11,000 seconds
and captures 8 MiB. The recipes retain every internal comparator, 15-second pair
guard, 2-second cleanup guard, full 128+512 words and distinct 20,000/80,000 limits.
Read the new result and complete census after its durable owner; exit zero alone
does not reproduce a published census or confer qualification.

Select `build` before `static`, retaining the build owner before selecting another
attempt. Build uses the existing public
`evaluation/early-entry-module/ret-inline/build.py`, invoked with
`/usr/bin/python3.9 -I -B` and the same six arguments plus `--logs`; use fresh
`${OUT}/build` and `${LOGS}/build`. Its original inner build request retains 120 CPU seconds, 180 wall seconds and 128 MiB files, with its 205-second/1 MiB owner. This reproduction adds a separately labeled 240-second/1 MiB outer backstop for public-script setup and cleanup; it does not change the recorded build limits.
The separately selected static attempt's recorded `prlimit`/`objdump` argv capture the symbol table and complete
selected extents. Exact artifact checks precede every objdump. Missing labels,
header-only output or incomplete extents are failures requiring review; command
exit zero is not static coverage. This reader reproduces bounded captures, not
the independent lowering review: after all owners close, independently verify
each recorded symbol/start/size against its complete contiguous instruction
extent and inspect the connected call path before drawing a static conclusion.
Preserve both original alias failure and the
corrected capture in history. No standalone-symbol absence, instruction count or
successful reproduction establishes savings or strict-profile fit.
