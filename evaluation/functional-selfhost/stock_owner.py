"""One root-witnessed six-chain STOCK action batch; no aggregate action loop."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import stat
import sys
import time

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit('Use assertions-enabled Python -I -B')
ROOT, PACKET = Path.cwd().resolve(), Path(__file__).resolve().parent
REV = '10a778d6415e51c66dfdc122d1e019e5c8c94c3c'
OWNER = ROOT / 'evaluation/admission/processes.py'
p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
p.add_argument('--binding-sha', required=True)
p.add_argument('--action-index', type=int, choices=(1,2,3,4), required=True)
p.add_argument('--first-generation', type=Path, required=True)
p.add_argument('--closure', type=Path, required=True)
p.add_argument('--closure-sha', required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--matrix',type=Path,required=True)
p.add_argument('--matrix-sha',required=True)
p.add_argument('--previous-closed-sha')
a = p.parse_args()
RUN, FIRST, CLOSURE = a.out.absolute(), a.first_generation.absolute(), a.closure.absolute()
assert RUN == RUN.resolve() and RUN.parent == ROOT/'ignored/a3'
assert FIRST == FIRST.resolve() and FIRST.parent == ROOT/'ignored/a3' and FIRST.is_dir()
assert CLOSURE == CLOSURE.resolve() and CLOSURE.parent == ROOT/'ignored/a3'
assert all(len(s) == 64 and all(c in '0123456789abcdef' for c in s) for s in (a.binding_sha,a.closure_sha,a.matrix_sha))
OUT = RUN.with_name(RUN.name+'-owner')
LOG = ROOT/'target/evaluation'/OUT.name
cpus = sorted(os.sched_getaffinity(0)); assert len(cpus) == 1
for key,value in ((resource.RLIMIT_CPU,2400),(resource.RLIMIT_AS,36*1024**3),
                  (resource.RLIMIT_FSIZE,512*1024**2),(resource.RLIMIT_CORE,0)):
    resource.setrlimit(key,(value,value))


def stamp(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def pin(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_size <= 32 * 1024**2
        h = hashlib.sha256()
        total = 0
        while True:
            block = os.read(fd, 1024**2)
            if not block:
                break
            total += len(block)
            assert total <= before.st_size <= 32 * 1024**2
            h.update(block)
        assert total == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat())
        return dict(bytes=before.st_size, sha256=h.hexdigest(), stat=stamp(before))
    finally:
        os.close(fd)


def save(name, value):
    target = OUT / name
    assert not target.exists()
    temporary = target.with_suffix('.tmp')
    with temporary.open('x') as f:
        json.dump(value, f, indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
    os.rename(temporary, target)


assert not any(os.path.lexists(p) for p in (OUT,RUN,LOG,ROOT/'target/evaluation'/RUN.name))
binding_path = PACKET/'owner-binding.json'; binding_pin = pin(binding_path)
assert binding_pin['sha256'] == a.binding_sha
binding = json.loads(binding_path.read_text()); assert pin(binding_path) == binding_pin
assert binding['revision'] == REV and binding['profile'] == 'stock-second-generation-action-v1'
assert binding['action_indices'] == [1,2,3,4] and binding['chain_attempt_limit'] == 6
assert binding['outer_wall_seconds'] == binding['outer_cpu_seconds'] == 2400
assert binding['outer_log_bytes'] == 8*1024**2
source_path = PACKET/'binding.json'; source_pin = pin(source_path)
assert all(source_pin[k] == binding['source_binding'][k] for k in ('bytes','sha256'))
source = json.loads(source_path.read_text()); assert pin(source_path) == source_pin
assert source['revision'] == REV and source['profile'] == binding['profile']
expected = {str(PACKET/name):q for name,q in source['members'].items()}
expected[str(Path(__file__).resolve())] = binding['owner']
expected[str(source_path)] = binding['source_binding']
manifest_path = PACKET/'inputs.json'
assert all(pin(manifest_path)[k] == expected[str(manifest_path)][k] for k in ('bytes','sha256'))
manifest = json.loads(manifest_path.read_text())
expected.update({str(ROOT/name):q for name,q in manifest['sources'].items()})
for path,q in manifest['runtime_dependencies'].items():
    assert str(Path(path).resolve()) == q['resolved']; expected[q['resolved']] = q
expected.update(binding['tools'])
expected[str(ROOT/'evaluation/functional-corpus/receipt.json')] = binding['canonical_receipt']
closure_pin = pin(CLOSURE); assert closure_pin['sha256'] == a.closure_sha
fresh = json.loads(CLOSURE.read_text()); assert pin(CLOSURE) == closure_pin
assert fresh['schema'] == 1 and fresh['status'] == 'FRESH_FIRST_GENERATION_CLOSED'
assert fresh['producer_revision'] == REV and fresh['first_generation'] == str(FIRST)
assert fresh['source_unchanged'] is True and fresh['parent_and_worker_and_scopes_gone'] is True
assert fresh['cases'] == 10 and fresh['dispatches'] == 40 and fresh['native_dispatches'] == 0
assert fresh['strict_status'] == 'FAILED_OUTCOME_RETAINED'
assert all(fresh['closure_script'][k] == binding['closer'][k] for k in ('bytes','sha256'))
closers = [Path(p) for p,q in fresh['frozen'].items() if Path(p).name == 'close_first_generation.py' and q == fresh['closure_script']]
assert len(closers) == 1 and closers[0] == closers[0].resolve()
meta = FIRST.with_name(FIRST.name+'-owner'); assert fresh['owner_directory'] == str(meta)
authorities = {FIRST/'receipt.json':fresh['receipt'], FIRST/'first-generation-wrapper-closed.json':fresh['wrapper_closed'],
               meta/'live.json':fresh['owner_live'], meta/'closed.json':fresh['owner_closed'], closers[0]:fresh['closure_script']}
# The closer's h.pin uses eight fields; this unchanged owner pin uses six.
# Join the exact stable field projection, not a fabricated historical stat.
for path,q in authorities.items():
    got = pin(path); assert len(q['stat']) == 8
    assert all(got[k] == q[k] for k in ('bytes','sha256'))
    assert got['stat'] == [q['stat'][i] for i in (0,1,2,5,6,7)]
    expected[str(path)] = q
expected[str(CLOSURE)] = closure_pin
assert str(OWNER) in expected and str(PACKET/'run_stock.py') in expected
frozen = {path:pin(Path(path)) for path in expected}
assert all(all(frozen[path][k] == q[k] for k in ('bytes','sha256')) for path,q in expected.items())
frozen[str(binding_path)] = binding_pin
matrix_path = a.matrix.absolute(); matrix_pin = pin(matrix_path)
assert matrix_pin['sha256'] == a.matrix_sha
matrix = json.loads(matrix_path.read_text()); assert pin(matrix_path) == matrix_pin
helper_path = PACKET/'matrix_disk.py'
assert str(helper_path) in frozen
spec = importlib.util.spec_from_file_location('stock_matrix_disk',helper_path)
md = importlib.util.module_from_spec(spec); spec.loader.exec_module(md)
assert pin(helper_path) == frozen[str(helper_path)]
paths = md.layout(ROOT,matrix_path,matrix); matrix_row = matrix['actions'][a.action_index-1]
assert matrix['revision'] == REV and ROOT/matrix_row['run'] == RUN
assert ROOT/matrix_row['owner'] == OUT and ROOT/matrix_row['owner_logs'] == LOG
assert matrix['first_generation'] == str(FIRST.relative_to(ROOT))
assert matrix['closure'] == str(CLOSURE.relative_to(ROOT)) and matrix['closure_sha256'] == a.closure_sha
assert all(matrix['source_binding'][k] == source_pin[k] for k in ('bytes','sha256'))
assert all(matrix['owner_binding'][k] == binding_pin[k] for k in ('bytes','sha256'))
lock_path = matrix_path.with_name('matrix.lock')
lock_fd = os.open(lock_path,os.O_RDWR|os.O_CREAT|os.O_CLOEXEC|os.O_NOFOLLOW,0o600)
q = os.fstat(lock_fd); assert stat.S_ISREG(q.st_mode) and q.st_nlink == 1 and q.st_size == 0
fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
initial_path = matrix_path.with_name('initial.json')
if a.action_index == 1:
    assert a.previous_closed_sha is None
    assert sorted(p.name for p in matrix_path.parent.iterdir()) == ['matrix.json','matrix.lock']
    initial = dict(md.initial_absence(paths),matrix_sha256=matrix_pin['sha256'],
                   pid=os.getpid(),stat=Path('/proc/self/stat').read_text())
    with initial_path.open('x') as f:
        json.dump(initial,f); f.write('\n'); f.flush(); os.fsync(f.fileno())
else:
    frozen.update(md.predecessors(ROOT,matrix,a.action_index,pin,matrix_pin,matrix_path,a.previous_closed_sha))
    for row in matrix['actions'][a.action_index-1:]:
        assert all(not os.path.lexists(ROOT/row[k]) for k in ('run','logs','owner','owner_logs'))
initial_pin = pin(initial_path)
initial = json.loads(initial_path.read_text()); assert pin(initial_path) == initial_pin
assert initial['matrix_sha256'] == matrix_pin['sha256']
assert initial['absent'] == [str(p) for p in paths['roots']]
frozen[str(matrix_path)] = matrix_pin; frozen[str(initial_path)] = initial_pin
md.local_admit(md.measure(paths),0,md.capture_remaining(ROOT,matrix_row))
OUT.mkdir(mode=0o700); LOG.mkdir(mode=0o700,parents=True)
root_ids = md.identities(paths)
unit = 'li2core-functional-stock-'+str(a.action_index)+'-'+str(os.getpid())
command = ['/usr/bin/systemd-run','--user','--scope','--collect','--quiet','--unit='+unit,
           '-p','AllowedCPUs='+str(cpus[0]),'-p','CPUQuota=100%','-p','MemoryMax=1073741824',
           '-p','MemorySwapMax=0','-p','TasksMax=64','--','/usr/bin/python3.9','-I','-B',
           str(PACKET/'run_stock.py'),'--first-generation',str(FIRST),'--closure',str(CLOSURE),
           '--closure-sha',a.closure_sha,'--action-index',str(a.action_index),
           '--matrix',str(matrix_path),'--matrix-sha',a.matrix_sha,
           '--cpu',str(cpus[0]),'--unit',unit,'--out',str(RUN)]
live = dict(pid=os.getpid(),stat=Path('/proc/self/stat').read_text(),cgroup=Path('/proc/self/cgroup').read_text(),
            cpus=cpus,load=os.getloadavg(),utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
            command=command,unit=unit,action_index=a.action_index,dispatch_limit=1,
            wall_seconds=2400,log_bytes=8*1024**2,frozen=frozen,matrix=matrix_pin,initial=initial_pin)
save('live.json',live)
frozen[str(OUT/'live.json')] = pin(OUT/'live.json')
deadline = time.monotonic()+30
while not (OUT/'root-live.json').exists():
    assert time.monotonic() < deadline, 'root witness deadline'
    time.sleep(.05)
witness_pin = pin(OUT/'root-live.json'); witness = json.loads((OUT/'root-live.json').read_text())
assert pin(OUT/'root-live.json') == witness_pin and witness['authenticated'] is True
assert witness['pid'] == os.getpid() and witness['cpus'] == cpus and witness['cgroup'] == live['cgroup']
assert witness['starttime'] == live['stat'].rsplit(')',1)[1].split()[19]
frozen[str(OUT/'root-live.json')] = witness_pin
assert all(pin(Path(p)) == q for p,q in frozen.items())
spec = importlib.util.spec_from_file_location('stock_outer_owner',OWNER)
owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
result = receipt = receipt_pin = error = None
same = normal = census = passed = False
md.local_admit(md.measure(paths,root_ids),0,md.capture_remaining(ROOT,matrix_row))
save('dispatch.json',dict(attempts=1,command=command))
try:
    result = owner.run_command(command,dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),LOG/'outer.log',2400,8*1024**2)
    save('owner-closed.json',dict(result=result,load_after=os.getloadavg()))
    normal = (result['exit_code'] in (0,1) and result['termination'] is None
              and result['cleanup_complete'] is True and result['reaped_descendants'] == 0)
    assert result['cleanup_complete'], 'No capture reads before cleanup'
    log_pin = pin(LOG/'outer.log'); assert log_pin['sha256'] == result['private_log_sha256']
    md.local_admit(md.measure(paths,root_ids),0,md.capture_remaining(ROOT,matrix_row))
    with (OUT/'outer.log').open('xb') as f:
        f.write((LOG/'outer.log').read_bytes()); f.flush(); os.fsync(f.fileno())
    assert pin(OUT/'outer.log')['sha256'] == log_pin['sha256']
    receipt_path = RUN/'receipt.json'
    if receipt_path.exists():
        receipt_pin = pin(receipt_path); receipt = json.loads(receipt_path.read_text())
        assert pin(receipt_path) == receipt_pin
    assert receipt is not None, 'No worker receipt'
    assert receipt['revision'] == REV and receipt['profile'] == binding['profile'] and receipt['action_index'] == a.action_index
    assert receipt['ordered_outcomes_status'] == 'UNOBSERVED_STOCK_PROFILE'
    assert receipt['strict_full_instrumentation'] == 'FAILED' and receipt['first_generation_strict_status'] == 'FAILED_OUTCOME_RETAINED'
    assert all(receipt[k] is False for k in ('all_selected_sites_executed','qualification_complete','performance_qualified'))
    pairs = [(r,s) for r in ('original','li2','e9') for s in ('e9tool','e9patch')]
    rows = receipt['chains']; assert [(r['role'],r['source']) for r in rows] == pairs
    attempts = receipt['dispatch_attempts']; assert type(attempts) is list and len(attempts) <= 6
    assert attempts == [r+'-'+s for r,s in pairs][:len(attempts)]
    for i,row in enumerate(rows):
        assert row['ordered_outcomes_status'] == 'UNOBSERVED_STOCK_PROFILE' and row['outcomes_equal'] is None
        assert row['attempts'] == int(i < len(attempts))
        if i >= len(attempts):
            assert row['status'] == 'UNOBSERVED' and row['byte_equal'] is None and 'owner' not in row
        else:
            assert row['status'] in ('STOCK_SECOND_GENERATION_BYTE_EQUAL','FAILED_OUTCOME_RETAINED','DISPATCHED','CLOSED')
    census = True
    passed = (normal and result['exit_code'] == 0 and receipt['status'] == 'STOCK_SECOND_GENERATION_BYTE_EQUAL'
              and receipt['source_unchanged'] is True and receipt['byte_equality_gate'] == 'PASS' and len(attempts) == 6
              and all(row['status'] == 'STOCK_SECOND_GENERATION_BYTE_EQUAL' and row['byte_equal'] is True
                      and row['owner']['exit_code'] == 0 and row['owner']['termination'] is None
                      and row['owner']['cleanup_complete'] is True and row['owner']['reaped_descendants'] == 0 for row in rows))
except BaseException as caught:
    error = dict(type=type(caught).__name__,message=str(caught)); passed = False
finally:
    if not (OUT/'owner-closed.json').exists():
        save('owner-closed.json',dict(result=result,error=error,load_after=os.getloadavg()))
    try:
        same = all(pin(Path(p)) == q for p,q in frozen.items()) and sorted(os.sched_getaffinity(0)) == cpus
    except BaseException as caught:
        error = dict(type=type(caught).__name__,message=str(caught)); same = False
    passed = passed and same
    matrix_continue = False
    matrix_capacity = None
    try:
        matrix_capacity = md.local_admit(md.measure(paths,root_ids),0,md.capture_remaining(ROOT,matrix_row))
        matrix_continue = (same and normal and census and receipt is not None
            and receipt['source_unchanged'] is True and bool(receipt.get('matrix_final_admission'))
            and len(receipt['dispatch_attempts']) == 6
            and all(r['owner']['cleanup_complete'] and r['owner']['reaped_descendants'] == 0 for r in receipt['chains']))
    except BaseException as caught:
        error = dict(type=type(caught).__name__,message=str(caught)); passed = False
    save('closed.json' ,dict(result=result,receipt=receipt_pin,source_unchanged=same,attempts=1,normal=normal,
         unit=unit,cpus=cpus,action_index=a.action_index,census_valid=census,error=error,
         matrix=matrix_pin,initial=initial_pin,matrix_continue=matrix_continue,
         live=pin(OUT/'live.json'),owner_closed=pin(OUT/'owner-closed.json'),
         prior_closed={str(ROOT/r['owner']/'closed.json'):frozen[str(ROOT/r['owner']/'closed.json')] for r in matrix['actions'][:a.action_index-1]},
         matrix_capacity=matrix_capacity,matrix_root_identities=md.identities(paths),
         comparison_status=receipt.get('status') if isinstance(receipt,dict) else 'NO_RECEIPT',
         chain_rows=[{k:r.get(k) for k in ('role','source','status','attempts','byte_equal','outcomes_equal','ordered_outcomes_status')}
                     for r in receipt.get('chains',[])] if isinstance(receipt,dict) else [],
         passed=passed,status='PASS' if passed else 'FAILED_OUTCOME_RETAINED'))
print(json.dumps(dict(normal=normal,exit_code=result['exit_code'] if result else None,receipt=receipt_pin,passed=passed)),flush=True)
raise SystemExit(0 if passed else (1 if normal else 125))
