#!/usr/bin/env python3
"""One finite original/LI2/E9 help comparison; see README for fresh input copies."""
import hashlib, importlib.util, json, os, pathlib, resource, stat, sys
if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit('Use assertions-enabled Python -I -B')
R = pathlib.Path.cwd().resolve()
REV = '392e4fbf82df434da0e782ff15556ad1a2b66812'
assert len(sys.argv) == 5, 'ORIGINAL FRESH_LI2_0500 FRESH_E9_0500 OUT required'
paths = [pathlib.Path(x).resolve(strict=True) for x in sys.argv[1:4]]
out = pathlib.Path(sys.argv[4]).absolute()
assert out == out.resolve() and out.parent == R/'ignored'
assert all(p.is_file() for p in paths) and len({(p.stat().st_dev,p.stat().st_ino) for p in paths}) == 3
assert all(stat.S_IMODE(p.stat().st_mode) == 0o500 for p in paths[1:])
cpus = sorted(os.sched_getaffinity(0)); assert len(cpus) == 1
for which, value in [(resource.RLIMIT_CPU,30),(resource.RLIMIT_AS,2147483648),
                     (resource.RLIMIT_FSIZE,1048576),(resource.RLIMIT_CORE,0)]:
    resource.setrlimit(which,(value,value))
base = R/'evaluation/full-program-entry-veneer/run_help_comparison.py'
raw = base.read_bytes()
assert len(raw)==9756 and hashlib.sha256(raw).hexdigest()=='618e171f7d04c05f3ab5e488de571cd3a8f650baf9f5c0d8111af932f1f83ab3'
old = b'(8769843, "43c11c7a4322d245516ab52c1e0e0523a68620c1e2f9a525561e282dcc1a16d9")'
new = b"(8896819, '8ef3638015783562a440bd52811c525c3c7162d0177e2723e199bc07686fd76e')"
assert raw.count(old)==1
raw = raw.replace(old,new)
assert len(raw)==9756 and hashlib.sha256(raw).hexdigest()=='c962cf9308eaa6c602e5d7018f493369ddae9f4c436c656667cf4a6850888324'
helper = R/'evaluation/admission/processes.py'
assert hashlib.sha256(helper.read_bytes()).hexdigest()=='0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
run = R/'target/evaluation'/out.name
log = R/'target/evaluation'/(out.name+'-owner.log')
assert not os.path.lexists(run) and not os.path.lexists(log)
out.mkdir(mode=0o700)
runner = out/'run_help_comparison.py'
with runner.open('xb') as f: f.write(raw)
def save(name,value):
    with (out/name).open('x') as f:
        json.dump(value,f,indent=2,sort_keys=True); f.write('\n'); f.flush(); os.fsync(f.fileno())
def capture(source,name,cap,digest=None):
    fd=os.open(source,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        a=os.fstat(fd); assert stat.S_ISREG(a.st_mode) and 0<=a.st_size<=cap
        with os.fdopen(os.dup(fd),'rb') as f: raw=f.read(cap+1)
        identity=lambda q:(q.st_dev,q.st_ino,q.st_mode,q.st_size,q.st_mtime_ns,q.st_ctime_ns)
        assert len(raw)==a.st_size and identity(a)==identity(os.fstat(fd))==identity(source.lstat())
    finally: os.close(fd)
    value=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    assert digest is None or value['sha256']==digest
    with (out/name).open('xb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())
    return raw,value
env = dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC')
argv = ['/usr/bin/prlimit','--cpu=30','--as=2147483648','--fsize=1048576','--core=0','--',
 '/usr/bin/python3.9','-I','-B',str(runner),'--revision',REV,'--cpu',str(cpus[0]),'--out',str(run)]
for role,path in zip(('original','li2','e9'),paths): argv += ['--'+role,str(path)]
save('intent.json',dict(argv=argv,environment=env,cpus=cpus,pid=os.getpid(),
 stat=pathlib.Path('/proc/self/stat').read_text(),cgroup=pathlib.Path('/proc/self/cgroup').read_text(),
 load=os.getloadavg(),dispatch_attempts=1,wall_seconds=60,log_bytes=131072))
spec = importlib.util.spec_from_file_location('fixed_owner',helper)
owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
result = owner.run_command(argv,env,log,60,131072)
save('owner.json',result)  # Closure is durable before any child-output read.
assert result['cleanup_complete'], 'unresolved ownership; do not read outputs'
capture(log,'owner.log',131072,result['private_log_sha256'])
receipt=None; receipt_pin=None
if (run/'receipt.json').exists():
    raw,receipt_pin=capture(run/'receipt.json','receipt.json',1048576)
    receipt=json.loads(raw)
    assert receipt['revision']==REV and set(receipt['arms'])<=set(('original','li2','e9'))
    for role,arm in receipt['arms'].items():
        if 'owner' in arm:
            assert arm['owner']['cleanup_complete'] is True
            for name in ('owner.log','stdout','stderr'):
                path=run/role/name
                if path.exists():
                    _,kept=capture(path,role+'-'+name,65536,
                        arm['owner']['private_log_sha256'] if name=='owner.log' else None)
                    expected=arm.get('streams',{}).get(name)
                    if expected is not None:
                        assert all(kept[k]==expected[k] for k in ('bytes','sha256'))
passed=(result['exit_code']==0 and result['termination'] is None and result['reaped_descendants']==0
    and receipt is not None and receipt['status']=='THREE_ARM_STARTUP_HELP_PARITY_PASS_ONLY'
    and receipt.get('pair_help_parity')=={'li2':True,'e9':True}
    and set(receipt['arms'])==set(('original','li2','e9'))
    and all(a['status']=='HELP_EXIT_ZERO' and a['dispatch_attempts']==1 for a in receipt['arms'].values()))
save('closed.json',dict(passed=passed,receipt=receipt_pin,qualification_complete=False,
    all_selected_sites_executed=False,performance_qualified=False))
raise SystemExit(0 if passed else 1)
