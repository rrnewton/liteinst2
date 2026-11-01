#!/usr/bin/env python3
"""Fixed c6220751 source build plus one packed entry-veneer mixed-neighbor attempt; supply six paths as documented."""
import datetime, hashlib, importlib.util, json, os, pathlib, re, subprocess, sys
if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit('Use assertions-enabled Python -I -B')
R = pathlib.Path.cwd().resolve()
REV = 'c622075116a0ab768c7d052b570f16baf2caf379'
original, ledger, sites, policy = map(lambda p: pathlib.Path(p).resolve(strict=True), sys.argv[1:5])
out = pathlib.Path(sys.argv[5]).absolute()
tc = pathlib.Path(sys.argv[6]).resolve(strict=True)
assert out.resolve() == out and out.parent == R / 'ignored'
out.mkdir(mode=0o700)
logs = R / 'target/evaluation' / out.name
logs.mkdir(mode=0o700)
(out / 'tmp').mkdir()
def pin(p):
    before = p.stat(); assert p.is_file() and before.st_size <= 512*1024**2
    b = p.read_bytes()
    stable = lambda s: (s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    assert stable(p.stat()) == stable(before) and len(b) == before.st_size
    return {'bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest()}
def save(name, value):
    with (out / name).open('x') as f:
        json.dump(value, f, indent=2, sort_keys=True); f.write('\n'); f.flush(); os.fsync(f.fileno())
expected = [(93520,'890f76cb5741b6c7cfba3414ae72a64fd7deddc7d2dd33b17d53e8b906529fdb'),
 (264399,'727d43acbbb31ac419ba2a87f75433a495c2b838fa9d6d08a138d16c6e52e60d'),
 (77822,'7d3e1d485fad55ed75139a40fc456374f9fcdbda101096a5d137d1df758b4f5f'),
 (359381,'ef09bcd4c78949ff4b93a928c59e04b545081f9e56c2056f2cfcdfe068604cce')]
assert len({original,ledger,sites,policy}) == 4, "four distinct resolved input paths required"
inputs = dict(zip((original,ledger,sites,policy), (dict(bytes=n,sha256=h) for n,h in expected)))
helper = R / 'evaluation/admission/processes.py'
assert pin(helper)['sha256'] == '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
cpus = sorted(os.sched_getaffinity(0)); assert len(cpus) == 1
frozen = dict(inputs)
frozen.update({p:pin(p) for p in (tc/'cargo',tc/'rustc',pathlib.Path('/usr/bin/prlimit'),pathlib.Path('/usr/bin/git'),pathlib.Path('/usr/bin/du'),helper)})
git = lambda *a: subprocess.check_output(['/usr/bin/git',*a], timeout=10)
def unchanged():
    assert git('rev-parse','HEAD').decode().strip() == REV
    assert not git('status','--porcelain','--untracked-files=no')
    assert sorted(os.sched_getaffinity(0)) == cpus
    assert all(pin(p) == v for p,v in frozen.items())
unchanged()
spec = importlib.util.spec_from_file_location('fixed_owner', helper)
owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
env = dict(os.environ, PATH=str(tc)+':/usr/bin:/bin', CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='1',
 RUST_TEST_THREADS='1', CARGO_TARGET_DIR=str(R/'target'), CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
 CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true',
 CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true', CARGO_NET_OFFLINE='true', PYTHONDONTWRITEBYTECODE='1')
save('environment.json', dict(revision=REV, cpus=cpus, load=os.getloadavg(),
 utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
 environment_overrides={k:env[k] for k in ('PATH','CARGO_INCREMENTAL','CARGO_BUILD_JOBS','RUST_TEST_THREADS',
 'CARGO_TARGET_DIR','CARGO_PROFILE_RELEASE_OPT_LEVEL','CARGO_PROFILE_RELEASE_DEBUG',
 'CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS','CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS','CARGO_NET_OFFLINE','PYTHONDONTWRITEBYTECODE')},
 tools={str(p):pin(p) for p in (tc/'cargo',tc/'rustc',pathlib.Path('/usr/bin/prlimit'),pathlib.Path('/usr/bin/git'),pathlib.Path('/usr/bin/du'),helper)},
 rustc=subprocess.check_output([str(tc/'rustc'),'-vV'],text=True,timeout=10)))
def run(name, argv, environment, wall):
    unchanged(); save(name+'-intent.json', dict(argv=argv,wall_seconds=wall,log_bytes=8388608,load=os.getloadavg()))
    result=owner.run_command(argv, environment, logs/(name+'.log'), wall, 8388608)
    save(name+'-owner.json',result)
    assert result['termination'] is None and result['cleanup_complete'] and result['reaped_descendants']==0
    raw=(logs/(name+'.log')).read_bytes()
    assert len(raw)<=8388608 and hashlib.sha256(raw).hexdigest()==result['private_log_sha256']
    with (out/(name+'.log')).open('xb') as f: f.write(raw)
    unchanged(); return result['exit_code']
def capacity(out, label, pending_output=True):
    paths = [R, R / "ignored", R / "target"]
    result = dict(reserve_bytes=(2147483648 + 67108864) if pending_output else 0, slot_limit_bytes=20000000000,
                  hardlinks="counted conservatively for each requested path", queries=[])
    for kind, option in [("allocated", []), ("apparent", ["--apparent-size"])]:
        command = ["/usr/bin/prlimit", "--cpu=30", "--as=268435456", "--fsize=65536", "--core=0", "--",
                   "/usr/bin/du", "--summarize", "--block-size=1", "--count-links", *option, "--", *map(str, paths)]
        capture = out / ("capacity-" + label + "-" + kind + ".log")
        with capture.open("xb") as stream:
            child = subprocess.run(command, cwd=R, env=dict(PATH="/usr/bin:/bin", LANG="C", LC_ALL="C"),
                stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, timeout=60)
        raw = capture.read_bytes()
        assert child.returncode == 0 and len(raw) <= 65536, "bounded capacity query failed"
        rows = [line.split("\t") for line in raw.decode().splitlines()]
        assert len(rows) == 3 and all(len(row) == 2 for row in rows)
        assert [row[1] for row in rows] == list(map(str, paths))
        assert all(re.fullmatch("[0-9]+", row[0]) for row in rows)
        result[kind] = dict(zip(("slot", "ignored", "target"), (int(row[0]) for row in rows)))
        result["queries"].append(dict(argv=command, exit_code=child.returncode, wall_limit_seconds=60,
            capture=dict(path=str(capture), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())))
    result["slot_max_bytes"] = max(result["allocated"]["slot"], result["apparent"]["slot"])
    result["admitted"] = result["slot_max_bytes"] + result["reserve_bytes"] <= result["slot_limit_bytes"]
    with (out / ("capacity-" + label + ".json")).open("x") as stream:
        json.dump(result, stream, indent=2, sort_keys=True); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
    assert result["admitted"], ("full 2GiB output plus 64MiB margin does not fit below 20GB" if pending_output
                                else "actual slot exceeds 20GB after closed planner")
    return result

build=['/usr/bin/prlimit','--cpu=240','--as=4294967296','--fsize=134217728','--core=0','--',
 'cargo','build','--offline','--locked','--release','-j1','-p','liteinst-rewrite',
 '--example','full_program_bridge','--example','disassembly_sites']
capacity(out, 'before-build')
assert run('build',build,env,300)==0
capacity(out, 'after-build')
planner=R/'target/release/examples/disassembly_sites'; built=pin(planner)
frozen[planner]=built
save('built-planner.json',dict(revision=REV,product=built))
argv=['/usr/bin/prlimit','--cpu=180','--as=3221225472','--fsize=536870912','--core=0','--',str(planner),
 '--whole-program-packed-entry-veneer-mixed-neighbors-4096',str(original),str(ledger),inputs[ledger]['sha256'],
 str(policy),inputs[policy]['sha256'],str(out/'planner')]
capacity(out, 'before-planner')
code=run('planner',argv,dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1',TMPDIR=str(out/'tmp')),240)
assert pin(planner)==built
capacity(out, 'after-planner', pending_output=False)
files=[p for p in out.rglob('*') if p.is_file()]
assert all(not p.is_symlink() and p.stat().st_size<=512*1024**2 for p in files)
assert max(sum(p.stat().st_size for p in files),sum(p.stat().st_blocks*512 for p in files))<=2*1024**3
save('outcome.json',dict(planner_exit_code=code,native_attempts=0,backend_attempts=0,qualification_complete=False))
raise SystemExit(code)
