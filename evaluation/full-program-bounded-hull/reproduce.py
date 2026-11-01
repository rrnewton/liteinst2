#!/usr/bin/env python3
"""Fixed 2dc600f controls, policy, release build and one complete bounded-hull attempt; see README."""
import datetime, hashlib, importlib.util, json, os, pathlib, re, subprocess, sys
if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit('Use assertions-enabled Python -I -B')
R = pathlib.Path.cwd().resolve()
REV = '2dc600f31e1803043e8d56abda721cc8a32b9d4f'
assert len(sys.argv) == 8, 'ORIGINAL LEDGER SITES POLICY_2G TARGET OUT TOOLCHAIN_BIN required'
original, ledger, sites, policy, target = map(lambda p: pathlib.Path(p).resolve(strict=True), sys.argv[1:6])
out = pathlib.Path(sys.argv[6]).absolute()
tc = pathlib.Path(sys.argv[7]).resolve(strict=True)
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
 (359381,'ef09bcd4c78949ff4b93a928c59e04b545081f9e56c2056f2cfcdfe068604cce'),
 (75,'6ac466f4721cc43cbecd450cd3f37cb75cfc8d372e22f1295ae6d2ba2182788c')]
assert len({original,ledger,sites,policy,target}) == 5, 'five distinct resolved inputs required'
inputs = dict(zip((original,ledger,sites,policy,target), (dict(bytes=n,sha256=h) for n,h in expected)))
helper = R / 'evaluation/admission/processes.py'
assert pin(helper)['sha256'] == '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
cpus = sorted(os.sched_getaffinity(0)); assert len(cpus) == 1
frozen = dict(inputs)
for name,digest in [('full_program_bounded_hull_policy.py','79bfd55dc82fd90205c5d0b0a7b1c4f7d2cf20db591daf6ae3e0f20486afd2c3'),
 ('full_program_bounded_hull_policy_controls.py','68d5c03154e94cef11b0f2e6bd901332bbe30ad44d3b4aec5520175032fb8167'),
 ('full_program_policy.py','abba5a403f60cd13669a2d60c10702a56ec31835c409dc4b7f6eedc61437b115')]:
    p=R/'evaluation/offline-corpus'/name; frozen[p]=pin(p); assert frozen[p]['sha256']==digest
frozen.update({p:pin(p) for p in (tc/'cargo',tc/'rustc',pathlib.Path('/usr/bin/prlimit'),pathlib.Path('/usr/bin/git'),pathlib.Path('/usr/bin/du'),helper)})
git = lambda *a: subprocess.check_output(['/usr/bin/git','--no-optional-locks','-c','index.threads=1','-c','core.preloadIndex=false',*a], timeout=10)
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
def run(name, argv, environment, wall, cap=8388608):
    unchanged(); save(name+'-intent.json', dict(argv=argv,wall_seconds=wall,log_bytes=cap,load=os.getloadavg()))
    result=owner.run_command(argv, environment, logs/(name+'.log'), wall, cap)
    save(name+'-owner.json',result)
    assert result['termination'] is None and result['cleanup_complete'] and result['reaped_descendants']==0
    raw=(logs/(name+'.log')).read_bytes()
    assert len(raw)<=cap and hashlib.sha256(raw).hexdigest()==result['private_log_sha256']
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

common=[item for name,p in [('original',original),('ledger',ledger),('inventory',sites),('target',target),('policy-2g',policy)] for item in ('--'+name,str(p))]
small=['/usr/bin/prlimit','--cpu=45','--as=536870912','--fsize=16777216','--core=0','--','/usr/bin/python3.9','-I','-B']
minimal=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1',TMPDIR=str(out/'tmp'))
control_names=['BoundedHullControls.test_allocation_preserves_hints_and_rejects_changed_role_caps', 'BoundedHullControls.test_clip_preserves_priority_duplicates_and_both_boundaries', 'BoundedHullControls.test_complete_pinned_population_and_legacy_outputs_remain_exact', 'BoundedHullControls.test_empty_intersections_refuse_the_role_without_inventing_ranges', 'BoundedHullControls.test_exact_upper_boundary_has_no_page_above_the_arena', 'BoundedHullControls.test_input_and_legacy_policy_identity_failures_are_not_repaired', 'BoundedHullControls.test_invalid_geometry_overflow_and_existing_range_cap_refuse']
assert run('controls',small+[str(R/'evaluation/offline-corpus/full_program_bounded_hull_policy_controls.py'),*common,'-v'],minimal,60,1048576)==0
lines=[n.split('.',1)[1]+' (__main__.BoundedHullControls) ... ok\n' for n in control_names]
pattern=re.escape(''.join(lines)+'\n'+'-'*70+'\nRan 7 tests in ')+r'[0-9]+\.[0-9]+s\n\nOK\n'
assert re.fullmatch(pattern,(out/'controls.log').read_text('ascii'))
assert run('policy',small+[str(R/'evaluation/offline-corpus/full_program_bounded_hull_policy.py'),*common,'--out',str(out/'policy')],minimal,60,1048576)==0
bounded=out/'policy/policy-packed-hull512m-v1.txt'
bounded_pin=dict(bytes=351481,sha256='dddb9d48b8175f14e7f0c2ce7e9b7cadac2ef3bce84c0c1df869b1b503925d58')
assert pin(bounded)==bounded_pin
assert pin(out/'policy/summary.json')==dict(bytes=1028,sha256='b560008dd06042b0449c1f23ad5e7f8f706a30274a05787b3c48a4eb10b6f960')
assert {p.name for p in bounded.parent.iterdir()}=={bounded.name,'summary.json'}
frozen[bounded]=bounded_pin

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
 str(bounded),bounded_pin['sha256'],str(out/'planner')]
capacity(out, 'before-planner')
code=run('planner',argv,dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1',TMPDIR=str(out/'tmp')),240)
assert pin(planner)==built
capacity(out, 'after-planner', pending_output=False)
files=[p for p in out.rglob('*') if p.is_file()]
assert all(not p.is_symlink() and p.stat().st_size<=512*1024**2 for p in files)
assert max(sum(p.stat().st_size for p in files),sum(p.stat().st_blocks*512 for p in files))<=2*1024**3
save('outcome.json',dict(planner_exit_code=code,native_attempts=0,backend_attempts=0,qualification_complete=False))
raise SystemExit(code)
