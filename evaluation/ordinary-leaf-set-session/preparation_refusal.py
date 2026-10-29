#!/usr/bin/env python3
"""One release preparation refusal; requires an external two-CPU/1200s/8MiB owner.

No target call, campaign, Schedule, scalar, architectural-state or timing credit.
The reservation tag and observed affinity do not prove a hard CPU reservation.
"""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import stat
import struct
import subprocess
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MIB = 1048576
EXPECTED = b'normal-leaf-set-session PREPARATION_FAILED stage=site class=core reason=no_patch_window\n'
CODE = bytes.fromhex('4889f0c3')
SYMBOL = b'leaf_preparation_refusal'
CONTROL = 'leaf_set_preparation_refusal_retains_fail_stop_and_aborts'
RECIPE = 'evaluation/ordinary-module-session/reproduce.py'
NATIVE = 'evaluation/ordinary-module-native/reproduce.py'
OWNER = 'evaluation/admission/processes.py'
BOUNDED = 'tools/unwind-oracle/bounded_command.py'
OWNER_SHA = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
BOUNDED_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
CONTROLS = ('test_complete_four_byte_elf_and_identity_refusals',
            'test_raw_wait_core_bit_and_every_acceptance_join',
            'test_first_pins_and_regular_file_capture_custody',
            'test_shared_cargo_product_and_independent_executable_copy')
STAGES = tuple('tool-'+n for n in ('cc1', 'collect2', 'as', 'ld')) + (
    'python-controls', 'fixture-build', 'application-build', 'preparation-refusal')


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode('ascii')


def pin(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def read(path, cap=MIB):
    # Also used before any authenticated project import and by the inner mode.
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        before = os.fstat(f.fileno())
        assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap
        data = f.read(cap+1)
        assert len(data) == before.st_size <= cap
        assert identity(before) == identity(os.fstat(f.fileno())) == identity(Path(path).lstat())
        return data


def save(path, value):
    data = canonical(value); assert len(data) <= 16*MIB
    with path.open('xb') as f: f.write(data)
    return pin(data)


def unchanged(pins):
    for name, expected in pins.items():
        assert pin(read(Path(name), max(MIB, expected['bytes']))) == expected


def elf_geometry(data):
    """Strict ELF64 little-endian fixture grammar, not a general ELF admission API."""
    assert 64 <= len(data) <= MIB
    h = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    assert h[0][:9] == b'\x7fELF\x02\x01\x01\x00\x00' and h[0][9:] == bytes(7)
    assert h[1:4] == (3, 62, 1) and h[4] == h[7] == 0
    assert h[8] == 64 and h[9] == 56 and h[11] == 64
    assert 1 <= h[10] <= 64 and 1 <= h[12] <= 128 and 0 < h[13] < h[12]
    def span(offset, size):
        assert 0 <= offset <= len(data) and 0 <= size <= len(data)-offset
        return data[offset:offset+size]
    ph = [struct.unpack('<IIQQQQQQ', span(h[5]+56*i, 56)) for i in range(h[10])]
    sh = [struct.unpack('<IIQQQQIIQQ', span(h[6]+64*i, 64)) for i in range(h[12])]
    loads = [p for p in ph if p[0] == 1]
    assert loads and not any(p[0] in (3, 7) for p in ph)  # no interpreter or TLS
    for p in loads:
        span(p[2], p[5]); assert p[5] <= p[6] and p[3]+p[6] < 1 << 64
        assert p[1] & 6 and not (p[1] & 2 and p[1] & 1)
        assert p[7] == 4096 and p[2] % 4096 == p[3] % 4096
    assert len([p for p in ph if p[0] == 0x6474e551 and p[1] == 6]) == 1
    # No dynamic dependencies, constructors, relocation effects or lazy binding.
    dynamic = [p for p in ph if p[0] == 2]; assert len(dynamic) == 1
    p = dynamic[0]; assert p[5] % 16 == 0 and 16 <= p[5] <= 4096
    tags = list(struct.iter_unpack('<qQ', span(p[2], p[5])))
    assert tags and any(t == 0 for t, _ in tags)
    end = next(i for i, (t, _) in enumerate(tags) if t == 0)
    assert all(t == v == 0 for t, v in tags[end:])
    assert not any(t == 1 or (t in (12, 13, 25, 26, 27, 28, 32, 33) and v) for t, v in tags[:end])
    assert any(t == 24 or t == 30 and v & 8 or t == 0x6ffffffb and v & 1 for t, v in tags[:end])
    assert all(s[5] == 0 for s in sh if s[1] in (4, 9))
    symbols = []
    assert len([s for s in sh if s[1] == 2]) == 1
    for s in sh:
        if s[1] not in (2, 11): continue
        assert s[9] == 24 and s[5] % 24 == 0 and 24 <= s[5] <= 24*256 and 0 < s[6] < len(sh)
        span(s[4], s[5])
        strings = sh[s[6]]; assert strings[1] == 3 and 0 < strings[5] <= 4096
        names = span(strings[4], strings[5])
        for offset in range(s[4], s[4]+s[5], 24):
            name, info, other, section, va, size = struct.unpack('<IBBHQQ', span(offset, 24))
            assert name < len(names) and b'\0' in names[name:]
            label = names[name:].split(b'\0', 1)[0]
            if label == SYMBOL or info & 15 == 2 and section != 0:
                symbols.append((label, info, other, section, va, size, s[1]))
    selected = [s for s in symbols if s[0] == SYMBOL]
    assert len(selected) == len(symbols) == 1  # this fixed fixture contains one defined FUNC
    _, info, other, section, va, size, kind = selected[0]
    assert info == 2 and other == 0 and kind == 2 and 0 < section < len(sh)
    assert size == 4 and 0 < va <= (1 << 64)-5
    section = sh[section]; assert section[1] == 1 and section[2] == 6
    assert section[3] <= va and va+4 <= section[3]+section[5]
    file_offset = section[4]+va-section[3]
    matches = [p for p in loads if p[3] <= va and va+4 <= p[3]+p[5]]
    assert len(matches) == 1 and matches[0][1] == 5
    load = matches[0]
    assert file_offset == load[2]+va-load[3] and span(file_offset, 4) == CODE
    return dict(elf_va=va, extent=4, file_offset=file_offset, bytes_hex=CODE.hex(),
                heads=[0, 3], returns=[3], policy='certified', operation='length',
                load=list(load), section=list(section), symbol_binding='LOCAL')


def raw_wait(pid, waited, status, parent, cpus, request_sha):
    return dict(child_pid=pid, waited_pid=waited, parent_pid=parent, raw_status=status,
                signaled=os.WIFSIGNALED(status), signal=os.WTERMSIG(status) if os.WIFSIGNALED(status) else None,
                core_dump=bool(os.WCOREDUMP(status)), normal_reaps=1, absence_proof='ECHILD',
                cpus=cpus, request_sha256=request_sha)


def check_wait(record, stdout, stderr, *, request_sha, cpus):
    assert set(record) == {'child_pid','waited_pid','parent_pid','raw_status','signaled','signal',
                           'core_dump','normal_reaps','absence_proof','cpus','request_sha256'}
    for key in ('child_pid', 'waited_pid', 'parent_pid'):
        assert type(record[key]) is int and 0 < record[key] < 1 << 31
    assert record['child_pid'] == record['waited_pid'] != record['parent_pid']
    status = record['raw_status']; assert type(status) is int and 0 <= status <= 65535
    assert record['signaled'] is True and type(record['signal']) is int and record['signal'] == signal.SIGABRT
    assert type(record['core_dump']) is bool and record['core_dump'] == bool(os.WCOREDUMP(status))
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGABRT
    assert status == signal.SIGABRT | (128 if record['core_dump'] else 0)
    assert type(record['normal_reaps']) is int and record['normal_reaps'] == 1
    assert record['absence_proof'] == 'ECHILD' and record['request_sha256'] == request_sha
    assert record['cpus'] == cpus and all(type(c) is int for c in record['cpus'])
    assert stdout == b'' and stderr == EXPECTED


def capture(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    s = os.fstat(fd)
    assert fd > 2 and stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1 and s.st_size == 0
    return fd, (s.st_dev, s.st_ino)


def artifact_identity(path):
    s = path.lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1
    return list(identity(s))


def unchanged_artifacts(pins):
    assert {p:artifact_identity(Path(p)) for p in pins} == pins


def load_checked(label, path, pins):
    assert pin(read(path)) == pins[str(path)]
    spec = importlib.util.spec_from_file_location(label, path); assert spec and spec.loader
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def inner(plan_path, plan_sha):
    # Dedicated raw-wait mode; existing authenticated owner helpers supply custody.
    data = read(plan_path); assert pin(data)['sha256'] == plan_sha
    plan = json.loads(data); directory = plan_path.parent
    assert directory.resolve(strict=True) == directory and directory.is_relative_to(ROOT/'ignored')
    assert resource.getrlimit(resource.RLIMIT_CPU) == (20, 20)
    assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
    assert resource.getrlimit(resource.RLIMIT_FSIZE) == (MIB, MIB)
    assert sorted(os.sched_getaffinity(0)) == plan['cpus']
    unchanged(plan['pins'])
    unchanged_artifacts(plan['identities'])
    assert plan['pins'][str(ROOT/OWNER)]['sha256'] == OWNER_SHA
    owner = load_checked('_preparation_inner_owner', ROOT/OWNER, plan['pins'])
    owner._preflight(); owner._subreaper(1); assert owner._subreaper() == 1
    assert elf_geometry(read(Path(plan['trusted']))) == plan['geometry']
    assert read(Path(plan['candidate'])) == read(Path(plan['trusted']))
    assert plan['argv'] == [plan['binary'], 'normal-leaf-set-session', plan['candidate'], plan['trusted'],
                            '10', '1', '1', '1', 'length', str(plan['geometry']['elf_va']), '4', 'certified']
    fds = [capture(directory/name) for name in ('app.stdout', 'app.stderr')]
    assert fds[0][1] != fds[1][1]
    save(directory/'app-launch.json', dict(argv=plan['argv'], env=plan['env'], cpus=plan['cpus'],
        limits=dict(cpu=[20,20], file=[MIB,MIB], core=[0,0]), captures=[list(i) for _,i in fds], plan_sha256=plan_sha))
    pid = os.fork()  # Exactly one APP, no retry, no target invocation by this driver.
    if pid == 0:
        try:
            null = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
            os.dup2(null, 0); os.close(null)
            for (fd, _), target in zip(fds, (1, 2)): os.dup2(fd, target)
            for fd, _ in fds: os.close(fd)
            for name in ('SIGPIPE', 'SIGXFZ', 'SIGXFSZ'):
                if hasattr(signal, name): signal.signal(getattr(signal, name), signal.SIG_DFL)
            os.execve(plan['binary'], plan['argv'], plan['env'])
        except BaseException:
            os._exit(127)
    save(directory/'app-pid.json', dict(parent_pid=os.getpid(), child_pid=pid, plan_sha256=plan_sha))
    waited, status = os.waitpid(pid, 0)  # The enclosing bounded owner supplies the 30s wall.
    # Nonreaping waitid/ECHILD through the existing owner; unexpected descendants
    # remain owned for the enclosing bounded helper to clean up after refusal.
    absence = owner._no_children()
    record = raw_wait(pid, waited, status, os.getpid(), plan['cpus'], plan_sha)
    if not absence: record['absence_proof'] = 'UNPROVED'
    save(directory/'app-wait.json', record)  # Retain actual signal/core bits before any acceptance.
    assert absence and waited == pid
    for (fd, expected), name in zip(fds, ('app.stdout', 'app.stderr')):
        s = os.fstat(fd); current = (directory/name).lstat()
        assert (s.st_dev, s.st_ino) == expected == (current.st_dev, current.st_ino)
        assert stat.S_ISREG(current.st_mode) and current.st_nlink == 1 and current.st_uid == os.getuid()
        os.close(fd)
    out, err = read(directory/'app.stdout'), read(directory/'app.stderr')
    check_wait(record, out, err, request_sha=plan_sha, cpus=plan['cpus'])
    unchanged(plan['pins'])
    unchanged_artifacts(plan['identities'])
    return 0


def product(native, data):
    # Shared target permits Cargo reuse; its actual boolean freshness is retained.
    binary, p = native.artifact(data, 'ordinary-interval', 'ordinary-interval/main.rs', 'bin', False)
    assert p['profile']['debug_assertions'] is True and p['profile']['overflow_checks'] is True
    return binary, p


def retain_executable(source, destination, expected):
    # Cargo may hardlink its product. Only this independent retained copy is APP.
    before = source.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_mode & 0o111
    data = read(source, 512*MIB)
    assert pin(data) == expected and identity(source.lstat()) == identity(before)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        assert f.write(data) == len(data)
        f.flush(); os.fchmod(f.fileno(), 0o500)
        copied = os.fstat(f.fileno())
        assert stat.S_ISREG(copied.st_mode) and copied.st_uid == os.getuid() and copied.st_nlink == 1
        assert (copied.st_dev, copied.st_ino) != (before.st_dev, before.st_ino)
    exact = artifact_identity(destination)
    assert exact == list(identity(copied)) and stat.S_IMODE(copied.st_mode) == 0o500
    assert pin(read(destination, 512*MIB)) == expected
    assert identity(source.lstat()) == identity(before) and pin(read(source, 512*MIB)) == expected
    return exact


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True); ap.add_argument('--reservation-tag', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'): ap.add_argument('--'+name, type=Path, required=True)
    a = ap.parse_args(); started = time.monotonic()
    assert re.fullmatch('[0-9a-f]{40}', a.revision) and re.fullmatch('[A-Za-z0-9_.-]{1,128}', a.reservation_tag)
    assert HERE == ROOT/'evaluation/ordinary-leaf-set-session'
    for p in (ROOT, a.toolchain, a.user_home, a.cargo_home):
        assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    assert a.raw.is_absolute() and a.raw.parent.resolve(strict=True) == a.raw.parent
    assert a.raw.is_relative_to(ROOT/'ignored') and not os.path.lexists(a.raw)
    logs = ROOT/'target/evaluation'/a.raw.name; assert not os.path.lexists(logs)
    a.raw.mkdir(mode=0o700); (a.raw/'tmp').mkdir(mode=0o700)
    result = dict(status='FAILED', revision=a.revision, reservation_tag=a.reservation_tag,
        reservation_authority='external hard two-CPU owner required', stages=[dict(name=n,status='UNRUN') for n in STAGES],
        control=dict(name=CONTROL,status='UNRUN',attempts=0), custody_closed=True, retention_verified=False,
        start_utc=dt.datetime.now(dt.timezone.utc).isoformat(), scope=__doc__)
    retained = {}; sources = {}; tool_pins = {}; artifact_ids = {}; safe = True
    def freeze(path, value):
        value = save(path, value); assert str(path) not in retained; retained[str(path)] = value; return value
    def remember(path, cap=512*MIB):
        value = pin(read(path, cap)); key = str(path)
        if key in retained: assert retained[key] == value
        else: retained[key] = value
        return value
    try:
        os.chdir(ROOT)
        assert os.uname().sysname=='Linux' and os.uname().machine=='x86_64'
        cpus = sorted(os.sched_getaffinity(0)); assert len(cpus) == 2 and all(0 <= c < 1024 for c in cpus)
        result.update(affinity=cpus, load_before=list(os.getloadavg()))
        tools = {n: (a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo','rustc','rustdoc')}
        tools.update({n: Path('/usr/bin', n).resolve(strict=True) for n in ('git','gcc')})
        tools['python'] = Path(sys.executable).resolve(strict=True)
        target = ROOT/'target'  # One shared Cargo build domain; APP is retained separately.
        env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home), PATH=str(a.toolchain/'bin')+':/usr/bin:/bin',
            RUSTC=str(tools['rustc']), RUSTDOC=str(tools['rustdoc']), CC=str(tools['gcc']),
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=str(tools['gcc']), CARGO_TARGET_DIR=str(target),
            CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true', CARGO_TERM_COLOR='never',
            CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0',
            CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
            LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', LITEINST_EVALUATION='1', TMPDIR=str(a.raw/'tmp'))
        def git(*args):
            data = subprocess.check_output([tools['git'], '-C', ROOT, *args], env=env, timeout=15)
            assert len(data) <= 32*MIB; return data
        def source_clean():
            assert git('rev-parse','HEAD').decode().strip() == a.revision
            assert git('status','--porcelain','--untracked-files=no') == b''
        source_clean(); assert git('rev-parse','--show-toplevel').decode().strip() == str(ROOT)
        required = {RECIPE, NATIVE, OWNER, BOUNDED, *[str((HERE/n).relative_to(ROOT)) for n in (
            'preparation_refusal.py','preparation_refusal.S','preparation_refusal_controls.py')],
            'tools/rapid-profiler/strnlen-work/localize.map',
            'tools/rapid-profiler/ordinary-interval/normal/leaf_set/preparation_diagnostic.rs'}
        names = git('ls-files','-z','--','src','crates','tests/support','tests/call_tree_truth.rs','tools/rapid-profiler',
            'Cargo.toml','Cargo.lock','build.rs','.cargo',':(glob)**/Cargo.toml',*sorted(required)).decode().rstrip('\0').split('\0')
        assert all(names) and len(names) == len(set(names)) and required <= set(names)
        for name in names:
            data = read(ROOT/name, 16*MIB); assert data == git('show', a.revision+':'+name)
            sources[str(ROOT/name)] = pin(data)
        assert sources[str(ROOT/OWNER)]['sha256'] == OWNER_SHA and sources[str(ROOT/BOUNDED)]['sha256'] == BOUNDED_SHA
        tool_pins.update({str(p):pin(read(p,512*MIB)) for p in tools.values()})
        # Only these already authenticated stdlib-only project modules load.
        recipe = load_checked('_preparation_recipe', ROOT/RECIPE, sources)
        native = load_checked('_preparation_native', ROOT/NATIVE, sources)
        owner = load_checked('_preparation_owner', ROOT/OWNER, sources)
        logs.mkdir(parents=True, exist_ok=False)
        freeze(a.raw/'sources.json', sources)
        with Path('/proc/cpuinfo').open('rb') as f: cpuinfo=f.read(MIB+1)
        assert len(cpuinfo)<=MIB
        freeze(a.raw/'hardware.json', dict(uname=list(os.uname()), cpuinfo=cpuinfo.decode('ascii'),
            affinity=cpus, load=list(os.getloadavg()), reservation_tag=a.reservation_tag, authority='external only'))
        freeze(a.raw/'plan.json', dict(revision=a.revision, app_children=1, attempts=1, retries=0, cpus=cpus,
            child_cpu=20, child_wall=30, child_file=MIB, outer_wall=1200, outer_log=8*MIB,
            build_cpu=120, build_wall=180, build_file=128*MIB, controls=list(CONTROLS), stages=list(STAGES),
            expected_stderr=EXPECTED.decode(), expected_signal='SIGABRT', core_bit='actual; either value retained',
            build_scratch=str(target), scope=__doc__))
        def audit():
            assert time.monotonic() < started+1200 and sorted(os.sched_getaffinity(0)) == cpus
            source_clean(); unchanged(sources); unchanged(tool_pins); unchanged(retained)
            unchanged_artifacts(artifact_ids)
        def stage(name, argv, cpu=20, wall=30, cap=MIB):
            nonlocal safe
            audit(); assert time.monotonic()+wall+28 < started+1200
            row = next(r for r in result['stages'] if r['name'] == name); assert row['status'] == 'UNRUN'
            d = a.raw/name; d.mkdir(mode=0o700)
            req = dict(argv=list(map(str,argv)), cwd=str(ROOT), env=env, stdout=str(d/'stdout'), stderr=str(d/'stderr'),
                       cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
            request = freeze(d/'request.json',req)
            command = [str(tools['python']),'-B',str(ROOT/BOUNDED),'--request',str(d/'request.json'),'--receipt',str(d/'receipt.json')]
            freeze(d/'command.json',dict(argv=command,env=env,wall_seconds=wall+25,log_bytes=MIB))
            row['status']='FAILED'; safe=False
            closed=owner.run_command(command,env,logs/(name+'.log'),wall+25,MIB)
            freeze(d/'closed.json',closed); row['closed']=closed
            # No child output is read unless the existing owner proves complete normal closure.
            recipe.normal_closed(closed)
            log=read(logs/(name+'.log')); assert pin(log)['sha256'] == closed['private_log_sha256']
            remember(logs/(name+'.log')); receipt=json.loads(read(d/'receipt.json'))
            out,err=read(d/'stdout',cap),read(d/'stderr',cap)
            for p in (d/'receipt.json',d/'stdout',d/'stderr'): remember(p, max(MIB,cap))
            code=recipe.bounded_join(receipt,closed,request,sources[str(ROOT/BOUNDED)],pin(out),pin(err))
            assert json.loads(log) == dict(exit=code,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=code==0)
            safe=True; row['exit']=code; audit()
            if code==0: row['status']='CLOSED_EXIT_0'
            return code,out,err
        for name in ('cc1','collect2','as','ld'):
            code,out,err=stage('tool-'+name,[tools['gcc'],'-print-prog-name='+name]); assert code==0 and err==b''
            assert out.endswith(b'\n') and out.count(b'\n')==1
            reported=out[:-1].decode('utf-8')
            p=Path(reported) if '/' in reported else Path(shutil.which(reported,path=env['PATH']) or '')
            assert p.is_absolute(); p=p.resolve(strict=True)
            value=pin(read(p,512*MIB))
            if str(p) in tool_pins: assert tool_pins[str(p)]==value
            else: tool_pins[str(p)]=value
        freeze(a.raw/'tools.json',tool_pins)
        code,out,err=stage('python-controls',[tools['python'],'-B',HERE/'preparation_refusal_controls.py','-v'])
        assert code==0 and out==b''
        lines=err.decode('ascii').splitlines(); assert len(lines)==len(CONTROLS)+5
        for name,line in zip(sorted(CONTROLS),lines):
            assert re.fullmatch(re.escape(name)+r' \(__main__\.Controls(?:\.'+re.escape(name)+r')?\) \.\.\. ok',line)
        assert lines[-5]==lines[-2]=='' and re.fullmatch('-+',lines[-4]) and lines[-1]=='OK'
        assert re.fullmatch(r'Ran 4 tests in [0-9]+\.[0-9]+s',lines[-3])
        final=a.raw/'fixture-final.so'; trusted=a.raw/'fixture-trusted.so'; candidate=a.raw/'fixture-candidate.so'
        code,out,err=stage('fixture-build',[tools['gcc'],'-fPIC','-shared','-nostdlib','-fcf-protection=none',
            '-Wl,--build-id=none,-z,now,-z,noexecstack','-Wl,--entry=0',
            '-Wl,--version-script=tools/rapid-profiler/strnlen-work/localize.map',HERE/'preparation_refusal.S','-o',final])
        assert code==0 and out==err==b''
        final_pin=remember(final,MIB); content=read(final); geometry=elf_geometry(content)
        for p in (trusted,candidate):
            with p.open('xb') as f: f.write(content)
            assert remember(p,MIB)==final_pin
        assert len({(p.stat().st_dev,p.stat().st_ino) for p in (final,trusted,candidate)})==3
        artifact_ids.update({str(p):artifact_identity(p) for p in (final,trusted,candidate)})
        freeze(a.raw/'geometry.json',geometry)
        code,out,err=stage('application-build',[tools['cargo'],'build','--locked','--offline','--release','--jobs','4',
            '-p','rapid-profiler','--bin','ordinary-interval','--message-format=json-render-diagnostics'],120,180,128*MIB)
        assert code==0
        shared_product,metadata=product(native,out); product_pin=remember(shared_product)
        binary=a.raw/'ordinary-interval'
        artifact_ids[str(binary)]=retain_executable(shared_product,binary,product_pin)
        assert remember(binary)==product_pin
        freeze(a.raw/'artifact-identities.json',artifact_ids)
        freeze(a.raw/'application.json',dict(product=metadata,product_path=str(shared_product),
            product_content=product_pin,executable=str(binary),binary=retained[str(binary)]))
        app=a.raw/'application'; app.mkdir(mode=0o700)
        plan=dict(binary=str(binary),candidate=str(candidate),trusted=str(trusted),geometry=geometry,cpus=cpus,env=env,
            argv=[str(binary),'normal-leaf-set-session',str(candidate),str(trusted),'10','1','1','1','length',str(geometry['elf_va']),'4','certified'],
            pins={**sources,**tool_pins,**retained},identities=artifact_ids)
        assert len(canonical(plan))<=MIB
        plan_pin=freeze(app/'plan.json',plan)
        audit(); result['control'].update(status='FAILED',attempts=1)
        code,out,err=stage('preparation-refusal',[tools['python'],'-B',HERE/'preparation_refusal.py','--inner',app/'plan.json',plan_pin['sha256']])
        # Preserve all normal-closure APP evidence before interpreting a failure.
        for name in ('app-launch.json','app-pid.json','app-wait.json','app.stdout','app.stderr'):
            p=app/name
            if os.path.lexists(p): remember(p,MIB)
        actual=json.loads(read(app/'app-wait.json')); result['control']['actual_wait']=actual
        assert code==0 and out==err==b''
        launch=json.loads(read(app/'app-launch.json'))
        assert launch == dict(argv=plan['argv'],env=env,cpus=cpus,limits=dict(cpu=[20,20],file=[MIB,MIB],core=[0,0]),
            captures=[list((p.stat().st_dev,p.stat().st_ino)) for p in (app/'app.stdout',app/'app.stderr')],plan_sha256=plan_pin['sha256'])
        check_wait(actual,read(app/'app.stdout'),read(app/'app.stderr'),request_sha=plan_pin['sha256'],cpus=cpus)
        assert json.loads(read(app/'app-pid.json')) == dict(parent_pid=actual['parent_pid'],child_pid=actual['child_pid'],plan_sha256=plan_pin['sha256'])
        audit(); result['control']['status']='EXPECTED_PREPARATION_REFUSAL'; result['status']='EXPECTED_PREPARATION_REFUSAL'
    except BaseException as error:
        result['error']=type(error).__name__
    finally:
        result.update(custody_closed=safe,retained=dict(retained),sources=sources,tools=tool_pins,
                      end_utc=dt.datetime.now(dt.timezone.utc).isoformat())
        if safe:
            try:
                unchanged(sources); unchanged(tool_pins); unchanged(retained)
                unchanged_artifacts(artifact_ids)
                source_clean()
                result['retention_verified']=True
            except BaseException as error:
                result['status']='FAILED'; result['final_error']=type(error).__name__
        else: result['status']='FAILED'
        if result['status']=='FAILED' and result['control']['attempts']:
            result['control']['status']='FAILED'
        save(a.raw/'result.json',result)
    print(json.dumps(dict(status=result['status'],control=result['control'],custody_closed=safe)))
    return 0 if result['status']=='EXPECTED_PREPARATION_REFUSAL' else 1


if __name__ == '__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--inner':
        try:
            raise SystemExit(inner(Path(sys.argv[2]),sys.argv[3]))
        except (AssertionError, OSError, ValueError, KeyError, IndexError, TypeError):
            raise SystemExit(1)
    raise SystemExit(main())
