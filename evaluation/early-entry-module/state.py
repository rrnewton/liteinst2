#!/usr/bin/env python3
"""Twelve fixed qualification-feature state/race cohorts; no timing claim or retry.

Run from exact committed source in one externally reserved CPU. This does not
qualify the default safe-wrapper binary. All source/output evidence stays private.
"""
import sys
if not __debug__ or not sys.flags.isolated or not sys.flags.dont_write_bytecode:
    raise SystemExit('use Python -I -B with assertions enabled')
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
import stat
import subprocess
import time

MIB = 1048576
FEATURE = 'frontend-native-qualification'
PROFILE = 'qualification-feature-v1'
SEEDS = (1311768467139281696, 18364758542526924135)
MODES = ('enabled', 'bypass', 'scheduled')
SCENARIOS = ('loaded-true-disarm', 'loaded-false-arm', 'admitted-rearm', 'returned-disarm')
OBSERVED = dict(enabled=4, bypass=0, **dict(zip(SCENARIOS, (0, 3, 4, 1))))
PAIR_HEADER = 'profile,scenario,k,seed,case,csv_index,status,children,comparisons,original_steps,candidate_steps,candidate_physical_calls,candidate_observed_entries,candidate_pre_rets,controller_handshakes,value0,value1,value2,value3,sum'
PLAN_HEADER = 'profile,index,scenario,k,seed,case,csv_index,status'
COVERAGE_HEADER = 'profile,k,seed,csv_cases,length_cases,csv_observed_heads,csv_declared_heads,csv_observed_edges,csv_declared_edges,csv_returns,length_heads,length_edges,length_returns'
# Frozen exact source paths include every new adapter/frontend member. Complete
# tracked Rust/support/profiler sources are additionally joined to the revision.
SOURCE_FILES = ('Cargo.lock', 'Cargo.toml', 'evaluation/early-entry-module/state.py', 'src/controls.rs', 'src/controls/entry_admission.rs', 'src/quiescent.rs', 'src/quiescent/entry_admission.rs', 'src/quiescent/whole_function.rs', 'src/trampoline.rs', 'src/trampoline/early_control/tests.rs', 'tests/entry_admission_planning.rs', 'tests/support/native_normal_caller.rs', 'tests/support/native_normal_module.rs', 'tests/support/native_normal_module/early_entry.rs', 'tests/support/native_normal_module/trace.rs', 'tests/support/native_normal_module/witness.rs', 'tests/support/quiescent_oracle.rs', 'tools/rapid-profiler/Cargo.toml', 'tools/rapid-profiler/native-interval/main.rs', 'tools/rapid-profiler/native-interval/normal/module.rs', 'tools/rapid-profiler/native-interval/normal/module/early_entry.rs', 'tools/rapid-profiler/normal-work/csv_fields.c', 'tools/rapid-profiler/normal-work/module_caller.c', 'tools/rapid-profiler/normal-work/module_caller_bytes.rs', 'tools/rapid-profiler/src/frontend_native/always_on/epoch_storage.rs', 'tools/rapid-profiler/src/frontend_native/always_on/normal.rs', 'tools/rapid-profiler/src/frontend_native/always_on/normal/module.rs', 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned.rs', 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry.rs', 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/controller.rs', 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/controller/tests.rs', 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/native.rs', 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/qualification.rs', 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/native.rs', 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/performance.rs', 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/session.rs', 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/session_history.rs', 'tools/rapid-profiler/src/frontend_native/always_on/site/ordinary.rs', 'tools/rapid-profiler/src/frontend_native/always_on/site/ordinary/normal_module.rs', 'tools/rapid-profiler/src/frontend_native/always_on/site/ordinary/normal_module/early_entry.rs', 'tools/rapid-profiler/src/frontend_native/always_on/site/ordinary/normal_module/early_entry/append.rs', 'tools/rapid-profiler/src/frontend_native/mod.rs', 'tools/rapid-profiler/src/frontend_native/ordinary/module_caller.rs', 'tools/rapid-profiler/strnlen-work/localize.map', 'tools/rapid-profiler/strnlen-work/strnlen.c')
PINS = {'evaluation/admission/processes.py': '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f', 'tools/unwind-oracle/bounded_command.py': 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44', 'evaluation/ordinary-module-native/reproduce.py': '5cce60e76d7ec2011c8facb0a5c1101e0100e13aac8ed9b6317846de35fd3146', 'tools/rapid-profiler/verify_normal_interval.py': '7a1e480c8fb815bb62165773650a0f8590c5bdc6ba39fc1189c63bceb1e085a7', 'tools/rapid-profiler/selected-work/check_output.py': '5855c42be2b9a42e85b121f9d8b763e51747f842c8cf85e05dc1736a4f10e4a9', 'tools/rapid-profiler/verify_strnlen_interval.py': '9a37fa20311984d5ba755458e7858578165e0d7a2df583599a1b2057e50e6126', 'tools/rapid-profiler/reference-work/check_output.py': 'a5e0683ade47a94913afb53a15123a53b316172d8d9936f3a925b8a2b64b7189', 'evaluation/ordinary-module-native/module_native.py': '17e90fa9e26f9174f715056af39e700ad1158c8d27abec43c9259205edac3697'}
MODULES = {'census': 'tools/rapid-profiler/selected-work/check_output.py', 'whole': 'tools/rapid-profiler/verify_strnlen_interval.py', 'legacy': 'tools/rapid-profiler/reference-work/check_output.py', 'data': 'evaluation/ordinary-module-native/module_native.py'}
CALIBRATION_SHA = '8e90b2caa345a1e9f85d05a9717a2873626cf00231b5239b0c1373a8133bb442'
CALIBRATION_NAMES_SHA = '24568d95bcd7810788f853bbd296cec395b06421341c00f94efe00cf0802c4cf'
# Integration tests implicitly build all package binaries, including src/main.rs.
# Declare those non-oracle prerequisites separately; keep the final controls
# command and every per-command limit unchanged.
PREPARATION_TARGETS = (
    ('tree-native-baseline', 'native-baseline/main.rs'),
    ('frontend-native-point', 'native-point/main.rs'),
    ('ordinary-interval', 'ordinary-interval/main.rs'),
    ('point-throughput', 'point-throughput/main.rs'),
    ('rapid-profiler', 'src/main.rs'),
)



def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()


def save(path, value):
    content = canonical(value); assert len(content) <= 16*MIB
    with path.open('xb') as stream: stream.write(content)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def table(content, header, count):
    assert type(content) is bytes and 0 < len(content) <= 65536 and content.endswith(b'\n')
    assert all(c == 10 or 32 <= c < 127 for c in content)
    lines = content.decode('ascii').splitlines(); assert len(lines) == count+1 and lines[0] == header
    keys = header.split(','); result = []
    for line in lines[1:]:
        words = line.split(','); assert len(words) == len(keys)
        row = dict(zip(keys, words)); assert row['profile'] == PROFILE
        for key in keys:
            if key in ('profile', 'scenario', 'status'): continue
            assert re.fullmatch(r'0|[1-9][0-9]{0,19}', row[key])
            row[key] = int(row[key]); assert row[key] < 1 << 64
        if 'status' in row: assert row['status'] == 'PASS'
        result.append(row)
    return result


def catalog(mode):
    scenarios = SCENARIOS if mode == 'scheduled' else (mode,)
    return [(seed, scenario, case) for seed in SEEDS for scenario in scenarios
            for case in ((16,) if mode == 'scheduled' else range(1, 17))]


def check_output(mode, k, order, content, stdout, stderr, geometry, data):
    expected = catalog(mode); count = len(expected)
    assert mode in MODES and k in (10, 1000) and order in (0, 1)
    assert set(content) == {'early-entry-plan.csv', 'early-entry-pairs.csv'} | ({'early-entry-coverage.csv'} if mode != 'scheduled' else set())
    assert stdout == f'EARLY_ENTRY_QUALIFICATION profile={PROFILE} mode={mode} k={k} pairs={count} children={2*count} PASS\n'.encode()
    assert stderr == b''
    plans = table(content['early-entry-plan.csv'], PLAN_HEADER, count)
    pairs = table(content['early-entry-pairs.csv'], PAIR_HEADER, count)
    for index, ((seed, scenario, case), plan, row) in enumerate(zip(expected, plans, pairs)):
        assert plan == dict(profile=PROFILE, index=index, scenario=scenario, k=k, seed=seed, case=case, csv_index=order, status='PASS')
        assert (row['scenario'], row['k'], row['seed'], row['case'], row['csv_index']) == (scenario, k, seed, case, order)
        assert (row['children'], row['candidate_physical_calls'], row['candidate_pre_rets']) == (2, 4, 4)
        assert (row['candidate_observed_entries'], row['controller_handshakes']) == (OBSERVED[scenario], int(mode == 'scheduled'))
        values = (data.CSV_VALUES[case-1], data.LENGTH_VALUES[(case-1) % 8])*2
        assert tuple(row['value'+str(i)] for i in range(4)) == values and row['sum'] == sum(values)
        # The unchanged native comparer owns exact per-head equality; this CSV
        # does not contain its visits and cannot independently replay that proof.
        assert 44 <= row['comparisons'] <= row['original_steps'] <= 20000
        assert row['comparisons'] <= row['candidate_steps'] <= 20000 and row['comparisons'] % 2 == 0
    coverage = []
    if mode != 'scheduled':
        coverage = table(content['early-entry-coverage.csv'], COVERAGE_HEADER, 2)
        for seed, row in zip(SEEDS, coverage):
            assert (row['k'], row['seed'], row['csv_cases'], row['length_cases']) == (k, seed, 16, 8)
            csv, length = geometry
            assert row['csv_declared_heads'] == len(csv['heads']) and row['csv_declared_edges'] == csv['edges']
            assert row['csv_returns'] == len(csv['returns'])
            assert row['csv_returns']+1 <= row['csv_observed_heads'] <= row['csv_declared_heads']
            assert row['csv_observed_heads']-1 <= row['csv_observed_edges'] <= row['csv_declared_edges']
            assert (row['length_heads'], row['length_edges'], row['length_returns']) == (len(length['heads']), length['edges'], len(length['returns']))
        assert {key: value for key, value in coverage[0].items() if key != 'seed'} == {key: value for key, value in coverage[1].items() if key != 'seed'}
    return dict(pairs=count, children=2*count, comparisons=sum(r['comparisons'] for r in pairs),
                candidate_physical_calls=4*count, candidate_observed_entries=sum(r['candidate_observed_entries'] for r in pairs),
                candidate_pre_rets=4*count, controller_handshakes=sum(r['controller_handshakes'] for r in pairs), coverage_rows=len(coverage))


def calibration_output(stdout, stderr, required, ignored, reason):
    assert stderr == b''
    lines = stdout.decode('ascii').splitlines(); assert lines[:2] == ['', 'running 233 tests']
    assert len(lines) == 238 and lines[-1] == lines[-3] == ''
    passed = {}; ignored_rows = {}
    for line in lines[2:235]:
        match = re.fullmatch(r'test ([A-Za-z_0-9:]+)( - should panic)? \.\.\. ok', line)
        if match:
            assert match[1] not in passed; passed[match[1]] = match[2] is not None
        else:
            assert line == f'test {ignored} ... ignored, {reason}' and not ignored_rows
            ignored_rows[ignored] = reason
    assert len(passed) == 232 and ignored_rows == {ignored: reason}
    assert all(passed.get(name) is panic for name, panic in required.items())
    assert hashlib.sha256(canonical(dict(passed=passed, ignored=ignored_rows))).hexdigest() == CALIBRATION_SHA
    assert re.fullmatch(r'test result: ok\. 232 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in [0-9]+\.[0-9]+s', lines[-2])


def reader_controls():
    # Synthetic metadata only; these are never claimed as native observations.
    path = Path(__file__).resolve().parents[2]/'evaluation/ordinary-module-native/module_native.py'
    assert hashlib.sha256(path.read_bytes()).hexdigest() == PINS['evaluation/ordinary-module-native/module_native.py']
    data = load('early_state_control_values', path)
    geometry = [dict(heads=[0, 1, 2], edges=2, returns=[2]), dict(heads=[0, 1], edges=1, returns=[1])]
    def encode(header, rows):
        return (header+'\n'+''.join(','.join(str(r[k]) for k in header.split(','))+'\n' for r in rows)).encode()
    def fixture(mode):
        plans=[]; pairs=[]
        for index,(seed,scenario,case) in enumerate(catalog(mode)):
            plans.append(dict(profile=PROFILE,index=index,scenario=scenario,k=10,seed=seed,case=case,csv_index=0,status='PASS'))
            values=(data.CSV_VALUES[case-1],data.LENGTH_VALUES[(case-1)%8])*2
            pairs.append(dict(profile=PROFILE,scenario=scenario,k=10,seed=seed,case=case,csv_index=0,status='PASS',children=2,
                comparisons=48,original_steps=48,candidate_steps=100,candidate_physical_calls=4,candidate_observed_entries=OBSERVED[scenario],
                candidate_pre_rets=4,controller_handshakes=int(mode=='scheduled'),**{'value'+str(i):v for i,v in enumerate(values)},sum=sum(values)))
        coverage=[dict(profile=PROFILE,k=10,seed=seed,csv_cases=16,length_cases=8,csv_observed_heads=3,csv_declared_heads=3,
            csv_observed_edges=2,csv_declared_edges=2,csv_returns=1,length_heads=2,length_edges=1,length_returns=1) for seed in SEEDS]
        content={'early-entry-plan.csv':encode(PLAN_HEADER,plans),'early-entry-pairs.csv':encode(PAIR_HEADER,pairs)}
        if mode!='scheduled':content['early-entry-coverage.csv']=encode(COVERAGE_HEADER,coverage)
        terminal=f'EARLY_ENTRY_QUALIFICATION profile={PROFILE} mode={mode} k=10 pairs={len(plans)} children={2*len(plans)} PASS\n'.encode()
        return content,terminal
    def verify(mode,content,terminal):return check_output(mode,10,0,content,terminal,b'',geometry,data)
    static,st=fixture('enabled');scheduled,rt=fixture('scheduled')
    assert verify('enabled',static,st)['pairs']==32;print('READER_CONTROL synthetic-static PASS')
    assert verify('scheduled',scheduled,rt)['pairs']==8;print('READER_CONTROL synthetic-scheduled PASS')
    corrupt=[]
    for name in ('missing-row','duplicate-case','wrong-physical-count'):
        content=dict(static);lines=content['early-entry-pairs.csv'].splitlines()
        if name=='missing-row':lines.pop()
        elif name=='duplicate-case':lines[2]=lines[1]
        else:
            row=lines[1].decode().split(',');row[PAIR_HEADER.split(',').index('candidate_physical_calls')]='3';lines[1]=','.join(row).encode()
        content['early-entry-pairs.csv']=b'\n'.join(lines)+b'\n';corrupt.append((name,'enabled',content,st))
    content=dict(scheduled);lines=content['early-entry-pairs.csv'].splitlines();lines[1],lines[2]=lines[2],lines[1]
    content['early-entry-pairs.csv']=b'\n'.join(lines)+b'\n';corrupt.append(('wrong-schedule-order','scheduled',content,rt))
    for name,mode,content,terminal in corrupt:
        try:verify(mode,content,terminal)
        except AssertionError:pass
        else:raise AssertionError('mutation accepted: '+name)
        print('READER_CONTROL '+name+' PASS')


def native_exec(request_path, expected):
    # Same-PID redirect/exec pattern from the pinned module-native recipe. The
    # external pinned timeout and process owner retain complete wait authority.
    assert re.fullmatch('[0-9a-f]{64}', expected)
    fields = ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')
    with os.fdopen(os.open(request_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno()); assert stat.S_ISREG(before.st_mode) and before.st_size <= MIB
        content = stream.read(MIB+1); after = os.fstat(stream.fileno()); current = request_path.lstat()
        assert len(content) == before.st_size and all(getattr(before,f) == getattr(after,f) == getattr(current,f) for f in fields)
    assert hashlib.sha256(content).hexdigest() == expected
    r = json.loads(content); assert set(r) == {'argv', 'cwd', 'env', 'stdout', 'stderr', 'pins'}
    root = Path(r['cwd']); assert root.is_absolute() and root.resolve(strict=True) == root
    assert request_path.resolve(strict=True) == request_path and request_path.is_relative_to(root/'ignored')
    argv = r['argv']; assert len(argv) == 14 and all(type(v) is str and '\0' not in v for v in argv)
    assert argv[:2] == [str(root/'target/release/frontend-native-oracle'), 'normal-early-entry-state']
    assert argv[2] in MODES and argv[3] in ('10', '1000')
    assert all(re.fullmatch('[1-9][0-9]{0,19}', argv[i]) for i in (6, 7, 8, 9, 12))
    directory = request_path.parent; assert request_path.name == 'request.json'
    match = re.fullmatch(r'native-order(01|10)-k(10|1000)-(enabled|bypass|scheduled)', directory.name)
    assert match and (match[2], match[3]) == (argv[3], argv[2])
    raw = directory.parent
    assert argv[4:6] == [str(raw/('order'+match[1]+'-candidate.so')), str(raw/('order'+match[1]+'-trusted.so'))]
    assert argv[10:12] == [str(raw/'caller-candidate.so'), str(raw/'caller-trusted.so')]
    csv_va,csv_size,length_va,length_size = map(int,argv[6:10])
    assert 5 <= csv_size <= 256 and 5 <= length_size <= 80
    spans = sorted(((csv_va,csv_size),(length_va,length_size)))
    assert spans[0][0]+spans[0][1] <= spans[1][0] and spans[1][0]+spans[1][1] < 1 << 64
    assert spans[0][0]//4096 == (spans[1][0]+spans[1][1]-1)//4096
    assert int(csv_va > length_va) == int(match[1][0]) and len(os.sched_getaffinity(0)) == 1
    assert r['stdout'] == str(directory/'stdout.txt') and r['stderr'] == str(directory/'stderr.txt')
    assert argv[13] == str(directory/'native-output') and not Path(argv[13]).exists()
    assert set((argv[0], *argv[4:6], *argv[10:12], str(Path(__file__).resolve()))) <= r['pins'].keys()
    assert all(type(k) is type(v) is str and '\0' not in k+v and '=' not in k for k,v in r['env'].items())
    for path, pin in r['pins'].items():
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
            before = os.fstat(stream.fileno()); assert stat.S_ISREG(before.st_mode) and before.st_size == pin['bytes'] <= 512*MIB
            h = hashlib.sha256(); total = 0
            for block in iter(lambda: stream.read(MIB), b''):
                total += len(block); assert total <= before.st_size <= 512*MIB
                h.update(block)
            assert total == before.st_size
            after = os.fstat(stream.fileno()); current = Path(path).lstat()
            fields = ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')
            assert all(getattr(before,f) == getattr(after,f) == getattr(current,f) for f in fields)
            assert h.hexdigest() == pin['sha256']
    for kind, wanted in ((resource.RLIMIT_CPU, 480), (resource.RLIMIT_FSIZE, MIB), (resource.RLIMIT_CORE, 0)):
        assert all(n == resource.RLIM_INFINITY or n >= wanted for n in resource.getrlimit(kind))
        resource.setrlimit(kind, (wanted, wanted)); assert resource.getrlimit(kind) == (wanted, wanted)
    files = []
    try:
        for key in ('stdout', 'stderr'):
            fd = os.open(r[key], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            files.append(fd); s = os.fstat(fd)
            assert fd > 2 and stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and s.st_nlink == 1 and s.st_size == 0
        assert (os.fstat(files[0]).st_dev, os.fstat(files[0]).st_ino) != (os.fstat(files[1]).st_dev, os.fstat(files[1]).st_ino)
        for fd, target in zip(files, (1, 2)): os.dup2(fd, target, inheritable=True)
    finally:
        for fd in files: os.close(fd)
    os.chdir(root); os.execve(argv[0], argv, r['env'])


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--revision', required=True)
    for name in ('root', 'toolchain', 'user-home', 'cargo-home', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    a = parser.parse_args(); assert re.fullmatch('[0-9a-f]{40}', a.revision)
    root = a.root.resolve(strict=True); assert root == a.root
    assert all(p.is_absolute() and p.resolve(strict=True) == p and p.is_dir() for p in (a.toolchain, a.user_home, a.cargo_home))
    assert Path(__file__).resolve() == root/'evaluation/early-entry-module/state.py'
    raw = a.output; assert raw.is_absolute() and raw.parent.resolve(strict=True) == raw.parent and raw.is_relative_to(root/'ignored')
    raw.mkdir(mode=0o700)
    cases = [dict(case=f'order{order}{1-order}-k{k}-{mode}', order=order, k=k, mode=mode, status='UNOBSERVED', attempts=0)
             for order in (0, 1) for k in (10, 1000) for mode in MODES]
    result = dict(status='FAILED', profile=PROFILE, revision=a.revision, native_attempts=0, cases=cases, stages=[],
                  performance_qualified=False, default_profile_qualified=False, A5_qualified=False)
    save(raw/'plan.json', dict(cases=cases, native_commands=12, static_pairs=256, scheduled_pairs=32, children=576, retries=0,
         pair_wall=15, child_steps=20000, child_cleanup=2, command_cpu=480, command_wall=510, owner_wall=535,
         file_and_capture=MIB, core=0, cumulative_reserved_data=2048*MIB, cumulative_reserved_metadata=64*MIB,
         preparation=dict(targets=PREPARATION_TARGETS, cpu_per_target=120, wall_per_target=180,
                          owner_wall_per_target=205, file_and_capture_per_target=128*MIB,
                          added_owner_wall_catalog=1025, retries=0)))
    frozen = {}; safe = True; started = time.monotonic()
    try:
        tools = {n:(a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo','rustc','rustdoc')}
        tools.update({n:Path('/usr/bin',n).resolve(strict=True) for n in ('gcc','readelf','objdump','git','timeout')})
        tools['python'] = Path(sys.executable).resolve(strict=True)
        env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home), PATH=str(a.toolchain/'bin')+':/usr/bin:/bin',
                   RUSTC=str(tools['rustc']), RUSTDOC=str(tools['rustdoc']), CC=str(tools['gcc']), CARGO_TARGET_DIR=str(root/'target'),
                   CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='1', CARGO_NET_OFFLINE='true', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
                   CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='false', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='false',
                   CARGO_TERM_COLOR='never', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
        def git(*args):
            data = subprocess.check_output([str(tools['git']), '-C', str(root), *args], env=env, timeout=15); assert len(data) <= 16*MIB
            return data
        def clean():
            assert git('rev-parse','--show-toplevel').decode().strip() == str(root)
            assert git('rev-parse','HEAD').decode().strip() == a.revision and git('status','--porcelain','--untracked-files=no') == b''
        clean()
        for name, expected in PINS.items():
            content = (root/name).read_bytes(); assert hashlib.sha256(content).hexdigest() == expected and content == git('show',a.revision+':'+name)
        recipe = load('early_state_existing_recipe',root/'evaluation/ordinary-module-native/reproduce.py')
        owner = load('early_state_owner',root/'evaluation/admission/processes.py')
        normal = load('early_state_normal',root/'tools/rapid-profiler/verify_normal_interval.py')
        modules = {name:load('early_state_'+name,root/path) for name,path in MODULES.items()}
        pin, read = recipe.digest, recipe.read
        def retain(path):
            value = pin(path)
            if str(path) in frozen: assert frozen[str(path)] == value
            else: frozen[str(path)] = value
            return value
        required = set(SOURCE_FILES)|set(PINS)|set(recipe.NATIVE_SOURCES)|set(recipe.MODULES.values())|{
            'evaluation/ordinary-module-native/controls.py','tests/call_tree_truth.rs'}
        names = git('ls-files','-z','--','src','crates','tests/support','tools/rapid-profiler','Cargo.toml','Cargo.lock','build.rs',':(glob)**/Cargo.toml',*sorted(required)).decode().rstrip('\0').split('\0')
        assert all(names) and len(names) == len(set(names)) and required <= set(names)
        for name in names:
            content = git('show',a.revision+':'+name); assert retain(root/name) == dict(bytes=len(content),sha256=hashlib.sha256(content).hexdigest())
        source_pins = dict(frozen)
        for path in tools.values(): retain(path)
        assert retain(root/'tools/rapid-profiler/normal-work/csv_fields.c')['sha256'] == recipe.CSV_SOURCE_SHA
        assert retain(root/'tools/rapid-profiler/strnlen-work/strnlen.c')['sha256'] == recipe.LENGTH_SOURCE_SHA
        assert retain(root/'tools/rapid-profiler/normal-work/module_caller.c')['sha256'] == recipe.CALLER_SOURCE_SHA
        save(raw/'sources.json',source_pins); retain(raw/'sources.json')
        cpus = sorted(os.sched_getaffinity(0)); assert len(cpus) == 1
        hardware = Path('/proc/cpuinfo').read_bytes(); assert len(hardware) <= 4*MIB
        (raw/'cpuinfo.txt').write_bytes(hardware)
        records = [dict(line.split(':',1) for line in block.splitlines() if ':' in line) for block in hardware.decode().strip().split('\n\n')]
        records = [{k.strip():v.strip() for k,v in r.items()} for r in records]
        cpu = [r for r in records if r.get('processor') == str(cpus[0])]; assert len(cpu) == 1
        assert 'rdtscp' in cpu[0]['flags'].split() and 'ibt' not in cpu[0]['flags'].split()
        result['host'] = dict(utc=dt.datetime.now(dt.timezone.utc).isoformat(),affinity=cpus,load=os.getloadavg(),uname=list(os.uname()),
                            cpu=cpu[0],cpuinfo=retain(raw/'cpuinfo.txt'),cgroup=Path('/proc/self/cgroup').read_text(),boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        result['tree'] = git('rev-parse','HEAD^{tree}').decode().strip()
        logs = root/'target/evaluation'/raw.name; logs.mkdir(parents=True,exist_ok=False)
        save(raw/'intent.json',dict(revision=a.revision,argv=sys.argv,env=env,tools={k:str(v) for k,v in tools.items()},host=result['host']))
        def unchanged():
            clean(); assert sorted(os.sched_getaffinity(0)) == cpus
            assert git('ls-files','-z','--',*names).decode().rstrip('\0').split('\0') == names
            recipe.pins_ok(frozen)
        def stage(name, argv, cpu_seconds=20, wall=30, cap=MIB):
            nonlocal safe
            unchanged(); directory = raw/name; directory.mkdir()
            request = dict(argv=list(map(str,argv)),cwd=str(root),env=env,stdout=str(directory/'stdout.txt'),stderr=str(directory/'stderr.txt'),cpu_seconds=cpu_seconds,wall_seconds=wall,file_bytes=cap)
            save(directory/'request.json',request); request_pin = retain(directory/'request.json')
            command = [str(tools['python']),'-I','-B',str(root/'tools/unwind-oracle/bounded_command.py'),'--request',str(directory/'request.json'),'--receipt',str(directory/'receipt.json')]
            save(directory/'intent.json',dict(argv=command,wall_seconds=wall+25,log_bytes=MIB))
            row = dict(name=name,status='DISPATCHED_UNKNOWN',request=request_pin);result['stages'].append(row);safe=False
            closed = owner.run_command(command,env,logs/(name+'.log'),wall+25,MIB)
            save(directory/'closed.json',closed);row['closed']=closed;safe=closed['cleanup_complete'] is True
            if safe: row['status']='CLOSED_FAILED'
            assert safe
            parent=read(logs/(name+'.log'),MIB);assert hashlib.sha256(parent).hexdigest()==closed['private_log_sha256']
            (directory/'parent.log').write_bytes(parent)
            for path in (logs/(name+'.log'),directory/'parent.log',directory/'receipt.json',directory/'stdout.txt',directory/'stderr.txt'):
                if path.exists():retain(path)
            unchanged();recipe.closed_ok(closed)
            receipt=json.loads(read(directory/'receipt.json',MIB));row['receipt']=receipt
            assert receipt['request_sha256']==request_pin['sha256'] and receipt['helper_sha256']==PINS['tools/unwind-oracle/bounded_command.py']
            assert receipt['exit']==0 and receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
            assert receipt['absence_proof']=='ECHILD' and receipt['unexpected_descendants']==receipt['cleanup_events']==[]
            assert receipt['aborted'] is receipt['cleanup_error'] is None
            for stream in ('stdout','stderr'):assert receipt[stream+'_sha256']==retain(directory/(stream+'.txt'))['sha256']
            unchanged();row['status']='CLOSED_EXIT_ZERO';return read(directory/'stdout.txt',cap),read(directory/'stderr.txt',cap)
        for name,path in tools.items():
            out,err=stage('version-'+name,[path,'-vV' if name=='rustc' else '--version'])
            result.setdefault('versions',{})[name]=dict(stdout=out.decode(),stderr=err.decode(),file=retain(path))
        for name in ('cc1','collect2','as','ld'):
            out,err=stage('gcc-'+name,[tools['gcc'],'-print-prog-name='+name]);assert err==b''
            value=out.decode().strip();assert out==(value+'\n').encode()
            path=Path(value) if '/' in value else Path(shutil.which(value,path=env['PATH']) or '')
            assert path.is_absolute();retain(path.resolve(strict=True))
        out,err=stage('python-controls',[tools['python'],'-I','-B',root/'evaluation/ordinary-module-native/controls.py','-v'])
        recipe.python_output(out,err)
        out,err=stage('reader-controls',[tools['python'],'-I','-B',Path(__file__).resolve(),'--reader-controls'])
        assert err==b'' and out==b''.join(('READER_CONTROL '+name+' PASS\n').encode() for name in ('synthetic-static','synthetic-scheduled','missing-row','duplicate-case','wrong-physical-count','wrong-schedule-order'))
        def artifact(content,target,source,kind,test,record=None):
            messages=[json.loads(line) for line in content.splitlines()];assert messages[-1]==dict(reason='build-finished',success=True)
            products=[m for m in messages if m.get('reason')=='compiler-artifact' and m['target']['name']==target and m['profile']['test'] is test]
            assert len(products)==1;p=products[0]
            assert p['manifest_path']==str(root/'tools/rapid-profiler/Cargo.toml') and p['target']['src_path']==str(root/'tools/rapid-profiler'/source)
            assert p['target']['kind']==[kind] and p['target']['crate_types']==['bin'] and p['features']==[FEATURE]
            assert p['profile']==dict(opt_level='3',debuginfo=0,test=test,debug_assertions=False,overflow_checks=False)
            binary=Path(p['executable']);assert binary.resolve(strict=True)==binary
            if test:assert binary.parent==root/'target/release/deps' and re.fullmatch(target.replace('-','_')+'-[0-9a-f]+',binary.name)
            else:assert binary==root/'target/release'/target
            save(raw/((record or target)+'-artifact.json'),dict(product=p,binary=retain(binary)));return binary
        common=['--locked','--offline','--release','--jobs','1','-p','rapid-profiler','--features',FEATURE,'--message-format=json-render-diagnostics']
        out,_=stage('release-oracle',[tools['cargo'],'build','--bin','frontend-native-oracle',*common],120,180,128*MIB)
        binary=artifact(out,'frontend-native-oracle','native-interval/main.rs','bin',False)
        for target,source in PREPARATION_TARGETS:
            name='prepare-'+target
            out,_=stage(name,[tools['cargo'],'build','--bin',target,*common],120,180,128*MIB)
            artifact(out,target,source,'bin',False,record=name)
        out,_=stage('release-controls',[tools['cargo'],'test','--test','frontend-native-calibrations','--bin','ordinary-interval','--no-run',*common],120,180,128*MIB)
        calibration=artifact(out,'frontend-native-calibrations','native-interval/calibrations.rs','test',True)
        caller_test=artifact(out,'ordinary-interval','ordinary-interval/main.rs','bin',True)
        required_controls=recipe.calibration_manifest(modules['legacy'],normal,modules['whole']);assert len(required_controls)==179
        out,err=stage('state-list',[calibration,'--list']);inventory=modules['census'].census(out,err)
        assert hashlib.sha256(canonical(sorted(inventory))).hexdigest()==CALIBRATION_NAMES_SHA
        assert set(required_controls)|{recipe.IGNORED} <= set(inventory)
        out,err=stage('state-controls',[calibration,'--test-threads=1'])
        calibration_output(out,err,required_controls,recipe.IGNORED,recipe.IGNORE_REASON)
        out,err=stage('caller-list',[caller_test,'--list']);inventory=modules['census'].census(out,err)
        expected=tuple('normal::caller::tests::'+n for n in normal.CALLER)
        assert set(n for n in inventory if n.startswith('normal::caller::tests::'))==set(expected)
        out,err=stage('caller-controls',[caller_test,*expected,'--exact','--test-threads=1']);modules['census'].controls(out,err,expected,inventory)
        fixtures={}
        for label,inputs,options in (('order01',['normal-work/csv_fields.c','strnlen-work/strnlen.c'],recipe.MODULE_FLAGS),
                                    ('order10',['strnlen-work/strnlen.c','normal-work/csv_fields.c'],recipe.MODULE_FLAGS),
                                    ('caller',['normal-work/module_caller.c'],normal.CALLER_FLAGS)):
            trusted,candidate=raw/(label+'-trusted.so'),raw/(label+'-candidate.so')
            out,err=stage(label+'-build',[tools['gcc'],*options,*[root/'tools/rapid-profiler'/p for p in inputs],'-o',trusted],60,90,128*MIB)
            assert out==err==b'';content=read(trusted,MIB);assert content
            with candidate.open('xb') as stream:stream.write(content)
            assert (trusted.stat().st_dev,trusted.stat().st_ino)!=(candidate.stat().st_dev,candidate.stat().st_ino) and retain(trusted)==retain(candidate)
            out,err=stage(label+'-elf',[tools['readelf'],'--wide','--file-header','--program-headers','--dynamic','--syms','--relocs',trusted])
            assert err==b'' and not re.search(rb'\((NEEDED|INIT|FINI|INIT_ARRAY|FINI_ARRAY|PREINIT_ARRAY)\)|\bIFUNC\b',out)
            fixtures[label]=dict(trusted=trusted,candidate=candidate,symbols=out)
        for order in (0,1):
            label=f'order{order}{1-order}';f=fixtures[label]
            selections=[recipe.selection(f['symbols'],n,ceiling) for n,ceiling in (('csv_fields',256),('strnlen',80))]
            spans=sorted(selections);assert spans[0][0]+spans[0][1]<=spans[1][0] and spans[0][0]//4096==(spans[1][0]+spans[1][1]-1)//4096
            assert int(selections[0][0]>selections[1][0])==order
            bodies=[]
            for name,(va,length) in zip(('csv_fields','strnlen'),selections):
                out,err=stage(label+'-'+name,[tools['objdump'],'-d','-M','intel','--insn-width=16','--disassemble='+name,f['trusted']]);assert err==b''
                bodies.append(recipe.body_geometry(recipe.geometry(out,name,va,length),va,length,name=='strnlen'))
            f.update(selections=selections,bodies=bodies)
        out,err=stage('caller-body',[tools['objdump'],'-d','-M','intel','--insn-width=16','--disassemble=normal_module_caller',fixtures['caller']['trusted']]);assert err==b''
        caller=recipe.caller_geometry(out,fixtures['caller']['symbols'])
        save(raw/'geometry.json',dict(orders={k:dict(selections=v['selections'],bodies=v['bodies']) for k,v in fixtures.items() if k!='caller'},caller=caller))
        commands=[]
        for row in cases:
            directory=raw/('native-'+row['case']);f=fixtures[f"order{row['order']}{1-row['order']}"];c=fixtures['caller']
            commands.append([str(binary),'normal-early-entry-state',row['mode'],str(row['k']),str(f['candidate']),str(f['trusted']),
                *[str(n) for span in f['selections'] for n in span],str(c['candidate']),str(c['trusted']),str(caller['elf_va']),str(directory/'native-output')])
        save(raw/'native-commands.json',dict(commands=commands,cpu=480,wall=510,owner_wall=535,file_and_capture=MIB,core=0));retain(raw/'native-commands.json')
        for row,declared in zip(cases,commands):
            unchanged();directory=raw/('native-'+row['case']);directory.mkdir()
            f=fixtures[f"order{row['order']}{1-row['order']}"];c=fixtures['caller'];mode,k=row['mode'],row['k']
            argv=[str(binary),'normal-early-entry-state',mode,str(k),str(f['candidate']),str(f['trusted']),
                  *[str(n) for span in f['selections'] for n in span],str(c['candidate']),str(c['trusted']),str(caller['elf_va']),str(directory/'native-output')]
            assert argv==declared
            request=dict(argv=argv,cwd=str(root),env=env,stdout=str(directory/'stdout.txt'),stderr=str(directory/'stderr.txt'),pins=dict(frozen))
            save(directory/'request.json',request);request_pin=retain(directory/'request.json')
            command=[str(tools['timeout']),'--kill-after=5s','510s',str(tools['python']),'-I','-B',str(Path(__file__).resolve()),'--native-request',str(directory/'request.json'),request_pin['sha256']]
            save(directory/'intent.json',dict(argv=command,env=env,owner_wall=535,capture=MIB,cpu=480,file=MIB,core=0))
            row.update(status='DISPATCHED_UNKNOWN',attempts=1,command=command,request=request_pin);result['native_attempts']+=1
            save(directory/'attempt.json',row);safe=False
            closed=owner.run_command(command,env,logs/(row['case']+'.log'),535,MIB)
            save(directory/'closed.json',closed);row['closed']=closed;safe=closed['cleanup_complete'] is True
            if safe:row['status']='FAILED'
            assert safe
            parent=read(logs/(row['case']+'.log'),MIB);assert hashlib.sha256(parent).hexdigest()==closed['private_log_sha256']
            (directory/'parent.log').write_bytes(parent)
            for path in (logs/(row['case']+'.log'),directory/'parent.log',directory/'stdout.txt',directory/'stderr.txt'):
                if path.exists():retain(path)
            output=directory/'native-output'
            if output.exists():
                for path in output.iterdir():retain(path)
            unchanged();recipe.closed_ok(closed);assert parent==b''
            files={p.name:read(p,65536) for p in output.iterdir()}
            row['census']=check_output(mode,k,row['order'],files,read(directory/'stdout.txt',MIB),read(directory/'stderr.txt',MIB),f['bodies'],modules['data'])
            row['status']='PASS'
        unchanged();assert result['native_attempts']==12 and all(r['status']=='PASS' and r['attempts']==1 for r in cases)
        assert sum(r['census']['pairs'] for r in cases)==288 and sum(r['census']['children'] for r in cases)==576
        result.update(status='EARLY_ENTRY_MODULE_QUALIFICATION_PASS',native_binary=retain(binary),source_unchanged=True)
    except BaseException as error:
        result['error']=type(error).__name__+': '+str(error)
        for row in cases:
            if row['status']=='DISPATCHED_UNKNOWN' and safe:row['status']='FAILED'
    finally:
        result.update(cleanup_complete=safe,seconds=time.monotonic()-started,load_after=os.getloadavg(),retained=frozen)
        save(raw/'result.json',result)
    return 0 if result['status']=='EARLY_ENTRY_MODULE_QUALIFICATION_PASS' else 1


if __name__ == '__main__':
    if sys.argv[1:]==['--reader-controls']:
        reader_controls()
    elif len(sys.argv)==4 and sys.argv[1]=='--native-request':
        native_exec(Path(sys.argv[2]),sys.argv[3])
    else:
        raise SystemExit(main())
