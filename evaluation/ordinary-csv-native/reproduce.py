#!/usr/bin/env python3
"""One complete release CSV native-state qualification; no retries or timing claim."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import argparse
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

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
MIB = 1048576
CSV_SOURCE_SHA = 'f8f98cc0550cf3ba72d2f2558f45057d2889870e804b51f599d4050ffb37cddd'
# Exact reviewed-source successor, not a claim that it has compiled or run.
ADAPTER = {
    'tests/support/native_normal_caller.rs': '02e6995756f9fad0d15b4c5616c15c9e4ba6d4effade2b81e71e183927705163',
    'tests/support/native_normal_csv.rs': '783d8ac3ec136295f6e97114ea5481d46cafd7421eecf1cac992fdc1184b85db',
    'tests/support/native_normal_csv/tests.rs': 'd7035987e585c2d50949b54a400ca6ca7f40f8d8f8340c21d9ededb786937503',
    'tools/rapid-profiler/native-interval/main.rs': 'dbfca6e6b736d4f6fb609ae399e5863a9920c5c2cfb62e224f9a8db3cfeb30ab',
    'tools/rapid-profiler/native-interval/normal.rs': 'fa2bbcc23912b419926bd4bc6387d6d0f6373ca4ea5fe76426bd045518bf6575',
    'tools/rapid-profiler/native-interval/normal/csv.rs': 'a1a8f6a51144718a7804a8b88145ea98f2f214f6d9b86bc95236ddc6557dae4e'}
CSV_FLAGS = ('-O2', '-fno-tree-vectorize', '-fno-if-conversion', '-fno-if-conversion2',
    '-fno-asynchronous-unwind-tables', '-fno-unwind-tables', '-fno-stack-protector',
    '-fcf-protection=none', '-fPIC', '-nostdlib', '-shared', '-Wl,--build-id=none,-z,now')
CSV_PREFIX = 'oracle::native_ordinary::normal_caller::csv::tests::'
CSV_TESTS = tuple(CSV_PREFIX + n for n in (
    'csv_cases_arguments_and_profile_keep_all_sixteen_and_legacy_limits',
    'csv_ready_keeps_complete_heads_returns_maps_and_distinct_extent_authority',
    'csv_body_inspection_refuses_wrong_input_path_value_and_return',
    'csv_pair_requires_both_calls_returns_reaps_and_complete_comparison_counts',
    'csv_population_requires_every_ordered_pair_and_each_seeds_return_union',
    'csv_trace_summary_keeps_source_and_observed_coverage_separate'))
SELECTED = tuple('oracle::native_ordinary::selected::tests::' + n for n in (
    'selected_arguments_require_canonical_complete_extent',
    'selected_population_requires_order_counts_and_scalar',
    'selected_ret_union_requires_all_declared_and_stable_ownership',
    'selected_deadline_never_renews_or_accepts_other_profiles'))
IGNORED = ('oracle::native_ordinary::hardware::control::'
           'owned_execution_breakpoint_restores_then_steps_then_stops')
IGNORE_REASON = 'requires explicit fresh-process release hardware-stop prerequisite'
PYTHON_CONTROLS = (
    'test_complete_population_and_descriptive_coverage',
    'test_framing_canonical_domains_and_exact_order',
    'test_scalar_values_lengths_and_two_call_conservation',
    'test_comparison_step_and_terminal_conservation',
    'test_ret_union_geometry_and_partial_tables',
    'test_source_local_import_and_optimization_refusal',
    'test_cargo_profile_symbol_and_request_authority',
    'test_closure_and_changed_pin_refuse_printed_success',
    'test_once_only_native_failure_and_unrun_prerequisites')
MODULES = {
    'owner': 'evaluation/admission/processes.py',
    'census': 'tools/rapid-profiler/selected-work/check_output.py',
    'normal': 'tools/rapid-profiler/verify_normal_interval.py',
    'whole': 'tools/rapid-profiler/verify_strnlen_interval.py',
    'legacy': 'tools/rapid-profiler/reference-work/check_output.py',
    'csv': 'evaluation/ordinary-csv-native/csv_native.py'}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def save(path, value):
    with path.open('xb') as f:
        f.write(canonical(value))


def digest(path, limit=512 * MIB):
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        before = os.fstat(f.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_size <= limit
        h = hashlib.sha256(); total = 0
        for block in iter(lambda: f.read(MIB), b''):
            total += len(block)
            assert total <= limit
            h.update(block)
        assert total == before.st_size
        assert identity(before) == identity(os.fstat(f.fileno())) == identity(Path(path).lstat())
    return dict(bytes=before.st_size, sha256=h.hexdigest())


def read(path, limit):
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        before = os.fstat(f.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_size <= limit
        data = f.read(limit + 1)
        assert len(data) == before.st_size <= limit
        assert identity(before) == identity(os.fstat(f.fileno())) == identity(Path(path).lstat())
    return data


def load(name, path):
    spec = importlib.util.spec_from_file_location('csv_native_' + name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def closed_ok(closed):
    assert closed['exit_code'] == 0 and closed['termination'] is None
    assert closed['cleanup_complete'] is True and closed['reaped_descendants'] == 0


def pins_ok(pins):
    for name, pin in pins.items():
        assert digest(Path(name)) == pin


def retain(pins, path, expected=None, limit=512*MIB):
    """Pin completed bytes once; later observations may only confirm them."""
    actual = digest(path, limit)
    if expected is not None:
        assert actual == expected
    key = str(path)
    if key in pins:
        assert actual == pins[key]
    else:
        pins[key] = actual
    return dict(pins[key])


def final_retention(result, pins, safe):
    """Export original pins even on failure; never adopt changed final bytes."""
    result['custody_closed'] = safe
    result['retained'] = {name: dict(pin) for name, pin in pins.items()}
    result['retention_verified'] = False
    if safe:
        try:
            pins_ok(pins)
            result['retention_verified'] = True
        except (OSError, AssertionError):
            result['status'] = 'FAILED'; result['retention_error'] = True
            if result['native']['attempts']:
                result['native']['status'] = 'FAILED'


def artifact(data, target, source, kind, test):
    messages = [json.loads(line) for line in data.splitlines()]
    assert messages and messages[-1] == dict(reason='build-finished', success=True)
    products = [m for m in messages if m.get('reason') == 'compiler-artifact'
                and m['target']['name'] == target and m['profile']['test'] is test]
    assert len(products) == 1
    p = products[0]
    assert p['manifest_path'] == str(ROOT/'tools/rapid-profiler/Cargo.toml')
    assert p['target']['src_path'] == str(ROOT/'tools/rapid-profiler'/source)
    assert p['target']['kind'] == [kind] and p['target']['crate_types'] == ['bin']
    assert p['profile'] == dict(opt_level='3', debuginfo=0, test=test,
                              debug_assertions=True, overflow_checks=True)
    assert type(p['profile']['debuginfo']) is int and type(p['fresh']) is bool
    path = Path(p['executable'])
    assert path.is_absolute() and path.resolve(strict=True) == path
    if test:
        assert path.parent == ROOT/'target/release/deps'
        assert re.fullmatch(re.escape(target.replace('-', '_')) + '-[0-9a-f]+', path.name)
    else:
        assert path == ROOT/'target/release'/target
    return path, p


def selection(data):
    rows = [line.split() for line in data.decode('ascii').splitlines()
            if line.split() and line.split()[-1] == 'csv_fields']
    assert len(rows) == 2
    assert all(len(r) == 8 and r[3:6] == ['FUNC', 'GLOBAL', 'DEFAULT']
               and r[6].isascii() and r[6].isdecimal() and int(r[6]) > 0 for r in rows)
    assert all(re.fullmatch('[0-9a-fA-F]+', r[1]) and re.fullmatch('[0-9]+', r[2]) for r in rows)
    extents = {(int(r[1], 16), int(r[2])) for r in rows}
    assert len(extents) == 1
    va, length = extents.pop()
    assert va > 0 and 5 <= length <= 256 and va + length <= (1 << 64) - 1
    return va, length


def calibration_manifest(legacy, normal, whole):
    expected = dict(legacy.CALIBRATION_TESTS)
    groups = (SELECTED, whole.STATE, normal.EXACT_STATE, normal.REFERENCE_WITNESS,
              normal.REFERENCE_GEOMETRY, normal.REFERENCE_CHILD, CSV_TESTS,
              tuple('oracle::native_ordinary::normal_caller::tests::' + n for n in normal.STATE),
              tuple('normal_check::tests::' + n for n in normal.CHILD),
              tuple(n.replace('normal::caller::reference_bytes::',
                              'oracle::native_ordinary::normal_caller::reference::bytes::', 1)
                    for n in normal.REFERENCE_WORK_CONTROLS
                    if n.startswith('normal::caller::reference_bytes::returned_tests::')))
    for group in groups:
        for name in group:
            assert name not in expected
            expected[name] = False
    assert len(expected) == 149 and IGNORED not in expected
    return expected


def calibration_output(stdout, stderr, expected):
    assert stderr == b''
    lines = stdout.decode('ascii').splitlines()
    count = len(expected) + 1
    assert lines[:2] == ['', f'running {count} tests'] and len(lines) == count + 5
    observed = {}
    ignored = f'test {IGNORED} ... ignored, {IGNORE_REASON}'
    body = lines[2:count + 2]
    assert body.count(ignored) == 1
    for line in body:
        if line == ignored:
            continue
        match = re.fullmatch(r'test ([A-Za-z_0-9:]+)( - should panic)? \.\.\. ok', line)
        assert match and match[1] not in observed
        observed[match[1]] = match[2] is not None
    assert observed == expected and lines[count + 2] == '' and lines[-1] == ''
    assert re.fullmatch(rf'test result: ok\. {len(expected)} passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in [0-9]+\.[0-9]+s', lines[-2])


def python_output(stdout, stderr):
    assert stdout == b''
    lines = stderr.decode('ascii').splitlines()
    assert len(lines) == len(PYTHON_CONTROLS) + 5
    for name, line in zip(sorted(PYTHON_CONTROLS), lines):
        assert re.fullmatch(re.escape(name) + r' \(__main__\.Controls(?:\.' + re.escape(name) + r')?\) \.\.\. ok', line)
    tail = lines[len(PYTHON_CONTROLS):]
    assert re.fullmatch('-+', tail[1]) and tail[0] == tail[3] == '' and tail[4] == 'OK'
    assert re.fullmatch(r'Ran 9 tests in [0-9]+\.[0-9]+s', tail[2])


def request_shape(request):
    assert set(request) == {'argv', 'cwd', 'env', 'stdout', 'stderr', 'pins'}
    argv = request['argv']
    assert isinstance(argv, list) and len(argv) == 9 and all(type(x) is str and '\0' not in x for x in argv)
    assert argv[:2] == [str(ROOT/'target/release/frontend-native-oracle'), 'normal-csv-state']
    assert re.fullmatch('[1-9][0-9]{0,19}', argv[4]) and re.fullmatch('[1-9][0-9]{0,2}', argv[5])
    va, extent = int(argv[4]), int(argv[5])
    assert 5 <= extent <= 256 and va + extent <= (1 << 64) - 1
    raw = Path(request['stdout']).parent
    assert raw.is_absolute() and raw.resolve(strict=True) == raw and raw.is_relative_to(ROOT/'ignored')
    assert request['stdout'] == str(raw/'stdout.txt') and request['stderr'] == str(raw/'stderr.txt')
    assert argv[2:4] == [str(raw/'csv-candidate.so'), str(raw/'csv-trusted.so')]
    assert argv[6:] == [str(raw/'caller-candidate.so'), str(raw/'caller-trusted.so'), str(raw/'native-output')]
    assert not Path(argv[-1]).exists() and request['cwd'] == str(ROOT)
    assert isinstance(request['env'], dict) and all(type(k) is type(v) is str and '\0' not in k + v and '=' not in k for k, v in request['env'].items())
    assert isinstance(request['pins'], dict)
    assert {str(Path(__file__).resolve()), *argv[2:4], *argv[6:8], argv[0]} <= request['pins'].keys()
    return raw


def native_exec(path, expected_hash):
    """Fixed same-PID limit/redirect/exec branch; the parent owns all waiting."""
    assert re.fullmatch('[0-9a-f]{64}', expected_hash)
    data = read(path, MIB)
    assert hashlib.sha256(data).hexdigest() == expected_hash
    request = json.loads(data)
    raw = request_shape(request)
    assert path == raw/'request.json'
    pins_ok(request['pins'])
    for fd in (0, 1, 2):
        os.fstat(fd)
    files = []
    try:
        for name in ('stdout', 'stderr'):
            fd = os.open(request[name], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            files.append(fd)
            s = os.fstat(fd)
            assert fd > 2 and stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and s.st_nlink == 1 and s.st_size == 0
        assert (os.fstat(files[0]).st_dev, os.fstat(files[0]).st_ino) != (os.fstat(files[1]).st_dev, os.fstat(files[1]).st_ino)
        for kind, wanted in ((resource.RLIMIT_CPU, 480), (resource.RLIMIT_FSIZE, MIB), (resource.RLIMIT_CORE, 0)):
            inherited = resource.getrlimit(kind)
            assert all(value == resource.RLIM_INFINITY or value >= wanted for value in inherited)
            resource.setrlimit(kind, (wanted, wanted))
            assert resource.getrlimit(kind) == (wanted, wanted)
        os.chdir(ROOT)
        for fd, target in zip(files, (1, 2)):
            os.dup2(fd, target, inheritable=True)
    finally:
        for fd in files:
            os.close(fd)
    os.execve(request['argv'][0], request['argv'], request['env'])


def once(row, invoke):
    assert row['status'] == 'UNRUN' and row['attempts'] == 0
    row.update(status='FAILED', attempts=1)
    closed = invoke()
    row['closed'] = closed
    return closed


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True)
    for name in ('toolchain', 'user-home', 'cargo-home', 'output'):
        ap.add_argument('--' + name, type=Path, required=True)
    a = ap.parse_args()
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    assert HERE == ROOT/'evaluation/ordinary-csv-native'
    for p in (ROOT, a.toolchain, a.user_home, a.cargo_home):
        assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    raw = a.output
    assert raw.is_absolute() and raw.parent.resolve(strict=True) == raw.parent
    assert raw.is_relative_to(ROOT/'ignored') and not raw.exists()
    raw.mkdir(mode=0o700)
    result = dict(status='FAILED', revision=a.revision, scope='CSV native state under the 67-byte helper; no Rust-caller, performance or full-A5 claim.',
                  native=dict(status='UNRUN', attempts=0, required_pairs=32, required_normal_reaps=64, required_target_calls=128), stages=[])
    save(raw/'plan.json', dict(revision=a.revision, native=result['native'],
         mode='normal-csv-state', seeds=[1311768467139281696, 18364758542526924135], cases=list(range(1, 17)),
         native_invocations=1, retries=0, pair_seconds=15, steps_per_child=20000, whole_wall_seconds=510))
    safe = True
    artifacts = {}
    result['plan'] = retain(artifacts, raw/'plan.json')
    try:
        logs = ROOT/'target/evaluation'/raw.name
        logs.mkdir(parents=True, exist_ok=False)
        (raw/'tmp').mkdir()
        tools = {n: (a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo', 'rustc', 'rustdoc')}
        tools.update({n: Path('/usr/bin', n).resolve(strict=True) for n in ('git', 'gcc', 'readelf', 'objdump')})
        tools['python'] = Path(sys.executable).resolve(strict=True)
        env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home), PATH=str(a.toolchain/'bin')+':/usr/bin:/bin',
            RUSTC=str(tools['rustc']), RUSTDOC=str(tools['rustdoc']), CC=str(tools['gcc']), CARGO_TARGET_DIR=str(ROOT/'target'),
            CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
            CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
            CARGO_TERM_COLOR='never', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', LITEINST_EVALUATION='1', TMPDIR=str(raw/'tmp'))
        def git(*args):
            data = subprocess.check_output([str(tools['git']), '-C', str(ROOT), *args], env=env, timeout=15)
            assert len(data) <= 16*MIB
            return data
        def clean():
            assert git('rev-parse', '--show-toplevel').decode().strip() == str(ROOT)
            assert git('rev-parse', 'HEAD').decode().strip() == a.revision
            assert git('status', '--porcelain', '--untracked-files=no') == b''
        clean()
        required = set(MODULES.values()) | {'evaluation/ordinary-csv-native/reproduce.py', 'evaluation/ordinary-csv-native/controls.py',
            'tools/unwind-oracle/bounded_command.py', 'tests/call_tree_truth.rs', 'tests/support/native_normal_csv.rs',
            'tests/support/native_normal_csv/tests.rs', 'tools/rapid-profiler/native-interval/normal/csv.rs'}
        names = git('ls-files', '-z', '--', 'src', 'tests/support', 'tools/rapid-profiler', 'Cargo.toml', 'Cargo.lock', 'README.md',
                    'build.rs', ':(glob)**/Cargo.toml', *sorted(required)).decode().rstrip('\0').split('\0')
        assert all(names) and len(names) == len(set(names)) and required <= set(names)
        before = {str(ROOT/n): digest(ROOT/n) for n in names}
        for name in names:
            blob = git('show', a.revision+':'+name)
            assert before[str(ROOT/name)] == dict(bytes=len(blob), sha256=hashlib.sha256(blob).hexdigest())
        assert before[str(ROOT/'tools/rapid-profiler/normal-work/csv_fields.c')]['sha256'] == CSV_SOURCE_SHA
        assert all(before[str(ROOT/p)]['sha256'] == h for p, h in ADAPTER.items())
        tool_pins = {str(p): digest(p) for p in tools.values()}
        save(raw/'sources-before.json', before)
        result['sources_before'] = retain(artifacts, raw/'sources-before.json')
        modules = {name: load(name, ROOT/path) for name, path in MODULES.items()}
        owner = modules['owner']
        affinity = sorted(os.sched_getaffinity(0))
        assert len(affinity) == 1
        result['affinity'] = affinity
        save(raw/'catalog.json', [dict(seed=s, case=i+1, length=n, value=v)
             for s in modules['csv'].SEEDS for i, (n, v) in enumerate(zip(modules['csv'].LENGTHS, modules['csv'].VALUES))])
        result['catalog'] = retain(artifacts, raw/'catalog.json')
        def unchanged():
            clean()
            assert set(git('ls-files', '-z', '--', *names).decode().rstrip('\0').split('\0')) == set(names)
            assert sorted(os.sched_getaffinity(0)) == affinity
            pins_ok(before); pins_ok(tool_pins); pins_ok(artifacts)
        def stage(name, argv, cpu=20, wall=30, cap=MIB):
            nonlocal safe
            unchanged()
            d = raw/name; d.mkdir()
            argv = list(map(str, argv))
            req = dict(argv=argv, cwd=str(ROOT), env=env, stdout=str(d/'stdout.txt'), stderr=str(d/'stderr.txt'),
                       cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
            save(d/'request.json', req)
            row = dict(name=name, status='FAILED', request=retain(artifacts, d/'request.json'))
            result['stages'].append(row)
            helper = ROOT/'tools/unwind-oracle/bounded_command.py'
            cmd = [str(tools['python']), '-B', str(helper), '--request', str(d/'request.json'), '--receipt', str(d/'receipt.json')]
            save(d/'command.json', dict(argv=cmd, env=env, wall_seconds=wall+25, log_bytes=MIB))
            row['command'] = retain(artifacts, d/'command.json')
            save(d/'state-before.json', row)
            retain(artifacts, d/'state-before.json')
            safe = False
            closed = owner.run_command(cmd, env, logs/(name+'.log'), wall+25, MIB)
            save(d/'closed.json', closed); row['closed'] = closed
            row['closed_file'] = retain(artifacts, d/'closed.json')
            safe = closed['cleanup_complete'] is True
            if safe:
                for p in (logs/(name+'.log'), d/'request.json', d/'receipt.json', d/'stdout.txt', d/'stderr.txt'):
                    if p.exists():
                        row[p.name] = retain(artifacts, p)
                parent_log = read(logs/(name+'.log'), MIB)
                with (d/'parent.log').open('xb') as f: f.write(parent_log)
                assert hashlib.sha256(parent_log).hexdigest() == closed['private_log_sha256']
                retain(artifacts, d/'parent.log', artifacts[str(logs/(name+'.log'))])
            closed_ok(closed)
            assert hashlib.sha256(parent_log).hexdigest() == closed['private_log_sha256']
            assert json.loads(parent_log) == dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)
            receipt = json.loads(read(d/'receipt.json', MIB))
            assert receipt['exit'] == 0 and receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
            assert receipt['absence_proof'] == 'ECHILD' and receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
            assert receipt['aborted'] is receipt['cleanup_error'] is None
            assert receipt['request_sha256'] == row['request']['sha256'] == digest(d/'request.json')['sha256']
            assert receipt['helper_sha256'] == before[str(helper)]['sha256']
            for stream in ('stdout', 'stderr'):
                assert receipt[stream+'_sha256'] == digest(d/(stream+'.txt'))['sha256']
            unchanged(); row['status'] = 'CLOSED_EXIT_ZERO'
            return read(d/'stdout.txt', cap), read(d/'stderr.txt', cap)
        # Pin compiler subtools selected by the same fixed PATH before compiling.
        for name in ('cc1', 'collect2', 'as', 'ld'):
            data, error = stage('tool-'+name, [tools['gcc'], '-print-prog-name='+name])
            assert error == b'' and data.endswith(b'\n') and data.count(b'\n') == 1
            reported = data[:-1].decode('utf-8')
            path = Path(reported) if '/' in reported else Path(shutil.which(reported, path=env['PATH']) or '')
            assert path.is_absolute(); path = path.resolve(strict=True)
            tool_pins[str(path)] = digest(path)
        save(raw/'tools.json', tool_pins)
        result['tools'] = retain(artifacts, raw/'tools.json')
        data, error = stage('python-controls', [tools['python'], '-B', HERE/'controls.py', '-v'])
        python_output(data, error)
        test_bins = {}
        for label, target, source, kind, flags in (
            ('native', 'frontend-native-oracle', 'native-interval/main.rs', 'bin', ['build', '--bin', 'frontend-native-oracle']),
            ('state', 'frontend-native-calibrations', 'native-interval/calibrations.rs', 'test', ['test', '--test', 'frontend-native-calibrations', '--no-run']),
            ('caller', 'ordinary-interval', 'ordinary-interval/main.rs', 'bin', ['test', '--bin', 'ordinary-interval', '--no-run'])):
            argv = [tools['cargo'], *flags, '--locked', '--offline', '--release', '--jobs', '4', '-p', 'rapid-profiler', '--message-format=json-render-diagnostics']
            data, _ = stage(label+'-build', argv, 120, 180, 128*MIB)
            binary, product = artifact(data, target, source, kind, label != 'native')
            retain(artifacts, binary); test_bins[label] = binary
            save(raw/(label+'-artifact.json'), dict(product=product, binary=artifacts[str(binary)]))
            result.setdefault('artifacts', {})[label] = retain(artifacts, raw/(label+'-artifact.json'))
        manifest = calibration_manifest(modules['legacy'], modules['normal'], modules['whole'])
        save(raw/'calibration-manifest.json', dict(expected=manifest, ignored={IGNORED: IGNORE_REASON}))
        result['calibration_manifest'] = retain(artifacts, raw/'calibration-manifest.json')
        data, error = stage('state-list', [test_bins['state'], '--list'])
        inventory = modules['census'].census(data, error)
        assert set(inventory) == set(manifest) | {IGNORED}
        data, error = stage('state-controls', [test_bins['state'], '--test-threads=1'])
        calibration_output(data, error, manifest)
        data, error = stage('caller-list', [test_bins['caller'], '--list'])
        inventory = modules['census'].census(data, error)
        expected = tuple('normal::caller::tests::'+n for n in modules['normal'].CALLER)
        assert set(n for n in inventory if n.startswith('normal::caller::tests::')) == set(expected)
        data, error = stage('caller-controls', [test_bins['caller'], *expected, '--exact', '--test-threads=1'])
        modules['census'].controls(data, error, expected, inventory)
        for label, source, flags in (
            ('csv', ROOT/'tools/rapid-profiler/normal-work/csv_fields.c', CSV_FLAGS),
            ('caller', ROOT/'tools/rapid-profiler/normal-work/caller.c', modules['normal'].CALLER_FLAGS)):
            trusted = raw/(label+'-trusted.so'); candidate = raw/(label+'-candidate.so')
            data, error = stage(label+'-c-build', [tools['gcc'], *flags, source, '-o', trusted])
            assert data == error == b''
            contents = read(trusted, MIB); assert contents
            retain(artifacts, trusted)
            with candidate.open('xb') as f: f.write(contents)
            assert (candidate.stat().st_dev, candidate.stat().st_ino) != (trusted.stat().st_dev, trusted.stat().st_ino)
            retain(artifacts, candidate)
            assert artifacts[str(candidate)] == artifacts[str(trusted)]
        data, error = stage('csv-symbols', [tools['readelf'], '--wide', '--syms', raw/'csv-trusted.so'])
        assert error == b''; va, extent = selection(data)
        _, error = stage('csv-disassembly', [tools['objdump'], '-d', '-M', 'intel', '--disassemble=csv_fields', raw/'csv-trusted.so'])
        assert error == b''
        _, error = stage('caller-disassembly', [tools['objdump'], '-d', '-M', 'intel', '--disassemble=normal_caller', raw/'caller-trusted.so'])
        assert error == b''
        save(raw/'selection.json', dict(symbol='csv_fields', elf_va=va, length=extent, label='normal-csv-fields-v1',
             candidate=artifacts[str(raw/'csv-candidate.so')], final=artifacts[str(raw/'csv-trusted.so')],
             caller_candidate=artifacts[str(raw/'caller-candidate.so')], caller_final=artifacts[str(raw/'caller-trusted.so')]))
        retain(artifacts, raw/'selection.json')
        unchanged()
        request = dict(argv=[str(test_bins['native']), 'normal-csv-state', str(raw/'csv-candidate.so'), str(raw/'csv-trusted.so'),
            str(va), str(extent), str(raw/'caller-candidate.so'), str(raw/'caller-trusted.so'), str(raw/'native-output')],
            cwd=str(ROOT), env=env, stdout=str(raw/'stdout.txt'), stderr=str(raw/'stderr.txt'), pins=before | tool_pins | artifacts)
        request_shape(request); save(raw/'request.json', request)
        request_pin = retain(artifacts, raw/'request.json')
        argv = [str(tools['python']), '-B', str(HERE/'reproduce.py'), '--native-request', str(raw/'request.json'), request_pin['sha256']]
        save(raw/'native-command.json', dict(argv=argv, env=env, wall_seconds=510, log_bytes=MIB,
             cpu_seconds_per_process=480, file_bytes=MIB, core_bytes=0, pair_seconds=15, steps_per_child=20000))
        retain(artifacts, raw/'native-command.json')
        safe = False
        def invoke():
            save(raw/'native-attempt.json', result['native'])
            retain(artifacts, raw/'native-attempt.json')
            return owner.run_command(argv, env, logs/'native.log', 510, MIB)
        closed = once(result['native'], invoke)
        save(raw/'native-closed.json', closed)
        retain(artifacts, raw/'native-closed.json')
        safe = closed['cleanup_complete'] is True
        if safe:
            native_log = read(logs/'native.log', MIB)
            with (raw/'native-parent.log').open('xb') as f: f.write(native_log)
            assert hashlib.sha256(native_log).hexdigest() == closed['private_log_sha256']
            expected_log = dict(bytes=len(native_log), sha256=closed['private_log_sha256'])
            retain(artifacts, logs/'native.log', expected_log)
            retain(artifacts, raw/'native-parent.log', expected_log)
            # Partial failed outputs get their first pin only after cleanup.
            for name in ('stdout.txt', 'stderr.txt', 'native-output/normal-csv-pairs.csv',
                         'native-output/normal-csv-coverage.csv'):
                p = raw/name
                if p.exists(): retain(artifacts, p, limit=MIB)
        closed_ok(closed)
        assert native_log == b''
        assert digest(logs/'native.log')['sha256'] == closed['private_log_sha256']
        unchanged(); assert digest(raw/'request.json') == request_pin
        files = (raw/'native-output'/'normal-csv-pairs.csv', raw/'native-output'/'normal-csv-coverage.csv')
        assert set(p.name for p in (raw/'native-output').iterdir()) == {p.name for p in files}
        parsed = modules['csv'].check(read(files[0], 32768), read(files[1], 1024),
                    read(raw/'stdout.txt', 1024), read(raw/'stderr.txt', MIB), extent)
        for p, data in ((files[0], parsed['pairs_table']), (files[1], parsed['coverage_table']),
                        (raw/'stdout.txt', parsed['terminal']), (raw/'stderr.txt', b'')):
            retain(artifacts, p, dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
        result['native'].update(status='NATIVE_STATE_PASS', comparisons=parsed['comparisons'],
            pairs=32, normal_reaps=64, target_calls=128, target_returns=128, outer_returns=64,
            rows=parsed['rows'], coverage=parsed['coverage'], source_attested=parsed['source_attested'])
        unchanged(); save(raw/'sources-after.json', before)
        result['sources_after'] = retain(artifacts, raw/'sources-after.json')
        result['status'] = 'NATIVE_STATE_PASS'
    except BaseException as error:
        result['error'] = type(error).__name__
        # Never relabel a failed final closure/source check after printed success.
        if result['native']['attempts']:
            result['native']['status'] = 'FAILED'
    finally:
        final_retention(result, artifacts, safe)
        save(raw/'result.json', result)
    print(json.dumps(dict(status=result['status'], attempts=result['native']['attempts'], native_status=result['native']['status'],
          result_sha256=digest(raw/'result.json')['sha256'], scope='CSV native state only; no performance/full-A5 claim'), sort_keys=True))
    return 0 if result['status'] == 'NATIVE_STATE_PASS' else 1


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--native-request':
        try:
            native_exec(Path(sys.argv[2]), sys.argv[3])
        except BaseException as error:
            print('csv-native exec FAILED: '+type(error).__name__, file=sys.stderr, flush=True)
            raise SystemExit(127)
    raise SystemExit(main())
