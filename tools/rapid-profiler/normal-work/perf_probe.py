#!/usr/bin/env python3
"""One fixed perf capability probe. Capture is unqualified until separate decoding review."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import argparse
import datetime
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import tempfile
import traceback

MIB = 1048576
PROTOCOL = 'c0661a1993a2a7e4820f01b0cbfa64ec529aeec7e4c60924a3f1e01c15199226'
CFLAGS = ['-O3', '-std=c11', '-Wall', '-Wextra', '-Werror']
RECORD = ['record', '-e', 'instructions:uDS', '-c', '4096', '-P', '-T',
    '--sample-cpu', '--sample-identifier', '--running-time', '-s', '--inherit',
    '-m', '256', '--no-buildid-cache', '--no-buildid-mmap', '--buildid-all']
DECODE = [('evlist', ['evlist', '-v']), ('script', ['script', '--ns', '--no-itrace',
    '-F', 'pid,tid,time,cpu,event,ip,period,misc', '--show-task-events',
    '--show-mmap-events', '--show-lost-events']), ('raw', ['script', '-D', '--no-itrace'])]
CONTROL_NAMES = ('lowered', 'equal', 'lower-refusal', 'existing', 'symlink',
    'missing-app', 'no-shell', 'overflow', 'missing-arg', 'relative-record',
    'relative-app', 'delimiter', 'token-short', 'token-long', 'token-upper', 'token-nonhex',
    'existing-stdout', 'symlink-stdout', 'existing-stderr', 'symlink-stderr')
STAGES = ('prerequisite', 'build-limit', 'build-control', 'build-timer',
    'limit-parser-controls', 'timer-parser-controls',
    *('limit-'+name for name in CONTROL_NAMES), 'capture', *('decode-'+n for n, _ in DECODE))
SCOPE = ('One capability probe, not a comparison. A completed capture and three bounded '
    'decodes are CAPTURED_UNQUALIFIED. PMU attributes, exec/mapping/sample attribution, '
    'enabled/running accounting, loss, throttle, unknown records and conservation remain '
    'UNREVIEWED. No filtering, scaling, retry, accuracy or full-A5 claim. All prior '
    'strict 2 ms failures remain failures.')


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)+'\n').encode('ascii')


def digest(path):
    value = hashlib.sha256(); count = 0
    with path.open('rb') as stream:
        for part in iter(lambda: stream.read(MIB), b''):
            value.update(part); count += len(part)
    return dict(bytes=count, sha256=value.hexdigest())


def freeze(path, data):
    with path.open('xb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    return digest(path)


def identity(path):
    st = path.lstat()
    return dict(device=st.st_dev, inode=st.st_ino, mode=st.st_mode, uid=st.st_uid,
        links=st.st_nlink, bytes=st.st_size, mtime_ns=st.st_mtime_ns, ctime_ns=st.st_ctime_ns)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def closure(closed, expected):
    assert type(closed['exit_code']) is int and closed['exit_code'] == expected
    assert closed['termination'] is None and closed['cleanup_complete'] is True
    assert type(closed['reaped_descendants']) is int and closed['reaped_descendants'] == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'):
        parser.add_argument('--'+name, type=Path, required=True)
    a = parser.parse_args()
    repo = Path(__file__).resolve().parents[3]
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    for path in (repo, a.toolchain, a.user_home, a.cargo_home):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
    assert a.raw.is_absolute() and a.raw.is_relative_to(repo/'ignored') and not a.raw.exists()
    assert a.raw.parent.resolve(strict=True) == a.raw.parent
    env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home),
        PATH=str(a.toolchain/'bin')+':/usr/bin:/bin', RUSTC=str(a.toolchain/'bin/rustc'),
        CC=str(Path('/usr/bin/gcc').resolve(strict=True)), CARGO_TARGET_DIR=str(repo/'target'),
        CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true',
        CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0',
        CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        CARGO_TERM_COLOR='never', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    def git(*args):
        data = subprocess.check_output(['/usr/bin/git', '-C', str(repo), *args], env=env, timeout=15)
        assert len(data) <= 4*MIB
        return data
    assert git('rev-parse', '--show-toplevel').decode().strip() == str(repo)
    assert git('rev-parse', 'HEAD').decode().strip() == a.revision
    assert git('status', '--porcelain', '--untracked-files=no') == b''
    required = {'evaluation/admission/processes.py', 'tools/unwind-oracle/bounded_command.py',
        'tools/rapid-profiler/verify_normal_interval.py', 'tools/rapid-profiler/normal-work/perf_probe.py',
        'tests/call_tree_truth.rs'}
    required.update('tools/rapid-profiler/tree-work/'+name for name in (
        'limit_exec.c', 'limit_exec_control.c', 'process_timer.c', 'process_timing.py',
        'test_process_timing.py', 'comparison_runner.py', 'limit_record.py', 'test_limit_record.py'))
    required.update('tools/rapid-profiler/normal-work/'+name for name in (
        'observer_work.py', 'exact_fixture.py', 'caller.c', 'caller.rs', 'caller_bytes.rs'))
    required.update(('tools/rapid-profiler/exact-work/exact_work.S',
        'tools/rapid-profiler/selected-work/provenance.py'))
    names = git('ls-files', '-z', '--', 'src', 'tests/support', 'tools/rapid-profiler',
        'Cargo.toml', 'Cargo.lock', 'README.md', 'build.rs', ':(glob)**/Cargo.toml', *sorted(required)).decode().rstrip('\0').split('\0')
    assert all(names) and len(names) == len(set(names)) and required.issubset(names)
    before = {name: digest(repo/name) for name in names}
    assert all((repo/name).read_bytes() == git('show', a.revision+':'+name) for name in names)
    tools = {name: path.resolve(strict=True) for name, path in (
        ('python', Path(sys.executable)), ('gcc', Path('/usr/bin/gcc')),
        ('perf', Path('/usr/bin/perf')), ('git', Path('/usr/bin/git')),
        ('cargo', a.toolchain/'bin/cargo'), ('rustc', a.toolchain/'bin/rustc'))}
    tool_pins = {name: digest(path) for name, path in tools.items()}
    # Source and executable hashes precede every project import and execution.
    processes = load('perf_probe_processes', repo/'evaluation/admission/processes.py')
    prior = load('perf_probe_prior', repo/'tools/rapid-profiler/verify_normal_interval.py')
    a.raw.mkdir(mode=0o700)
    logs_root = repo/'target/evaluation'; logs_root.mkdir(parents=True, exist_ok=True)
    assert logs_root.resolve(strict=True) == logs_root
    logs = Path(tempfile.mkdtemp(prefix='perf-probe-', dir=logs_root))
    frozen_identities = {}
    pins = {repo/name: value for name, value in before.items()}
    pins.update({path: tool_pins[name] for name, path in tools.items()})
    def retain(path, expected=None):
        value = digest(path)
        if expected is not None: assert value == expected
        if path in pins: assert value == pins[path]
        pins[path] = value
        return value
    source_manifest = freeze(a.raw/'sources-before.json', encoded(before))
    retain(a.raw/'sources-before.json', source_manifest)
    result = dict(schema=1, status='FAILED', revision=a.revision, protocol_sha256=PROTOCOL,
        scope=SCOPE, stage='setup', stages=[dict(name=n, status='UNRUN') for n in STAGES],
        sources=dict(count=len(before), manifest=source_manifest),
        tools={n: dict(path=str(p), **tool_pins[n]) for n, p in tools.items()},
        capability=dict(status='UNREVIEWED', decoded_record_limit=100000,
            record_size_min=8, record_size_max=65535,
            scope='These are subsequent decoder obligations, not inferred from text or exit zero.'))
    def save():
        temporary = a.raw/'result.tmp'
        temporary.write_bytes(encoded(result)); temporary.replace(a.raw/'result.json')
    cpus = sorted(os.sched_getaffinity(0))
    def unchanged():
        assert git('rev-parse', 'HEAD').decode().strip() == a.revision
        assert git('status', '--porcelain', '--untracked-files=no') == b''
        assert sorted(os.sched_getaffinity(0)) == cpus
        assert all(digest(path) == expected for path, expected in pins.items())
        assert all(identity(path) == expected for path, expected in frozen_identities.items())
    def active(name):
        index = STAGES.index(name); row = result['stages'][index]
        assert row['status'] == 'UNRUN' and all(r['status'] == 'PASS' for r in result['stages'][:index])
        result['stage'] = name; row['status'] = 'FAILED'; save()
        return row
    def done(row, **values):
        unchanged(); row.update(values, status='PASS'); save()
    def observation():
        return dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            affinity=sorted(os.sched_getaffinity(0)), load_average=list(os.getloadavg()))
    def run(name, argv, cap=MIB, expected=0, environment=None):
        unchanged(); row = active(name)
        directory = a.raw/name; directory.mkdir(exist_ok=True); (directory/'tmp').mkdir()
        request = dict(argv=[str(x) for x in argv], cwd=str(repo),
            env=dict(environment or env, TMPDIR=str(directory/'tmp')),
            stdout=str(directory/'stdout.txt'), stderr=str(directory/'stderr.txt'),
            cpu_seconds=20, wall_seconds=30, file_bytes=cap)
        freeze(directory/'request.json', encoded(request)); retain(directory/'request.json')
        helper = repo/'tools/unwind-oracle/bounded_command.py'
        parent = [str(tools['python']), '-B', str(helper), '--request', str(directory/'request.json'),
            '--receipt', str(directory/'receipt.json')]
        freeze(directory/'command.json', encoded(dict(argv=parent, env=env,
            wall_seconds=55, log_bytes=MIB, request=retain(directory/'request.json'))))
        retain(directory/'command.json')
        row.update(command=request['argv'], cpu_seconds=20, wall_seconds=30, file_bytes=cap,
            before=observation()); save()
        closed = processes.run_command(parent, env, logs/(name+'.log'), 55, MIB)
        freeze(directory/'parent-closed.json', encoded(closed))
        parent_log = (logs/(name+'.log')).read_bytes()
        freeze(directory/'parent.log', parent_log)
        row['after'] = observation(); row['actual_parent_exit'] = closed['exit_code']
        row['outer_owner_closed'] = closed['cleanup_complete'] is True and closed['termination'] is None and closed['reaped_descendants'] == 0
        row['files'] = {p.name: retain(p) for p in (directory/n for n in
            ('command.json', 'request.json', 'parent-closed.json', 'parent.log',
             'receipt.json', 'stdout.txt', 'stderr.txt')) if p.exists()}
        save()  # Keep actual failure, truncation and absent receipts before validation.
        assert row['files']['parent.log']['sha256'] == closed['private_log_sha256']
        closure(closed, 0 if expected == 0 else 1)
        assert json.loads((directory/'request.json').read_bytes()) == request
        receipt = json.loads((directory/'receipt.json').read_bytes())
        assert type(receipt['exit']) is int and receipt['exit'] == expected
        assert receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
        assert receipt['absence_proof'] == 'ECHILD'
        assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
        assert receipt['cleanup_error'] is receipt['aborted'] is None
        assert receipt['request_sha256'] == pins[directory/'request.json']['sha256']
        assert receipt['helper_sha256'] == before['tools/unwind-oracle/bounded_command.py']['sha256']
        assert json.loads(parent_log) == dict(exit=expected, wall_timeout=False,
            absence_proof='ECHILD', descendants=0, success=expected == 0)
        for stream in ('stdout', 'stderr'):
            assert receipt[stream+'_sha256'] == row['files'][stream+'.txt']['sha256']
            assert row['files'][stream+'.txt']['bytes'] <= cap
        row['actual_exit'] = expected; row['owner_closed'] = True
        unchanged()
        return directory, row
    try:
        assert len(cpus) == 4
        result['reservation'] = dict(affinity=cpus, application_cpu=cpus[0],
            authority='Fresh four-CPU reservation and hard AllowedCPUs are outer-owner authority; affinity alone is not reservation or host isolation.')
        result['before'] = observation(); save()
        row = active('prerequisite'); qualified = a.raw/'qualification'
        argv = [str(tools['python']), '-B', str(repo/'tools/rapid-profiler/verify_normal_interval.py'),
            '--revision', a.revision, '--raw', str(qualified), '--toolchain', str(a.toolchain),
            '--user-home', str(a.user_home), '--cargo-home', str(a.cargo_home),
            '--reference-exact', '--reference-work', '--reference-leg', '--observer-work']
        freeze(a.raw/'prerequisite-command.json', encoded(dict(argv=argv, env=env,
            wall_seconds=1200, log_bytes=8*MIB, affinity=cpus)))
        retain(a.raw/'prerequisite-command.json')
        closed = processes.run_command(argv, env, logs/'prerequisite.log', 1200, 8*MIB)
        freeze(a.raw/'prerequisite-closed.json', encoded(closed))
        freeze(a.raw/'prerequisite.log', (logs/'prerequisite.log').read_bytes())
        row['files'] = {n: retain(a.raw/n) for n in ('prerequisite-command.json',
            'prerequisite-closed.json', 'prerequisite.log')}
        if (qualified/'result.json').exists(): row['result'] = retain(qualified/'result.json')
        row['actual_exit'] = closed['exit_code']
        row['outer_owner_closed'] = closed['cleanup_complete'] is True and closed['termination'] is None and closed['reaped_descendants'] == 0
        save(); closure(closed, 0)
        assert row['files']['prerequisite.log']['sha256'] == closed['private_log_sha256']
        old = json.loads((qualified/'result.json').read_bytes())
        assert old['revision'] == a.revision and old['status'] == 'PASS' and old['stage'] == 'complete'
        expected_stages = (prior.STAGES + prior.REFERENCE_STAGES + prior.REFERENCE_WORK_STAGES
            + prior.REFERENCE_LEG_STAGES + prior.OBSERVER_WORK_STAGES)
        assert len(expected_stages) == 34 and tuple(r['name'] for r in old['stages']) == expected_stages
        assert all(r['status'] == 'PASS' for r in old['stages'])
        assert old['closure'] == dict(owned_stages=34, nested_normal_helpers=46, nested_outer_owners=48, rescues=0)
        for name, count in (('reference_exact', 13), ('reference_work', 3), ('reference_leg', 4), ('observer_work', 4)):
            group = old[name]
            assert group['status'] == 'PASS' and len(group['stages']) == count
            assert all(r['status'] == 'PASS' for r in group['stages'])
            assert group['closure'] == dict(owned_stages=count, normal_helpers=count, outer_owners=count, rescues=0)
        source_before = json.loads((qualified/'sources-before.json').read_bytes())
        assert source_before == json.loads((qualified/'sources-after.json').read_bytes())
        assert all(before[name] == value for name, value in source_before.items())
        assert old['sources'] == dict(count=len(source_before), manifest=retain(qualified/'sources-before.json'))
        retain(qualified/'sources-after.json')
        private_path = qualified/'strnlen-prerequisite/private-environment.json'
        retain(private_path)
        private = json.loads(private_path.read_bytes())
        assert private['env'] == env and private['affinity'] == cpus
        for name, path in private['tools'].items():
            path = Path(path); assert path.resolve(strict=True) == path
            retain(path, old['tools'][name])
            if name in tools: assert path == tools[name]
        for cohort_name in ('old_exact', 'reference'):
            assert old['reference_exact'][cohort_name]['status'] == 'PASS'
        assert old['reference_work']['collector']['status'] == 'PASS'
        assert [(c['phase'], c['trial'], c['leg'], c['calls'], c['status'])
            for c in old['reference_leg']['legs']] == [
                ('qualification', 1, 'original', 24, 'PASS'), ('qualification', 1, 'installed', 24, 'PASS')]
        assert old['native']['pairs'] == 17 and old['native']['children'] == 34
        result['prerequisite'] = dict(result=row['result'], closure=old['closure'],
            tools=old['tools'], versions=old['versions'], hardware=old['hardware'])
        binary = repo/'target/release/ordinary-interval'
        retain(binary, old['artifacts']['ordinary-interval'])
        subject, trusted = qualified/'reference-exact-candidate.so', qualified/'reference-exact-final.so'
        selection = qualified/'reference-exact-selection.json'
        candidate, caller = qualified/'caller-candidate.so', qualified/'caller.so'
        cohort = old['observer_work']['modes']
        assert [(c['mode'], c['status']) for c in cohort] == [('native', 'PASS'), ('always-on', 'PASS')]
        authority = cohort[0]
        for p, field in ((binary, 'binary'), (trusted, 'subject'), (selection, 'selection'),
                (candidate, 'helper_candidate'), (caller, 'helper')):
            retain(p, authority[field])
        retain(subject, old['reference_exact']['subject']['candidate'])
        for c in cohort:
            assert c['calls'] == c['observation']['calls'] == 3072
            assert c['observation']['helper_calls'] == 1536 and c['observation']['instructions'] == 614400
            assert all(c[k] == authority[k] for k in ('binary', 'subject', 'selection', 'helper', 'helper_candidate'))
            assert (c['process_cpu_seconds'], c['process_wall_seconds'], c['file_bytes']) == (20, 30, MIB)
        assert candidate.read_bytes() == caller.read_bytes()
        assert (candidate.stat().st_dev, candidate.stat().st_ino) != (caller.stat().st_dev, caller.stat().st_ino)
        assert pins[caller] == old['artifacts']['caller']
        # The fresh recipe authenticates the release Cargo profile and the 67-byte
        # owner; these hashes are from that exact revision, never a cache guess.
        fixture = load('perf_probe_fixture', repo/'tools/rapid-profiler/normal-work/exact_fixture.py')
        observed = load('perf_probe_observer', repo/'tools/rapid-profiler/normal-work/observer_work.py')
        timing = load('perf_probe_timing', repo/'tools/rapid-profiler/tree-work/process_timing.py')
        limits = load('perf_probe_limits', repo/'tools/rapid-profiler/tree-work/limit_record.py')
        unchanged()
        details = json.loads(selection.read_bytes())
        assert details['revision'] == a.revision
        selected = fixture.authenticate(subject, trusted, details['elf_va'], 37,
            selection, pins[selection]['sha256'])
        assert selected == {k: v for k, v in details.items() if k != 'revision'}
        result['artifacts'] = {str(p): pins[p] for p in (binary, subject, trusted, selection, candidate, caller)}
        done(row, required_stages=34)

        tree = repo/'tools/rapid-profiler/tree-work'
        limiter, control, timer = (a.raw/n for n in ('limit-exec', 'limit-control', 'process-timer'))
        for name, source, target in (('limit', 'limit_exec.c', limiter),
                ('control', 'limit_exec_control.c', control), ('timer', 'process_timer.c', timer)):
            d, row = run('build-'+name, [tools['gcc'], *CFLAGS, tree/source, '-o', target])
            assert (d/'stdout.txt').read_bytes() == (d/'stderr.txt').read_bytes() == b''
            artifact = retain(target); assert 0 < artifact['bytes'] <= MIB
            assert target.resolve(strict=True) == target and stat.S_ISREG(target.stat().st_mode)
            with target.open('rb') as stream: assert stream.read(4) == b'\x7fELF'
            done(row, artifact=artifact)
        for name, script, count in (('limit-parser-controls', 'test_limit_record.py', 7),
                ('timer-parser-controls', 'test_process_timing.py', 5)):
            d, row = run(name, [tools['python'], '-B', tree/script])
            assert (d/'stdout.txt').read_bytes() == b''
            assert re.fullmatch(rb'\.{'+str(count).encode()+rb'}\n-+\nRan '+str(count).encode()+
                rb' tests in [0-9]+\.[0-9]+s\n\nOK\n', (d/'stderr.txt').read_bytes())
            done(row, controls=count)
        def wrap(record, argv):
            return [str(timer), str(record), timing.token(argv), '--', *argv]
        def owned_file(path, bound, empty=False):
            st = path.lstat()
            assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600
            assert st.st_uid == os.geteuid() and st.st_nlink == 1 and 0 <= st.st_size <= bound
            if empty: assert st.st_size == 0
            return dict(content=retain(path), identity=identity(path))
        def setup(record, app, pid):
            info = owned_file(record, 511)
            assert record.stat().st_size > 0
            value = limits.check(record.read_bytes(), app, pid)
            value['record_file'] = info
            return value
        def distinct_files(paths):
            assert len({(p.stat().st_dev, p.stat().st_ino) for p in paths}) == len(paths)
        inherited = {n: list(resource.getrlimit(k)) for n, k in
            (('nofile', resource.RLIMIT_NOFILE), ('stack', resource.RLIMIT_STACK))}
        assert sys.maxsize == (1 << 63)-1
        assert all(type(v) is int and (v == resource.RLIM_INFINITY or 0 <= v < 1 << 64)
            for pair in inherited.values() for v in pair)
        result['inherited_limits'] = dict(cpu=[20, 20], core=[0, 0], **inherited)
        plans = []
        for name in CONTROL_NAMES:
            d = a.raw/('limit-'+name); d.mkdir()
            record = d/'limit.txt'; app = [str(control), 'probe']
            cap = MIB if name == 'equal' else MIB//2 if name == 'lower-refusal' else 16*MIB
            if name == 'lowered': app += ['', 'é\n雪']
            if name == 'missing-app': app = [str(d/'absent-application')]
            if name == 'no-shell':
                shell_text = d/'not-an-executable'; freeze(shell_text, b'echo forbidden-shell-fallback\n')
                shell_text.chmod(0o700); retain(shell_text); app = [str(shell_text)]
            if name == 'overflow': app = [str(control), 'overflow']
            seeded = record if name in ('existing', 'symlink') else d/('app-stderr.txt' if name.endswith('-stderr') else 'app-stdout.txt')
            if name in ('existing', 'symlink', 'existing-stdout', 'symlink-stdout', 'existing-stderr', 'symlink-stderr'):
                target = d/'target' if name.startswith('symlink') else seeded
                freeze(target, b'preexisting record\n'); target.chmod(0o600); retain(target)
                if name.startswith('symlink'): seeded.symlink_to(target)
                frozen_identities[target] = identity(target)
                frozen_identities[seeded] = identity(seeded)
            argv = [str(limiter), str(record), timing.token(app),
                str(d/'app-stdout.txt'), str(d/'app-stderr.txt'), '--', *app]
            if name == 'missing-arg': argv = argv[:6]
            if name == 'relative-record': argv[1] = 'relative-record'
            if name == 'relative-app': argv[6] = 'relative-app'
            if name == 'delimiter': argv[5] = '-'
            if name == 'token-short': argv[2] = 'a'*63
            if name == 'token-long': argv[2] = 'a'*65
            if name == 'token-upper': argv[2] = 'A'*64
            if name == 'token-nonhex': argv[2] = 'g'*64
            plans.append(dict(name=name, app=app, limiter=argv, cap=cap,
                argv=wrap(d/'timing.txt', argv), expected_timer=0 if name in ('lowered', 'equal') else 1))
        freeze(a.raw/'limiter-plan.json', encoded(dict(children=plans,
            seeded_identities={str(p): value for p, value in frozen_identities.items()})))
        retain(a.raw/'limiter-plan.json')
        for plan in plans:
            name, app, argv = plan['name'], plan['app'], plan['limiter']
            d, row = run('limit-'+name, plan['argv'], plan['cap'], plan['expected_timer'])
            measured = timing.parse((d/'timing.txt').read_bytes(), argv); retain(d/'timing.txt')
            assert measured['exec_errno'] == measured['core'] == 0
            assert measured['process_wall_ns'] <= 30_000_000_000
            assert (d/'stdout.txt').read_bytes() == (d/'stderr.txt').read_bytes() == b''
            record = d/'limit.txt'
            app_out, app_err = d/'app-stdout.txt', d/'app-stderr.txt'
            output = error = None
            if name in ('lowered', 'equal', 'missing-app', 'no-shell', 'overflow'):
                row['setup'] = setup(record, app, measured['child_pid'])
                row['app_streams'] = dict(stdout=owned_file(app_out, MIB), stderr=owned_file(app_err, MIB))
                distinct_files((record, app_out, app_err))
                output, error = app_out.read_bytes(), app_err.read_bytes()
            if name in ('lowered', 'equal'):
                timing.successful(measured); assert error == b''
                expected = dict(pid=measured['child_pid'], ppid=measured['timer_pid'], argc=len(app),
                    fsize_soft=MIB, fsize_hard=MIB, cpu_soft=20, cpu_hard=20, core_soft=0, core_hard=0)
                for key, pair in inherited.items():
                    assert list(resource.getrlimit(getattr(resource, 'RLIMIT_'+key.upper()))) == pair
                    for suffix, value in zip(('soft', 'hard'), pair):
                        expected[key+'_'+suffix] = (1 << 64)-1 if value == resource.RLIM_INFINITY else value
                assert output == ('limit-exec-control-v1 '+' '.join(f'{k}={v}' for k, v in expected.items())+'\n').encode('ascii')
                outcome = 'EXPECTED_SUCCESS_OBSERVED'
            elif name in ('missing-app', 'no-shell'):
                assert (measured['exit'], measured['signal']) == (127, 0) and output == b''
                expected_errno = errno.ENOENT if name == 'missing-app' else errno.ENOEXEC
                assert error == f'limit-exec: execv failed errno={expected_errno}\n'.encode('ascii')
                outcome = 'EXPECTED_EXEC_REFUSAL_OBSERVED'
            elif name == 'overflow':
                assert (measured['exit'], measured['signal'], measured['wait_status']) == (-1, signal.SIGXFSZ, signal.SIGXFSZ)
                assert output == b'x'*MIB and error == b''
                outcome = 'EXPECTED_SIGNAL_OBSERVED'
            else:
                assert (measured['exit'], measured['signal']) == (2, 0)
                seeded = record if name in ('existing', 'symlink') else app_err if name.endswith('-stderr') else app_out
                if name.startswith(('existing', 'symlink')):
                    target = d/'target' if name.startswith('symlink') else seeded
                    assert target.read_bytes() == b'preexisting record\n' and stat.S_IMODE(target.stat().st_mode) == 0o600
                    if name.startswith('symlink'):
                        assert seeded.is_symlink() and os.readlink(seeded) == str(target)
                    if name.endswith(('-stdout', '-stderr')): owned_file(record, 511, empty=True)
                    if name.endswith('-stderr'): owned_file(app_out, MIB, empty=True)
                    else: assert not app_err.exists() and not app_err.is_symlink()
                    if name in ('existing', 'symlink'): assert not app_out.exists() and not app_out.is_symlink()
                else:
                    assert all(not p.exists() and not p.is_symlink() for p in (record, app_out, app_err))
                outcome = 'EXPECTED_SETUP_REFUSAL_OBSERVED'
            done(row, outcome=outcome, timing=measured)

        isolated = a.raw/'perf-isolated'; isolated.mkdir()
        for name in ('home', 'config', 'cache', 'build-id'): (isolated/name).mkdir()
        config = isolated/'perf.config'; freeze(config, b''); retain(config)
        perf_env = dict(env, HOME=str(isolated/'home'), XDG_CONFIG_HOME=str(isolated/'config'),
            XDG_CACHE_HOME=str(isolated/'cache'), PERF_CONFIG=str(config),
            PERF_CONFIG_NOSYSTEM='1', PERF_CONFIG_NOGLOBAL='1',
            PERF_BUILDID_DIR=str(isolated/'build-id'), PERF_PAGER='cat', PAGER='cat')
        capture = a.raw/'capture'; capture.mkdir()
        data = capture/'perf.data'; outer_record = capture/'outer-timing.txt'
        inner_record = capture/'app-timing.txt'; limit_record = capture/'limit.txt'
        app = [str(binary), 'normal-observer-work', 'native', str(subject), str(trusted),
            str(details['elf_va']), '37', str(candidate), str(caller)]
        app_stdout, app_stderr = capture/'app-stdout.txt', capture/'app-stderr.txt'
        limit_argv = [str(limiter), str(limit_record), timing.token(app),
            str(app_stdout), str(app_stderr), '--', *app]
        perf_argv = [str(tools['perf']), *RECORD, '-o', str(data), '--', *wrap(inner_record, limit_argv)]
        capture_argv = wrap(outer_record, perf_argv)
        decode_argv = [[str(tools['perf']), *args, '-i', str(data)] for _, args in DECODE]
        freeze(a.raw/'capture-plan.json', encoded(dict(protocol_sha256=PROTOCOL,
            app=app, limiter=limit_argv, inner_timer=wrap(inner_record, limit_argv),
            perf=perf_argv, outer_timer=capture_argv, decode=decode_argv, env=perf_env,
            capture=dict(cpu_seconds=20, wall_seconds=30, file_bytes=16*MIB),
            decode_limits=dict(cpu_seconds=20, wall_seconds=30, file_bytes=64*MIB))))
        retain(a.raw/'capture-plan.json')
        assert fixture.authenticate(subject, trusted, details['elf_va'], 37, selection,
            pins[selection]['sha256']) == selected
        d, row = run('capture', capture_argv, 16*MIB, environment=perf_env)
        outer = timing.successful(timing.parse(outer_record.read_bytes(), perf_argv))
        inner = timing.successful(timing.parse(inner_record.read_bytes(), limit_argv))
        for path in (outer_record, inner_record): retain(path)
        assert len({outer['timer_pid'], outer['child_pid'], inner['timer_pid'], inner['child_pid']}) == 4
        endpoint = lambda r, end: timing.scaled(r['end_sec' if end else 'start_sec'],
            r['end_nsec' if end else 'start_nsec'], 10**9)
        assert endpoint(outer, False) <= endpoint(inner, False) < endpoint(inner, True) <= endpoint(outer, True)
        row['setup'] = setup(limit_record, app, inner['child_pid'])
        app_streams = dict(stdout=owned_file(app_stdout, MIB), stderr=owned_file(app_stderr, MIB))
        distinct_files((limit_record, app_stdout, app_stderr))
        # These are the limiter's actual redirected APP files. Perf and early
        # setup diagnostics remain in the independently retained outer streams.
        functional = observed.check(app_stdout.read_bytes(), app_stderr.read_bytes(), 'native')
        assert functional['pid'] == functional['tid'] == inner['child_pid']
        assert (functional['calls'], functional['helper_calls'], functional['instructions']) == (3072, 1536, 614400)
        assert len(functional['rows']) == 3072
        table = capture/'app-rows.csv'; freeze(table, functional['table']); retain(table)
        data_info = retain(data); assert 0 < data_info['bytes'] <= 16*MIB
        st = data.lstat(); assert stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and st.st_nlink == 1
        residual = outer['child_cpu_us']-inner['child_cpu_us']
        result['capture'] = dict(status='CAPTURED_UNQUALIFIED', data=data_info,
            app={k: v for k, v in functional.items() if k not in ('rows', 'table')},
            app_table=pins[table], app_streams=app_streams, outer_timer=outer, inner_timer=inner,
            accounting=dict(app_cpu_includes_limit_setup=True,
                combined_perf_and_timer_wrapper_cpu_us=residual if residual >= 0 else None,
                residual_status='OBSERVED_NONNEGATIVE' if residual >= 0 else 'UNRESOLVED_NEGATIVE',
                signed_residual_cpu_us=residual, wall_subtraction=False),
            stderr_scope='Actual APP stderr is separately parsed; complete perf, timer and early-limiter diagnostics remain in outer stderr.',
            perf_exec_mapping_identity='UNREVIEWED_PENDING_FINITE_DECODER')
        done(row, data=data_info, app_pid=inner['child_pid'], calls=3072)
        for (label, _), argv in zip(DECODE, decode_argv):
            d, row = run('decode-'+label, argv, 64*MIB, environment=perf_env)
            done(row, decode_status='COMMAND_COMPLETED_UNQUALIFIED')
        unchanged()
        freeze(a.raw/'sources-after.json', encoded({name: digest(repo/name) for name in names}))
        result['sources']['after'] = retain(a.raw/'sources-after.json')
        assert all(row['status'] == 'PASS' for row in result['stages'])
        result.update(status='CAPTURED_UNQUALIFIED', stage='complete', after=observation(),
            closure=dict(probe_owned_stages=29, prerequisite_outer_owners=1,
                prerequisite_owned_stages=34, nested_normal_helpers=46, nested_outer_owners=48, rescues=0))
    except BaseException as error:
        result['error_type'] = type(error).__name__
        freeze(a.raw/'failure.txt', traceback.format_exc().encode('utf-8'))
        result['failure'] = digest(a.raw/'failure.txt')
        # Partial raw data is retained even when a child or decoder failed before
        # a usable timer/setup record. Hash only existing regular known outputs;
        # do not parse partial files or turn their presence into success.
        partial = {}
        for name in CONTROL_NAMES + ('capture',):
            stage_name = 'limit-'+name if name != 'capture' else name
            stage_row = result['stages'][STAGES.index(stage_name)]
            if stage_row.get('owner_closed') is not True: continue
            directory = a.raw/stage_name
            for leaf in ('timing.txt', 'outer-timing.txt', 'app-timing.txt', 'limit.txt',
                    'app-stdout.txt', 'app-stderr.txt', 'perf.data'):
                path = directory/leaf
                if path.exists() and not path.is_symlink() and path.is_file():
                    partial[str(path.relative_to(a.raw))] = digest(path)
        result['closed_partial_files'] = partial
        result['after'] = observation()
    finally:
        save()
    print('perf-probe '+result['status']+' stage='+result['stage'])
    return 0 if result['status'] == 'CAPTURED_UNQUALIFIED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
