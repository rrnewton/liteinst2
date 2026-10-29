#!/usr/bin/env python3
"""Two fixed STOP path controls; prerequisite qualification belongs to the caller."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import argparse
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

MIB = 1048576
SUBJECT = '8a238b77d4cf32c3dcea5aa0fc2a9ec55e58dbc8dc233c7c9d4100e998bd491d'
CASES = (('t1-stop-k10', 'session_driver.py', 1),
         ('t2-stop-k10', 'session_two_driver.py', 2))
NUMBERS = ('arms', 'actions', 'accepted', 'calls', 'sampled', 'admitted',
           'retained', 'dropped', 'unsampled', 'batches', 'flushes', 'detach',
           'detaches', 'joins', 'cancelled', 'unfinished', 'normal_reaps', 'rescues',
           'child_exit', 'input_bytes', 'transcript_bytes')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    data = path.read_bytes()
    return dict(bytes=len(data), sha256=sha(data))


def save(path, value):
    with path.open('w') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('revision', 'binary-sha256', 'manifest-sha256', 'cpus'):
        ap.add_argument('--'+name, required=True)
    for name in ('raw', 'binary', 'candidate', 'final', 'manifest'):
        ap.add_argument('--'+name, type=Path, required=True)
    a = ap.parse_args()
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    assert all(re.fullmatch('[0-9a-f]{64}', s) for s in (a.binary_sha256, a.manifest_sha256))
    assert re.fullmatch('(0|[1-9][0-9]*)(,(0|[1-9][0-9]*)){3}', a.cpus)
    cpus = list(map(int, a.cpus.split(',')))
    assert cpus == sorted(set(cpus)) and sorted(os.sched_getaffinity(0)) == cpus
    repo = Path.cwd().resolve(strict=True)
    script = Path(__file__).resolve(strict=True)
    python = Path(sys.executable).resolve(strict=True)
    git_tool = Path('/usr/bin/git').resolve(strict=True)
    env = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    def git(*args):
        data = subprocess.check_output([str(git_tool), '-C', str(repo), *args], env=env, timeout=15)
        assert len(data) <= 8*MIB
        return data
    assert git('rev-parse', '--show-toplevel').decode().strip() == str(repo)
    assert git('rev-parse', 'HEAD').decode().strip() == a.revision
    assert git('status', '--porcelain', '--untracked-files=no') == b''
    assert a.raw.is_absolute() and a.raw.is_relative_to(repo/'ignored') and not a.raw.exists()
    assert a.raw.parent.resolve(strict=True) == a.raw.parent
    inputs = (a.binary, a.candidate, a.final, a.manifest)
    assert len(set(inputs)) == 4
    for path in inputs:
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_file()
    assert os.access(a.binary, os.X_OK)
    assert digest(a.binary)['sha256'] == a.binary_sha256
    assert digest(a.manifest)['sha256'] == a.manifest_sha256
    required = {'evaluation/admission/processes.py', 'tools/unwind-oracle/bounded_command.py',
                'tools/rapid-profiler/verify_normal_session.py',
                'tools/rapid-profiler/normal-work/session_driver.py',
                'tools/rapid-profiler/normal-work/session_two_driver.py',
                'tools/rapid-profiler/normal-work/check_session_two.py',
                'tools/rapid-profiler/normal-work/exact_fixture.py',
                'tools/rapid-profiler/normal-work/exact_session.py',
                'tools/rapid-profiler/ordinary-interval/joined_task.rs'}
    names = git('ls-files', '-z', '--', 'src', 'tests', 'tools/rapid-profiler',
                'Cargo.toml', 'Cargo.lock', 'README.md', 'build.rs',
                ':(glob)**/Cargo.toml', *sorted(required)).decode().rstrip('\0').split('\0')
    assert all(names) and len(names) == len(set(names)) and required.issubset(names)
    before = {n: digest(repo/n) for n in names}
    for n in names:
        assert (repo/n).read_bytes() == git('show', a.revision+':'+n)
    artifacts = {p: digest(p) for p in (*inputs, script, python, git_tool)}
    identities = {p: (p.stat().st_dev, p.stat().st_ino) for p in inputs}
    assert identities[a.candidate] != identities[a.final]
    # Only authenticated source modules are imported; no project entrypoint runs here.
    shared = load('stop_shared', repo/'tools/rapid-profiler/verify_normal_session.py')
    processes = load('stop_processes', repo/'evaluation/admission/processes.py')
    one = load('stop_one', repo/'tools/rapid-profiler/normal-work/session_driver.py')
    two = load('stop_two_check', repo/'tools/rapid-profiler/normal-work/check_session_two.py')
    selection = shared.read(a.manifest)
    assert selection['revision'] == a.revision and selection['label'] == 'freebsd-strnlen-14.1-v1'
    assert (shared.integer(selection['elf_va']), shared.integer(selection['length'])) == (4096, 41)
    assert digest(a.candidate) == digest(a.final) == selection['final']
    assert digest(a.final)['sha256'] == SUBJECT and digest(a.final)['bytes'] <= 4*MIB
    offset = shared.integer(selection['file_offset'])
    code = a.final.read_bytes()[offset:offset+41]
    assert len(code) == 41 and code[34] == code[40] == 0xc3
    assert dict(bytes=41, sha256=sha(code)) == selection['selected_code']
    a.raw.mkdir(mode=0o700)
    logs_root = repo/'target/evaluation'; logs_root.mkdir(parents=True, exist_ok=True)
    assert logs_root.resolve(strict=True) == logs_root
    logs = Path(tempfile.mkdtemp(prefix='joined-stop-', dir=logs_root))
    result = dict(status='FAILED', revision=a.revision, scope='Two STOP path controls only; no timed-campaign, accuracy or A5 claim.',
        prerequisite='Caller authenticated fresh release profile/build and fixture before launch; this script joins their supplied hashes.',
        binary=digest(a.binary), selection=digest(a.manifest), subject=digest(a.final),
        source_count=len(before), source_sha256=sha((json.dumps(before, sort_keys=True, separators=(',', ':'))+'\n').encode()),
        script=digest(script), tools=dict(python=digest(python), git=digest(git_tool)), cpus=cpus,
        runs=[dict(name=n, status='UNRUN') for n, _, _ in CASES])
    save(a.raw/'result.json', result)
    def pin(path):
        value = digest(path)
        if path in artifacts: assert artifacts[path] == value
        artifacts[path] = value
        return value
    def unchanged():
        assert git('rev-parse', 'HEAD').decode().strip() == a.revision
        assert git('status', '--porcelain', '--untracked-files=no') == b''
        assert {n: digest(repo/n) for n in names} == before
        assert all(digest(p) == h for p, h in artifacts.items())
        assert all((p.stat().st_dev, p.stat().st_ino) == identity for p, identity in identities.items())
        assert sorted(os.sched_getaffinity(0)) == cpus
    expected = [('CALL', 10000+3*i, 64, b'x'*64) for i in range(64)]
    try:
        for row, (name, driver, workers) in zip(result['runs'], CASES):
            unchanged()
            row.update(status='FAILED', custody='UNRESOLVED')
            save(a.raw/'result.json', result)
            d = a.raw/name; d.mkdir(); (d/'tmp').mkdir()
            output = d/'producer'
            argv = [str(python), '-B', str(repo/'tools/rapid-profiler/normal-work'/driver),
                '--binary', str(a.binary), '--candidate', str(a.candidate), '--trusted', str(a.final),
                '--elf-va', '4096', '--length', '41', '--output', str(output), '--k', '10', '--mode', 'stop']
            request = dict(argv=argv, cwd=str(repo), env=dict(env, TMPDIR=str(d/'tmp')),
                stdout=str(d/'stdout.txt'), stderr=str(d/'stderr.txt'), cpu_seconds=20, wall_seconds=30, file_bytes=4*MIB)
            save(d/'request.json', request); pin(d/'request.json')
            parent = [str(python), '-B', str(repo/'tools/unwind-oracle/bounded_command.py'),
                '--request', str(d/'request.json'), '--receipt', str(d/'receipt.json')]
            parent_request = dict(argv=parent, env=env, affinity=cpus, wall_seconds=55, output_bytes=MIB)
            save(d/'parent-command.json', parent_request); pin(d/'parent-command.json')
            closed = processes.run_command(parent, env, logs/(name+'.log'), 55, MIB)
            save(d/'parent-closed.json', closed)
            (d/'parent.log').write_bytes((logs/(name+'.log')).read_bytes())
            row['outer'] = closed
            assert type(closed['exit_code']) is int and closed['exit_code'] in (0, 1)
            assert closed['termination'] is None and closed['cleanup_complete'] is True
            assert type(closed['reaped_descendants']) is int and closed['reaped_descendants'] == 0
            assert closed['private_log_sha256'] == digest(d/'parent.log')['sha256']
            receipt = shared.read(d/'receipt.json')
            assert type(receipt['exit']) is int and receipt['exit'] in (0, 1)
            assert closed['exit_code'] == receipt['exit']
            assert receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
            assert receipt['absence_proof'] == 'ECHILD'
            assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
            assert receipt['cleanup_error'] is receipt['aborted'] is None
            assert receipt['request_sha256'] == digest(d/'request.json')['sha256']
            assert receipt['helper_sha256'] == before['tools/unwind-oracle/bounded_command.py']['sha256']
            assert shared.read(d/'request.json') == request and shared.read(d/'parent-command.json') == parent_request
            assert shared.read(d/'parent.log') == dict(exit=receipt['exit'], wall_timeout=False,
                absence_proof='ECHILD', descendants=0, success=(receipt['exit'] == 0))
            for stream in ('stdout', 'stderr'):
                assert receipt[stream+'_sha256'] == digest(d/(stream+'.txt'))['sha256']
            summary = shared.read(output/'result.json')
            assert shared.decode((d/'stdout.txt').read_bytes()) == summary
            assert summary['mode'] == 'stop' and summary['k'] == 10
            assert summary['rescue'] is False and type(summary['child_exit']) is int
            row['custody'] = 'NORMAL_CLOSED'
            row['files'] = {str(p.relative_to(d)): pin(p) for p in (
                d/'request.json', d/'parent-command.json', d/'receipt.json', d/'parent-closed.json',
                d/'parent.log', d/'stdout.txt', d/'stderr.txt', output/'result.json', output/'stdout.txt', output/'stderr.txt')}
            unchanged()
            if receipt['exit'] == 1:
                assert summary['status'] == 'FAILED'
                row.update(failure=('PRODUCER_NATIVE_SIGNAL' if summary['child_exit'] < 0
                                    else 'PRODUCER_FUNCTIONAL_FAILURE'), child_exit=summary['child_exit'])
            else:
                try:
                    assert summary['status'] == 'PASS' and summary['child_exit'] == 0
                    assert (d/'stderr.txt').read_bytes() == (output/'stderr.txt').read_bytes() == b''
                    raw = (output/'stdout.txt').read_bytes()
                    assert digest(output/'stdout.txt') == dict(bytes=shared.integer(summary['transcript_bytes'], 1, 4*MIB), sha256=summary['transcript_sha256'])
                    parsed = (one if workers == 1 else two).check(raw.decode('ascii'), expected, 10, 520, 'Requested')
                    assert all(summary[key] == value for key, value in parsed.items())
                    assert shared.integer(summary['normal_reaps']) == 1 and shared.integer(summary['rescues']) == 0
                    assert shared.integer(summary['input_bytes'], 1) > 0
                    assert summary['calls'] == summary['accepted'] == 64 and summary['flushes'] == 0
                    assert summary['joins'] == workers and summary['stop_reason'] == 'Requested'
                    assert summary['actions'] == summary['arms']+1 and 1 <= summary['arms'] <= 520
                    assert 1 <= summary['maximum_batch_calls'] <= 4
                    assert 1 <= summary['batches'] <= 64 <= 4*summary['batches']
                    if workers == 1:
                        assert summary['detach'] == 1 and summary['sampled']+summary['unsampled'] == 64
                    else:
                        assert summary['absence'] == 'ECHILD' and summary['detaches'] == 2
                        assert summary['cancelled'] == summary['unfinished'] == 0
                        assert summary['admitted'] == summary['retained']+summary['dropped']
                        assert summary['admitted']+summary['unsampled'] == 64
                        assert [w['worker'] for w in summary['workers']] == [1, 2]
                        assert [w['calls'] for w in summary['workers']] == [32, 32]
                    row.update(status='PASS', numbers={k: shared.integer(summary[k]) for k in NUMBERS if k in summary})
                except (AssertionError, KeyError, ValueError, UnicodeError) as error:
                    row.update(failure='OUTPUT_VALIDATION_FAILURE', error_type=type(error).__name__)
            save(a.raw/'result.json', result)
        unchanged()
        result['status'] = 'PASS' if all(r['status'] == 'PASS' for r in result['runs']) else 'FAILED'
    except BaseException as error:
        result.update(status='FAILED', withheld=True, error_type=type(error).__name__)
    finally:
        save(a.raw/'result.json', result)
        with (a.raw/'stops.csv').open('x', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=('case', 'status', *NUMBERS), lineterminator='\n')
            writer.writeheader()
            for row in result['runs']:
                writer.writerow(dict(case=row['name'], status=row['status'], **row.get('numbers', {})))
    print(json.dumps(dict(status=result['status'], runs=[dict(name=r['name'], status=r['status']) for r in result['runs']])))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
