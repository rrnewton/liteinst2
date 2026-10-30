#!/usr/bin/env python3
"""Fixed caller-admitted preemption profiles (legacy five, inline six); never builds."""
import argparse
import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import stat
import statistics
import struct
import subprocess
import sys
import time

MIB = 1048576
HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
CASES = ('countdown-jnz', 'signed-jg', 'unsigned-jb', 'direct-jmp')
MODES = ('native', 'counter-only', 'before-taken-backedge-stop-resume')
PROFILES = ('full-callback-v1', 'inline-clock-v1', 'inline-clock-spsc-v1', 'inline-clock-spsc-fatal-v1')
INLINE_AUTHORITIES = {
    'inline-clock-v1': 'ROOT_REVIEWED_INLINE_CLOCK_RELEASE_BINARY',
    'inline-clock-spsc-v1': 'ROOT_REVIEWED_INLINE_CLOCK_SPSC_RELEASE_BINARY',
    'inline-clock-spsc-fatal-v1': 'ROOT_REVIEWED_INLINE_CLOCK_SPSC_FATAL_RELEASE_BINARY',
}
FAULTS = ('wrong-site', 'wrong-count', 'no-reply')
BUILD_ENV = dict(CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4',
    CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0',
    CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def six(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read(p, cap=128*MIB):
    p = Path(p)
    assert p.is_absolute() and '..' not in p.parts and p.parent.resolve(strict=True) == p.parent
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        a = os.fstat(f.fileno())
        assert stat.S_ISREG(a.st_mode) and 0 <= a.st_size <= cap
        data = f.read(a.st_size + 1)
        assert six(a) == six(os.fstat(f.fileno())) == six(p.lstat()) and len(data) == a.st_size
    return data, dict(sha256=sha(data), bytes=len(data), stat=six(a))


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def save(root, name, value):
    data = encoded(value)
    assert len(data) <= 16*MIB
    with (root/name).open('xb') as f:
        f.write(data)


def require_refusal_witness(fault, data):
    # Independently specified callback outcome, not a controller intent marker.
    # Exact bytes reject truncated/trailing output and any changed parked fact.
    outcomes = {'wrong-site': (1, 1, 28, 1), 'wrong-count': (1, 1, 27, 2),
                'no-reply': (2, 0, 0, 0)}
    assert fault in outcomes
    cause, present, actual_site, actual_count = outcomes[fault]
    expected = b'LI2SPSC1' + struct.pack('<12Q', cause, 27, 1, 1, 0, 1,
        present, actual_site, actual_count, 2, 1, 1)
    assert data == expected, 'actual callback rejection cause and parked state'


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binding', type=Path, required=True)
    ap.add_argument('--binding-sha256', required=True)
    ap.add_argument('--raw', type=Path, required=True)
    ap.add_argument('--profile', choices=PROFILES, default='full-callback-v1')
    a = ap.parse_args()
    original, binding_owner = read(a.binding, 16*MIB)
    assert sha(original) == a.binding_sha256
    b = json.loads(original)
    inline = a.profile != 'full-callback-v1'
    spsc = a.profile in ('inline-clock-spsc-v1', 'inline-clock-spsc-fatal-v1')
    fatal_controls = a.profile == 'inline-clock-spsc-fatal-v1'
    if inline:
        assert b.keys() == {'schema', 'authority', 'revision', 'repo', 'caller_sha256', 'binary',
                            'binary_owner', 'sources', 'tools', 'affinity', 'build', 'profile'}
        assert b['profile'] == a.profile
    else:
        assert b.keys() == {'schema', 'authority', 'revision', 'repo', 'caller_sha256', 'binary',
                            'binary_owner', 'sources', 'tools', 'affinity', 'build'}
    assert type(b['schema']) is int and b['schema'] == 1
    if inline:
        assert b['authority'] == INLINE_AUTHORITIES[a.profile]
    else:
        assert b['authority'] == 'ROOT_REVIEWED_PREEMPT_RELEASE_BINARY'
    assert type(b['revision']) is str and re.fullmatch('[0-9a-f]{40}', b['revision'])
    repo, raw = Path(b['repo']), a.raw
    assert repo.is_absolute() and repo.resolve(strict=True) == repo
    assert raw.is_absolute() and raw.is_relative_to(repo/'ignored') and not raw.exists() and not raw.is_symlink()
    assert raw.parent.resolve(strict=True) == raw.parent
    assert a.binding.is_relative_to(repo/'ignored') and not a.binding.is_relative_to(raw)
    assert sha(read(Path(__file__).resolve())[0]) == b['caller_sha256']
    assert len(b['affinity']) == len(set(b['affinity'])) == 4
    assert all(type(x) is int and x >= 0 for x in b['affinity'])
    assert set(b['affinity']) <= os.sched_getaffinity(0)
    os.sched_setaffinity(0, b['affinity'])
    assert sorted(os.sched_getaffinity(0)) == sorted(b['affinity'])
    helper = repo/'tools/unwind-oracle/bounded_command.py'
    assert b['tools'].keys() == {'python', 'timeout', 'git', 'helper'}
    tools = b['tools']
    assert all(row.keys() == {'path', 'owner'} for row in tools.values())
    assert Path(tools['helper']['path']) == helper
    assert tools['helper']['owner']['sha256'] == HELPER_SHA
    assert Path(sys.executable).resolve(strict=True) == Path(tools['python']['path']).resolve(strict=True)
    binary = Path(b['binary'])
    assert binary == repo/'target/release/liteinst-preempt'
    build = b['build']
    assert build.keys() == {'command', 'closed', 'files'}
    assert build['command']['argv'][1:] == ['build', '--locked', '--offline', '--release', '--bin', 'liteinst-preempt']
    assert build['command']['cwd'] == str(repo)
    assert all(build['command']['env'][key] == value for key, value in BUILD_ENV.items())
    assert type(build['closed']['exit']) is int and build['closed']['exit'] == 0
    assert build['closed']['parent_wait_returned'] is True
    assert build['files'] and all(Path(p).is_relative_to(repo/'ignored') for p in build['files'])
    env = dict(PATH='/usr/bin:/bin', LANG='C.UTF-8', LC_ALL='C.UTF-8',
               PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    def git(*args):
        return subprocess.check_output([tools['git']['path'], '-C', str(repo), *args], env=env, timeout=15)
    def source():
        assert git('rev-parse', 'HEAD').decode().strip() == b['revision']
        assert git('status', '--porcelain', '--untracked-files=no') == b''
        names = git('ls-files', '-z').decode().rstrip('\0').split('\0')
        assert set(names) == set(b['sources']) and len(names) == len(set(names))
        rows = {name:read(repo/name)[1] for name in names}
        assert rows == b['sources']
        return rows
    def watched():
        rows = {str(a.binding):read(a.binding)[1], str(binary):read(binary)[1]}
        assert rows[str(a.binding)] == binding_owner and rows[str(binary)] == b['binary_owner']
        for row in tools.values():
            rows[row['path']] = read(row['path'])[1]
            assert rows[row['path']] == row['owner']
        for p, owner in build['files'].items():
            rows[p] = read(p)[1]
            assert rows[p] == owner
        return rows
    before_source, before = source(), watched()
    raw.mkdir(mode=0o700)
    save(raw, 'binding.json', b)
    save(raw, 'sources-before.json', before_source)
    save(raw, 'inputs-before.json', before)
    fs = os.statvfs(raw)
    assert fs.f_bavail * fs.f_frsize >= 64*MIB
    save(raw, 'capacity.json', dict(available_bytes=fs.f_bavail*fs.f_frsize, required_free_bytes=64*MIB,
        scope='filesystem headroom for fixed small outputs; caller separately enforces the managed-slot cap'))
    save(raw, 'hardware.json', dict(architecture=platform.machine(), kernel=platform.release(),
        libc=platform.libc_ver(), affinity=sorted(os.sched_getaffinity(0)),
        cpu_model=next(x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name'))))
    rows = [dict(id='qualify', status='UNRUN')] + [dict(id=name, status='UNRUN') for name in CASES]
    if fatal_controls:
        rows = [dict(id=name, kind='expected-refusal-control', expected_exit=123, status='UNRUN') for name in FAULTS]
    elif inline:
        rows.insert(0, dict(id='gates', status='UNRUN'))
    cpu_seconds, wall_seconds, outer_seconds, parent_seconds = (5, 8, 18, 33) if fatal_controls else (60, 90, 100, 115)
    metrics = []
    try:
        for row in rows:
            work = raw/row['id'];work.mkdir();(work/'tmp').mkdir()
            row['status'] = 'FAILED'
            child = None;parent_error = None;began = time.monotonic()
            try:
                assert watched() == before
                argv = [str(binary), 'qualify', str(work/'output')] if row['id']=='qualify' else [str(binary), 'bench', row['id'], str(work/'output')]
                if inline:
                    argv = [str(binary), 'inline-gates', str(work/'output')] if row['id']=='gates' else (
                        [str(binary), 'inline-qualify', str(work/'output')] if row['id']=='qualify' else
                        [str(binary), 'inline-bench', row['id'], str(work/'output')])
                if spsc and row['id'] != 'gates':
                    argv[1] = argv[1].replace('inline-', 'inline-spsc-', 1)
                if fatal_controls:
                    argv = [str(binary), 'inline-spsc-fault', row['id'], str(work/'output')]
                case_env = dict(env, TMPDIR=str(work/'tmp'))
                request = dict(argv=argv, cwd=str(repo), env=case_env, stdout=str(work/'stdout.txt'),
                    stderr=str(work/'stderr.txt'), cpu_seconds=cpu_seconds, wall_seconds=wall_seconds, file_bytes=MIB)
                save(work, 'request.json', request)
                outer = [tools['timeout']['path'], '--signal=TERM', '--kill-after=10s', str(outer_seconds)+'s', tools['python']['path'],
                         '-B', str(helper), '--request', str(work/'request.json'), '--receipt', str(work/'receipt.json')]
                save(work, 'command.json', dict(argv=outer, cwd=str(repo), env=case_env, affinity=b['affinity'],
                    parent_timeout_seconds=parent_seconds, parent_failure_cleanup_seconds=10))
                with (work/'helper.stdout').open('xb') as out, (work/'helper.stderr').open('xb') as err:
                    try:
                        child = subprocess.Popen(outer, cwd=repo, env=case_env, stdin=subprocess.DEVNULL,
                            stdout=out, stderr=err, start_new_session=True)
                        save(work, 'started.json', dict(pid=child.pid))
                        child.wait(timeout=parent_seconds)
                    except BaseException as error:
                        parent_error = repr(error)
                        if child is not None:
                            if child.poll() is None:
                                try:os.killpg(child.pid, signal.SIGKILL)
                                except BaseException as e:parent_error += '; kill: '+repr(e)
                            try:child.wait(timeout=10)
                            except BaseException as e:parent_error += '; cleanup: '+repr(e)
                        raise
                    finally:
                        if child is not None:
                            save(work, 'closed.json', dict(pid=child.pid, exit=child.returncode,
                                parent_wait_returned=child.returncode is not None, parent_error=parent_error,
                                elapsed_seconds=time.monotonic()-began))
                receipt = json.loads(read(work/'receipt.json', MIB)[0])
                if fatal_controls:
                    assert child.returncode == 1 and parent_error is None
                    assert type(receipt['exit']) is int and receipt['exit'] == 123
                else:
                    assert child.returncode == 0 and parent_error is None
                    assert type(receipt['exit']) is int and receipt['exit'] == 0
                assert receipt['request_sha256'] == sha(read(work/'request.json')[0]) and receipt['helper_sha256'] == HELPER_SHA
                assert receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
                assert receipt['absence_proof'] == 'ECHILD' and receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
                assert receipt['cleanup_error'] is receipt['aborted'] is None
                assert math.isfinite(receipt['elapsed_seconds']) and 0 <= receipt['elapsed_seconds'] <= wall_seconds
                for name in ('stdout', 'stderr'):
                    assert receipt[name+'_sha256'] == sha(read(work/(name+'.txt'),MIB)[0])
                assert read(work/'stderr.txt')[0] == read(work/'helper.stderr')[0] == b''
                if fatal_controls:
                    # An expected rejection is not relabelled as a successful
                    # child: retain the actual nonzero exit and helper failure.
                    assert json.loads(read(work/'helper.stdout')[0]) == dict(exit=123,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=False)
                    assert read(work/'stdout.txt')[0] == b''
                    output = work/'output'
                    assert {p.name for p in output.iterdir()} == {'parked.json', 'refusal.bin'}
                    assert read(output/'parked.json', MIB)[0] == ('{\"fault\":\"'+row['id']+'\",\"site\":27,\"count\":1,\"encounters\":1,\"words\":[2,1,1],\"remaining\":0}\n').encode()
                    witness, witness_owner = read(output/'refusal.bin', 104)
                    require_refusal_witness(row['id'], witness)
                    save(work, 'output-files.json', {'parked.json':read(output/'parked.json',MIB)[1],
                        'refusal.bin':witness_owner})
                    assert watched() == before
                    row['observed_exit'] = receipt['exit']
                    row['status'] = 'PASS'
                    continue
                assert json.loads(read(work/'helper.stdout')[0]) == dict(exit=0,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=True)
                terminal = 'preemption:qualify:96-stop-cells:16-native:16-counter:512-setcc:48-exact-repeats\n' if row['id']=='qualify' else 'preemption:benchmark:'+row['id']+':27-rows:2-warmups:7-measured:equal-work\n'
                if inline:
                    terminal = ('preemption:inline-gates:28-pairs:56-children:28-full-state-prefixes\n'
                        if row['id']=='gates' else terminal.replace('preemption:', 'preemption:inline-', 1))
                if spsc and row['id'] != 'gates':
                    terminal = terminal.replace('preemption:inline-', 'preemption:inline-spsc-', 1)
                assert read(work/'stdout.txt', MIB)[0] == terminal.encode()
                output = work/'output'
                names = {'qualification.csv','stops.csv','summary.json'} if row['id']=='qualify' else {'measurements.csv'}
                if row['id']=='gates':
                    assert inline
                    names = {'gate-controls.csv','summary.json'}
                assert {p.name for p in output.iterdir()} == names
                assert all(p.is_file() and not p.is_symlink() for p in output.iterdir())
                save(work, 'output-files.json', {name:read(output/name,MIB)[1] for name in sorted(names)})
                if row['id']=='gates':
                    summary = json.loads(read(output/'summary.json')[0])
                    assert summary == dict(status='PASS', profile='inline-clock-v1', pairs=28, children=56,
                        comparisons=28, stack_bytes=65536, scope='new-gate-prefix-only')
                    gates = list(csv.DictReader(io.StringIO(read(output/'gate-controls.csv')[0].decode())))
                    expected = [(case, str(taken).lower(), str(remaining), str(seed))
                        for case in CASES for taken in ((True,) if case=='direct-jmp' else (False,True))
                        for remaining in (1,2) for seed in (7,42)]
                    assert [(r['case'],r['taken'],r['remaining'],r['seed']) for r in gates] == expected
                    assert len(gates)==28 and all(r['status']=='PASS' and 1<=int(r['steps'])<=20000 for r in gates)
                    assert all(r['boundary']==('zero-before-save' if r['taken']=='true' and r['remaining']=='1'
                        else 'fast-before-original-branch') for r in gates)
                elif row['id']=='qualify':
                    summary = json.loads(read(output/'summary.json')[0])
                    if inline:
                        assert summary['status']=='PASS' and summary['scope']==a.profile+'-before-taken-backedge'
                    else:
                        assert summary['status']=='PASS' and summary['scope']=='finite-before-taken-backedge'
                    assert [summary[x] for x in ('stop_cells','native_cells','counter_cells','condition_controls','deterministic_repeats')] == [96,16,16,512,48]
                    assert summary['parked_checks'] == 256
                    assert len(list(csv.DictReader(io.StringIO(read(output/'qualification.csv')[0].decode())))) == 96
                    assert len(list(csv.DictReader(io.StringIO(read(output/'stops.csv')[0].decode())))) == 256
                else:
                    data = list(csv.DictReader(io.StringIO(read(output/'measurements.csv')[0].decode())))
                    assert len(data)==27
                    for mode in MODES:
                        selected = [r for r in data if r['mode']==mode]
                        assert [int(r['repetition']) for r in selected] == list(range(9))
                        assert [r['phase'] for r in selected] == ['warmup']*2+['measured']*7
                        assert all(r['case']==row['id'] and (int(r['n']),int(r['rounds']),int(r['work_units']))==(256,128,32768) and int(r['elapsed_ns'])>0 for r in selected)
                        ns = [int(r['elapsed_ns']) for r in selected[2:]]
                        metrics.append(dict(case=row['id'],mode=mode,repetitions=7,work_units=32768,
                            median_elapsed_ns=statistics.median(ns),min_elapsed_ns=min(ns),max_elapsed_ns=max(ns)))
                assert watched() == before
                row['status']='PASS'
            except BaseException as error:
                row['error']=repr(error)
                break
    finally:
        try:
            after, after_source = watched(), source()
            save(raw, 'inputs-after.json', after);save(raw, 'sources-after.json', after_source)
            stable = after==before and after_source==before_source
        except BaseException as error:
            stable=False;save(raw,'postcheck-error.json',dict(error=repr(error)))
        success=stable and all(r['status']=='PASS' for r in rows)
        save(raw,'summary.json',dict(revision=b['revision'],status='PASS' if success else 'FAILED',commands=rows,
            sources_unchanged=stable,metrics=metrics,scope=('expected callback rejection controls; no qualification or timing credit' if fatal_controls else 'finite authored taken-backedge prototype; no general progress bound')))
    return 0 if success else 1


if __name__ == '__main__':
    raise SystemExit(main())
