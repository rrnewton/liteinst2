#!/usr/bin/env python3
"""One immutable module-session input case; child closure is checked separately."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import subprocess
import time

CAP = 4 * 1024 * 1024
CORPUS = '6feddb81816cc509e1357edec646ab60ba433a4a857d094ddce4d09a0c3ee738'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def pins_unchanged(pins):
    assert pins
    for name, digest in pins.items():
        path = Path(name)
        assert path.is_absolute() and path.resolve(strict=True) == path and sha(path) == digest


def case_spec(corpus, index):
    assert type(index) is int and 0 <= index < 32
    if index < 30:
        case = corpus.cases()[index]
        if case.outcome != 'input_error':
            error = 'none'
        elif index <= 19:
            error = 'syntax'
        elif index <= 21:
            error = 'overlong'
        elif index <= 24:
            error = 'unterminated'
        else:
            error = 'record_limit'
        return dict(name=case.name, data=case.data, records=case.accepted,
                    outcome=case.outcome, input_error=error, close=case.close_input)
    if index == 30:
        return dict(name='history', data=corpus.framed(corpus.LITERALS),
                    records=corpus.LITERALS * 3, outcome='eof', input_error='none', close=True)
    records = tuple(corpus.Record(b'x' * 64, 1) for _ in range(2048))
    return dict(name='pressure', data=corpus.framed(records), records=records,
                outcome='eof', input_error='none', close=True)


def remaining(deadline):
    left = deadline - time.monotonic()
    assert left > 0, 'producer absolute 15-second deadline'
    return left


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--plan', type=Path, required=True)
    ap.add_argument('--plan-sha', required=True)
    ap.add_argument('--raw', type=Path, required=True)
    a = ap.parse_args()
    repo = Path(__file__).resolve().parents[2]
    assert a.plan.is_absolute() and a.plan.resolve(strict=True) == a.plan
    assert a.raw.is_absolute() and a.raw.is_relative_to(repo / 'ignored') and not a.raw.exists()
    assert a.raw.parent.resolve(strict=True) == a.raw.parent
    assert a.plan.stat().st_size <= 1024 * 1024 and sha(a.plan) == a.plan_sha
    plan = json.loads(a.plan.read_bytes())
    pins_unchanged(plan['pins'])
    own = Path(__file__).resolve()
    assert str(own) in plan['pins']
    for name in ('output.py', 'corpus.py'):
        assert str(own.with_name(name)) in plan['pins']
    assert plan['pins'][str(own.with_name('corpus.py'))] == CORPUS
    checker = load('_module_session_output', own.with_name('output.py'))
    corpus = load('_module_session_corpus', own.with_name('corpus.py'))
    case = case_spec(corpus, plan['case'])
    assert case['name'] == plan['name']
    cpus = plan['cpus']
    assert len(cpus) == 3 and cpus == sorted(set(cpus))
    assert all(type(cpu) is int and 0 <= cpu < 1024 for cpu in cpus)
    assert os.sched_getaffinity(0) == set(cpus)
    geometry = plan['geometry']
    argv = plan['argv']
    assert argv == [plan['binary'], 'normal-module-session', plan['candidate'], plan['trusted'],
                    str(geometry['csv_va']), str(geometry['csv_length']),
                    str(geometry['length_va']), str(geometry['length_length']), str(plan['k']), '520']
    assert plan['k'] in (10, 1000)
    assert all(str(Path(path).resolve(strict=True)) == path and path in plan['pins']
               for path in (plan['binary'], plan['candidate'], plan['trusted']))
    a.raw.mkdir()
    transcript, errors, buffer, outgoing = bytearray(), bytearray(), bytearray(), bytearray()
    sent, phase, prefix = 0, 0, 0
    hold_until = None
    selector = None
    rescue = False
    normal_reaps = 0
    failure = None
    result = dict(status='FAILED', case=plan['case'], name=case['name'], k=plan['k'])
    deadline = time.monotonic() + 15
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        os.sched_setaffinity(0, {cpus[2]})
        assert os.sched_getaffinity(0) == {cpus[2]}
        remaining(deadline)
        selector = selectors.DefaultSelector()
        for pipe, role in ((child.stdout, 'out'), (child.stderr, 'err')):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, role)
        os.set_blocking(child.stdin.fileno(), False)
        def line(raw):
            nonlocal phase, hold_until, prefix
            assert len(raw) + 1 <= 350
            row = raw.decode('ascii').split(',')
            if row[0] == 'READY':
                assert phase == 0
                outgoing.extend(case['data'])
                phase = 1
                if plan['case'] == 31:
                    selector.unregister(child.stdout)
                    hold_until = time.monotonic() + .250
            elif row[0] == 'HISTORY':
                assert len(row) == 5
                prefix = checker.uint(row[2])
                if plan['case'] == 30 and phase == 1 and prefix >= 513:
                    outgoing.extend(corpus.framed(corpus.LITERALS * 2))
                    phase = 2
        while selector.get_map() or hold_until is not None:
            remaining(deadline)
            if hold_until is not None and time.monotonic() >= hold_until:
                selector.register(child.stdout, selectors.EVENT_READ, 'out')
                hold_until = None
            if outgoing and not child.stdin.closed:
                try:
                    count = os.write(child.stdin.fileno(), outgoing[:8192])
                    assert count > 0
                    sent += count
                    del outgoing[:count]
                except BlockingIOError:
                    pass
                except BrokenPipeError:
                    child.stdin.close()
            close = case['close'] and phase > 0 and not outgoing
            if plan['case'] == 30:
                close = close and phase == 2 and prefix >= 520
            if close and not child.stdin.closed:
                child.stdin.close()
            for key, _ in selector.select(min(.001, remaining(deadline))):
                try:
                    data = os.read(key.fd, 8192)
                except BlockingIOError:
                    continue
                if not data:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                target = transcript if key.data == 'out' else errors
                assert len(target) + len(data) <= CAP
                target.extend(data)
                if key.data == 'out':
                    buffer.extend(data)
                    while b'\n' in buffer:
                        raw, _, rest = buffer.partition(b'\n')
                        buffer = bytearray(rest)
                        line(raw)
                    assert len(buffer) < 350
        code = child.wait(timeout=remaining(deadline))
        normal_reaps = 1
        remaining(deadline)
        assert not buffer and not outgoing and phase > 0
        expected_bytes = corpus.framed(case['records']) if plan['case'] >= 30 else case['data']
        assert sent == len(expected_bytes)
        assert type(code) is int and code == (0 if case['outcome'] == 'eof' else 1)
        checked = checker.check(bytes(transcript), bytes(errors), records=tuple((r.payload, r.fields) for r in case['records']),
                                k=plan['k'], epochs=520, outcome=case['outcome'], input_error=case['input_error'],
                                lengths=(geometry['csv_length'], geometry['length_length']),
                                returns=tuple(tuple(values) for values in geometry['returns']),
                                continuation=geometry['continuation'], cpus=tuple(cpus[:2]))
        assert checked['rows']['READY'][0]['pid'] == child.pid
        if plan['case'] == 30:
            assert phase == 2 and checked['totals']['epochs'] == 520
            assert checked['rows']['DONE'][0]['history_end'] == 521
            assert any(row['owner'] == 'sampled' and row['history_prefix'] >= 513 for row in checked['rows']['CALL'])
        if plan['case'] == 31:
            assert checked['rows']['IO'][0]['write_blocked'] > 0
        pins_unchanged(plan['pins'])
        assert sha(a.plan) == a.plan_sha
        remaining(deadline)
        result.update(status='PASS', totals=checked['totals'], done=checked['rows']['DONE'][0],
                      write_blocked=checked['rows']['IO'][0]['write_blocked'],
                      original_values=[[row['id'], row['length'], row['checksum'], row['csv_value'], row['length_value']]
                                       for row in checked['rows']['RESULT']])
    except BaseException as error:
        failure = type(error).__name__ + ': ' + str(error)
        result.update(error=failure)
    finally:
        if selector is not None:
            selector.close()
        if not child.stdin.closed:
            child.stdin.close()
        cleanup_error = None
        try:
            if child.poll() is None:
                rescue = True
                child.kill()
                child.wait(timeout=2)
        except BaseException as error:
            cleanup_error = type(error).__name__ + ': ' + str(error)
            result.update(status='FAILED', error='child cleanup incomplete')
        for pipe in (child.stdout, child.stderr):
            if not pipe.closed:
                pipe.close()
        result.update(child_pid=child.pid, child_exit=child.returncode, normal_reaps=normal_reaps,
                      rescue=rescue, cleanup_error=cleanup_error, sent_bytes=sent,
                      stdout_sha256=hashlib.sha256(transcript).hexdigest(), stderr_sha256=hashlib.sha256(errors).hexdigest())
        (a.raw / 'stdout.txt').write_bytes(transcript)
        (a.raw / 'stderr.txt').write_bytes(errors)
        if failure is None and time.monotonic() >= deadline:
            result.update(status='FAILED', error='producer deadline at final acceptance')
        (a.raw / 'result.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True))
    if result['status'] == 'PASS':
        remaining(deadline)
    return 0 if result['status'] == 'PASS' and not rescue else 1


if __name__ == '__main__':
    raise SystemExit(main())
