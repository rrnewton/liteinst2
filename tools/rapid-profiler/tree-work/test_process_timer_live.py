#!/usr/bin/env python3
"""Bounded real-child controls for the timer, under both unchanged owners."""
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


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def main():
    ap = argparse.ArgumentParser()
    for name in ('timer', 'control', 'output'): ap.add_argument('--'+name, type=Path, required=True)
    a = ap.parse_args()
    root = Path(__file__).resolve().parents[3]
    for p in (a.timer, a.control): assert p.is_absolute() and p.resolve(strict=True) == p
    assert a.output.is_absolute() and a.output.is_relative_to(root/'ignored')
    assert a.output.parent.resolve(strict=True) == a.output.parent and not a.output.exists()
    a.output.mkdir()
    timing = load('process_timing', Path(__file__).with_name('process_timing.py'))
    processes = load('timer_processes', root/'evaluation/admission/processes.py')
    helper = root/'tools/unwind-oracle/bounded_command.py'
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    pins = {str(p): sha(p) for p in (a.timer, a.control, helper, Path(__file__),
        Path(__file__).with_name('process_timing.py'), root/'evaluation/admission/processes.py')}
    env = dict(os.environ)
    result = dict(status='FAILED', controls=[], inputs=pins)
    def save(path, value):
        with path.open('x') as f: json.dump(value, f, indent=2, sort_keys=True); f.write('\n')

    def run(mode, wall=5, cap=1048576, executable=None, existing=False):
        directory = a.output/mode; directory.mkdir()
        record = directory/'timing.txt'
        if existing: record.write_bytes(b'already exists\n')
        argv = [str(executable or a.control), mode]
        wrapped = [str(a.timer), str(record), timing.token(argv), '--', *argv]
        request = dict(argv=wrapped, cwd=str(root), env=env, stdout=str(directory/'stdout.txt'),
            stderr=str(directory/'stderr.txt'), cpu_seconds=2, wall_seconds=wall, file_bytes=cap)
        save(directory/'request.json', request)
        # Preserve the complete campaign-relative name: every campaign calls
        # its control directory "timer-controls", so a basename-only log path
        # collides with an earlier, deliberately retained campaign.
        log = root/'target/evaluation/process-timer'/a.output.relative_to(root/'ignored')/(mode+'.log')
        log.parent.mkdir(parents=True, exist_ok=True)
        assert not log.exists()
        closed = processes.run_command([sys.executable, '-B', str(helper), '--request',
            str(directory/'request.json'), '--receipt', str(directory/'receipt.json')], env, log, wall+25, 1048576)
        save(directory/'parent.json', closed)
        assert closed['termination'] is None and closed['cleanup_complete'] and closed['reaped_descendants'] == 0
        receipt = json.loads((directory/'receipt.json').read_text())
        assert receipt['request_sha256'] == sha(directory/'request.json') and receipt['helper_sha256'] == pins[str(helper)]
        assert receipt['inputs_unchanged'] and receipt['absence_proof'] == 'ECHILD'
        assert receipt['cleanup_error'] is receipt['aborted'] is None
        for stream in ('stdout', 'stderr'): assert receipt[stream+'_sha256'] == sha(directory/(stream+'.txt'))
        terminal = json.loads(log.read_text())
        assert terminal == dict(exit=receipt['exit'], wall_timeout=receipt['wall_timeout'],
            absence_proof='ECHILD', descendants=len(receipt['unexpected_descendants']), success=closed['exit_code'] == 0)
        result['controls'].append(dict(mode=mode, parent=closed, helper=receipt,
            record_sha256=sha(record) if record.exists() else None))
        return directory, record, argv, receipt, closed

    try:
        for mode in ('zero', 'converters'):
            directory, record, argv, receipt, closed = run(mode)
            row = timing.successful(timing.parse(record.read_bytes(), argv))
            assert closed['exit_code'] == receipt['exit'] == 0 and not receipt['wall_timeout']
            assert receipt['cleanup_events'] == receipt['unexpected_descendants'] == []
            assert (directory/'stderr.txt').read_bytes() == b''
            expected = f'child_pid={row["child_pid"]}\n'.encode() if mode == 'zero' else b'converters PASS\n'
            assert (directory/'stdout.txt').read_bytes() == expected
            try: timing.parse(record.read_bytes().replace(b' token=', b' wrong='), argv)
            except AssertionError: pass
            else: raise AssertionError('tampered timer record accepted')
        for mode in ('nonzero', 'signal', 'exec-failure'):
            directory, record, argv, receipt, closed = run(mode,
                executable=a.output/'missing-executable' if mode == 'exec-failure' else None)
            row = timing.parse(record.read_bytes(), argv)
            assert closed['exit_code'] == receipt['exit'] == 1 and not receipt['wall_timeout']
            assert receipt['cleanup_events'] == receipt['unexpected_descendants'] == []
            assert (row['exit'], row['signal'], row['exec_errno']) == {
                'nonzero': (7, 0, 0), 'signal': (-1, 15, 0), 'exec-failure': (127, 0, 2)}[mode]
            try: timing.successful(row)
            except AssertionError: pass
            else: raise AssertionError('failed subject earned timing credit')
        for mode in ('closed-output', 'kill-timer', 'descendant'):
            directory, record, argv, receipt, closed = run(mode, wall=1)
            assert closed['exit_code'] == 1 and receipt['unexpected_descendants'] and receipt['cleanup_events']
            if mode == 'closed-output': assert receipt['wall_timeout']
            if mode == 'kill-timer': assert receipt['exit'] == -9 and not receipt['wall_timeout']
            if mode == 'descendant':
                assert receipt['exit'] == 0 and not receipt['wall_timeout']
                # A locally valid record cannot override the owner's rescue.
                timing.successful(timing.parse(record.read_bytes(), argv))
        directory, record, argv, receipt, closed = run('record-exists', existing=True)
        assert closed['exit_code'] == 1 and receipt['exit'] == 2 and record.read_bytes() == b'already exists\n'
        assert not receipt['wall_timeout'] and receipt['cleanup_events'] == receipt['unexpected_descendants'] == []
        for mode, cap in (('output', 8192), ('quiet', 1)):
            directory, record, argv, receipt, closed = run(mode, cap=cap)
            assert closed['exit_code'] == 1 and receipt['exit'] != 0
            assert not receipt['wall_timeout'] and receipt['cleanup_events'] == receipt['unexpected_descendants'] == []
            if mode == 'output':
                assert receipt['exit'] == 1
                row = timing.parse(record.read_bytes(), argv)
                assert row['signal'] == 25 and len((directory/'stdout.txt').read_bytes()) == cap
            else:
                assert receipt['exit'] == -25 and len(record.read_bytes()) <= cap
                try: timing.parse(record.read_bytes(), argv)
                except AssertionError: pass
                else: raise AssertionError('truncated record accepted')
        assert {p: sha(Path(p)) for p in pins} == pins
        result['status'] = 'PASS'
    finally:
        save(a.output/'controls.json', result)
    print('process-timer-controls PASS controls=11 owners=2 original_helpers=true')
    return 0


if __name__ == '__main__': raise SystemExit(main())
