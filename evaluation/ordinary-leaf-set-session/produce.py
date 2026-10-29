#!/usr/bin/env python3
"""One immutable LeafSet input case; child closure is checked separately."""
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
CATALOG = '7f2faf14fd394bf6b4a3a40acb116cd03608b2756f6198594e00f03edcbe57ff'


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


def plan_arguments(plan, catalog, checker):
    assert type(plan['index']) is int and 0 <= plan['index'] < 24
    coordinate = catalog.references()[plan['index']]
    assert (plan['n'], plan['k'], plan['kind']) == (coordinate['n'], coordinate['k'], coordinate['kind'])
    case = catalog.case(plan['n'], plan['k'], plan['kind'])
    assert plan['name'] == case['name'] and plan['epochs'] == 520
    assert plan['data_sha256'] == hashlib.sha256(case['data']).hexdigest()
    cpus = plan['cpus']
    assert type(cpus) is list and len(cpus) == 3 and cpus == sorted(set(cpus))
    assert all(type(cpu) is int and 0 <= cpu < 1024 for cpu in cpus)
    table = tuple(dict(leaf, returns=tuple(leaf['returns'])) for leaf in plan['table'])
    assert len(table) == plan['n']
    checker.geometry(table, plan['caller'], tuple(cpus[:2]))
    wanted = dict(zip(catalog.OPERATIONS[:plan['n']], zip(catalog.FUNCTION_IDS[:plan['n']], catalog.POLICIES[:plan['n']])))
    assert {leaf['operation']: (leaf['function_id'], leaf['policy']) for leaf in table} == wanted
    argv = [plan['binary'], 'normal-leaf-set-session', plan['candidate'], plan['trusted'], str(plan['k']), '520', str(plan['n'])]
    for leaf in table:
        argv += [str(leaf['function_id']), leaf['operation'], str(leaf['elf_va']), str(leaf['extent']), leaf['policy']]
    assert plan['argv'] == argv
    return case, dict(records=case['records'], table=table, caller=plan['caller'], k=plan['k'], epochs=520,
                      outcome=case['outcome'], input_error=case['input_error'], cpus=tuple(cpus[:2]))


def ready_row(raw, pid, checker):
    assert type(raw) is bytes and 0 < len(raw) + 1 <= 350
    row = raw.decode('ascii').split(',')
    assert len(row) == 19 and row[:2] == ['READY', 'leaf-set-session-v1']
    assert type(pid) is int and pid > 0
    assert checker.uint(row[11]) == checker.uint(row[12]) == pid


def remaining(deadline):
    left = deadline - time.monotonic()
    assert left > 0, 'producer absolute 15-second deadline'
    return left


def _main(*, binding=None):
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
    for name in ('output.py', 'catalog.py'):
        assert str(own.with_name(name)) in plan['pins']
    assert plan['pins'][str(own.with_name('catalog.py'))] == CATALOG
    if binding is not None:
        binding.check_sources(repo, plan['pins'])
        binding.check_plan(plan)
    checker = load('_leaf_set_session_output', own.with_name('output.py'))
    catalog = load('_leaf_set_session_catalog', own.with_name('catalog.py') if binding is None else repo/binding.catalog_path)
    case, checker_args = plan_arguments(plan, catalog, checker)
    cpus, argv = plan['cpus'], plan['argv']
    assert os.sched_getaffinity(0) == set(cpus)
    assert all(str(Path(path).resolve(strict=True)) == path and path in plan['pins']
               for path in (plan['binary'], plan['candidate'], plan['trusted']))
    a.raw.mkdir()
    transcript, errors, buffer, outgoing = bytearray(), bytearray(), bytearray(), bytearray()
    sent, phase = 0, 0
    selector = None
    rescue = False
    normal_reaps = 0
    failure = None
    result = dict(status='FAILED', index=plan['index'], name=case['name'], n=plan['n'], k=plan['k'])
    if binding is not None:
        result.update(binding.fields())
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
            nonlocal phase
            assert len(raw) + 1 <= 350
            row = raw.decode('ascii').split(',')
            if row[0] == 'READY':
                assert phase == 0
                ready_row(bytes(raw), child.pid, checker)
                outgoing.extend(case['data'])
                phase = 1
        while selector.get_map():
            remaining(deadline)
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
        assert sent == len(case['data'])
        assert type(code) is int and code == (0 if case['outcome'] == 'eof' else 1)
        checked = checker.check(bytes(transcript), bytes(errors), **checker_args)
        assert checked['rows']['READY'][0]['pid'] == child.pid
        pins_unchanged(plan['pins'])
        assert sha(a.plan) == a.plan_sha
        remaining(deadline)
        result.update(status='PASS', totals=checked['totals'], done=checked['rows']['DONE'][0],
                      write_blocked=checked['rows']['IO'][0]['write_blocked'],
                      original_values=[[row['record_id'], row['length'], row['checksum'], *[row['value_' + str(i)] for i in range(plan['n'])]]
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


def main():
    return _main()


if __name__ == '__main__':
    raise SystemExit(main())
