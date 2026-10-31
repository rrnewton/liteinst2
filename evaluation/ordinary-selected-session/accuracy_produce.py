#!/usr/bin/env python3
"""One fixed, READY-gated Exact37 accuracy functional attempt; no metric verdict."""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import subprocess
import time

CAP, CHUNK, LINE = 8 * 1024 * 1024, 8192, 350
PROFILE = 'selected-accuracy-functional-first-v1'
PHASE_PROFILE = 'selected-accuracy-phase-functional-first-v1'
PREPARED_PHASE_PROFILE = 'selected-accuracy-prepared-phase-functional-first-v1'
MASTER = '16b3b34b02c2f1054381195ee3d0767b493b427ad041bbfd8924e630d0f369b1'
POLICY = dict(k=10, period_ms=10, epochs=520, phase='locked', delay_ns=0)
BODY = bytes.fromhex('31c04c8d04370fb60f83f15a4801c848ffc74c39c772ef48ba157c4a7fb979379e4831d0c3')
ABI = 'sysv-amd64-u64-pointer-length-v1'
MATERIALS = ('manifest.json', 'input.csv', 'selected.txt', 'truth.csv')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, cap):
    # Match the existing recipe's no-follow, whole-file before/after identity read.
    import stat
    stamp = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    assert path.is_absolute() and path.resolve(strict=True) == path
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap
        data = stream.read(cap + 1)
        assert len(data) == before.st_size <= cap
        assert stamp(before) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat())
    return data


def pins_unchanged(pins):
    assert type(pins) is dict and pins
    for name, pin in pins.items():
        assert set(pin) == {'bytes', 'sha256'} and type(pin['bytes']) is int and 0 <= pin['bytes'] <= 512 * 1024 * 1024
        raw = read(Path(name), pin['bytes'])
        assert len(raw) == pin['bytes'] and sha(raw) == pin['sha256']


def phase_policy(checker, kind):
    assert type(kind) is str and kind in ('random', 'locked')
    _, manifest = checker.truth.artifacts(MASTER, 'calibration', 1, 'late_expensive')
    choices = [p for p in manifest['policies'] if (p['k'], p['period_ms'], p['phase']) == (10, 10, kind)]
    assert len(choices) == 1
    return dict(choices[0], epochs=520)


def arguments(plan, checker):
    return _arguments(plan, checker, None)


def phase_arguments(plan, checker):
    assert checker.VERSION == 'selected-accuracy-phase-session-v1'
    return _arguments(plan, checker, plan['policy']['phase'])


def prepared_target(policy):
    assert set(policy) == {'k', 'period_ms', 'epochs', 'phase', 'delay_ns'}
    assert type(policy['k']) is int and policy['k'] in (1, 10, 100, 1000)
    assert type(policy['phase']) is str and policy['phase'] in ('locked', 'random')
    assert type(policy['epochs']) is int and 2 <= policy['epochs'] <= 520
    assert type(policy['period_ms']) is int and policy['period_ms'] in (1, 10, 100)
    assert type(policy['delay_ns']) is int and 0 <= policy['delay_ns'] < policy['period_ms'] * 1000000
    return dict(target_epoch=1, arm_number=2, target_ns=policy['period_ms'] * 1000000 + policy['delay_ns'])


def prepared_phase_arguments(plan, checker):
    assert checker.VERSION == 'selected-accuracy-prepared-phase-session-v1'
    return _arguments(plan, checker, plan['policy']['phase'], prepared=True)


def _arguments(plan, checker, epoch_phase, *, prepared=False):
    assert type(prepared) is bool and (not prepared or epoch_phase is not None)
    policy = POLICY if epoch_phase is None else phase_policy(checker, epoch_phase)
    profile = PREPARED_PHASE_PROFILE if prepared else (PROFILE if epoch_phase is None else PHASE_PROFILE)
    assert plan['profile'] == profile and plan['attempt'] == 1
    assert type(plan['revision']) is str and len(plan['revision']) == 40 and all(c in '0123456789abcdef' for c in plan['revision'])
    assert plan['policy'] == policy and all(type(plan['policy'][k]) is type(v) for k, v in policy.items())
    cpus = plan['cpus']
    assert type(cpus) is list and len(cpus) == 3 and cpus == sorted(set(cpus))
    assert all(type(cpu) is int and 0 <= cpu < 1024 for cpu in cpus)
    paths = {name: Path(plan['materials'][name]) for name in MATERIALS}
    assert set(plan['materials']) == set(MATERIALS)
    for path in (*paths.values(), *(Path(plan[k]) for k in ('binary', 'candidate', 'trusted', 'geometry', 'preparation'))):
        assert str(path) in plan['pins']
    # The directly invocable adapter retains the same externally accepted facts;
    # a body/table pin alone is never whole-ELF or caller authority.
    gate_path = Path(__file__).resolve().with_name('accuracy_functional.py')
    assert str(gate_path) in plan['pins']
    gate = load('_accuracy_functional_geometry_gate', gate_path)
    geometry = json.loads(read(Path(plan['geometry']), 1024 * 1024))
    gate.accept_geometry(geometry, plan['facts'], plan['preparation_sha256'], plan['revision'], epoch_phase=epoch_phase, prepared=prepared)
    assert plan['pins'][plan['preparation']]['sha256'] == plan['preparation_sha256']
    facts = plan['facts']
    assert facts['table'] == plan['table'] and facts['caller'] == plan['caller'] and facts['policy'] == policy
    if prepared:
        target = prepared_target(policy)
        assert plan['prepared_phase'] == facts['prepared_phase'] == target
        assert all(type(plan['prepared_phase'][k]) is type(facts['prepared_phase'][k]) is int for k in target)
    assert facts['abi'] == ABI and facts['revision'] == plan['revision'] and facts['profile'] == profile
    for key in ('binary','candidate','trusted'):
        assert facts[key] == dict(path=plan[key], **plan['pins'][plan[key]])
    assert facts['materials'] == {name:dict(path=str(path), **plan['pins'][str(path)]) for name,path in paths.items()}
    table = tuple(dict(row, returns=tuple(row['returns'])) for row in plan['table'])
    checked = dict(manifest_bytes=read(paths['manifest.json'], 65536), input_bytes=read(paths['input.csv'], CAP),
        selected_bytes=read(paths['selected.txt'], CAP), truth_bytes=read(paths['truth.csv'], CAP),
        table=table, caller=plan['caller'], body_bytes=BODY, abi=ABI, policy=dict(policy), cpus=tuple(cpus[:2]))
    manifest, _, records, _ = checker.authority(**checked)
    assert (manifest['master'], manifest['phase'], manifest['trial'], manifest['workload']) == (MASTER, 'calibration', 1, 'late_expensive')
    assert len(records) == 2048 and tuple(map(len, records)) == (1,) * 1024 + (64,) * 1024
    assert len(checked['input_bytes']) == 68608 and plan['input_sha256'] == sha(checked['input_bytes'])
    assert plan['caller'] == dict(extent=20, continuation=15)
    assert len(table) == 1 and table[0] == dict(function_id=41, operation='exact_work_nonempty', policy='whole',
        elf_va=table[0]['elf_va'], extent=37, returns=(36,))
    assert read(Path(plan['candidate']), 1024 * 1024) == read(Path(plan['trusted']), 1024 * 1024)
    identities = [(Path(plan[k]).stat().st_dev, Path(plan[k]).stat().st_ino) for k in ('candidate','trusted')]
    assert identities[0] != identities[1]
    argv = [plan['binary'], 'normal-selected-accuracy-session', plan['candidate'], plan['trusted'],
        str(paths['selected.txt']), '10', '10', '520', '1', '41', 'exact_work_nonempty', str(table[0]['elf_va']), '37', 'whole']
    if epoch_phase is not None:
        argv[1] = 'normal-selected-accuracy-phase-session'
        argv[8:8] = [policy['phase'], str(policy['delay_ns'])]
    if prepared:
        argv[1] = 'normal-selected-accuracy-prepared-phase-session'
        argv[10:10] = ['1']
    assert plan['argv'] == argv
    return checked


def ready_row(raw, pid, cpus, checker):
    assert type(raw) is bytes and 0 < len(raw) + 1 <= LINE
    row = raw.decode('ascii').split(',')
    assert len(row) == 19 and row[:2] == ['READY', checker.VERSION]
    values = [checker.uint(word) for word in row[2:]]
    assert values[:9] == [10, 520, 10, 2, 64, 2048, 1, 1, checker.shared.INSTALL]
    assert type(pid) is int and 0 < pid <= (1 << 32) - 1
    assert values[9:11] == [pid, pid] and 0 < values[11] != pid
    assert values[12:14] == list(cpus[:2]) and 0 < values[14] <= (1 << 64) - 21
    assert values[15:] == [1, 1]


def remaining(deadline):
    left = deadline - time.monotonic()
    assert left > 0, 'producer absolute 15-second deadline'
    return left


def append_observed(target, data, role, overflow):
    """Keep exactly the consumed bytes; never claim bytes still in the child's pipe."""
    assert type(data) is bytes and 0 < len(data) <= CHUNK and role in ('out', 'err')
    if len(target) + len(data) > CAP:
        assert overflow == {}
        overflow.update(stream=role, prefix_bytes=len(target), chunk=data)
        raise ValueError('accepted stream exceeds 8 MiB; consumed offending chunk retained separately')
    target.extend(data)


def write_input(fd, outgoing, sent, writes, clock=time.monotonic_ns, writer=os.write):
    assert outgoing and sent >= 0 and len(writes) < 68608
    before = clock()
    count = writer(fd, outgoing[:CHUNK])
    after = clock()
    assert type(count) is int and 0 < count <= min(CHUNK, len(outgoing)) and before <= after
    sent += count
    writes.append([before, after, sent, count])
    del outgoing[:count]
    return sent


def exchange(plan, checked, checker):
    return _exchange(plan, checked, checker, phase_profile=False)


def phase_exchange(plan, checked, checker):
    assert plan['profile'] == PHASE_PROFILE and checker.VERSION == 'selected-accuracy-phase-session-v1'
    return _exchange(plan, checked, checker, phase_profile=True)


def prepared_phase_exchange(plan, checked, checker):
    assert plan['profile'] == PREPARED_PHASE_PROFILE and checker.VERSION == 'selected-accuracy-prepared-phase-session-v1'
    return _exchange(plan, checked, checker, phase_profile=True, prepared=True)


def _exchange(plan, checked, checker, *, phase_profile, prepared=False):
    assert type(prepared) is bool and (not prepared or phase_profile)
    transcript, errors, buffer, outgoing = bytearray(), bytearray(), bytearray(), bytearray()
    result = dict(status='FAILED', profile=PREPARED_PHASE_PROFILE if prepared else (PHASE_PROFILE if phase_profile else PROFILE), revision=plan['revision'], attempt=1,
        hardware_status='UNRESOLVED', requested_phase_status='UNRESOLVED', metric_qualified=False,
        native_state_qualified=False, performance_qualified=False, writes=[], ready_receipt_ns=None, eof_close_ns=None)
    sent, phase, lines, normal_reaps = 0, 0, 0, 0
    selector, child, failure = None, None, None
    rescue, overflow = False, {}
    deadline = time.monotonic() + 15
    try:
        child = subprocess.Popen(plan['argv'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.sched_setaffinity(0, {plan['cpus'][2]})
        assert os.sched_getaffinity(0) == {plan['cpus'][2]}
        remaining(deadline)
        selector = selectors.DefaultSelector()
        for pipe, role in ((child.stdout, 'out'), (child.stderr, 'err')):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, role)
        os.set_blocking(child.stdin.fileno(), False)
        while selector.get_map():
            remaining(deadline)
            if outgoing and not child.stdin.closed:
                try:
                    sent = write_input(child.stdin.fileno(), outgoing, sent, result['writes'])
                except BlockingIOError:
                    pass
                except BrokenPipeError:
                    child.stdin.close()
                    raise
            if phase == 1 and not outgoing and not child.stdin.closed:
                child.stdin.close()
                result['eof_close_ns'] = time.monotonic_ns()
            for key, _ in selector.select(min(.001, remaining(deadline))):
                try:
                    data = os.read(key.fd, CHUNK)
                except BlockingIOError:
                    continue
                if not data:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                append_observed(transcript if key.data == 'out' else errors, data, key.data, overflow)
                if key.data == 'out':
                    buffer.extend(data)
                    while b'\n' in buffer:
                        raw, _, rest = buffer.partition(b'\n')
                        buffer = bytearray(rest)
                        assert 0 < len(raw) + 1 <= LINE and b'\r' not in raw
                        lines += 1
                        assert lines <= (checker.envelope_limit(520) if prepared else (checker.row_limit(520) if phase_profile else 11820))
                        if phase == 0:
                            ready_row(bytes(raw), child.pid, plan['cpus'], checker)
                            result['ready_receipt_ns'] = time.monotonic_ns()
                            outgoing.extend(checked['input_bytes'])
                            phase = 1
                        else:
                            assert not raw.startswith(b'READY,')
                    assert len(buffer) < LINE
        code = child.wait(timeout=remaining(deadline))
        normal_reaps = 1
        remaining(deadline)
        assert not buffer and not outgoing and phase == 1
        assert sent == len(checked['input_bytes']) and result['eof_close_ns'] is not None
        assert type(code) is int and code == 0
        joined = checker.check(bytes(transcript), bytes(errors), **checked)
        assert joined['numeric']['rows']['READY'][0]['pid'] == child.pid
        pins_unchanged(plan['pins'])
        remaining(deadline)
        result.update(status='PASS', totals=joined['totals'], recorded_arm_deadlines_satisfied=True)
    except BaseException as error:
        failure = type(error).__name__ + ': ' + str(error)
        result['error'] = failure
    finally:
        if selector is not None:
            selector.close()
        cleanup_error = None
        if child is not None:
            if not child.stdin.closed:
                child.stdin.close()
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
        result.update(child_pid=None if child is None else child.pid, child_exit=None if child is None else child.returncode,
            normal_reaps=normal_reaps, rescue=rescue, cleanup_error=cleanup_error, sent_bytes=sent,
            stdout_sha256=sha(transcript), stderr_sha256=sha(errors),
            overflow=None if not overflow else dict(stream=overflow['stream'], prefix_bytes=overflow['prefix_bytes'],
                bytes=len(overflow['chunk']), sha256=sha(overflow['chunk'])))
        if failure is None and time.monotonic() >= deadline:
            result.update(status='FAILED', error='producer deadline at final acceptance')
    return result, bytes(transcript), bytes(errors), overflow.get('chunk', b''), deadline


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--plan-sha', required=True)
    parser.add_argument('--raw', type=Path, required=True)
    parser.add_argument('--profile', choices=(PROFILE, PHASE_PROFILE, PREPARED_PHASE_PROFILE), default=PROFILE)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    assert args.raw.is_absolute() and args.raw.is_relative_to(repo / 'ignored') and not os.path.lexists(args.raw)
    assert args.raw.parent.resolve(strict=True) == args.raw.parent
    raw_plan = read(args.plan, 1024 * 1024)
    assert sha(raw_plan) == args.plan_sha
    plan = json.loads(raw_plan)
    pins_unchanged(plan['pins'])
    own = Path(__file__).resolve()
    required = (own, repo/'evaluation/ordinary-accuracy/output.py', repo/'evaluation/ordinary-accuracy/truth.py',
        repo/'evaluation/ordinary-leaf-set-session/output.py')
    assert all(str(path) in plan['pins'] for path in required)
    prepared = args.profile == PREPARED_PHASE_PROFILE
    phase_profile = args.profile in (PHASE_PROFILE, PREPARED_PHASE_PROFILE)
    reader = repo/'evaluation/ordinary-accuracy'/('prepared_phase_output.py' if prepared else 'phase_output.py') if phase_profile else required[1]
    if prepared:
        assert str(repo/'evaluation/ordinary-accuracy/phase_output.py') in plan['pins']
    assert str(reader) in plan['pins']
    checker = load('_functional_accuracy_output', reader)
    checked = prepared_phase_arguments(plan, checker) if prepared else (phase_arguments(plan, checker) if phase_profile else arguments(plan, checker))
    assert os.sched_getaffinity(0) == set(plan['cpus'])
    args.raw.mkdir(mode=0o700)
    result, out, err, overflow, deadline = (prepared_phase_exchange if prepared else (phase_exchange if phase_profile else exchange))(plan, checked, checker)
    try:
        assert read(args.plan, 1024 * 1024) == raw_plan
    except BaseException as error:
        result.update(status='FAILED', error='producer plan recheck: '+type(error).__name__+': '+str(error))
    for name, data in (('stdout.txt', out), ('stderr.txt', err), ('overflow.bin', overflow)):
        with (args.raw/name).open('xb') as stream:
            stream.write(data)
    raw_result = (json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    assert len(raw_result) <= CAP
    with (args.raw/'result.json').open('xb') as stream:
        stream.write(raw_result)
    print(raw_result.decode('ascii'), end='')
    if result['status'] == 'PASS':
        remaining(deadline)
    return 0 if result['status'] == 'PASS' and not result['rescue'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
