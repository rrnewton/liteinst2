#!/usr/bin/env python3
"""One bounded diagnostic recorder facade; never repository qualification."""
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
import sys
import traceback

sys.dont_write_bytecode = True
PACKET = Path(__file__).resolve().parent
WALL, LOG = 180, 8 * 1024 * 1024


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def fact(path):
    need(path.is_file() and not path.is_symlink(), 'regular input required')
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                mode=stat.S_IMODE(path.stat().st_mode))


def unique(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate timing field')
        result[key] = value
    return result


def timings(raw, cpus):
    """Pair only emitted start/stop observations; no duration for an open test."""
    rows, active, seen, worker_identity = [], {}, set(), {}
    for line in raw.decode('utf-8', errors='strict').splitlines():
        match = re.fullmatch(r'\[worker ([0-3])\] RECORDER_TIMING (.+)', line)
        if not match:
            continue
        index = int(match[1])
        row = json.loads(match[2], object_pairs_hook=unique,
                         parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
        need(type(row) is dict and set(row) == {'schema', 'event', 'test', 'pid',
             'affinity', 'monotonic_ns', 'process_time_ns'}, 'timing row shape')
        need(type(row['schema']) is int and row['schema'] == 1
             and row['event'] in ('start', 'stop') and type(row['test']) is str
             and re.fullmatch(r'test_[A-Za-z0-9_]+\.[A-Za-z0-9_]+\.test_[A-Za-z0-9_]+', row['test']),
             'timing identity')
        need(all(type(row[k]) is int and row[k] > 0
                 for k in ('pid', 'monotonic_ns', 'process_time_ns'))
             and row['affinity'] == [cpus[index]], 'actual worker timing clocks and CPU')
        identity = (row['pid'], tuple(row['affinity']))
        need(worker_identity.setdefault(index, identity) == identity, 'worker timing identity changed')
        if row['event'] == 'start':
            need(index not in active and row['test'] not in seen, 'duplicate or overlapping timed test')
            seen.add(row['test']); active[index] = row
        else:
            before = active.pop(index, None)
            need(before is not None and before['test'] == row['test']
                 and before['pid'] == row['pid'], 'timed stop without exact start')
            wall = row['monotonic_ns'] - before['monotonic_ns']
            cpu = row['process_time_ns'] - before['process_time_ns']
            need(wall >= 0 and cpu >= 0, 'negative observed test timing')
            rows.append(dict(worker=index, test=row['test'], pid=row['pid'],
                             cpu=cpus[index], wall_ns=wall, process_cpu_ns=cpu,
                             start_monotonic_ns=before['monotonic_ns'],
                             stop_monotonic_ns=row['monotonic_ns']))
    modules = {}
    for row in rows:
        key = row['test'].split('.', 1)[0]
        total = modules.setdefault(key, dict(completed=0, wall_ns=0, process_cpu_ns=0, workers=[]))
        total['completed'] += 1
        total['wall_ns'] += row['wall_ns']; total['process_cpu_ns'] += row['process_cpu_ns']
        if row['worker'] not in total['workers']:
            total['workers'].append(row['worker'])
    return dict(completed=rows, modules=modules,
                open_tests=[dict(worker=i, test=r['test'], pid=r['pid'], cpu=cpus[i],
                                 start_monotonic_ns=r['monotonic_ns'], wall_ns=None,
                                 process_cpu_ns=None) for i, r in sorted(active.items())],
                timing_scope='inclusive result/output bookkeeping; worker process CPU excludes descendants')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--expect-revision', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    output = args.output.resolve()
    need(output.is_relative_to((root / 'target/evaluation/inprocess').resolve(strict=True))
         and not output.exists(), 'fresh private diagnostic output')
    cpus = sorted(os.sched_getaffinity(0))
    need(len(cpus) == 4, 'exactly four reserved CPUs required')
    manifest = json.loads((PACKET / 'SOURCE.json').read_bytes(), object_pairs_hook=unique)
    need(args.expect_revision == manifest['base_revision'], 'reviewed exact source revision')
    packet_before = {name: fact(PACKET / name) for name in
                     ('SOURCE.json', *manifest['artifacts'])}
    for name, wanted in manifest['artifacts'].items():
        need(packet_before[name] == wanted, 'private packet bytes or mode changed')
    for name, wanted in manifest['inputs'].items():
        need(fact(root / name) == wanted, 'actual tracked prerequisite bytes changed')
    os.chdir(root)
    admission = root / 'evaluation/admission'
    sys.path.insert(0, str(admission))
    spec = importlib.util.spec_from_file_location('diagnostic_admission_owner', admission / 'run.py')
    owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
    need(owner.ROOT == root and sys.modules['processes'].ROOT == root
         and Path(owner.run_command.__code__.co_filename).resolve() == admission / 'processes.py',
         'unchanged actual process owner and ROOT')

    def source():
        value = owner.source_state()
        need(value['revision'] == args.expect_revision and value['tracked_clean']
             and value['head_sources_match'], 'source revision or tracked bytes changed')
        for name in owner.git('ls-files', '--others', '--exclude-standard').decode().splitlines():
            need(name == 'BRIEF-li2adm.md' or name.startswith(
                ('evaluation/admission/results/', 'evaluation/inprocess/results/')), 'unexpected untracked source')
        return value

    before = source()
    output.mkdir(parents=True, exist_ok=False)
    temporary = output / 'tmp'; temporary.mkdir()
    record = dict(schema=1, profile='private-recorder-timing-facade-v1', status='preflight',
                  facade_only=True, qualification_credit=False, performance_credit=False,
                  source=before, packet=packet_before, source_unchanged=False,
                  packet_unchanged=False, configuration_unchanged=False,
                  cpu=cpus, hardware=owner.hardware(),
                  limits=dict(wall_seconds=WALL, log_bytes=LOG, cleanup_seconds=3,
                              workers=4, rlimit_core=0), command=None, timing=None)
    env = None
    try:
        original_env = owner.controlled_environment(os.environ, temporary)
        need('LI2_RECORDER_SOURCE_ROOT' not in original_env, 'diagnostic environment collision')
        env = original_env | {'LI2_RECORDER_SOURCE_ROOT': str(root)}
        record['environment'] = env
        record['diagnostic_environment_keys'] = ['LI2_RECORDER_SOURCE_ROOT']
        record['configuration'] = owner.cargo_configuration(env)
        python = Path(shutil.which('python3', path=env['PATH']) or '').resolve(strict=True)
        record['python'] = dict(path=str(python), **fact(python))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        argv = ['python3', str(PACKET / 'recorder_parallel.py')]
        log = output / 'recorder_tests.log'
        record['status'] = 'running'
        observed = owner.run_command(argv, env, log, WALL, max_log_bytes=LOG)
        record['command'] = dict(argv=argv, **observed, log=fact(log))
        record['timing'] = timings(log.read_bytes(), cpus)
        need(Path(shutil.which('python3', path=env['PATH']) or '').resolve(strict=True) == python
             and fact(python) == {k: record['python'][k] for k in ('bytes', 'sha256', 'mode')},
             'actual Python changed')
        passed = observed['exit_code'] == 0 and observed['termination'] is None and observed['cleanup_complete']
        record['status'] = 'facade_complete' if passed else 'failed_prefix'
        if passed:
            need(len(record['timing']['completed']) == 366 and not record['timing']['open_tests'],
                 'complete facade timing population')
    except BaseException as error:
        record['status'] = 'failed'
        record['error'] = type(error).__name__ + ': ' + str(error)
        traceback.print_exc()
    finally:
        errors = []
        for key, check in (
            ('source_unchanged', lambda: source() == before),
            ('packet_unchanged', lambda: {name: fact(PACKET / name) for name in packet_before} == packet_before),
            ('configuration_unchanged', lambda: env is not None and owner.cargo_configuration(env) == record['configuration']),
            ('affinity_unchanged', lambda: sorted(os.sched_getaffinity(0)) == cpus),
        ):
            try:
                record[key] = check()
                need(record[key], key)
            except BaseException as error:
                errors.append(key + ': ' + type(error).__name__ + ': ' + str(error))
        record['final_errors'] = errors
        if errors:
            record['status'] = 'failed'
        (output / 'receipt.json').write_text(json.dumps(record, indent=2, sort_keys=True, allow_nan=False) + '\n')
        print(json.dumps(dict(status=record['status'], qualification_credit=False,
                              timing_completed=len(record['timing']['completed']) if record['timing'] else None,
                              receipt=str(output / 'receipt.json')), sort_keys=True), flush=True)
    return 0 if record['status'] == 'facade_complete' else 1


if __name__ == '__main__':
    raise SystemExit(main())
