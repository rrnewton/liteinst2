#!/usr/bin/env python3
"""Run the complete recorder discovery in at most four isolated exec workers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LIMIT = 8 * 1024 * 1024
WALL = 180
MARKER = b'RECORDER_WORKER '


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(identities):
    return hashlib.sha256(json.dumps(identities, separators=(',', ':')).encode()).hexdigest()


def flatten(suite):
    require(type(suite) is unittest.TestSuite, 'unexpected_test_suite')
    result = []
    for item in suite:
        if isinstance(item, unittest.TestCase):
            result.append(item)
        else:
            result.extend(flatten(item))
    return result


def discover():
    # These are the original unittest CLI discovery arguments and loader.
    loader = unittest.defaultTestLoader
    cases = flatten(loader.discover('evaluation/admission', pattern='test_*.py'))
    require(not loader.errors, 'discovery_errors')
    identities = [case.id() for case in cases]
    from core_5cda_inventory import python_identities
    declared = python_identities(HERE)
    count = json.loads((HERE / 'corpus.json').read_bytes())['recorder_tests']
    require(type(count) is int and count == 366 and len(identities) == count
            and len(set(identities)) == count and sorted(identities) == sorted(declared),
            'changed_recorder_identity_population')
    from recorder_shards_inventory import ADDED
    require(all(name in identities for name in ADDED), 'missing_historical_shard')
    from core_367_inventory import ADDED as ABSOLUTE_STARTUP_CONTROL
    require(ABSOLUTE_STARTUP_CONTROL in identities, 'missing_absolute_startup_control')
    from core_c712_inventory import ADDED as SOFTWARE_PREEMPTION_CONTROL
    require(SOFTWARE_PREEMPTION_CONTROL in identities, 'missing_software_preemption_control')
    from core_0fb574_inventory import ADDED as NATIVE_STARTUP_CONTROL
    require(NATIVE_STARTUP_CONTROL in identities, 'missing_native_startup_control')
    from core_af81_inventory import ADDED as ADC_COMPILED_CONTROL
    require(ADC_COMPILED_CONTROL in identities, 'missing_adc_compiled_control')
    from core_dd75_inventory import ADDED as SELECTED_SDK_CONTROL
    require(SELECTED_SDK_CONTROL in identities, 'missing_selected_sdk_control')
    from core_981419_inventory import ADDED as ACCURACY_SDK_CONTROL
    require(ACCURACY_SDK_CONTROL in identities, 'missing_accuracy_sdk_control')
    from core_20cbe_inventory import ADDED as EXACT37_CONTROL
    require(EXACT37_CONTROL in identities, 'missing_exact37_control')
    from core_acc247_inventory import ADDED as PHASE_CONTROL
    require(PHASE_CONTROL in identities, 'missing_phase_control')
    from core_34c47_inventory import ADDED as PREPARED_CONTROL
    require(PREPARED_CONTROL in identities, 'missing_prepared_control')
    from core_d8d85_inventory import ADDED as ARTIFACT_CONTROL
    require(ARTIFACT_CONTROL in identities, 'missing_artifact_control')
    from core_f353_inventory import ADDED as INDEXED_CONTROL
    require(INDEXED_CONTROL in identities, 'missing_indexed_control')
    from core_97ab_inventory import ADDED as NATIVE_INDEXED_CONTROL
    require(NATIVE_INDEXED_CONTROL in identities, 'missing_native_indexed_control')
    return cases, identities


def partition(identities, workers):
    require(type(workers) is int and 1 <= workers <= 4, 'invalid_worker_count')
    require(type(identities) is list and identities and all(type(x) is str for x in identities)
            and len(set(identities)) == len(identities), 'invalid_identity_population')
    from recorder_shards_inventory import ADDED
    # The pure helper also accepts synthetic/non-shard populations.
    # Actual workers authenticate all366 and allfour in discover().
    if not all(name in identities for name in ADDED):
        modules = list(dict.fromkeys(name.split('.', 1)[0] for name in identities))
        groups = [[] for _ in range(workers)]
        heavy = 'test_main813_inventory'
        if workers > 1 and heavy in modules and len(modules) >= workers:
            # Keep the complete inventory module isolated; no test is split or omitted.
            others = [module for module in modules if module != heavy]
            for name in identities:
                module = name.split('.', 1)[0]
                index = 0 if module == heavy else 1 + others.index(module) % (workers - 1)
                groups[index].append(name)
        else:
            for name in identities:
                groups[modules.index(name.split('.', 1)[0]) % workers].append(name)
        require(all(groups) and sum(map(len, groups)) == len(identities), 'empty_worker_partition')
        return groups
    # Four complete historical cases run on different workers when four CPUs
    # are supplied. All remaining modules retain stable module grouping; the
    # five other main813 cases are ordinary cases, without cross-case state.
    modules = list(dict.fromkeys(name.split('.', 1)[0] for name in identities
                                if name not in ADDED))
    assigned = {name: index % workers for index, name in enumerate(ADDED)}
    if workers == 4:
        # Measured ordinary-module costs; preserve the four historical shards
        # and every worker's original discovery order.
        moved = {'test_main_query_inventory': 1, 'test_runtime_inventory': 1,
                 'test_runtime_stack_consumer_inventory': 3, 'test_backing_cleanup': 3}
        for name in identities:
            module = name.split('.', 1)[0]
            if name not in assigned and module in moved:
                assigned[name] = moved[module]
    groups = [[] for _ in range(workers)]
    for name in identities:
        index = assigned[name] if name in assigned else modules.index(name.split('.', 1)[0]) % workers
        groups[index].append(name)
    require(all(groups) and sum(map(len, groups)) == len(identities), 'empty_worker_partition')
    return groups


class Ledger(unittest.TextTestResult):
    def __init__(self, *args):
        super().__init__(*args)
        self.started_ids = []
        self.completed_ids = []
        self.success_ids = []

    def startTest(self, test):
        self.started_ids.append(test.id())
        super().startTest(test)

    def stopTest(self, test):
        self.completed_ids.append(test.id())
        super().stopTest(test)

    def addSuccess(self, test):
        self.success_ids.append(test.id())
        super().addSuccess(test)


def worker_row(result, identities, assigned, index, workers, cpu):
    return dict(schema=1, worker=index, workers=workers, cpu=cpu,
                discovery_sha256=digest(identities), assigned=assigned,
                started=result.started_ids, completed=result.completed_ids,
                success=result.success_ids, tests_run=result.testsRun,
                failures=[test.id() for test, _ in result.failures],
                errors=[test.id() for test, _ in result.errors],
                skipped=[test.id() for test, _ in result.skipped],
                expected_failures=[test.id() for test, _ in result.expectedFailures],
                unexpected_successes=[test.id() for test in result.unexpectedSuccesses],
                should_stop=result.shouldStop)


def validate(row, identities, assigned, index, workers, cpu):
    keys = {'schema', 'worker', 'workers', 'cpu', 'discovery_sha256', 'assigned',
            'started', 'completed', 'success', 'tests_run', 'failures', 'errors',
            'skipped', 'expected_failures', 'unexpected_successes', 'should_stop'}
    require(type(row) is dict and set(row) == keys, 'worker_row_shape')
    for key, wanted in (('schema', 1), ('worker', index), ('workers', workers),
                        ('cpu', cpu), ('tests_run', len(assigned))):
        require(type(row[key]) is int and row[key] == wanted, 'worker_integer_identity')
    require(type(row['discovery_sha256']) is str and row['discovery_sha256'] == digest(identities),
            'worker_discovery_differs')
    for key in ('assigned', 'started', 'completed', 'success', 'failures', 'errors',
                'skipped', 'expected_failures', 'unexpected_successes'):
        require(type(row[key]) is list and all(type(x) is str for x in row[key]), 'worker_identity_types')
    require(all(row[key] == assigned for key in ('assigned', 'started', 'completed', 'success')),
            'worker_execution_differs')
    require(all(row[key] == [] for key in ('failures', 'errors', 'skipped',
                'expected_failures', 'unexpected_successes')) and row['should_stop'] is False,
            'worker_failed_or_incomplete')


def worker(index, workers, cpu):
    require(type(index) is int and 0 <= index < workers <= 4
            and cpu in os.sched_getaffinity(0), 'worker_launch_identity')
    os.sched_setaffinity(0, {cpu})
    require(os.sched_getaffinity(0) == {cpu}, 'worker_affinity')
    cases, identities = discover()
    assigned = partition(identities, workers)[index]
    selected = set(assigned)
    suite = unittest.TestSuite(case for case in cases if case.id() in selected)
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2, resultclass=Ledger).run(suite)
    row = worker_row(result, identities, assigned, index, workers, cpu)
    print(MARKER.decode() + json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False), flush=True)
    validate(row, identities, assigned, index, workers, cpu)
    return 0


def unique(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate_worker_field')
        result[key] = value
    return result


def parse_worker(data):
    rows = [line[len(MARKER):] for line in data.splitlines() if line.startswith(MARKER)]
    require(len(rows) == 1, 'missing_or_duplicate_worker_row')
    return json.loads(rows[0], object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def coordinate():
    begin = time.monotonic()
    cases, identities = discover()
    del cases
    cpus = sorted(os.sched_getaffinity(0))[:4]
    os.sched_setaffinity(0, set(cpus))
    require(os.sched_getaffinity(0) == set(cpus), 'coordinator_affinity')
    groups = partition(identities, len(cpus))
    children = []
    captures = [bytearray() for _ in cpus]
    pending = [bytearray() for _ in cpus]
    total = 0
    success = False
    # The unchanged outer processes.run_command owns the complete tree and its
    # original180-second/8MiB deadlines, including escaped/adopted descendants.
    try:
        with selectors.DefaultSelector() as selector:
            for index, cpu in enumerate(cpus):
                child = subprocess.Popen([sys.executable, '-B', str(Path(__file__).resolve()),
                    '--worker', str(index), '--workers', str(len(cpus)), '--cpu', str(cpu)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    close_fds=True, cwd=ROOT, env=os.environ | {'PYTHONDONTWRITEBYTECODE': '1'})
                children.append(child)
                os.set_blocking(child.stdout.fileno(), False)
                selector.register(child.stdout, selectors.EVENT_READ, index)
            while selector.get_map() or any(child.poll() is None for child in children):
                require(time.monotonic() - begin < WALL, 'recorder_deadline')
                for key, _ in selector.select(0.05):
                    index = key.data
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        if pending[index]:
                            sys.stdout.buffer.write(b'[worker %d] ' % index + pending[index] + b'\n')
                            sys.stdout.buffer.flush()
                            pending[index].clear()
                        continue
                    total += len(data)
                    require(total <= LIMIT, 'recorder_worker_output_limit')
                    captures[index].extend(data)
                    pending[index].extend(data)
                    while b'\n' in pending[index]:
                        line, _, tail = pending[index].partition(b'\n')
                        pending[index] = bytearray(tail)
                        sys.stdout.buffer.write(b'[worker %d] ' % index + line + b'\n')
                    sys.stdout.buffer.flush()
            rows = []
            for index, child in enumerate(children):
                require(child.wait() == 0, 'worker_exit_failure')
                row = parse_worker(bytes(captures[index]))
                validate(row, identities, groups[index], index, len(cpus), cpus[index])
                rows.append(row)
            require(sorted(x for row in rows for x in row['success']) == sorted(identities),
                    'aggregate_identity_differs')
            print('RECORDER_AGGREGATE ' + json.dumps(dict(schema=1, workers=len(cpus),
                discovery_sha256=digest(identities), identities=identities, tests_run=len(identities)),
                sort_keys=True, separators=(',', ':')), flush=True)
            success = True
    finally:
        deadline = time.monotonic() + 3
        for child in children:
            if child.poll() is None:
                child.kill()
        for child in children:
            child.wait(timeout=max(0.001, deadline - time.monotonic()))
            if child.stdout is not None:
                child.stdout.close()
    if success:
        print('\nRan %d tests in %.3fs\n\nOK' % (len(identities), time.monotonic() - begin), flush=True)
        return 0
    return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=int)
    parser.add_argument('--workers', type=int)
    parser.add_argument('--cpu', type=int)
    args = parser.parse_args()
    os.chdir(ROOT)
    if args.worker is None:
        require(args.workers is None and args.cpu is None, 'unexpected_worker_arguments')
        return coordinate()
    require(args.workers is not None and args.cpu is not None, 'missing_worker_arguments')
    return worker(args.worker, args.workers, args.cpu)


if __name__ == '__main__':
    raise SystemExit(main())
