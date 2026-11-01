#!/usr/bin/env python3
"""One bounded module-cost diagnostic; installed tests and runner stay unchanged."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time
import unittest

sys.dont_write_bytecode = True
ROOT = Path.cwd().resolve()
HERE = Path(__file__).resolve().parent
ADMISSION = ROOT / 'evaluation/admission'
MODULES = ('test_runtime_kernel_inventory', 'test_runtime_inventory',
           'test_source_census_fixtures', 'test_main_query_inventory')
sys.path.insert(0, str(ADMISSION))


def fact(path):
    data = Path(path).read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def source():
    def git(*args):
        return subprocess.check_output(['git', '-C', str(ROOT), *args]).decode().strip()
    return dict(revision=git('rev-parse', 'HEAD'), tree=git('rev-parse', 'HEAD^{tree}'),
                tracked_status=git('status', '--porcelain', '--untracked-files=no'))


def measured():
    resource.setrlimit(resource.RLIMIT_CPU, (180, 180))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    assert sys.version_info[:2] == (3, 12) and not sys.flags.optimize
    assert len(os.sched_getaffinity(0)) == 1
    import recorder_parallel as original
    start = time.monotonic_ns()
    cases, identities = original.discover()
    print('DISCOVERY ' + json.dumps(dict(tests=len(identities),
          sha256=original.digest(identities), wall_ns=time.monotonic_ns()-start,
          worker_counts=list(map(len, original.partition(identities, 4))))), flush=True)
    cpu = min(os.sched_getaffinity(0))
    for module in MODULES:
        selected = [case for case in cases if case.id().split('.', 1)[0] == module]
        assigned = [case.id() for case in selected]
        assert assigned and all(name in original.partition(identities, 4)[1] for name in assigned)
        timings = []
        class Timed(original.Ledger):
            def startTest(self, test):
                self.wall_start = time.monotonic_ns()
                self.cpu_start = time.process_time_ns()
                super().startTest(test)
            def stopTest(self, test):
                super().stopTest(test)
                timings.append(dict(identity=test.id(),
                    wall_ns=time.monotonic_ns()-self.wall_start,
                    cpu_ns=time.process_time_ns()-self.cpu_start))
        wall, process = time.monotonic_ns(), time.process_time_ns()
        result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2,
                                        resultclass=Timed).run(unittest.TestSuite(selected))
        row = original.worker_row(result, identities, assigned, 0, 1, cpu)
        print('MODULE ' + json.dumps(dict(module=module, wall_ns=time.monotonic_ns()-wall,
              cpu_ns=time.process_time_ns()-process, cases=timings, ledger=row), sort_keys=True), flush=True)
        original.validate(row, identities, assigned, 0, 1, cpu)
    print('DIAGNOSTIC_COMPLETE', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--measure', action='store_true')
    parser.add_argument('--expect-revision')
    parser.add_argument('--output')
    args = parser.parse_args()
    os.chdir(ROOT)
    if args.measure:
        assert args.expect_revision is None and args.output is None
        measured()
        return 0
    assert args.expect_revision and len(args.expect_revision) == 40
    assert len(os.sched_getaffinity(0)) == 1 and sys.version_info[:2] == (3, 12)
    assert args.output is not None
    output = (ROOT / args.output).resolve()
    assert output.parent == ROOT / 'target/evaluation/inprocess'
    output.mkdir()
    temporary = output / 'tmp'
    temporary.mkdir()
    import processes
    from run import controlled_environment
    before = source()
    assert before['revision'] == args.expect_revision and not before['tracked_status']
    paths = [ADMISSION / (module + '.py') for module in MODULES]
    paths += [ADMISSION / name for name in ('recorder_parallel.py', 'recorder_shards_inventory.py',
              'recorder_shards_inventory.json', 'corpus.json', 'processes.py')]
    inputs = {str(path.relative_to(ROOT)): fact(path) for path in paths}
    argv = [sys.executable, '-B', str(Path(__file__).resolve()), '--measure']
    record = dict(schema=1, status='failed', scope='module-cost diagnostic only; not a full-suite result',
                  source=before, cpu=min(os.sched_getaffinity(0)), python=sys.version,
                  argv=argv, bounds=dict(cpu_seconds=180, wall_seconds=180, output_bytes=8388608),
                  inputs=inputs, driver=fact(__file__), command=None, modules=[],
                  qualification_credit=False, performance_credit=False)
    log = output / 'measurement.log'
    try:
        record['command'] = processes.run_command(argv, controlled_environment(os.environ, temporary),
                                                  log, 180, 8 * 1024 * 1024)
        data = log.read_bytes()
        record['capture'] = dict(path=str(log.relative_to(ROOT)), **fact(log))
        record['modules'] = [json.loads(line[7:]) for line in data.splitlines() if line.startswith(b'MODULE ')]
        record['discovery'] = [json.loads(line[10:]) for line in data.splitlines() if line.startswith(b'DISCOVERY ')]
        record['source_unchanged'] = source() == before
        record['inputs_unchanged'] = all(fact(ROOT / path) == value for path, value in inputs.items())
        command = record['command']
        assert command['exit_code'] == 0 and command['termination'] is None and command['cleanup_complete']
        assert record['source_unchanged'] and record['inputs_unchanged']
        assert len(record['discovery']) == 1 and record['discovery'][0]['tests'] == 366
        assert [row['module'] for row in record['modules']] == list(MODULES)
        assert data.splitlines()[-1] == b'DIAGNOSTIC_COMPLETE'
        record['status'] = 'measured_unqualified'
    except BaseException as error:
        record['error'] = repr(error)
        raise
    finally:
        (output / 'receipt.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
        print(json.dumps(dict(status=record['status'], receipt=str((output / 'receipt.json').relative_to(ROOT)))))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
