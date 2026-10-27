#!/usr/bin/env python3
"""Run exact-revision synthetic profile controls with closed bounded records."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time

REVISION = '59c026e4da35b25dae2e270a5a63aa1b9e8cd41b'
HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
CONTROLS = {
    'production': ('evaluation/e9-common-app/test_production_profile.py',
                   '6427c579bff011e69d3c56c39d26e21d75a8bfa37f40ead36f2f2790a7f5fd1c', 10),
    'ordinary': ('evaluation/e9-common-app/test_candidate_profile.py',
                 '85574aab13c1c8fe7a72a3a4ae5ac374efbc1af527846a0bebf8e6fc24df1e3a', 11),
}


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--repo', required=True, type=Path)
    ap.add_argument('--output', required=True, type=Path)
    ap.add_argument('--phase', required=True, choices=CONTROLS)
    args = ap.parse_args()
    repo, out = args.repo, args.output
    assert repo.is_absolute() and repo.resolve(strict=True) == repo
    assert out.is_absolute() and out.is_relative_to(repo / 'ignored') and not out.exists()
    assert out.parent.resolve(strict=True) == out.parent
    env = dict(PATH='/usr/bin:/bin', LANG='C.UTF-8', LC_ALL='C.UTF-8',
               PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', TMPDIR=str(out / 'tmp'))
    git = lambda *parts: subprocess.check_output(['/usr/bin/git', '-C', str(repo), *parts], env=env, timeout=30)
    sha = lambda b: hashlib.sha256(b).hexdigest()
    assert git('rev-parse', 'HEAD').decode().strip() == REVISION
    assert not git('diff', '--binary', 'HEAD', '--')
    source, source_sha, methods = CONTROLS[args.phase]
    assert sha((repo / source).read_bytes()) == source_sha
    helper = repo / 'tools/unwind-oracle/bounded_command.py'
    assert sha(helper.read_bytes()) == HELPER_SHA
    observer = repo / 'evaluation/trampoline-parallel.py'
    assert observer.read_bytes() == git('show', REVISION + ':evaluation/trampoline-parallel.py')
    spec = importlib.util.spec_from_file_location('_profile_observation', observer)
    observe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(observe)
    own = Path(__file__).resolve().read_bytes()
    os.sched_setaffinity(0, [0, 1, 2, 3])
    out.mkdir()
    (out / 'tmp').mkdir()
    def save(name, value):
        (out / name).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    def snapshot():
        return dict(source=observe.source(repo, '/usr/bin/git', env),
                    python=observe.tool(Path('/usr/bin/python3.9')),
                    helper=observe.tool(helper))
    before = snapshot()
    save('inputs-before.json', before)
    save('hardware.json', dict(host_label='AMD EPYC Zen 5 dev host', architecture=platform.machine(),
         cpu_model=next(x.split(':', 1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines()
                        if x.startswith('model name')), kernel_release=platform.release(), libc=platform.libc_ver()))
    request = dict(argv=['/usr/bin/python3.9', '-B', str(repo / source), '-v'], cwd=str(repo), env=env,
                   stdout=str(out / 'stdout.txt'), stderr=str(out / 'stderr.txt'),
                   cpu_seconds=10, wall_seconds=15, file_bytes=1024 * 1024)
    save('request.json', request)
    argv = ['/usr/bin/timeout', '--signal=TERM', '--kill-after=10s', '25s', '/usr/bin/python3.9', '-B',
            str(helper), '--request', str(out / 'request.json'), '--receipt', str(out / 'receipt.json')]
    save('command.json', dict(argv=argv, cwd=str(repo), env=env, affinity=[0, 1, 2, 3],
         parent_timeout_seconds=40, request_sha256=sha((out / 'request.json').read_bytes()),
         source_revision=REVISION, caller_sha256=sha(own), control_sha256=source_sha,
         helper_sha256=HELPER_SHA, planned_test_methods=methods))
    start = time.monotonic()
    with (out / 'helper.stdout').open('xb') as stdout, (out / 'helper.stderr').open('xb') as stderr:
        child = subprocess.Popen(argv, cwd=repo, env=env, stdin=subprocess.DEVNULL,
                                 stdout=stdout, stderr=stderr, start_new_session=True)
        save('started.json', dict(pid=child.pid))
        try:
            code = child.wait(timeout=40)
            error = None
        except BaseException as exception:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            code, error = child.returncode, repr(exception)
    save('closed.json', dict(exit=code, pid=child.pid, parent_wait_returned=True, parent_error=error,
         seconds=time.monotonic() - start, stdout_sha256=sha((out / 'helper.stdout').read_bytes()),
         stderr_sha256=sha((out / 'helper.stderr').read_bytes())))
    after = snapshot()
    save('inputs-after.json', after)
    receipt = json.loads((out / 'receipt.json').read_bytes())
    passed = (code == 0 and error is None and before == after and own == Path(__file__).resolve().read_bytes()
              and receipt['exit'] == 0 and receipt['absence_proof'] == 'ECHILD'
              and not receipt['unexpected_descendants'] and not receipt['wall_timeout']
              and receipt['cleanup_error'] is None and receipt['aborted'] is None and receipt['inputs_unchanged'])
    result = dict(status='PASS' if passed else 'FAILED', tested_revision=REVISION, phase=args.phase,
                  source_tools_equal=before == after, planned_test_methods=methods,
                  scope='synthetic saved-record admission controls only', qualification_complete=False,
                  actual_production=False, ordinary_application_execution=False, native_execution=False)
    save('summary.json', result)
    print(json.dumps(result, sort_keys=True))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
