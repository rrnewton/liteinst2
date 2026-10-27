#!/usr/bin/env python3
"""Build and run the finite preemption experiment; keep detailed records private."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    ap = argparse.ArgumentParser(description=__doc__)
    for key in ('repo', 'raw', 'toolchain', 'user-home', 'cargo-home'):
        ap.add_argument('--' + key, type=Path, required=True)
    ap.add_argument('--profile', choices=('full-callback-v1', 'inline-clock-v1'), default='full-callback-v1')
    args = ap.parse_args()
    repo, raw = args.repo, args.raw
    for path in (repo, args.toolchain, args.user_home, args.cargo_home):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
    assert raw.is_absolute() and raw.is_relative_to(repo/'ignored') and not raw.exists()
    assert raw.parent.resolve(strict=True) == raw.parent
    cpus = sorted(os.sched_getaffinity(0))[:4]
    assert len(cpus) == 4
    os.sched_setaffinity(0, cpus)
    spec = importlib.util.spec_from_file_location('preemption_run', repo/'tools/software-preemption/run.py')
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    read, save = runner.read, runner.save
    owner = lambda p: read(p)[1]
    tool = args.toolchain/'bin'
    env = dict(HOME=str(args.user_home), CARGO_HOME=str(args.cargo_home),
        PATH=str(tool)+':/usr/bin:/bin', CARGO_TARGET_DIR=str(repo/'target'),
        CARGO_NET_OFFLINE='true', CARGO_TERM_COLOR='never',
        CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0',
        LANG='C.UTF-8', LC_ALL='C.UTF-8', PYTHONDONTWRITEBYTECODE='1',
        PYTHONNOUSERSITE='1', **runner.BUILD_ENV)
    python = Path(sys.executable).resolve(strict=True)
    timeout, git = Path('/usr/bin/timeout').resolve(), Path('/usr/bin/git').resolve()
    helper = repo/'tools/unwind-oracle/bounded_command.py'
    assert owner(helper)['sha256'] == runner.HELPER_SHA
    def git_command(*parts):
        return subprocess.check_output([str(git), '-C', str(repo), *parts], env=env, timeout=15)
    revision = git_command('rev-parse', 'HEAD').decode().strip()
    def sources():
        assert git_command('rev-parse', 'HEAD').decode().strip() == revision
        assert git_command('status', '--porcelain', '--untracked-files=no') == b''
        names = git_command('ls-files', '-z').decode().rstrip('\0').split('\0')
        return {name: owner(repo/name) for name in names}
    before = sources()
    assert 'BRIEF-li2core.md' not in before
    assert 'tools/software-preemption/run.py' in before
    assert Path(__file__).resolve() == repo/'tools/software-preemption/evaluate.py'
    assert 'tools/software-preemption/evaluate.py' in before
    raw.mkdir(mode=0o700)
    save(raw, 'sources-before.json', before)
    tools = {name: path for name, path in [('cargo', tool/'cargo'), ('rustc', tool/'rustc'), ('python', python), ('timeout', timeout), ('git', git), ('helper', helper)]}
    tool_owners = {name: owner(path) for name, path in tools.items()}
    save(raw, 'tools.json', tool_owners)
    cfg_spec = importlib.util.spec_from_file_location('preemption_configuration', repo/'evaluation/trampoline-parallel.py')
    cfg = importlib.util.module_from_spec(cfg_spec)
    cfg_spec.loader.exec_module(cfg)
    configs = cfg.configuration(repo, args.cargo_home)
    save(raw, 'configurations.json', configs)
    save(raw, 'revision.json', dict(revision=revision,
        caller_sha256=owner(Path(__file__).resolve())['sha256']))

    def launch(directory, argv, environment, bound):
        directory.mkdir()
        command = dict(argv=argv, cwd=str(repo), env=environment,
            affinity=cpus, timeout_seconds=bound, failure_cleanup_seconds=10)
        save(directory, 'command.json', command)
        child, error = None, None
        began = time.monotonic()
        try:
            with (directory/'stdout.txt').open('xb') as out, (directory/'stderr.txt').open('xb') as err:
                child = subprocess.Popen(argv, cwd=repo, env=environment, stdin=subprocess.DEVNULL,
                    stdout=out, stderr=err, start_new_session=True)
                try:
                    save(directory, 'started.json', dict(pid=child.pid))
                    child.wait(timeout=bound)
                except BaseException as failure:
                    error = repr(failure)
                    if child.poll() is None:
                        try: os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError: pass
                    child.wait(timeout=10)
                    raise
        finally:
            if child is not None:
                closed = dict(exit=child.returncode, pid=child.pid, parent_error=error,
                    parent_wait_returned=child.returncode is not None, seconds=time.monotonic()-began)
                save(directory, 'closed.json', closed)
        assert child is not None and child.returncode == 0 and error is None
        return command, closed

    build = raw/'build'; build.mkdir(); (build/'tmp').mkdir()
    build_env = dict(env, TMPDIR=str(build/'tmp'))
    argv = [str(tool/'cargo'), 'build', '--locked', '--offline', '--release', '--bin', 'liteinst-preempt']
    request = dict(argv=argv, cwd=str(repo), env=build_env,
        stdout=str(build/'stdout.txt'), stderr=str(build/'stderr.txt'),
        cpu_seconds=120, wall_seconds=180, file_bytes=128*1048576)
    save(build, 'request.json', request)
    outer = [str(timeout), '--signal=TERM', '--kill-after=10s', '190s', str(python), '-B', str(helper),
        '--request', str(build/'request.json'), '--receipt', str(build/'receipt.json')]
    _, build_closed = launch(build/'parent', outer, env, 205)
    receipt = json.loads(read(build/'receipt.json')[0])
    assert receipt['exit'] == 0 and receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
    assert receipt['request_sha256'] == owner(build/'request.json')['sha256']
    assert receipt['helper_sha256'] == runner.HELPER_SHA and receipt['absence_proof'] == 'ECHILD'
    assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
    assert receipt['cleanup_error'] is receipt['aborted'] is None
    for name in ('stdout', 'stderr'):
        assert receipt[name+'_sha256'] == owner(build/(name+'.txt'))['sha256']
    assert read(build/'parent/stderr.txt')[0] == b''
    assert json.loads(read(build/'parent/stdout.txt')[0]) == dict(exit=0,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=True)
    assert sources() == before
    assert {name: owner(path) for name, path in tools.items()} == tool_owners
    assert cfg.configuration(repo, args.cargo_home) == configs
    save(raw, 'sources-after-build.json', before)
    binary = repo/'target/release/liteinst-preempt'
    # This invocation's successful Cargo build and unchanged source catalog admit
    # its exact product. A fresh compiler process is not required on a cache hit.
    build_command = dict(argv=argv, cwd=str(repo), env=build_env)
    save(build, 'cargo-command.json', build_command)
    evidence = [build/name for name in ('request.json', 'receipt.json', 'cargo-command.json', 'stdout.txt', 'stderr.txt', 'parent/command.json', 'parent/closed.json')]
    evidence += [raw/name for name in ('sources-before.json', 'sources-after-build.json', 'tools.json', 'configurations.json', 'revision.json')]
    binding = dict(schema=1, authority='ROOT_REVIEWED_PREEMPT_RELEASE_BINARY', revision=revision,
        repo=str(repo), caller_sha256=before['tools/software-preemption/run.py']['sha256'],
        binary=str(binary), binary_owner=owner(binary), sources=before, affinity=cpus,
        tools={name:dict(path=str(path), owner=owner(path)) for name,path in
            [('python',python),('timeout',timeout),('git',git),('helper',helper)]},
        build=dict(command=build_command, closed=build_closed, files={str(p):owner(p) for p in evidence}))
    if args.profile == 'inline-clock-v1':
        binding['authority'] = 'ROOT_REVIEWED_INLINE_CLOCK_RELEASE_BINARY'
        binding['profile'] = args.profile
    save(raw, 'binding.json', binding)
    call = [str(python), '-B', str(repo/'tools/software-preemption/run.py'),
        '--binding', str(raw/'binding.json'), '--binding-sha256', owner(raw/'binding.json')['sha256'],
        '--raw', str(raw/'experiment')]
    if args.profile == 'inline-clock-v1':
        call += ['--profile', 'inline-clock-v1']
        # Six fixed commands: 6 * 115 seconds + the same 75-second caller allowance.
        # This changes only the whole-experiment parent, never a child/resource cap.
        launch(raw/'experiment-parent', call, env, 765)
    else:
        launch(raw/'experiment-parent', call, env, 650)
    summary = json.loads(read(raw/'experiment/summary.json')[0])
    assert summary['status'] == 'PASS' and sources() == before
    print(json.dumps(summary, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
