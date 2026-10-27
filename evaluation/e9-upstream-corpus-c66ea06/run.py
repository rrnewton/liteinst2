#!/usr/bin/env python3
"""Run the unmodified pinned E9Patch self-rewrite corpus in a fresh directory."""
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time

if sys.flags.optimize:
    raise SystemExit('assertions required')
R = Path(__file__).resolve().parents[3]
SOURCE = R / 'ignored/a3/upstream/e9patch-pldi2020'
OUT = R / 'ignored/a3/e9-upstream-corpus-v1'
HELPER = R / 'tools/unwind-oracle/bounded_command.py'
HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
PINS = {
    'e9test.sh': '99456c781101671a7722003ee0f0970ccd24f4d03320734b44ddc080764a6dc5',
    'e9compile.sh': 'd5c3d1e34dc6c2cdf9ffcfb815b679a7af97b8419b12b9e52fee1ff49a225e2b',
    'examples/nop.c': '7ca4be4b594591a4287579862df63af80462b74856b2a85a57444148bcc7f32b',
    'e9tool': '36b05e9a47c9193041d71ed4e14dda87e835e0e2b47e4a82a7d30a7c0d4eeb5e',
    'e9patch': '890f76cb5741b6c7cfba3414ae72a64fd7deddc7d2dd33b17d53e8b906529fdb',
}
ACTIONS = ['=.*:passthru', '=.*:call entry@nop', '=.*:call[naked,after] entry@nop',
           '=.*:call entry(instrAsmStr,instrBytes,rflags,rdi,rip,instrAddr)@nop', '=.*:print']
ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write(name, value):
    with (OUT / name).open('x') as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write('\n')

def main():
    caller_hash = digest(Path(__file__))
    tool_paths = {name: Path('/usr/bin/' + name).resolve(strict=True)
                  for name in ('bash', 'gcc', 'diff', 'dirname', 'timeout', 'python3.9')}
    tool_hashes = {name: digest(path) for name, path in tool_paths.items()}
    assert digest(HELPER) == HELPER_SHA
    assert not OUT.exists() and not OUT.is_symlink()
    assert {0, 1, 2, 3} <= os.sched_getaffinity(0)
    os.sched_setaffinity(0, {0, 1, 2, 3})
    OUT.mkdir()
    write('context.json', dict(revision=subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=R, env=ENV, timeout=10, text=True).strip(),
          hardware='AMD EPYC Zen 5 dev host', architecture=platform.machine(),
          cpu_model=next(line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')),
          tool_hashes=tool_hashes, compiler=subprocess.check_output(['/usr/bin/gcc', '--version'], env=ENV, timeout=10, text=True).splitlines()[0],
          provenance_scope='Selected file bytes only; not complete compiler-chain or runtime-owner admission',
          benchmark=False, caller_sha256=caller_hash))
    work = OUT / 'work'
    work.mkdir()
    for name, sha in PINS.items():
        source = SOURCE / name
        assert digest(source) == sha
        target = work / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        target.chmod(0o644 if name.endswith('.c') else 0o755)
        assert digest(target) == sha
    request = dict(argv=['/bin/bash', './e9test.sh'], cwd=str(work), env=ENV,
                   stdout=str(OUT / 'stdout.txt'), stderr=str(OUT / 'stderr.txt'),
                   cpu_seconds=120, wall_seconds=180, file_bytes=128*1024*1024)
    write('request.json', request)
    argv = ['/usr/bin/timeout', '--signal=TERM', '--kill-after=10s', '190s',
            '/usr/bin/python3.9', '-B', str(HELPER), '--request', str(OUT / 'request.json'),
            '--receipt', str(OUT / 'receipt.json')]
    write('command.json', dict(argv=argv, cwd=str(R), env=ENV, cpus=[0, 1, 2, 3],
          parent_seconds=205, cleanup_seconds=10, source_pins=PINS,
          caller_sha256=digest(Path(__file__)),
          upstream_revision='0d5d36e4c4edcac37ca2499694d64302a391136f'))
    start = time.monotonic()
    child = None
    error = None
    try:
        with (OUT / 'controller.stdout').open('xb') as stdout, (OUT / 'controller.stderr').open('xb') as stderr:
            child = subprocess.Popen(argv, cwd=R, env=ENV, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                child.wait(timeout=205)
            except BaseException as failure:
                error = type(failure).__name__
                if child.poll() is None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    error += ':CLEANUP_WAIT_EXPIRED'
                    raise
                raise
    finally:
        if child is not None:
            write('closed.json', dict(exit=child.returncode, parent_error=error,
                  parent_wait_returned=child.returncode is not None, pid=child.pid,
                  seconds=time.monotonic()-start))
    assert all(digest(SOURCE / n) == digest(work / n) == sha for n, sha in PINS.items())
    assert digest(HELPER) == HELPER_SHA
    assert digest(Path(__file__)) == caller_hash
    assert {name: digest(path) for name, path in tool_paths.items()} == tool_hashes
    receipt = json.loads((OUT / 'receipt.json').read_text())
    assert set(receipt) == {'request_sha256', 'helper_sha256', 'exit', 'wall_timeout', 'unexpected_descendants',
                           'absence_proof', 'stdout_sha256', 'stderr_sha256', 'elapsed_seconds', 'cleanup_events',
                           'cleanup_error', 'aborted', 'inputs_unchanged'}
    assert receipt['request_sha256'] == digest(OUT / 'request.json')
    assert receipt['helper_sha256'] == HELPER_SHA and receipt['inputs_unchanged'] is True
    assert receipt['absence_proof'] == 'ECHILD' and receipt['unexpected_descendants'] == []
    assert receipt['cleanup_events'] == [] and receipt['cleanup_error'] is receipt['aborted'] is None
    assert all(receipt[s + '_sha256'] == digest(OUT / (s + '.txt')) for s in ('stdout', 'stderr'))
    helper_success = receipt['exit'] == 0 and receipt['wall_timeout'] is False
    helper_terminal = dict(exit=receipt['exit'], wall_timeout=receipt['wall_timeout'],
                           absence_proof='ECHILD', descendants=0, success=helper_success)
    assert (OUT / 'controller.stdout').read_text() == json.dumps(helper_terminal) + '\n'
    assert (OUT / 'controller.stderr').read_bytes() == b''
    assert child.returncode == (0 if helper_success else 1) and error is None
    expected = [f'PASSED: {program}' + ('  ' if program == 'e9tool' else ' ') + action
                for action in ACTIONS for program in ('e9tool', 'e9patch')]
    lines = (OUT / 'stdout.txt').read_text().splitlines()
    rows = []
    for index, wanted in enumerate(expected):
        actual = lines[index] if index < len(lines) else None
        status = 'PASS' if actual == wanted else 'FAILED' if actual == wanted.replace('PASSED:', 'FAILED:', 1) else 'UNOBSERVED' if actual is None else 'INVALID_TERMINAL'
        rows.append(dict(expected=wanted, actual=actual, status=status))
    passed = child.returncode == 0 and error is None and receipt['exit'] == 0 and receipt['wall_timeout'] is False and lines == expected
    write('result.json', dict(status='PASS' if passed else 'FAILED', expected_rows=expected,
          actual_rows=lines, cases=rows, unobserved_meaning='No terminal observed; the corresponding rewrite may have started before abort',
          exit=receipt['exit'], qualification_complete=False,
          scope='Upstream self-rewrite corpus only; no LiteInst comparison or performance claim'))
    print(json.dumps(dict(status='PASS' if passed else 'FAILED', observed_rows=len(lines), expected_rows=10)))
    return 0 if passed else 1

if __name__ == '__main__':
    raise SystemExit(main())
