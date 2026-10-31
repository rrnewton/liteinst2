#!/usr/bin/env python3
"""Repeat one fixed focused phase using the existing bounded process owner."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REVISION = '27e57a250104f0b0e55e9ac441e0b96217ec010d'
LIMIT = 8 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=sha(raw))


def save(path, value):
    pending = path.with_suffix('.next')
    pending.write_bytes(canonical(value) + b'\n')
    pending.replace(path)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def commands(phase, cargo, python, legacy):
    if phase == 'python':
        rows = [(name, argv) for name, kind, argv in legacy.commands(cargo, python)
                if kind == 'python_tests']
        rows += [('python-18', [python, '-I', '-B', '-m', 'unittest', 'discover', '-s',
                              'evaluation/ordinary-accuracy', '-p', 'prepared_phase_controls.py', '-v']),
                 ('python-19', [python, '-I', '-B',
                                'evaluation/ordinary-selected-session/prepared_phase_functional_controls.py', '-v'])]
        assert len(rows) == 19
        return rows
    assert phase == 'rust'
    common = ['--locked', '--offline', '--jobs', '4', '-p', 'rapid-profiler']
    test = [cargo, 'test'] + common + ['--bin', 'ordinary-interval', '--all-features', '--']
    return [('fmt', [cargo, 'fmt', '--all', '--', '--check']),
            ('check', [cargo, 'check'] + common + ['--all-targets', '--all-features']),
            ('clippy', [cargo, 'clippy'] + common + ['--all-targets', '--all-features', '--', '-D', 'warnings']),
            ('ordinary-list', test + ['--list']), ('ordinary-run', test + ['--test-threads=316'])]


def rust_census(raw, name, expected, legacy):
    text = raw.decode()
    if name == 'ordinary-list':
        names = re.findall(r'^(\S+): test$', text, re.M)
        legacy.identity(names, expected)
        assert re.findall(r'^(\d+) tests, (\d+) benchmarks$', text, re.M) == [('507', '0')]
        return 0
    if name != 'ordinary-run':
        return 0
    ignored = 'ignored, ' + expected['ignored_reason']
    pattern = r'^test (\S+)(?: - should panic)? \.\.\. (ok|FAILED|' + re.escape(ignored) + r')$'
    rows = re.findall(pattern, text, re.M)
    legacy.identity([n for n, _ in rows], expected)
    assert [n for n, status in rows if status == ignored] == [expected['ignored_name']]
    assert sum(status == 'ok' for _, status in rows) == 506
    assert all(status in ('ok', ignored) for _, status in rows)
    assert len(re.findall(r'^test (\S+) - should panic \.\.\. ok$', text, re.M)) == 22
    assert all(sum(n.endswith('::' + required) and status == 'ok' for n, status in rows) == 1
               for required in expected['new_names'])
    assert re.findall(r'^running (\d+) tests$', text, re.M) == ['507']
    summaries = re.findall(r'^test result:.*$', text, re.M)
    assert len(summaries) == 1 and re.fullmatch(
        r'test result: ok\. 506 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in [0-9.]+s', summaries[0])
    return 506


def main():
    assert __debug__ and not sys.flags.optimize
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'toolchain', 'user-home', 'cargo-home'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--phase', choices=('rust', 'python'), required=True)
    parser.add_argument('--cpus', required=True, help='Four CPUs held by one caller-owned reservation')
    parser.add_argument('--name', required=True, help='Fresh target/evaluation basename; no resume')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    root, toolchain = args.root.resolve(strict=True), args.toolchain.resolve(strict=True)
    user_home, cargo_home = args.user_home.resolve(strict=True), args.cargo_home.resolve(strict=True)
    assert re.fullmatch(r'[a-zA-Z0-9_-]+', args.name)
    cpus = list(map(int, args.cpus.split(',')))
    assert len(cpus) == 4 and cpus == sorted(set(cpus)) and set(cpus) <= os.sched_getaffinity(0)
    os.sched_setaffinity(0, cpus)
    os.chdir(root)
    receipt_bytes = (HERE / 'receipt.json').read_bytes()
    receipt = json.loads(receipt_bytes)
    tools = {name: toolchain / 'bin' / name for name in receipt['tools'] if name != 'python3.9'}
    tools['python3.9'] = Path(sys.executable).resolve(strict=True)
    publication = {HERE / 'receipt.json': pin(HERE / 'receipt.json'), Path(__file__).resolve(): pin(Path(__file__).resolve())}

    def unchanged():
        def git(*argv):
            return subprocess.check_output(['git', '-C', str(root), *argv], timeout=10)
        assert git('rev-parse', 'HEAD').decode().strip() == REVISION
        assert not git('diff', '--name-only', 'HEAD', '--') and not git('diff', '--cached', '--name-only', '--')
        assert not git('ls-files', '--', 'BRIEF-li2core.md')
        assert set(git('ls-files', '--others', '--exclude-standard', '-z').split(b'\0')) <= {b'', b'BRIEF-li2core.md'}
        paths = git('diff', '--name-only', '-z', receipt['execution_base'], REVISION, '--').decode().rstrip('\0').split('\0')
        assert len(paths) == receipt['source_overlay']['files'] == 39
        assert sha(canonical({name: pin(root / name) for name in paths})) == receipt['source_overlay']['manifest_sha256']
        assert {name: pin(path) for name, path in tools.items()} == receipt['tools']
        assert all(pin(root / name) == value for name, value in receipt['helpers'].items())
        assert all(pin(path) == value for path, value in publication.items())
        assert os.sched_getaffinity(0) == set(cpus)

    unchanged()
    owner = load(root / 'evaluation/admission/processes.py', 'prepared_public_owner')
    legacy = load(root / 'evaluation/ordinary-accuracy-results/focused-071/reproduce.py', 'prepared_public_census')
    stages = commands(args.phase, str(tools['cargo']), str(tools['python3.9']), legacy)
    assert sha(canonical(commands(args.phase, '$CARGO', '$PYTHON', legacy))) == receipt['commands_sha256'][args.phase]
    out = root / 'target/evaluation' / args.name
    if not args.worker:
        out.mkdir(parents=True, exist_ok=False)
        (out / 'tmp').mkdir()
    assert out.is_dir()
    env = {k: v for k, v in receipt['environment'].items() if not v.startswith('$')}
    env.update(HOME=str(user_home), CARGO_HOME=str(cargo_home), PATH=str(toolchain / 'bin') + ':/usr/bin:/bin',
               RUSTC=str(tools['rustc']), RUSTDOC=str(tools['rustdoc']), CARGO_TARGET_DIR=str(root / 'target'),
               TMPDIR=str(out / 'tmp'), TMP=str(out / 'tmp'), TEMP=str(out / 'tmp'))
    if not args.worker:
        argv = [str(tools['python3.9']), '-B', str(Path(__file__).resolve()), '--root', str(root),
                '--toolchain', str(toolchain), '--user-home', str(user_home), '--cargo-home', str(cargo_home),
                '--phase', args.phase, '--cpus', args.cpus, '--name', args.name, '--worker']
        load_before = os.getloadavg()
        closed = owner.run_command(argv, env, out / 'outer.log', 1200, LIMIT)
        result = dict(status='FAILED', revision=REVISION, phase=args.phase, cpus=cpus, reservation='caller-held',
                      load_before=load_before, load_after=os.getloadavg(), closed=closed, qualification='NONE')
        save(out / 'result.json', result)
        if closed['cleanup_complete'] is True:
            unchanged()
            raw = (out / 'outer.log').read_bytes()
            assert len(raw) <= LIMIT and sha(raw) == closed['private_log_sha256']
            child = json.loads((out / 'child.json').read_bytes()) if (out / 'child.json').exists() else None
            result['child'] = child
            if legacy.normal(closed, 1200) and child is not None and child['all_pass']:
                result['status'] = 'PASS'
        save(out / 'result.json', result)
        print(json.dumps(dict(status=result['status'], phase=args.phase)))
        return int(result['status'] != 'PASS')
    rows = [dict(name=name, status='UNRUN', attempts=0) for name, _ in stages]

    def checkpoint(complete=False):
        passed = complete and all(row['status'] == 'PASS' for row in rows)
        save(out / 'child.json', dict(all_pass=passed, rows=rows, qualification='PENDING_OUTER_CLOSURE; NONE'))
        return passed

    checkpoint()
    for (name, argv), row in zip(stages, rows):
        if name == 'ordinary-run' and rows[-2]['status'] != 'PASS':
            row['reason'] = 'required complete listing did not pass'
            checkpoint()
            continue
        unchanged()
        seconds = 180 if args.phase == 'rust' else 60
        row.update(status='DISPATCHED_UNRESOLVED', attempts=1, argv=argv, load_before=os.getloadavg())
        checkpoint()
        closed = owner.run_command(argv, env, out / (name + '.log'), seconds, LIMIT)
        row.update(status='CLOSED_UNRESOLVED', closed=closed)
        checkpoint()
        if closed['cleanup_complete'] is not True:
            break
        unchanged()
        raw = (out / (name + '.log')).read_bytes()
        assert len(raw) <= LIMIT and sha(raw) == closed['private_log_sha256']
        row.update(status='FAILED', load_after=os.getloadavg())
        try:
            count = (rust_census(raw, name, receipt['rust_census'], legacy) if args.phase == 'rust'
                     else legacy.census(raw, 'python_tests', receipt['python_census'][name]))
            if legacy.normal(closed, seconds):
                row.update(status='PASS', passed=count)
        except (AssertionError, UnicodeError, ValueError) as error:
            row['census_refused'] = str(error) or type(error).__name__
        checkpoint()
    unchanged()
    return int(not checkpoint(complete=True))


if __name__ == '__main__':
    raise SystemExit(main())
