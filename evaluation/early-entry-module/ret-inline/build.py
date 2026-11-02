#!/usr/bin/env python3
"""Produce CLOSED release-build custody for inspect.py; never execute the ELF.

Use unoptimized Python -I -B on one externally reserved CPU. --toolchain names
the Rust toolchain directory containing bin/. --output must be fresh under
ROOT/ignored; --logs must be fresh under ROOT/target/evaluation. The build uses
120 CPU seconds, 180 wall seconds and 128 MiB files, with a 205-second/1 MiB
process owner. No private validation receipt or prior request is required.
"""
import sys
if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit('require unoptimized Python -I -B')
import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
from pathlib import Path


def stamp(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def pin(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as f:
        before = os.fstat(f.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_size <= 512 << 20
        digest = hashlib.sha256()
        size = 0
        while chunk := f.read(1 << 20):
            digest.update(chunk)
            size += len(chunk)
            assert size <= 512 << 20
        assert size == before.st_size
        assert stamp(before) == stamp(os.fstat(f.fileno())) == stamp(os.lstat(path))
    return dict(bytes=size, sha256=digest.hexdigest())


def save(path, value):
    with path.open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'revision', 'toolchain', 'user-home', 'cargo-home', 'output', 'logs'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    assert re.fullmatch('[0-9a-f]{40}', args.revision)
    root = Path(args.root).resolve(strict=True)
    bins = Path(args.toolchain).resolve(strict=True) / 'bin'
    user_home = Path(args.user_home).resolve(strict=True)
    cargo_home = Path(args.cargo_home).resolve(strict=True)
    out, logs = Path(args.output).absolute(), Path(args.logs).absolute()
    for path, parent in ((out, root / 'ignored'), (logs, root / 'target/evaluation')):
        assert path.resolve() == path and path != parent and not os.path.lexists(path)
        path.relative_to(parent.resolve())
    cpus = sorted(os.sched_getaffinity(0))
    assert len(cpus) == 1
    out.mkdir(parents=True)
    logs.mkdir(parents=True)
    env = dict(CARGO_BUILD_JOBS='1', CARGO_HOME=str(cargo_home), CARGO_INCREMENTAL='0',
               CARGO_NET_OFFLINE='true', CARGO_PROFILE_RELEASE_DEBUG='0',
               CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='false', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
               CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='false', CARGO_TARGET_DIR=str(root / 'target'),
               CARGO_TERM_COLOR='never', CC='/usr/bin/gcc', HOME=str(user_home), LC_ALL='C',
               PATH=str(bins) + ':/usr/bin:/bin', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1',
               RUSTC=str(bins / 'rustc'), RUSTDOC=str(bins / 'rustdoc'))
    argv = [str(bins / 'cargo'), 'build', '--bin', 'frontend-native-oracle', '--locked', '--offline',
            '--release', '--jobs', '1', '-p', 'rapid-profiler', '--features',
            'frontend-native-qualification', '--message-format=json-render-diagnostics']
    request = dict(argv=argv, env=env, cwd=str(root), cpu_seconds=120, wall_seconds=180,
                   file_bytes=128 << 20, stdout=str(out / 'stdout.txt'), stderr=str(out / 'stderr.txt'))
    helper = root / 'evaluation/admission/processes.py'
    bound = root / 'tools/unwind-oracle/bounded_command.py'
    source = Path(__file__).resolve(strict=True)
    tools = [helper, bound, bins / 'cargo', bins / 'rustc', bins / 'rustdoc',
             Path('/usr/bin/git'), Path('/usr/bin/gcc'), Path('/usr/bin/python3.9')]
    frozen = {path.resolve(strict=True): pin(path.resolve(strict=True)) for path in [source] + tools}
    assert frozen[helper]['sha256'] == '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
    assert frozen[bound]['sha256'] == 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
    git = ['/usr/bin/git', '-c', 'index.threads=1', '-c', 'core.preloadIndex=false', '-C', str(root)]

    def clean():
        assert subprocess.check_output(git + ['rev-parse', 'HEAD'], env=env, timeout=15).decode().strip() == args.revision
        assert subprocess.check_output(git + ['status', '--porcelain', '--untracked-files=no'], env=env, timeout=15) == b''
        assert sorted(os.sched_getaffinity(0)) == cpus
        assert all(pin(path) == expected for path, expected in frozen.items())

    command = ['/usr/bin/python3.9', '-I', '-B', str(bound), '--request', str(out / 'request.json'),
               '--receipt', str(out / 'receipt.json')]
    closed = dict(status='FAILED', revision=args.revision, cpus=cpus, load=os.getloadavg(),
                  command=command, source=frozen[source], performance_qualified=False,
                  tools={str(path): value for path, value in frozen.items()}, subject_executions=0)
    try:
        clean()
        closed['tree'] = subprocess.check_output(git + ['rev-parse', 'HEAD^{tree}'], env=env, timeout=15).decode().strip()
        save(out / 'request.json', request)
        save(out / 'intent.json', closed)
        spec = importlib.util.spec_from_file_location('publisher_build_owner', helper)
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        record = owner.run_command(command, env, logs / 'build.log', 205, 1 << 20)
        save(out / 'owner.json', record)
        closed['owner'] = record
        assert record['cleanup_complete'] is True
        assert pin(logs / 'build.log')['sha256'] == record['private_log_sha256']
        data = (logs / 'build.log').read_bytes()
        assert hashlib.sha256(data).hexdigest() == record['private_log_sha256']
        with (out / 'parent.log').open('xb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        assert pin(out / 'parent.log') == pin(logs / 'build.log')
        receipt = json.loads((out / 'receipt.json').read_text())
        closed['receipt'] = receipt
        assert record['exit_code'] == 0 and record['termination'] is None and record['reaped_descendants'] == 0
        assert receipt['request_sha256'] == pin(out / 'request.json')['sha256']
        assert receipt['helper_sha256'] == frozen[bound]['sha256']
        assert receipt['exit'] == 0 and receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
        assert receipt['absence_proof'] == 'ECHILD' and receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
        assert receipt['cleanup_error'] is receipt['aborted'] is None
        for stream in ('stdout', 'stderr'):
            assert pin(out / (stream + '.txt'))['sha256'] == receipt[stream + '_sha256']
        messages = [json.loads(line) for line in (out / 'stdout.txt').read_text().splitlines()]
        assert messages[-1] == dict(reason='build-finished', success=True)
        products = [m for m in messages if m.get('reason') == 'compiler-artifact'
                    and m['target']['name'] == 'frontend-native-oracle' and m['profile']['test'] is False]
        assert len(products) == 1
        product = products[0]
        assert product['manifest_path'] == str(root / 'tools/rapid-profiler/Cargo.toml')
        assert product['target']['src_path'] == str(root / 'tools/rapid-profiler/native-interval/main.rs')
        assert product['target']['kind'] == product['target']['crate_types'] == ['bin']
        assert product['features'] == ['frontend-native-qualification']
        assert product['profile'] == dict(opt_level='3', debuginfo=0, test=False, debug_assertions=False, overflow_checks=False)
        elf = root / 'target/release/frontend-native-oracle'
        assert product['executable'] == str(elf) and product['filenames'] == [str(elf)] and elf.resolve(strict=True) == elf
        clean()
        save(out / 'artifact.json', dict(revision=args.revision, product=product, binary=pin(elf)))
        closed['status'] = 'RELEASE_BUILD_PASS'
    except BaseException as error:
        closed['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        save(out / 'closed.json', closed)
    print(json.dumps(dict(status=closed['status'], closed=pin(out / 'closed.json'))))
    return 0 if closed['status'] == 'RELEASE_BUILD_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
