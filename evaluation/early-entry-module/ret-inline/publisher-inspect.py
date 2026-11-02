#!/usr/bin/env python3
"""Capture two exact release symbols with closed build custody; never run the ELF.

Run with unoptimized Python -I -B on one externally reserved CPU, inside an
external 120-second owner. --output and --logs must be fresh; --logs must be
beneath ROOT/target/evaluation. Build custody uses the existing
closed.json/owner.json/receipt.json/request.json/artifact.json/Cargo-stream schema.
Symbol overrides are explicit for revisions whose Rust symbol spelling changed.
Optional --snapshot-symbol adds one exact qualification_snapshot_into capture.
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
import resource
import stat
from pathlib import Path

CAP = 1 << 20
OWNER_SHA = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
SHAPE = '_RNvMs0_NtNtNtNtNtNtCs9CC3unfuwZQ_14rapid_profiler15frontend_native9always_on6normal6module5owned11early_entryNtB5_13PhysicalState5shape'
OBSERVER = '_RNCNvNtNtNtCs7JXSczIkGWb_22frontend_native_oracle6normal6module11early_entry5childs6_0B9_'


def stamp(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read(path, cap=CAP):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as f:
        before = os.fstat(f.fileno())
        assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap
        data = f.read(cap + 1)
        assert len(data) == before.st_size
        assert stamp(before) == stamp(os.fstat(f.fileno())) == stamp(os.lstat(path))
    return data, dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), stat=stamp(before))


def pin(path, cap=CAP):
    return read(path, cap)[1]


def save(path, value):
    with path.open('x') as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())


def normal(owner):
    assert owner['exit_code'] == 0 and owner['termination'] is None
    assert owner['cleanup_complete'] is True and owner['reaped_descendants'] == 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'revision', 'executable', 'build-dir', 'build-closed-sha256',
                 'artifact-sha256', 'output', 'logs'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--shape-symbol', default=SHAPE)
    p.add_argument('--observer-symbol', default=OBSERVER)
    p.add_argument('--snapshot-symbol', default=None)
    args = p.parse_args()
    assert re.fullmatch('[0-9a-f]{40}', args.revision)
    for digest in (args.build_closed_sha256, args.artifact_sha256):
        assert re.fullmatch('[0-9a-f]{64}', digest)
    assert re.fullmatch('_RNv[A-Za-z0-9_]+13PhysicalState5shape', args.shape_symbol)
    assert 'early_entry' in args.shape_symbol
    assert re.fullmatch('_RNCNv[A-Za-z0-9_]+11early_entry5child[A-Za-z0-9_]+', args.observer_symbol)
    if args.snapshot_symbol is not None:
        assert re.fullmatch('_RNv[A-Za-z0-9_]+11early_entry13qualification27qualification_snapshot_into',
                            args.snapshot_symbol)
    cpus = sorted(os.sched_getaffinity(0))
    assert len(cpus) == 1
    for which, value in ((resource.RLIMIT_CPU, 15), (resource.RLIMIT_AS, 256 << 20),
                         (resource.RLIMIT_FSIZE, CAP), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(which, (value, value))
    root = Path(args.root).resolve(strict=True)
    elf = Path(args.executable).absolute()
    assert elf.resolve(strict=True) == elf
    build = Path(args.build_dir).resolve(strict=True)
    out = Path(args.output).absolute()
    assert out.resolve() == out and not os.path.lexists(out)
    logs = Path(args.logs).absolute()
    assert logs.resolve() == logs and not os.path.lexists(logs)
    assert logs != root / 'target/evaluation'
    logs.relative_to((root / 'target/evaluation').resolve())
    out.mkdir(parents=True)
    logs.mkdir(parents=True)
    result = dict(status='FAILED', analysis_only=True, subject_executions=0,
                  revision=args.revision, argv=sys.argv, cpus=cpus, logs=str(logs), commands=[], inputs={})
    frozen = {}
    active = None
    try:
        def load(name, digest=None):
            path = build / name
            data, record = read(path)
            if digest is not None:
                assert record['sha256'] == digest
            frozen[path] = record
            result['inputs'][name] = record
            return json.loads(data)

        # Authenticate every cleanup record before reading any build capture.
        closed = load('closed.json', args.build_closed_sha256)
        artifact = load('artifact.json', args.artifact_sha256)
        owner_record = load('owner.json')
        receipt = load('receipt.json')
        request = load('request.json')
        assert closed['owner'] == owner_record and closed['receipt'] == receipt
        normal(owner_record)
        assert receipt['request_sha256'] == result['inputs']['request.json']['sha256']
        assert receipt['exit'] == 0 and receipt['wall_timeout'] is False
        assert receipt['inputs_unchanged'] is True and receipt['absence_proof'] == 'ECHILD'
        assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
        assert receipt['cleanup_error'] is receipt['aborted'] is None
        assert closed['revision'] == artifact['revision'] == args.revision
        assert request['cwd'] == str(root)
        assert request['cpu_seconds'] == 120 and request['wall_seconds'] == 180
        assert request['file_bytes'] == 128 << 20
        assert request['argv'][1:] == ['build', '--bin', 'frontend-native-oracle', '--locked',
            '--offline', '--release', '--jobs', '1', '-p', 'rapid-profiler', '--features',
            'frontend-native-qualification', '--message-format=json-render-diagnostics']
        for name, digest in [('parent.log', owner_record['private_log_sha256']),
                             ('stdout.txt', receipt['stdout_sha256']),
                             ('stderr.txt', receipt['stderr_sha256'])]:
            data, record = read(build / name)
            assert record['sha256'] == digest
            frozen[build / name] = record
            result['inputs'][name] = record
            if name == 'stdout.txt':
                messages = [json.loads(line) for line in data.splitlines()]
        assert messages[-1] == dict(reason='build-finished', success=True)
        products = [m for m in messages if m.get('reason') == 'compiler-artifact'
                    and m['target']['name'] == 'frontend-native-oracle'
                    and m['profile']['test'] is False]
        assert products == [artifact['product']]
        product = products[0]
        assert product['target']['kind'] == product['target']['crate_types'] == ['bin']
        assert product['target']['src_path'] == str(root / 'tools/rapid-profiler/native-interval/main.rs')
        assert product['manifest_path'] == str(root / 'tools/rapid-profiler/Cargo.toml')
        assert product['features'] == ['frontend-native-qualification']
        assert product['profile'] == dict(opt_level='3', debuginfo=0, test=False,
                                          debug_assertions=False, overflow_checks=False)
        assert product['executable'] == str(elf) and product['filenames'] == [str(elf)]
        binary = pin(elf, 32 << 20)
        assert {k: binary[k] for k in ('bytes', 'sha256')} == artifact['binary']
        result['elf_before'] = binary
        result['build'] = dict(path=str(build), tree=closed['tree'], request=request,
                               owner=owner_record, receipt=receipt, artifact=artifact)
        source = Path(__file__).resolve(strict=True)
        tools = {'owner': root / 'evaluation/admission/processes.py',
                 'git': Path('/usr/bin/git'), 'objdump': Path('/usr/bin/objdump'),
                 'prlimit': Path('/usr/bin/prlimit')}
        tools = {name: path.resolve(strict=True) for name, path in tools.items()}
        frozen[source] = pin(source)
        for path in tools.values():
            frozen[path] = pin(path, 8 << 20)
        assert frozen[tools['owner']]['sha256'] == OWNER_SHA
        bound = root / 'tools/unwind-oracle/bounded_command.py'
        frozen[bound] = pin(bound)
        assert frozen[bound]['sha256'] == receipt['helper_sha256']
        result['source'] = frozen[source]
        result['tools'] = {name: dict(path=str(path), **frozen[path]) for name, path in tools.items()}
        spec = importlib.util.spec_from_file_location('publisher_static_owner', tools['owner'])
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)

        def unchanged():
            assert sorted(os.sched_getaffinity(0)) == cpus
            assert pin(elf, 32 << 20) == binary
            for path, expected in frozen.items():
                assert pin(path, max(CAP, expected['bytes'])) == expected

        def capture(name, argv, wall):
            nonlocal active
            command = [str(tools['prlimit']), '--cpu=10', '--as=268435456',
                       '--fsize=1048576', '--core=0', '--'] + argv
            active = dict(name=name, status='DISPATCHED', command=command,
                          wall_seconds=wall, capture_bytes=CAP)
            result['commands'].append(active)
            record = owner.run_command(command, dict(PATH='/usr/bin:/bin', LC_ALL='C'),
                                       logs / (name + '.log'), wall, CAP)
            active['owner'] = record
            save(out / (name + '-owner.json'), active)
            assert record['cleanup_complete'] is True
            data, captured = read(logs / (name + '.log'))
            assert captured['sha256'] == record['private_log_sha256']
            retained = out / (name + '.log')
            with retained.open('xb') as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            assert pin(logs / (name + '.log')) == captured
            retained_pin = pin(retained)
            assert all(retained_pin[k] == captured[k] for k in ('bytes', 'sha256'))
            active['raw_capture'] = dict(path=str(logs / (name + '.log')), **captured)
            active['capture'] = dict(path=str(retained), **retained_pin)
            normal(record)
            active['status'] = 'CLOSED_ZERO'
            return data.decode('utf-8')

        def git_status(name):
            text = capture(name, [str(tools['git']), '-c', 'index.threads=1', '-c',
                'core.preloadIndex=false', '-C', str(root), 'status', '--porcelain=v2',
                '--branch', '--untracked-files=no'], 10)
            lines = text.splitlines()
            assert '# branch.oid ' + args.revision in lines
            assert all(line.startswith('# branch.') for line in lines), 'tracked changes'

        git_status('git-before')
        unchanged()
        roles = [('shape', args.shape_symbol), ('observer', args.observer_symbol)]
        if args.snapshot_symbol is not None:
            roles.append(('snapshot', args.snapshot_symbol))
        for role, symbol in roles:
            text = capture(role, [str(tools['objdump']), '-d', '-M', 'intel',
                                 '--disassemble=' + symbol, str(elf)], 30)
            labels = re.findall(r'^([0-9a-f]+) <([^>]+)>:$', text, re.MULTILINE)
            assert len(labels) == 1 and labels[0][1] == symbol, 'missing/ambiguous exact symbol'
            instructions = re.findall(r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s*\S', text, re.MULTILINE)
            assert instructions and int(instructions[0], 16) == int(labels[0][0], 16)
            active['symbol'] = symbol
            active['start'] = int(labels[0][0], 16)
            unchanged()
        git_status('git-after')
        unchanged()
        result['elf_after'] = pin(elf, 32 << 20)
        result['status'] = 'INSPECTION_COMPLETE'
    except BaseException as error:
        if active is not None:
            active['status'] = 'FAILED'
        result['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        result['limits'] = 'Static capture only; no subject execution, timing, native qualification or strict-profile success.'
        save(out / 'closed.json', result)
    print(json.dumps(dict(status=result['status'], closed=pin(out / 'closed.json'))))
    return 0 if result['status'] == 'INSPECTION_COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
