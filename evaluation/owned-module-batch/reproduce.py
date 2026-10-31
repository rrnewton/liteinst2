#!/usr/bin/env python3
"""Build the fixed two-DSO owned-batch fixture and run its one native test once.

Run under an externally owned one-CPU HARD reservation. Private evidence stays
under ignored/; existing command owners provide all child/descendant cleanup.
This is an integration control, not a performance or full-A5 qualification.
"""
import sys
if not __debug__ or not sys.flags.isolated or not sys.flags.dont_write_bytecode:
    raise SystemExit('use Python -I -B with assertions enabled')
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

MIB = 1048576
TEST = 'frontend_native::always_on::normal::module::owned::native::owned_module_native_four_call_batches_epochs_and_close'
PINS = {
    'evaluation/admission/processes.py': '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f',
    'tools/unwind-oracle/bounded_command.py': 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44',
    'evaluation/ordinary-module-native/reproduce.py': '5cce60e76d7ec2011c8facb0a5c1101e0100e13aac8ed9b6317846de35fd3146',
    'tools/rapid-profiler/verify_normal_interval.py': '7a1e480c8fb815bb62165773650a0f8590c5bdc6ba39fc1189c63bceb1e085a7',
}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', required=True)
    for name in ('root', 'toolchain', 'user-home', 'cargo-home', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    a = parser.parse_args()
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    root = a.root.resolve(strict=True)
    assert root == a.root and all(p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
                                  for p in (a.toolchain, a.user_home, a.cargo_home))
    raw = a.output
    assert raw.is_absolute() and raw.parent.resolve(strict=True) == raw.parent and raw.is_relative_to(root/'ignored')
    raw.mkdir(mode=0o700)  # Exclusive campaign directory: never resume/retry.
    save = lambda path, value: path.open('x').write(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n')
    result = dict(status='FAILED', revision=a.revision, native_attempts=0, stages=[], performance_qualified=False, A5_qualified=False)
    frozen = {}; tools = {}; safe = True; started = time.monotonic()
    try:
        tools = {n: (a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo', 'rustc', 'rustdoc')}
        tools.update({n: Path('/usr/bin', n).resolve(strict=True) for n in ('gcc', 'readelf', 'objdump', 'git')})
        tools['python'] = Path(sys.executable).resolve(strict=True)
        env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home), PATH=str(a.toolchain/'bin')+':/usr/bin:/bin',
                   RUSTC=str(tools['rustc']), RUSTDOC=str(tools['rustdoc']), CC=str(tools['gcc']),
                   CARGO_TARGET_DIR=str(root/'target'), CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='1',
                   CARGO_NET_OFFLINE='true', CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0',
                   CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
                   CARGO_TERM_COLOR='never', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
        def git(*args):
            data = subprocess.check_output([str(tools['git']), '-C', str(root), *args], env=env, timeout=15)
            assert len(data) <= 16*MIB
            return data
        def clean():
            assert git('rev-parse', '--show-toplevel').decode().strip() == str(root)
            assert git('rev-parse', 'HEAD').decode().strip() == a.revision
            assert git('status', '--porcelain', '--untracked-files=no') == b''
        clean()
        for name, expected in PINS.items():
            content = (root/name).read_bytes()
            assert hashlib.sha256(content).hexdigest() == expected and content == git('show', a.revision+':'+name)
        recipe = load('owned_module_existing_recipe', root/'evaluation/ordinary-module-native/reproduce.py')
        owner = load('owned_module_existing_owner', root/'evaluation/admission/processes.py')
        normal = load('owned_module_existing_flags', root/'tools/rapid-profiler/verify_normal_interval.py')
        pin, read = recipe.digest, recipe.read
        def retain(path):
            value = pin(path)
            if str(path) in frozen: assert frozen[str(path)] == value
            else: frozen[str(path)] = value
            return value
        sources = [*PINS, 'Cargo.toml', 'Cargo.lock', 'tools/rapid-profiler/Cargo.toml',
                   'tools/rapid-profiler/normal-work/csv_fields.c', 'tools/rapid-profiler/strnlen-work/strnlen.c',
                   'tools/rapid-profiler/strnlen-work/localize.map', 'tools/rapid-profiler/normal-work/module_caller.c',
                   'tools/rapid-profiler/normal-work/module_caller_bytes.rs',
                   'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned.rs',
                   'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/native.rs']
        for name in sources:
            assert read(root/name, MIB) == git('show', a.revision+':'+name)
            retain(root/name)
        for path in [Path(__file__).resolve(), *tools.values()]: retain(path)
        assert retain(root/sources[7])['sha256'] == recipe.CSV_SOURCE_SHA
        assert retain(root/sources[8])['sha256'] == recipe.LENGTH_SOURCE_SHA
        assert retain(root/'tools/rapid-profiler/normal-work/module_caller.c')['sha256'] == recipe.CALLER_SOURCE_SHA
        cpus = sorted(os.sched_getaffinity(0)); assert len(cpus) == 1
        hardware = Path('/proc/cpuinfo').read_bytes(); assert len(hardware) <= 4*MIB
        (raw/'cpuinfo.txt').write_bytes(hardware)
        records = [dict(line.split(':', 1) for line in block.splitlines() if ':' in line) for block in hardware.decode().strip().split('\n\n')]
        records = [{k.strip(): v.strip() for k, v in row.items()} for row in records]
        cpu = [row for row in records if row.get('processor') == str(cpus[0])]; assert len(cpu) == 1
        flags = cpu[0]['flags'].split(); assert 'rdtscp' in flags and 'ibt' not in flags
        result['host'] = dict(utc=dt.datetime.now(dt.timezone.utc).isoformat(), affinity=cpus, load=os.getloadavg(),
                            uname=list(os.uname()), cpu=cpu[0], cpuinfo=retain(raw/'cpuinfo.txt'),
                            cgroup=Path('/proc/self/cgroup').read_text(), boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        logs = root/'target/evaluation'/raw.name; logs.mkdir(parents=True, exist_ok=False)
        save(raw/'intent.json', dict(revision=a.revision, argv=sys.argv, env=env, tools={k: str(v) for k,v in tools.items()},
                                    native_test=TEST, native_attempts=1, retries=0, scope='fixed owned-batch integration only', host=result['host']))
        def stage(name, argv, cpu_seconds=20, wall=30, cap=MIB, extra=None):
            nonlocal safe
            assert time.monotonic()-started < 1200 and sorted(os.sched_getaffinity(0)) == cpus
            directory = raw/name; directory.mkdir()
            request = dict(argv=list(map(str, argv)), cwd=str(root), env=env | (extra or {}),
                           stdout=str(directory/'stdout.txt'), stderr=str(directory/'stderr.txt'),
                           cpu_seconds=cpu_seconds, wall_seconds=wall, file_bytes=cap)
            save(directory/'request.json', request); request_pin = retain(directory/'request.json')
            command = [str(tools['python']), '-I', '-B', str(root/'tools/unwind-oracle/bounded_command.py'),
                       '--request', str(directory/'request.json'), '--receipt', str(directory/'receipt.json')]
            save(directory/'intent.json', dict(argv=command, wall_seconds=wall+25, log_bytes=MIB))
            row = dict(name=name, status='DISPATCHED_UNKNOWN', request=request_pin); result['stages'].append(row)
            if name == 'native': result['native_attempts'] = 1
            safe = False
            closed = owner.run_command(command, env, logs/(name+'.log'), wall+25, MIB)
            save(directory/'closed.json', closed); row['closed'] = closed; safe = closed['cleanup_complete'] is True
            assert safe
            parent = read(logs/(name+'.log'), MIB)
            assert hashlib.sha256(parent).hexdigest() == closed['private_log_sha256']
            (directory/'parent.log').write_bytes(parent)
            recipe.closed_ok(closed)  # Authenticate terminal owner before any child output.
            receipt = json.loads(read(directory/'receipt.json', MIB)); row['receipt'] = receipt
            assert receipt['request_sha256'] == request_pin['sha256'] and receipt['helper_sha256'] == PINS['tools/unwind-oracle/bounded_command.py']
            assert receipt['exit'] == 0 and receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
            assert receipt['absence_proof'] == 'ECHILD' and receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
            assert receipt['aborted'] is receipt['cleanup_error'] is None
            for stream in ('stdout', 'stderr'): assert receipt[stream+'_sha256'] == retain(directory/(stream+'.txt'))['sha256']
            row['status'] = 'CLOSED_EXIT_ZERO'
            return read(directory/'stdout.txt', cap), read(directory/'stderr.txt', cap)
        for name, path in tools.items():
            out, err = stage('version-'+name, [path, '-vV' if name == 'rustc' else '--version'])
            result.setdefault('versions', {})[name] = dict(stdout=out.decode(), stderr=err.decode(), file=retain(path))
        for name in ('cc1', 'collect2', 'as', 'ld'):
            out, err = stage('gcc-'+name, [tools['gcc'], '-print-prog-name='+name]); assert err == b''
            value = out.decode().strip(); assert out == (value+'\n').encode()
            path = Path(value) if '/' in value else Path(shutil.which(value, path=env['PATH']) or '')
            assert path.is_absolute(); retain(path.resolve(strict=True))
        for label, inputs, options in (
                ('module', ['normal-work/csv_fields.c', 'strnlen-work/strnlen.c'], recipe.MODULE_FLAGS),
                ('caller', ['normal-work/module_caller.c'], normal.CALLER_FLAGS)):
            expected, candidate = raw/(label+'-trusted.so'), raw/(label+'-candidate.so')
            out, err = stage(label+'-build', [tools['gcc'], *options, *[root/'tools/rapid-profiler'/p for p in inputs], '-o', expected], 60, 90, 128*MIB)
            assert out == err == b''; content = read(expected, MIB); assert content
            with candidate.open('xb') as stream: stream.write(content)
            assert (expected.stat().st_dev, expected.stat().st_ino) != (candidate.stat().st_dev, candidate.stat().st_ino)
            assert retain(expected) == retain(candidate)
            result.setdefault('fixtures', {})[label] = {p.name: dict(device=p.stat().st_dev, inode=p.stat().st_ino, **retain(p)) for p in (expected, candidate)}
        symbols = {}
        for label in ('module', 'caller'):
            out, err = stage(label+'-elf', [tools['readelf'], '--wide', '--file-header', '--program-headers', '--dynamic', '--syms', '--relocs', raw/(label+'-trusted.so')])
            assert err == b'' and not re.search(rb'\((NEEDED|INIT|FINI|INIT_ARRAY|FINI_ARRAY|PREINIT_ARRAY)\)|\bIFUNC\b', out)
            symbols[label] = out
        selections = [recipe.selection(symbols['module'], n, ceiling) for n,ceiling in (('csv_fields',256), ('strnlen',80))]
        spans = sorted(selections); assert spans[0][0]+spans[0][1] <= spans[1][0]
        assert spans[0][0]//4096 == (spans[1][0]+spans[1][1]-1)//4096
        bodies = []
        for name, (va, length) in zip(('csv_fields', 'strnlen'), selections):
            out, err = stage(name+'-body', [tools['objdump'], '-d', '-M', 'intel', '--insn-width=16', '--disassemble='+name, raw/'module-trusted.so']); assert err == b''
            bodies.append(recipe.body_geometry(recipe.geometry(out,name,va,length),va,length,name=='strnlen'))
        out, err = stage('caller-body', [tools['objdump'], '-d', '-M', 'intel', '--insn-width=16', '--disassemble=normal_module_caller', raw/'caller-trusted.so']); assert err == b''
        caller = recipe.caller_geometry(out, symbols['caller'])
        save(raw/'geometry.json', dict(selections=selections, bodies=bodies, caller=caller))
        out, _ = stage('release-libtest', [tools['cargo'], 'test', '--locked', '--offline', '--release', '--jobs', '1', '-p', 'rapid-profiler', '--lib', '--no-run', '--message-format=json-render-diagnostics'], 120, 180, 128*MIB)
        messages = [json.loads(line) for line in out.splitlines()]; assert messages[-1] == dict(reason='build-finished', success=True)
        products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == 'rapid_profiler' and m['profile']['test']]
        assert len(products) == 1; product = products[0]
        assert product['manifest_path'] == str(root/'tools/rapid-profiler/Cargo.toml')
        assert product['target']['src_path'] == str(root/'tools/rapid-profiler/src/lib.rs')
        assert product['target']['kind'] == product['target']['crate_types'] == ['lib']
        assert product['profile'] == dict(opt_level='3', debuginfo=0, test=True, debug_assertions=True, overflow_checks=True)
        binary = Path(product['executable']); assert binary.resolve(strict=True) == binary and binary.parent == root/'target/release/deps'
        assert re.fullmatch('rapid_profiler-[0-9a-f]+', binary.name)
        save(raw/'artifact.json', dict(product=product, binary=retain(binary)))
        extra = {f'RAPID_OWNED_{kind}_{role}': str(raw/(name+'-'+suffix+'.so'))
                 for kind,name in (('MODULE','module'),('CALLER','caller')) for role,suffix in (('EXPECTED','trusted'),('CANDIDATE','candidate'))}
        for prefix, (va,length) in zip(('CSV','LENGTH'), selections):
            extra['RAPID_OWNED_'+prefix+'_VA'] = str(va); extra['RAPID_OWNED_'+prefix+'_LENGTH'] = str(length)
        extra['RAPID_OWNED_CALLER_VA'] = str(caller['elf_va'])
        clean(); recipe.pins_ok(frozen)
        out, err = stage('native', [binary, TEST, '--exact', '--ignored', '--test-threads=1', '--nocapture'], extra=extra)
        assert err == b'' and out.decode().splitlines()[0:3] == ['', 'running 1 test', 'test '+TEST+' ... ok']
        assert re.fullmatch(r'\ntest result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s\n\n', '\n'.join(out.decode().splitlines()[3:])+'\n')
        clean(); recipe.pins_ok(frozen); assert sorted(os.sched_getaffinity(0)) == cpus
        result.update(status='OWNED_BATCH_INTEGRATION_PASS', native_test=TEST, tests_passed=1)
    except BaseException as error:
        result['error'] = type(error).__name__+': '+str(error)
    finally:
        result.update(cleanup_complete=safe, seconds=time.monotonic()-started, load_after=os.getloadavg(), retained=frozen)
        save(raw/'result.json', result)
    return 0 if result['status'] == 'OWNED_BATCH_INTEGRATION_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
