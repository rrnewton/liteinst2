#!/usr/bin/env python3
"""Fresh release admission and the fixed 80-case authored offline comparison."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import time

MIB = 1048576
HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
PROFILE = dict(opt_level='3', debuginfo=0, debug_assertions=True, overflow_checks=True, test=False)
SOURCE_PINS = {
    'compare.py': '1fa50991916fc6912b632cbbac9dd29517c40e9a9c3d8cd51344c9e2673769dc',
    'adapter.py': 'db7d33395fa0af59eaffaa648039e28bc0e42f68461f2902f1fec1dc582dbb30',
    'corpus.py': '007e529b3716061d8b7f11f3e33541ee80292027165703663db2f72a81e35b07',
    'checksum.S': '7a265d79394772b9bc4d9e9c48b4b1461251ff91df939b8a6ad26ce884148dfe',
    'rle-roundtrip.S': '5f0aca8bf3e158c9393d50558b5138f4d6f777098bc9ce23f2cae45a67f52b3e',
    'layout.ld': 'c55eb8bfc9b91251be5486d99de4a9d0458c937540a936dcc9ac0a93d60a535c'}
E9_PINS = {
    'stock_frontend': '36b05e9a47c9193041d71ed4e14dda87e835e0e2b47e4a82a7d30a7c0d4eeb5e',
    'stock_backend': '890f76cb5741b6c7cfba3414ae72a64fd7deddc7d2dd33b17d53e8b906529fdb',
    'stock_loader': '4d39f324ab8a3a9420d2436129ba941e17fd78aa2c4e35eff3d27311e0683477',
    'transport_frontend': '0fea3c8bc0701dffeb16b524e7159e458be9add11bcf3df5f47b9714c1005acc',
    'abi_backend': '3750339187ffc4a084d075de77d1c653c255abd96e396870ea691b495f0c5453',
    'abi_loader': '126b6143c5668e4d390e0b9626824f5007b54d56e47a07bb72b415757b51773c'}
HISTORY = (
    'evaluation/results/e9-common-originals-b0d94f0/summary.json',
    'evaluation/results/e9-common-production-b0d94f0/summary.json',
    'evaluation/results/e9-common-production-29be7f8/summary.json',
    'evaluation/results/common-native-9884b7a/build-controls/summary.json',
    'evaluation/results/common-native-9884b7a/originals-and-archive-failures/summary.json',
    'evaluation/results/common-native-9884b7a/canonical-verifier/summary.json',
    'evaluation/results/common-native-9884b7a/e9-null-all-eight/summary.json')


def read(path):
    path = Path(path)
    assert path.is_absolute() and '..' not in path.parts
    assert path.parent.resolve(strict=True) == path.parent
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        a = os.fstat(f.fileno())
        assert stat.S_ISREG(a.st_mode) and 0 <= a.st_size <= 256*MIB
        data = f.read(a.st_size + 1)
        six = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
        assert six(a) == six(os.fstat(f.fileno())) == six(path.lstat()) and len(data) == a.st_size
    return data, dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), stat=six(a))


def owner(path):
    return read(path)[1]


def save(path, value):
    data = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()
    assert len(data) <= 16*MIB
    with Path(path).open('xb') as f:
        f.write(data)


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    sys.dont_write_bytecode = True
    ap = argparse.ArgumentParser(description=__doc__)
    for key in ('repo', 'raw', 'toolchain', 'user-home', 'cargo-home',
                'e9-stock-dir', 'e9-transport', 'e9-abi-dir'):
        ap.add_argument('--'+key, type=Path, required=True)
    a = ap.parse_args()
    repo, raw = a.repo, a.raw
    for path in (repo, a.toolchain, a.user_home, a.cargo_home, a.e9_stock_dir, a.e9_abi_dir):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
    assert raw.is_absolute() and raw.is_relative_to(repo/'ignored') and not raw.exists()
    assert not raw.is_symlink() and raw.parent.resolve(strict=True) == raw.parent
    source_dir = repo/'evaluation/offline-corpus'
    assert Path(__file__).resolve(strict=True) == source_dir/'reproduce.py'
    cpus = sorted(os.sched_getaffinity(0))[:4]
    assert len(cpus) == 4
    os.sched_setaffinity(0, cpus)
    assert sorted(os.sched_getaffinity(0)) == cpus
    cpu = next(line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
               if line.startswith('model name'))
    assert platform.machine() == 'x86_64' and cpu == 'AMD EPYC 9D85 158-Core Processor', 'existing exact comparison host profile'
    bin_dir = a.toolchain/'bin'
    env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home), PATH=str(bin_dir)+':/usr/bin:/bin',
        CARGO_TARGET_DIR=str(repo/'target'), CARGO_NET_OFFLINE='true', CARGO_TERM_COLOR='never',
        CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
        CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true',
        CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true', LANG='C.UTF-8', LC_ALL='C.UTF-8',
        PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    assert 'RUSTFLAGS' not in env and 'CARGO_ENCODED_RUSTFLAGS' not in env
    helper = repo/'tools/unwind-oracle/bounded_command.py'
    tools = dict(cargo=bin_dir/'cargo', rustc=bin_dir/'rustc', python=Path(sys.executable).resolve(strict=True),
        timeout=Path('/usr/bin/timeout').resolve(strict=True), git=Path('/usr/bin/git'), helper=helper,
        **{'as': Path('/usr/bin/as').resolve(strict=True), 'ld': Path('/usr/bin/ld').resolve(strict=True)},
        stock_frontend=a.e9_stock_dir/'e9tool', stock_backend=a.e9_stock_dir/'e9patch',
        stock_loader=a.e9_stock_dir/'e9loader.bin', transport_frontend=a.e9_transport,
        abi_backend=a.e9_abi_dir/'e9patch', abi_loader=a.e9_abi_dir/'e9loader.bin')
    tool_before = {role: owner(path) for role, path in tools.items()}
    assert tool_before['helper']['sha256'] == HELPER_SHA
    for role, row in tool_before.items():
        if role not in ('stock_loader', 'abi_loader', 'helper'):
            assert row['stat'][2] & 0o111
    for role, digest in E9_PINS.items():
        assert tool_before[role]['sha256'] == digest
    def git(*args):
        return subprocess.check_output([str(tools['git']), '-C', str(repo), *args], env=env, timeout=15)
    revision = git('rev-parse', 'HEAD').decode().strip()
    assert re.fullmatch('[0-9a-f]{40}', revision)
    def sources():
        assert git('rev-parse', 'HEAD').decode().strip() == revision
        assert git('status', '--porcelain', '--untracked-files=no') == b''
        rows = {}
        for item in git('ls-tree', '-rz', '--full-tree', revision).split(b'\0'):
            if not item: continue
            metadata, name = item.split(b'\t', 1)
            mode, kind, oid = metadata.decode().split(); name = name.decode()
            assert kind == 'blob' and mode in ('100644', '100755')
            assert not Path(name).is_absolute() and '..' not in Path(name).parts
            data, row = read(repo/name)
            assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest() == oid
            assert bool(row['stat'][2] & 0o111) == (mode == '100755')
            rows[name] = dict(row, git_blob=oid, git_mode=mode)
        assert 'evaluation/offline-corpus/reproduce.py' in rows and 'BRIEF-li2core.md' not in rows
        return rows
    source_before = sources()
    for name, digest in SOURCE_PINS.items():
        assert source_before['evaluation/offline-corpus/'+name]['sha256'] == digest
    for name in HISTORY:
        assert name in source_before
    configuration_source = repo/'evaluation/trampoline-parallel.py'
    assert str(configuration_source.relative_to(repo)) in source_before
    spec = importlib.util.spec_from_file_location('offline_configuration', configuration_source)
    configuration = importlib.util.module_from_spec(spec); spec.loader.exec_module(configuration)
    configs = configuration.configuration(repo, a.cargo_home)
    products = {}
    def stable():
        assert sources() == source_before
        assert {role: owner(path) for role, path in tools.items()} == tool_before
        assert configuration.configuration(repo, a.cargo_home) == configs
        assert all(owner(repo/'target/release'/name) == value for name, value in products.items())
    raw.mkdir(mode=0o700)
    save(raw/'sources-before.json', source_before); save(raw/'tools-before.json', tool_before)
    save(raw/'configurations-before.json', configs)
    save(raw/'environment.json', dict(revision=revision, env=env, affinity=cpus,
        hardware='AMD EPYC Zen 5 dev host', cpu_model=cpu, architecture=platform.machine(),
        kernel=platform.release(), libc=platform.libc_ver(), full_runtime_configuration=False))
    fs = os.statvfs(raw)
    save(raw/'capacity.json', dict(free_bytes=fs.f_bavail*fs.f_frsize, minimum_free_bytes=256*MIB,
        managed_slot_quota_proof=False, scope='caller separately admits compilation/storage under its slot cap'))
    assert fs.f_bavail*fs.f_frsize >= 256*MIB
    phases = [dict(id=name, status='UNRUN') for name in ('build-core', 'build-target', 'target', 'compare')]
    save(raw/'planned.json', dict(phases=phases, comparison_cases=80))

    def execute(row, argv, environment, limits):
        row['status'] = 'FAILED'; stable()
        directory = raw/row['id']; directory.mkdir(); (directory/'tmp').mkdir()
        environment = dict(environment, TMPDIR=str(directory/'tmp'))
        cpu_seconds, wall_seconds, file_mib = limits
        request = dict(argv=list(map(str, argv)), cwd=str(repo), env=environment,
            stdout=str(directory/'stdout.txt'), stderr=str(directory/'stderr.txt'),
            cpu_seconds=cpu_seconds, wall_seconds=wall_seconds, file_bytes=file_mib*MIB)
        save(directory/'request.json', request)
        outer = [str(tools['timeout']), '--signal=TERM', '--kill-after=10s', str(wall_seconds+10)+'s',
            str(tools['python']), '-B', str(helper), '--request', str(directory/'request.json'),
            '--receipt', str(directory/'receipt.json')]
        parent = directory/'parent'; parent.mkdir()
        save(parent/'command.json', dict(argv=outer, cwd=str(repo), env=environment, affinity=cpus,
            timeout_seconds=wall_seconds+25, failure_cleanup_seconds=10))
        child = None; began = time.monotonic()
        closed = dict(exit=None, wait_returned=False, parent_error=None)
        try:
            with (parent/'stdout.txt').open('xb') as stdout, (parent/'stderr.txt').open('xb') as stderr:
                child = subprocess.Popen(outer, cwd=repo, env=environment, stdin=subprocess.DEVNULL,
                    stdout=stdout, stderr=stderr, start_new_session=True)
                try:
                    save(parent/'started.json', dict(pid=child.pid))
                    closed['exit'] = child.wait(timeout=wall_seconds+25); closed['wait_returned'] = True
                except BaseException as error:
                    closed['parent_error'] = repr(error)
                    if child.poll() is None:
                        try: os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError: pass
                    closed['exit'] = child.wait(timeout=10); closed['wait_returned'] = True
                    raise
        finally:
            if child is not None:
                closed.update(pid=child.pid, exit=child.returncode, seconds=time.monotonic()-began)
                save(parent/'closed.json', closed)
                row['parent'] = str(parent/'closed.json')
        receipt = json.loads(read(directory/'receipt.json')[0]); row['receipt'] = str(directory/'receipt.json')
        assert receipt['request_sha256'] == owner(directory/'request.json')['sha256']
        assert receipt['helper_sha256'] == HELPER_SHA and receipt['absence_proof'] == 'ECHILD'
        assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
        assert receipt['cleanup_error'] is receipt['aborted'] is None
        assert receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
        assert type(receipt['exit']) is int and closed['exit'] == (0 if receipt['exit'] == 0 else 1)
        assert closed['wait_returned'] and closed['parent_error'] is None
        for name in ('stdout', 'stderr'):
            assert receipt[name+'_sha256'] == owner(directory/(name+'.txt'))['sha256']
        assert read(parent/'stderr.txt')[0] == b''
        assert json.loads(read(parent/'stdout.txt')[0]) == dict(exit=receipt['exit'], wall_timeout=False,
            absence_proof='ECHILD', descendants=0, success=receipt['exit']==0)
        stable(); row.update(exit=receipt['exit'], elapsed_seconds=receipt['elapsed_seconds'])
        assert receipt['exit'] == 0, 'closed failure retained; no retry or outcome substitution'
        row['command_status'] = 'PASS'
        return directory, request

    error = None
    try:
        evidence = [raw/name for name in ('sources-before.json', 'tools-before.json', 'configurations-before.json',
                                         'environment.json', 'capacity.json', 'planned.json')]
        builds = {}
        for row, package, binary_name, manifest_path, source_path in (
            (phases[0], 'liteinst-rewrite', 'liteinst-rewrite', 'tools/elf-rewrite/Cargo.toml', 'tools/elf-rewrite/src/main.rs'),
            (phases[1], 'liteinst2', 'elf-exec-oracle', 'Cargo.toml', 'tests/support/elf_exec_driver.rs')):
            argv = ['cargo', 'build', '--release', '--locked', '--offline', '--package', package,
                    '--bin', binary_name, '--message-format=json']
            directory, request = execute(row, argv, env, (120, 180, 128))
            messages = [json.loads(line) for line in read(directory/'stdout.txt')[0].splitlines()]
            assert [m for m in messages if m.get('reason') == 'build-finished'] == [dict(reason='build-finished', success=True)]
            selected = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == binary_name and m.get('executable')]
            assert len(selected) == 1
            message = selected[0]; binary = repo/'target/release'/binary_name
            assert message['profile'] == PROFILE and message['target']['kind'] == ['bin']
            assert message['manifest_path'] == str(repo/manifest_path) and message['target']['src_path'] == str(repo/source_path)
            assert message['executable'] == str(binary) and str(binary) in message['filenames']
            products[binary_name] = owner(binary); assert products[binary_name]['stat'][2] & 0o111
            record = dict(status='PASS', revision=revision, profile=PROFILE, product=products[binary_name],
                argv=argv, env=request['env'], command=str(directory/'request.json'),
                receipt=str(directory/'receipt.json'), parent_closed=str(directory/'parent/closed.json'),
                cargo_messages=str(directory/'stdout.txt'))
            builds[binary_name] = raw/(row['id']+'-admission.json'); save(builds[binary_name], record)
            evidence.append(builds[binary_name])
            evidence.extend(directory/name for name in ('request.json', 'receipt.json', 'stdout.txt', 'stderr.txt',
                'parent/command.json', 'parent/started.json', 'parent/closed.json', 'parent/stdout.txt', 'parent/stderr.txt'))
            assert all(owner(repo/'target/release'/name) == value for name, value in products.items())
            row['status'] = 'PASS'
        save(raw/'sources-after-build.json', sources()); evidence.append(raw/'sources-after-build.json')
        target_driver = repo/'target/release/elf-exec-oracle'
        directory, _ = execute(phases[2], [target_driver, 'target'], dict(PATH='/usr/bin:/bin', LC_ALL='C'), (20, 30, 16))
        assert read(directory/'stdout.txt')[0] and read(directory/'stderr.txt')[0] == b''
        target = raw/'target-admission.json'
        save(target, dict(driver=products['elf-exec-oracle'], record=str(directory/'stdout.txt'),
            request=str(directory/'request.json'), receipt=str(directory/'receipt.json'), parent_closed=str(directory/'parent/closed.json')))
        phases[2]['status'] = 'PASS'
        evidence.append(target)
        evidence.extend(directory/name for name in ('request.json', 'receipt.json', 'stdout.txt', 'stderr.txt',
            'parent/command.json', 'parent/started.json', 'parent/closed.json', 'parent/stdout.txt', 'parent/stderr.txt'))
        selected_tools = {role: str(tools[role]) for role in ('python', 'timeout', 'as', 'ld', *E9_PINS)}
        selected_tools.update(core=str(repo/'target/release/liteinst-rewrite'), target_driver=str(target_driver))
        required = [*tools.values(), *map(Path, selected_tools.values()), *evidence,
            *(source_dir/name for name in SOURCE_PINS), source_dir/'reproduce.py', configuration_source,
            repo/'tools/elf-rewrite/e9-sites.py', repo/'evaluation/elf-exec/render_selection.py',
            *(repo/name for name in HISTORY)]
        files = {str(path): owner(path) for path in required}
        assert all(files[str(path)] == tool_before[role] for role, path in tools.items())
        assert all(files[str(repo/'target/release'/name)] == value for name, value in products.items())
        stable()
        inputs = raw/'inputs.json'
        save(inputs, dict(schema=1, revision=revision, hardware='AMD EPYC Zen 5 dev host', tools=selected_tools,
            files=files, release_build=str(builds['liteinst-rewrite']), target=str(target),
            retained_heap_evidence=[str(repo/name) for name in HISTORY]))
        argv = [str(tools['python']), '-B', str(source_dir/'compare.py'), '--repo', str(repo),
                '--inputs', str(inputs), '--inputs-sha256', owner(inputs)['sha256'], '--out', str(raw/'comparison')]
        execute(phases[3], argv, dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1'), (120, 180, 256))
        summary = json.loads(read(raw/'comparison/summary.json')[0])
        assert summary['revision'] == revision and summary['cases'] == 80 and summary['fatal'] is None
        assert summary['counts'] == dict(PASS=80, FAILED=0, UNSUPPORTED=0, UNRUN=0)
        assert summary['full_a3'] is False and summary['architectural_full_state'] is False and summary['qualification_complete'] is False
        assert all(owner(path) == value for path, value in files.items())
        phases[3]['status'] = 'PASS'
    except BaseException as failure:
        error = type(failure).__name__+': '+str(failure)
    finally:
        try:
            after = sources(); after_tools = {role: owner(path) for role, path in tools.items()}
            after_configs = configuration.configuration(repo, a.cargo_home)
            save(raw/'sources-after.json', after); save(raw/'tools-after.json', after_tools)
            save(raw/'configurations-after.json', after_configs)
            assert after == source_before and after_tools == tool_before and after_configs == configs
            assert all(owner(repo/'target/release'/name) == value for name, value in products.items())
        except BaseException as failure:
            error = (error+'; ' if error else '')+'final continuity: '+type(failure).__name__+': '+str(failure)
        result = dict(schema=1, revision=revision, status='PASS' if error is None and all(r['status']=='PASS' for r in phases) else 'FAILED',
            phases=phases, error=error, comparison_cases=80, common_core_null_pairs=704, common_recording_pairs=2112,
            common_obligations_satisfied=False, full_a3=False, native_full_state=False,
            historical_summaries={name: source_before[name]['sha256'] for name in HISTORY},
            scope='fresh release build admission plus finite whole-output/selected-branch comparison only')
        save(raw/'summary.json', result)
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
