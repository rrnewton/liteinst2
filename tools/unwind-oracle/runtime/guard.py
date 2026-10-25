"""Read-only local admission: no historical imports and no subprocesses."""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
import errno
import hashlib
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent

def sha(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(512 * 1024), b""):
            result.update(block)
    return result.hexdigest()

def read(path):
    return json.loads(Path(path).read_text())

def files(directory):
    result = {}
    for p in sorted(Path(directory).rglob("*")):
        assert not p.is_symlink(), str(p)
        if p.is_file():
            result[str(p.relative_to(directory))] = sha(p)
    return result

def elf(path):
    data = Path(path).read_bytes()
    assert data[:7] == b'\x7fELF\x02\x01\x01'
    assert struct.unpack_from('<H', data, 18)[0] == 62
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    assert size == 56 and 1 <= count <= 256 and offset + size * count <= len(data)
    interpreters, loads = [], []
    for index in range(count):
        kind, flags, file, address, _, filesz, memsz, _ = struct.unpack_from('<IIQQQQQQ', data, offset + index * size)
        assert file + filesz <= len(data)
        if kind == 3:
            value = data[file:file + filesz]
            assert value[-1:] == b'\0' and b'\0' not in value[:-1]
            interpreters.append(value[:-1].decode())
        if kind == 1:
            loads.append(dict(flags=flags, file_offset=file, virtual_address=address,
                              file_size=filesz, memory_size=memsz))
    assert len(interpreters) <= 1
    return dict(interpreter=interpreters[0] if interpreters else None, loads=loads)


def libgcc_symbols(path):
    """Require six defined dynamic functions, each in one executable segment."""
    data = Path(path).read_bytes()
    geometry = elf(path)
    offset = struct.unpack_from("<Q", data, 40)[0]
    size, count = struct.unpack_from("<HH", data, 58)
    assert size == 64 and 1 <= count <= 4096 and offset + size * count <= len(data)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, offset + i * size) for i in range(count)]
    tables = [row for row in sections if row[1] == 11]
    assert len(tables) == 1
    table = tables[0]
    assert table[9] == 24 and table[5] % 24 == 0 and table[5] // 24 <= 65536
    assert 0 <= table[6] < count and table[4] + table[5] <= len(data)
    strings = sections[table[6]]
    assert strings[1] == 3 and strings[4] + strings[5] <= len(data)
    names = data[strings[4]:strings[4] + strings[5]]
    required = {"__register_frame", "_Unwind_Find_FDE", "_Unwind_Backtrace", "_Unwind_GetIPInfo", "_Unwind_GetCFA", "_Unwind_GetGR"}
    result = {}
    for index in range(table[5] // 24):
        name, info, other, section, value, width = struct.unpack_from("<IBBHQQ", data, table[4] + index * 24)
        assert name < len(names)
        stop = names.find(b"\0", name)
        assert stop >= name
        label = names[name:stop].decode("ascii")
        if label not in required:
            continue
        assert label not in result and info & 15 == 2 and info >> 4 in (1, 2)
        assert other & 3 in (0, 3) and 0 < section < count and width > 0
        owners = [s for s in geometry["loads"] if s["flags"] == 5 and s["virtual_address"] <= value
                  and value + width <= s["virtual_address"] + s["file_size"]]
        assert len(owners) == 1
        result[label] = dict(symbol_index=index, value=value, size=width, section=section,
                             file_offset=owners[0]["file_offset"] + value - owners[0]["virtual_address"])
    assert set(result) == required
    return result

def identity(row):
    path = Path(row['path'])
    assert str(path.resolve(strict=True)) == row['resolved']
    state = path.stat()
    assert (state.st_dev, state.st_ino, state.st_size) == (row['device'], row['inode'], row['size'])
    assert sha(path) == row['sha256']
    if 'elf' in row:
        assert elf(path) == row['elf']


def tool_identity(row):
    path = Path(row['path'])
    state = path.stat()
    assert str(path.resolve(strict=True)) == row['resolved_path']
    assert [state.st_dev, state.st_ino, state.st_size, state.st_mode & 0o777] == row['stat']
    assert sha(path) == row['sha256']


def verify():
    assert sys.flags.optimize == 0 and sys.dont_write_bytecode is True and sys.pycache_prefix is None
    frozen = read(HERE / 'manifest.json')
    assert frozen['status'] == 'FROZEN_PUBLIC_CONSUMER_RUNTIME_REVIEW_REQUIRED'
    for path, digest in frozen['files'].items():
        assert sha(HERE / path) == digest, path
    for path, digest in frozen['references'].items():
        assert sha(path) == digest, path
    inputs = read(HERE / 'inputs.json')
    assert str(HERE.resolve(strict=True)) == str(HERE)
    assert Path(inputs['runtime_directory']) == HERE
    root = Path(inputs['root'])
    assert sha(HERE / 'runtime-source-admission.json') == inputs['source_admission_sha256']
    assert read(HERE / 'runtime-source-admission.json') == inputs['source_admission']
    for name, checksum in inputs['source_admission']['source_files'].items():
        assert sha(root / name) == checksum
    adapter = Path(inputs['public_adapter_directory'])
    selected = [root / 'Cargo.toml', root / 'Cargo.lock', root / 'README.md']
    selected += sorted((root / 'src').rglob('*.rs'))
    selected += [root / 'tests/support' / name for name in
                 ('quiescent_oracle.rs', 'entry_signal.rs', 'parked_signal.rs',
                  'boundary_signal.rs', 'process_text.rs', 'word_sync.rs', 'word_trace_method.rs')]
    selected += [p for p in sorted(adapter.rglob('*')) if p.is_file()]
    assert all(not p.is_symlink() and p.resolve(strict=True) == p for p in selected)
    assert {str(p.relative_to(root)): sha(p) for p in selected} == inputs['source_selection']
    for row in inputs['tool_identities']:
        tool_identity(row)
    for row in inputs['tools'].values():
        tool_identity(row)
    for row in inputs['source_identities']:
        tool_identity(row)
    for row in inputs['binary'].values():
        identity(row)
        assert row['elf']['interpreter'] in inputs['interpreters']
    for row in inputs['interpreters'].values():
        identity(row)
    for key in ('libgcc', 'libgcc_alias', 'libgcc_snapshot'):
        identity(inputs[key])
    assert inputs['libgcc_alias']['resolved'] == inputs['libgcc']['resolved']
    assert inputs['libgcc_snapshot']['resolved'] != inputs['libgcc']['resolved']
    assert Path(inputs['libgcc_snapshot']['path']).read_bytes() == Path(inputs['libgcc']['path']).read_bytes()
    assert len(inputs['libgcc_symbols']) == 6
    assert libgcc_symbols(inputs['libgcc']['path']) == inputs['libgcc_symbols']
    preload = inputs['global_preload']
    if preload['kind'] == 'absent':
        assert not Path(preload['path']).exists()
    else:
        assert preload['kind'] == 'inactive-file'
        identity(preload)
        assert Path(preload['path']).read_bytes().strip() == b''
    cache = inputs['loader_cache']
    if cache.get('kind') == 'absent':
        assert not Path(cache['path']).exists()
    else:
        identity(cache)
        assert sha(HERE / 'snapshots/ld.so.cache') == cache['sha256']
    assert sha(HERE / 'loader-epoch.json') == inputs['loader_epoch_sha256']
    epoch = read(HERE / 'loader-epoch.json')
    assert epoch['cache'] == cache and epoch['global_preload'] == preload
    assert epoch['configuration'] == inputs['loader_configuration']
    assert epoch['directories'] == inputs['loader_configuration_directories']
    for directory, children in inputs['loader_configuration_directories'].items():
        path = Path(directory)
        assert sorted(str(p) for p in path.iterdir()) == children
    for path, row in inputs['loader_configuration'].items():
        if row is None:
            assert not Path(path).exists()
        else:
            identity(row)
    for path in inputs['absent_configuration']:
        assert not Path(path).exists()
    for path, row in inputs['unreadable_configuration'].items():
        try:
            Path(path).exists()
        except OSError as error:
            assert error.errno in (errno.EPERM, errno.EACCES)
            assert row == dict(kind='unreadable', operation='exists', errno=error.errno)
        else:
            raise AssertionError(path)
    build = Path(inputs['build_directory'])
    assert sha(build / 'build-audit.json') == inputs['build_audit_sha256']
    audit = read(build / 'build-audit.json')
    assert audit['status'] == 'BUILT_REVIEW_REQUIRED_NO_EXECUTION'
    assert files(build) == dict(audit['files'], **{'build-audit.json': inputs['build_audit_sha256']})
    assert sha(build / 'binary-binding.json') == inputs['binary_binding_sha256']
    binding = read(build / 'binary-binding.json')
    assert set(binding['binaries']) == set(inputs['binary']) == {'consumer-unit-tests','consumer-main','consumer-launcher','consumer-calibrations'}
    for name, row in binding['binaries'].items():
        bound = inputs['binary'][name]
        assert row['path'] == bound['path'] and row['sha256'] == bound['sha256']
    assert sha(inputs['binding_review']['path']) == inputs['binding_review']['sha256']
    expected = read(HERE / 'expected.json')
    assert len(expected['launcher']) == 32 and len(expected['shared_calibrations']) == 26
    assert len(expected['consumer_models']) == 6 and len(expected['full_library_name_counts']) == 190
    assert set(expected['activation_inventory']['legacy_launcher_names']) <= set(expected['launcher'])
    assert set(expected['activation_inventory']['legacy_shared_calibration_names']) <= set(expected['shared_calibrations'])
    plan = read(HERE / 'plan.json')
    order = ['launcher-list','consumer-models','full-library','shared-calibrations',
             'frameless','frame-pointer','no-fde-frameless','no-fde-frame-pointer',
             'keep-gated-frameless','keep-gated-frame-pointer']
    assert len(plan['steps']) == 10 and plan['serial'] is True
    assert [step['name'] for step in plan['steps']] == order
    modes = expected['inventory']['native_modes']
    assert [(s['cohort'], s['kind'], s['test']) for s in plan['steps'][4:]] == [(s['cohort'], s['kind'], s['test']) for s in modes]
    environment = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', RUST_TEST_THREADS='1')
    for step in plan['steps']:
        assert sha(step['request']) == step['request_sha256']
        request = read(step['request'])
        assert request['cwd'] == str(root)
        name = step['name']
        wanted_env = dict(environment)
        if name == 'launcher-list':
            argv = [inputs['binary']['consumer-launcher']['path'], '--list']
        elif name == 'consumer-models':
            argv = [inputs['binary']['consumer-unit-tests']['path'], 'generated_unwind::tests::', '--test-threads=1']
        elif name == 'full-library':
            argv = [inputs['binary']['consumer-unit-tests']['path'], '--test-threads=1']
        elif name == 'shared-calibrations':
            argv = [inputs['binary']['consumer-calibrations']['path'], '--test-threads=1']
        else:
            argv = [inputs['binary']['consumer-launcher']['path'], step['test'], '--exact', '--test-threads=1', '--nocapture']
            wanted_env.update(LITEINST_UNWIND_CONSUMER_MAIN_THREAD_DRIVER=inputs['binary']['consumer-main']['path'],
                LITEINST_UNWIND_CONSUMER_MAIN_THREAD_CAPTURES=str(HERE / 'run/captures' / name),
                UW_LIBGCC_FILE=inputs['libgcc']['path'], UW_LIBGCC_SNAPSHOT=inputs['libgcc_snapshot']['path'])
        assert request['argv'] == argv and request['env'] == wanted_env
        assert all(not name.startswith('LD_') for name in request['env'])
        assert (request['cpu_seconds'], request['wall_seconds']) == ((30,45) if 'cohort' in step else (20,30))
        assert request['file_bytes'] == 16 * 1024 * 1024
        assert request['stdout'] == str(HERE / 'run' / (name + '.stdout'))
        assert request['stderr'] == str(HERE / 'run' / (name + '.stderr'))
    final = plan['final_audit']
    assert sha(final['request']) == final['request_sha256']
    request = read(final['request'])
    assert request['argv'] == [inputs['tools']['helper_python']['path'], '-B', str(HERE / 'entry.py'), 'audit', sha(HERE / 'source-files.json')]
    assert request['env'] == environment and (request['cpu_seconds'], request['wall_seconds'],request['file_bytes']) == (20,30,16*1024*1024)
    assert request['cwd'] == str(root)
    assert request['stdout'] == str(HERE / 'audit-output/final-audit.stdout')
    assert request['stderr'] == str(HERE / 'audit-output/final-audit.stderr')
    for step in plan['steps'] + [plan['final_audit']]:
        capture = HERE / ('audit-output' if step['name'] == 'final-audit' else 'run')
        assert step['receipt'] == str(capture / (step['name'] + '.receipt.json'))
        assert step['helper_stdout'] == str(capture / (step['name'] + '.helper.stdout'))
        assert step['helper_stderr'] == str(capture / (step['name'] + '.helper.stderr'))
    assert inputs['helper'] == inputs['tools']['helper']
    return inputs


def verify_records():
    """Authenticate retained records, never readmit current tools or a loader epoch.

    Original path/device/inode records are evidence about the completed run.
    This path rehashes private snapshots and closed build artifacts; it does not
    compare those old observations to today's canonical files or source tree.
    The original verify() remains the sole live launch admission.
    """
    assert sys.flags.optimize == 0 and sys.dont_write_bytecode is True and sys.pycache_prefix is None
    frozen = read(HERE / 'manifest.json')
    assert frozen['status'] == 'FROZEN_PUBLIC_CONSUMER_RUNTIME_REVIEW_REQUIRED'
    for path, digest in frozen['files'].items():
        saved = HERE / path
        assert saved.is_file() and not saved.is_symlink() and sha(saved) == digest, path
    inputs = read(HERE / 'inputs.json')
    assert Path(inputs['runtime_directory']) == HERE
    root = Path(inputs['root'])  # Recorded coordinate only; no current-root reads.
    assert sha(HERE / 'runtime-source-admission.json') == inputs['source_admission_sha256']
    assert read(HERE / 'runtime-source-admission.json') == inputs['source_admission']
    archive = HERE.parent
    build_freeze = read(archive / 'freeze.json')
    assert sha(archive / 'freeze.json') == frozen['references'][str(archive / 'freeze.json')]
    assert sha(archive / 'source-admission.json') == inputs['build_source_admission_sha256']
    assert read(archive / 'source-admission.json') == inputs['build_source_admission'] == build_freeze['source_admission']
    assert build_freeze['source_admission_sha256'] == inputs['build_source_admission_sha256']
    assert sha(archive / 'toolchain.json') == build_freeze['toolchain_sha256']
    assert inputs['source_selection'] == build_freeze['source_files'] == files(archive / 'sources')
    for name, checksum in inputs['source_selection'].items():
        assert inputs['source_admission']['source_files'][name] == checksum
        assert frozen['references'][str(root / name)] == checksum
    for row in build_freeze['cargo_configuration'].values():
        if row is not None and row.get('kind') != 'unreadable':
            assert sha(archive / 'cargo-configuration' / row['sha256']) == row['sha256']
    # Capture parsers below use the frozen identity domains, not today's stat.
    assert inputs['libgcc_alias']['resolved'] == inputs['libgcc']['resolved']
    assert inputs['libgcc_snapshot']['resolved'] != inputs['libgcc']['resolved']
    snapshot = HERE / 'snapshots/libgcc_s.so.1'
    assert str(snapshot) == inputs['libgcc_snapshot']['path']
    assert snapshot.stat().st_size == inputs['libgcc_snapshot']['size'] == inputs['libgcc']['size']
    assert sha(snapshot) == inputs['libgcc_snapshot']['sha256'] == inputs['libgcc']['sha256']
    assert elf(snapshot) == inputs['libgcc']['elf']
    assert libgcc_symbols(snapshot) == inputs['libgcc_symbols'] and len(inputs['libgcc_symbols']) == 6
    assert sha(HERE / 'loader-epoch.json') == inputs['loader_epoch_sha256']
    epoch = read(HERE / 'loader-epoch.json')
    assert epoch['cache'] == inputs['loader_cache']
    assert epoch['global_preload'] == inputs['global_preload']
    assert epoch['configuration'] == inputs['loader_configuration']
    assert epoch['directories'] == inputs['loader_configuration_directories']
    cache = inputs['loader_cache']
    if cache.get('kind') != 'absent':
        assert sha(HERE / 'snapshots/ld.so.cache') == cache['sha256']
    build = Path(inputs['build_directory'])
    assert build == archive / 'build'
    assert sha(build / 'build-audit.json') == inputs['build_audit_sha256']
    audit = read(build / 'build-audit.json')
    assert audit['status'] == 'BUILT_REVIEW_REQUIRED_NO_EXECUTION'
    assert files(build) == dict(audit['files'], **{'build-audit.json': inputs['build_audit_sha256']})
    assert sha(build / 'binary-binding.json') == inputs['binary_binding_sha256']
    binding = read(build / 'binary-binding.json')
    assert set(binding['binaries']) == set(inputs['binary']) == {'consumer-unit-tests','consumer-main','consumer-launcher','consumer-calibrations'}
    for name, row in binding['binaries'].items():
        bound = inputs['binary'][name]
        assert row['path'] == bound['path'] and row['sha256'] == bound['sha256']
        saved = Path(bound['path'])
        assert saved.is_relative_to(build) and saved.is_file() and not saved.is_symlink()
        assert sha(saved) == bound['sha256'] and saved.stat().st_size == bound['size']
        assert elf(saved) == bound['elf'] and bound['elf']['interpreter'] in inputs['interpreters']
    assert sha(inputs['binding_review']['path']) == inputs['binding_review']['sha256']
    expected = read(HERE / 'expected.json')
    assert len(expected['launcher']) == 32 and len(expected['shared_calibrations']) == 26
    assert len(expected['consumer_models']) == 6 and len(expected['full_library_name_counts']) == 190
    assert set(expected['activation_inventory']['legacy_launcher_names']) <= set(expected['launcher'])
    assert set(expected['activation_inventory']['legacy_shared_calibration_names']) <= set(expected['shared_calibrations'])
    plan = read(HERE / 'plan.json')
    order = ['launcher-list','consumer-models','full-library','shared-calibrations',
             'frameless','frame-pointer','no-fde-frameless','no-fde-frame-pointer',
             'keep-gated-frameless','keep-gated-frame-pointer']
    assert len(plan['steps']) == 10 and plan['serial'] is True
    assert [step['name'] for step in plan['steps']] == order
    modes = expected['inventory']['native_modes']
    assert [(s['cohort'], s['kind'], s['test']) for s in plan['steps'][4:]] == [(s['cohort'], s['kind'], s['test']) for s in modes]
    environment = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', RUST_TEST_THREADS='1')
    for step in plan['steps']:
        assert sha(step['request']) == step['request_sha256']
        request = read(step['request'])
        assert request['cwd'] == str(root)
        name = step['name']
        wanted_env = dict(environment)
        if name == 'launcher-list':
            argv = [inputs['binary']['consumer-launcher']['path'], '--list']
        elif name == 'consumer-models':
            argv = [inputs['binary']['consumer-unit-tests']['path'], 'generated_unwind::tests::', '--test-threads=1']
        elif name == 'full-library':
            argv = [inputs['binary']['consumer-unit-tests']['path'], '--test-threads=1']
        elif name == 'shared-calibrations':
            argv = [inputs['binary']['consumer-calibrations']['path'], '--test-threads=1']
        else:
            argv = [inputs['binary']['consumer-launcher']['path'], step['test'], '--exact', '--test-threads=1', '--nocapture']
            wanted_env.update(LITEINST_UNWIND_CONSUMER_MAIN_THREAD_DRIVER=inputs['binary']['consumer-main']['path'],
                LITEINST_UNWIND_CONSUMER_MAIN_THREAD_CAPTURES=str(HERE / 'run/captures' / name),
                UW_LIBGCC_FILE=inputs['libgcc']['path'], UW_LIBGCC_SNAPSHOT=inputs['libgcc_snapshot']['path'])
        assert request['argv'] == argv and request['env'] == wanted_env
        assert all(not name.startswith('LD_') for name in request['env'])
        assert (request['cpu_seconds'], request['wall_seconds']) == ((30,45) if 'cohort' in step else (20,30))
        assert request['file_bytes'] == 16 * 1024 * 1024
        assert request['stdout'] == str(HERE / 'run' / (name + '.stdout'))
        assert request['stderr'] == str(HERE / 'run' / (name + '.stderr'))
    final = plan['final_audit']
    assert sha(final['request']) == final['request_sha256']
    request = read(final['request'])
    assert request['argv'] == [inputs['tools']['helper_python']['path'], '-B', str(HERE / 'entry.py'), 'audit', sha(HERE / 'source-files.json')]
    assert request['env'] == environment and (request['cpu_seconds'], request['wall_seconds'],request['file_bytes']) == (20,30,16*1024*1024)
    assert request['cwd'] == str(root)
    assert request['stdout'] == str(HERE / 'audit-output/final-audit.stdout')
    assert request['stderr'] == str(HERE / 'audit-output/final-audit.stderr')
    for step in plan['steps'] + [plan['final_audit']]:
        capture = HERE / ('audit-output' if step['name'] == 'final-audit' else 'run')
        assert step['receipt'] == str(capture / (step['name'] + '.receipt.json'))
        assert step['helper_stdout'] == str(capture / (step['name'] + '.helper.stdout'))
        assert step['helper_stderr'] == str(capture / (step['name'] + '.helper.stderr'))
    assert inputs['helper'] == inputs['tools']['helper']
    return inputs
