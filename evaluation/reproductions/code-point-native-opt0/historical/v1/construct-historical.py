#!/usr/bin/env python3
"""Capture current inputs for the reviewed fixed native-point caller; run no subject."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
from types import SimpleNamespace

R = Path.cwd().resolve()
REV = 'dd94a43b7986509f70635896ab759659fbd81ba4'
HERE = R / 'ignored/a4/code-point-native-runtime-activation-v1'
RAW = R / 'ignored/a4/code-point-native-runtime-v1'
BUILD = R / 'ignored/a4/code-point-native-validation-v1/native-build'
PARENT = R / 'ignored/a4/code-point-native-validation-v1/native-build-launch'
PROPOSAL = R / 'ignored/a4/code-point-native-caller-proposal-v2/runtime'
SCHEMA = R / 'ignored/a4/code-point-native-caller-proposal-v1/runtime'
ENV = dict(PATH='/usr/bin:/bin', LANG='C.UTF-8', LC_ALL='C.UTF-8',
           PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def put(path, value):
    data = value if isinstance(value, bytes) else (
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
    with path.open('xb') as stream:
        stream.write(data)


assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == REV
assert not subprocess.check_output(['git', 'diff', '--binary', 'HEAD', '--'])
assert not RAW.exists()
observer = R / 'evaluation/trampoline-parallel.py'
source = observer.read_bytes()
assert sha(source) == '0d3697eaaf433fc76d22f4ec7b6bc8047d0260f90bf9227072ad8dee2f4662ba'
namespace = dict(__name__='_native_point_input_observer', __file__=str(observer))
exec(compile(source, str(observer), 'exec'), namespace)
observe = SimpleNamespace(**namespace)

caller = (PROPOSAL / 'run.py').read_bytes()
assert sha(caller) == '0bed078506421db3eb5f880eb56031ee7dd67828d6b5d0b8020ce4521eed42cb'
assert caller.count(b'REVISION = None') == 1
caller = caller.replace(b'REVISION = None', ('REVISION = ' + repr(REV)).encode())
compile(caller, str(HERE / 'run.py'), 'exec')
put(HERE / 'run.py', caller)

before = json.loads((BUILD / 'inputs-before.json').read_text())
assert (BUILD / 'inputs-before.json').read_bytes() == (BUILD / 'inputs-after.json').read_bytes()
assert observe.source(R, '/usr/bin/git', ENV) == before['source']
assert before['source']['revision'] == REV and len(before['source']['files']) == 2189
summary = json.loads((BUILD / 'summary.json').read_text())
assert summary['status'] == 'PASS' and summary['source_tools_configs_equal'] is True
log = (BUILD / 'command.log').read_bytes()
assert sha(log) == 'a06670451f0192d03840e1c98a1acc84f5b44109ec1a70c0b5d236a9be664174'
rows = []
for line in log.splitlines():
    try:
        rows.append(json.loads(line))
    except json.JSONDecodeError:
        pass
artifacts = [row for row in rows if row.get('reason') == 'compiler-artifact'
             and row['target']['name'] == 'frontend-native-point']
assert len(artifacts) == 1
artifact = artifacts[0]
binary = R / 'target/debug/frontend-native-point'
assert artifact['executable'] == str(binary) and artifact['filenames'] == [str(binary)]
actual = observe.tool(binary)
s = binary.stat()
assert actual['stat'] == [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
assert actual['resolved'] == str(binary) and actual['lookup_stat'] == actual['stat']
assert s.st_mode & 0o111
product = dict(revision=REV, build_summary_sha256=sha((BUILD / 'summary.json').read_bytes()),
    build_log_sha256=sha(log), artifact=artifact,
    product=dict(path=str(binary), sha256=actual['sha256'], bytes=actual['bytes'],
        dev=s.st_dev, ino=s.st_ino, mode=s.st_mode, mtime_ns=s.st_mtime_ns,
        ctime_ns=s.st_ctime_ns, uid=s.st_uid, gid=s.st_gid))
put(BUILD / 'product.json', product)


def interpreter(path):
    data, owner = observe.read(path.resolve(strict=True))
    assert data[:7] == b'\x7fELF\x02\x01\x01' and len(data) >= 64
    off, count = struct.unpack_from('<Q', data, 32)[0], struct.unpack_from('<H', data, 56)[0]
    assert 1 <= count <= 128 and struct.unpack_from('<H', data, 54)[0] == 56
    assert off + count * 56 <= len(data)
    headers = [struct.unpack_from('<IIQQQQQQ', data, off + i * 56) for i in range(count)]
    selected = [row for row in headers if row[0] == 3]
    assert len(selected) == 1
    row = selected[0]
    assert 1 < row[5] <= 4096 and row[2] + row[5] <= len(data)
    value = data[row[2]:row[2] + row[5]]
    assert value.endswith(b'\0') and b'\0' not in value[:-1]
    return value[:-1].decode()


tools = {name: observe.tool(Path(path)) for name, path in dict(
    python='/usr/bin/python3.9', timeout='/usr/bin/timeout', git='/usr/bin/git',
    helper=str(R / 'tools/unwind-oracle/bounded_command.py'), du='/usr/bin/du').items()}
runtime = dict(schema=1, authority='ROOT_REVIEWED_BYTE_POINT_SELECTED_RUNTIME',
    scope='selected-host-owners-only', revision=REV, driver_sha256=actual['sha256'],
    python_sha256=tools['python']['sha256'], owners={
        'driver_interpreter': observe.tool(Path(interpreter(binary))),
        'python_interpreter': observe.tool(Path(interpreter(Path('/usr/bin/python3.9')))),
        'libc': observe.tool(Path('/lib64/libc.so.6')),
        'loader_cache': observe.tool(Path('/etc/ld.so.cache'))})
put(HERE / 'runtime.json', runtime)
put(HERE / 'capacity.json', dict(schema=1, authority='ROOT_REVIEWED_BYTE_POINT_CAPACITY',
    revision=REV, raw=str(RAW), max_slot_bytes=20000000000, reserved_growth_bytes=1073741824,
    minimum_available_memory_bytes=536870912, sole_writer_required=True))

binding = json.loads((SCHEMA / 'binding.pending.json').read_text())
binding.update(revision=REV, caller_sha256=sha(caller), build=str(BUILD), build_launch=str(PARENT),
    build_parent_source=str(R / 'ignored/a4/code-point-native-validation-source-v1/launch.py'),
    runtime=str(HERE / 'runtime.json'), capacity=str(HERE / 'capacity.json'), tools=tools)
selected = [HERE / 'run.py', HERE / 'runtime.json', HERE / 'capacity.json',
    Path(binding['source_manifest']), Path(binding['cases']), Path(binding['build_parent_source']),
    R / 'ignored/a4/code-point-native-validation-source-v1/validate.py',
    R / 'ignored/a4/code-point-native-build-review-v1/binding.json',
    R / 'ignored/a4/code-point-native-runtime-caller-review-v1/binding.json']
selected += [BUILD / name for name in ('inputs-before.json', 'inputs-after.json', 'summary.json',
    'command.json', 'command.log', 'process-result.json', 'hardware.json', 'product.json')]
selected += [PARENT / name for name in ('closed.json', 'started.json', 'command.json', 'stdout.txt', 'stderr.txt')]
assert len(selected) == len(set(selected)) and len(selected) <= 64
for path in selected:
    data, owner = observe.read(path)
    binding['files'][str(path)] = dict(sha256=sha(data), bytes=len(data), stat=owner)
put(HERE / 'binding.json', binding)
assert observe.tool(binary) == actual
assert observe.source(R, '/usr/bin/git', ENV) == before['source']
put(HERE / 'constructed.json', dict(revision=REV, binding_sha256=sha((HERE / 'binding.json').read_bytes()),
    caller_sha256=sha(caller), selected_files=len(selected), product_owner_observed_now=True,
    product_origin='Exact saved Cargo artifact path; current hash/owner observed during construction',
    native_cases='UNRUN'))
print(json.dumps(json.loads((HERE / 'constructed.json').read_text()), sort_keys=True))
