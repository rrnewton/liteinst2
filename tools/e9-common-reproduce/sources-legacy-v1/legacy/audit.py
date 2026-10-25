#!/usr/bin/env python3
"""Authored finite E9 calibration auditors; no tool or rewritten-app execution."""
import hashlib
import json
import math
import re
import struct
import sys
from pathlib import Path

if sys.flags.optimize:
    raise SystemExit("optimized Python disables calibration assertions")

MAX_FILE = 16 * 1024 * 1024
MAX_RPC_MESSAGES = 4096
MANIFEST_SHA256 = "735ad95670b93ecb1f710262d64943e5ea0df2443e98963b133f1866d4f73fea"
CASE_IDS = [f"{label}-{name}" for label in ("unstripped", "stripped")
            for name in ("pie", "exec", "libcarrierfixture.so")]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_file(path):
    path = Path(path)
    assert path.is_file() and not path.is_symlink(), str(path)
    assert 0 < path.stat().st_size <= MAX_FILE, str(path)
    data = path.read_bytes()
    assert 0 < len(data) <= MAX_FILE, str(path)
    return data


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, "duplicate JSON object key: " + key
        result[key] = value
    return result


def loads(text):
    def no_constant(value):
        raise AssertionError("non-JSON numeric constant: " + value)
    return json.loads(text, object_pairs_hook=unique_object, parse_constant=no_constant)


def integer(value, maximum=(1 << 64) - 1):
    # Every address/offset in this fixed original cohort fits signed int32,
    # so the pinned frontend emits numbers, never its optional hex-string form.
    assert type(value) is int and 0 <= value <= maximum
    return value


def elf64(data):
    assert 64 <= len(data) <= MAX_FILE
    assert data[:7] == b"\x7fELF\x02\x01\x01"
    kind, machine, version = struct.unpack_from("<HHI", data, 16)
    assert kind in (2, 3) and machine == 62 and version == 1
    entry, phoff = struct.unpack_from("<QQ", data, 24)
    ehsize, phsize, count = struct.unpack_from("<HHH", data, 52)
    assert ehsize == 64 and phsize == 56 and 1 <= count <= 4096
    assert phoff + count * phsize <= len(data)
    headers, interpreters, dynamic = [], [], []
    for index in range(count):
        tag, flags, offset, vaddr, paddr, filesz, memsz, align = struct.unpack_from("<IIQQQQQQ", data, phoff + index * phsize)
        assert offset + filesz <= len(data)
        assert vaddr + memsz <= (1 << 64) - 1
        row = dict(index=index, type=tag, flags=flags, offset=offset, vaddr=vaddr,
                   paddr=paddr, filesz=filesz, memsz=memsz, align=align)
        headers.append(row)
        if tag == 1:
            assert filesz <= memsz
            assert align in (0, 1) or (align & (align - 1)) == 0
            assert align in (0, 1) or offset % align == vaddr % align
        if tag == 3:
            assert 1 <= filesz <= 4096
            raw = data[offset:offset + filesz]
            assert raw.endswith(b"\0") and b"\0" not in raw[:-1]
            interpreters.append(dict(index=index, bytes_hex=raw.hex()))
        if tag == 2:
            assert filesz % 16 == 0 and filesz // 16 <= 4096
            rows = [struct.unpack_from("<qQ", data, at) for at in range(offset, offset + filesz, 16)]
            assert rows and any(tag == 0 for tag, _ in rows)
            # Capture every row, including padding after DT_NULL. This is an
            # inventory, not permission to execute any loader hook.
            dynamic.append(dict(index=index, rows=[list(row) for row in rows]))
    assert any(row['type'] == 1 for row in headers)
    return dict(kind=kind, machine=machine, entry=entry, phoff=phoff,
                phentsize=phsize, phnum=count, headers=headers,
                interpreters=interpreters, dynamic=dynamic)


def executable_offset(elf, address, length):
    integer(address); integer(length)
    assert length > 0 and address + length <= (1 << 64) - 1
    owners = [row for row in elf['headers'] if row['type'] == 1
              and row['vaddr'] <= address
              and address + length <= row['vaddr'] + row['filesz']]
    assert len(owners) == 1 and owners[0]['flags'] & 1
    return owners[0]['offset'] + address - owners[0]['vaddr']


def authenticate_case(case):
    original = read_file(case['input']); core = read_file(case['core_output'])
    assert digest(original) == case['input_sha256']
    assert digest(core) == case['core_output_sha256']
    elf = elf64(original)
    assert elf['kind'] == (2 if case['name'] == 'exec' else 3)
    offset = executable_offset(elf, case['pc'], 6)
    assert offset == case['file_offset']
    assert original[offset:offset + 6] == b'\xb8' + case['value'].to_bytes(4, 'little') + b'\xc3'
    assert original[executable_offset(elf, case['hook'], 1)] == 0xc3
    return original, elf


def validate_rpc(raw, case, original, elf):
    assert 0 < len(raw) <= MAX_FILE and raw.endswith(b'\n')
    lines = raw.decode('utf-8').splitlines()
    assert 5 <= len(lines) <= MAX_RPC_MESSAGES and all(lines)
    messages = [loads(line) for line in lines]
    for index, message in enumerate(messages):
        assert message.keys() == {'jsonrpc', 'method', 'params', 'id'}
        assert message['jsonrpc'] == '2.0' and type(message['params']) is dict
        assert type(message['id']) is int and message['id'] == index
    count = len(messages) - 4
    assert [message['method'] for message in messages] == ['binary', 'trampoline'] + ['instruction'] * count + ['patch', 'emit']
    assert messages[0]['params'] == dict(filename=case['input'], mode='dso' if case['name'] == 'libcarrierfixture.so' else 'exe')
    assert messages[1]['params'] == dict(name='passthru', template=['$instruction', '$continue'])
    instructions, physical = [], []
    for message in messages[2:-2]:
        record = message['params']
        assert record.keys() == {'address', 'length', 'offset'}
        address, length, offset = (integer(record[key]) for key in ('address', 'length', 'offset'))
        assert 1 <= length <= 15 and offset + length <= len(original)
        assert executable_offset(elf, address, length) == offset
        assert all(end <= offset or offset + length <= start for start, end in physical)
        physical.append((offset, offset + length)); instructions.append(record)
    selected = [row for row in instructions if row['address'] == case['pc'] or row['offset'] == case['file_offset']]
    assert selected == [dict(address=case['pc'], length=5, offset=case['file_offset'])]
    assert messages[-2]['params'] == dict(trampoline='passthru', offset=case['file_offset'])
    emit = messages[-1]['params']
    assert emit.keys() == {'filename', 'format', 'mapping_size'}
    assert emit['filename'] == 'a.out' and emit['format'] == 'binary'
    # Default frontend compression level9 makes the exact mapping unit4096.
    assert integer(emit['mapping_size']) == 4096
    return dict(rpc_sha256=digest(raw), messages=len(messages), instruction_records=count,
                selected=selected[0], patch_count=1, trampoline='passthru', emit=emit)


def backend_stats(stdout, stderr, case, input_bytes, output_bytes):
    out, err = stdout.decode('utf-8'), stderr.decode('utf-8')
    # Keep ANSI/progress bytes intact in raw logs. Only anchored statistic lines
    # are parsed; no arbitrary escape stripping or substring success test.
    expected = {'num_patched': 1, 'num_patched_B1': 1, 'num_patched_B2': 0,
                'num_patched_T1': 0, 'num_patched_T2': 0, 'num_patched_T3': 0}
    parsed = {}
    for name, value in expected.items():
        rows = re.findall(r'^' + name + r'\s*=\s*(\d+) / (\d+) \((\d+\.\d{2})%\)$', out, re.M)
        assert len(rows) == 1, name
        actual, total, percent = rows[0]
        assert (int(actual), int(total), percent) == (value, 1, '100.00' if value else '0.00'), name
        assert len(re.findall(r'^' + name + r'\s*=', out, re.M)) == 1
        parsed[name] = int(actual)
    inputs = re.findall(r'^input_binary\s*= (.*)$', out, re.M)
    modes = re.findall(r'^input_mode\s*= (.*)$', out, re.M)
    assert inputs == [case['input']]
    assert modes == ['SHARED_OBJECT' if case['name'] == 'libcarrierfixture.so' else 'EXECUTABLE']
    sizes = {}
    for name, expected_size in [('input_file_size', len(input_bytes)), ('output_file_size', len(output_bytes))]:
        rows = re.findall(r'^' + name + r'\s*= (\d+)(?: \(\d+\.\d{2}%\))?$', out, re.M)
        assert len(rows) == 1 and int(rows[0]) == expected_size
        sizes[name] = int(rows[0])
    address = r'(?:\[absolute\] )?-?0x[0-9a-f]+'
    rows = re.findall(r'^debug: patched instruction (0x[0-9a-f]+) \[size=(\d+), tactic=([^,]+), trampoline=(' + address + r')\.\.(' + address + r')\]$', err, re.M)
    assert len(rows) == 1
    pc, length, tactic, start, end = rows[0]
    assert (int(pc, 16), int(length), tactic) == (case['pc'], 5, 'B1')
    assert len(re.findall(r'^debug: patched instruction ', err, re.M)) == 1
    assert 'failed to patch instruction' not in err
    assert not re.search(r'^(?:error|warning):', err, re.M)
    def coordinate(text):
        absolute = text.startswith('[absolute] ')
        return absolute, int(text.removeprefix('[absolute] '), 16)
    absolute, low = coordinate(start); other_absolute, high = coordinate(end)
    assert absolute == other_absolute and 0 < high - low <= MAX_FILE
    assert out.count('\x1b[32m.\x1b[0m') == 1 and '\x1b[31mX\x1b[0m' not in out
    return dict(statistics=parsed, sizes=sizes, reported_site=dict(pc=int(pc, 16), length=5,
                tactic='B1', trampoline_start=start, trampoline_end=end),
                rewritten_app_executed=False, architectural_equivalence_proved=False)


def validate_helper_receipt(receipt, request_raw, helper_sha256, stdout, stderr):
    # Exact reviewed bounded_command.py schema; runtime binding also pins its
    # source digest. A successful outer process alone never proves cleanup.
    required = {'request_sha256', 'helper_sha256', 'exit', 'wall_timeout',
                'unexpected_descendants', 'absence_proof', 'stdout_sha256',
                'stderr_sha256', 'elapsed_seconds', 'cleanup_events', 'cleanup_error',
                'aborted', 'inputs_unchanged'}
    assert required == receipt.keys()
    assert receipt['request_sha256'] == digest(request_raw)
    assert receipt['helper_sha256'] == helper_sha256
    assert type(receipt['exit']) is int and receipt['exit'] == 0
    assert receipt['wall_timeout'] is False
    assert receipt['aborted'] is None and receipt['cleanup_error'] is None
    assert receipt['inputs_unchanged'] is True
    assert receipt['unexpected_descendants'] == []
    assert receipt['absence_proof'] == 'ECHILD'
    assert receipt['stdout_sha256'] == digest(stdout)
    assert receipt['stderr_sha256'] == digest(stderr)
    elapsed = receipt['elapsed_seconds']
    assert type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= 50
    assert receipt['cleanup_events'] == []
    return True
