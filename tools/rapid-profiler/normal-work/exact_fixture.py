#!/usr/bin/env python3
"""Closed Exact37 ELF selection; the recipe separately pins the build before copying."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import hashlib
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('normal_exact_elf',
    Path(__file__).resolve().parents[1]/'selected-work/provenance.py')
assert spec is not None and spec.loader is not None
elf = importlib.util.module_from_spec(spec); spec.loader.exec_module(elf)
CODE = bytes.fromhex('31c04c8d04370fb60f83f15a4801c848ffc74c39c772ef48ba157c4a7fb979379e4831d0c3')
HEADS = [0, 2, 6, 9, 12, 15, 18, 21, 23, 33, 36]
LABEL = 'normal-exact-37-v1'
NAME = 'exact_work_nonempty'


def describe(data):
    parsed = elf.elf(data)
    assert set(parsed['tables']) == {'.dynsym', '.symtab'}
    selected = []
    for table in parsed['tables'].values():
        functions = [r for r in table if r[1] & 15 == 2]
        assert len(functions) == 1
        row = functions[0]
        assert row[0] == NAME and row[1:3] == (0x12, 0) and row[5] == 37
        assert 0 < row[3] < len(parsed['sections'])
        section = parsed['sections'][row[3]][1]
        assert section[2] & 6 == 6 and section[2] & 1 == 0
        assert section[3] <= row[4] and row[4]+37 <= section[3]+section[5]
        selected.append(row)
    assert selected[0] == selected[1]
    address = selected[0][4]
    offset, code = elf.mapped(data, parsed['loads'], address, 37, 5)
    assert code == CODE
    return dict(schema=1, label=LABEL, symbol=NAME, final=elf.digest(data),
        elf_va=address, length=37, file_offset=offset, selected_code=elf.digest(code),
        head_offsets=HEADS, return_offsets=[36])


def unique(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result
        result[key] = value
    return result


def authenticate(candidate, trusted, elf_va, length, selection, selection_sha256):
    assert re.fullmatch('[0-9a-f]{64}', selection_sha256)
    assert 0 < selection.stat().st_size <= elf.MIB
    metadata = selection.read_bytes()
    assert hashlib.sha256(metadata).hexdigest() == selection_sha256
    record = json.loads(metadata, object_pairs_hook=unique)
    assert isinstance(record, dict) and re.fullmatch('[0-9a-f]{40}', record.get('revision', ''))
    assert 0 < trusted.stat().st_size <= elf.MIB and 0 < candidate.stat().st_size <= elf.MIB
    data = trusted.read_bytes()
    details = describe(data)
    assert json.dumps(record, sort_keys=True) == json.dumps(dict(details, revision=record['revision']), sort_keys=True)
    assert type(elf_va) is type(length) is int and (elf_va, length) == (details['elf_va'], 37)
    assert candidate.read_bytes() == data
    assert (candidate.stat().st_dev, candidate.stat().st_ino) != (trusted.stat().st_dev, trusted.stat().st_ino)
    return details
