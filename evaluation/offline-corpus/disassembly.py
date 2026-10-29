#!/usr/bin/env python3
"""Authored-source/object/ELF joins only; never decode, plan, map or execute code.

The caller supplies independently frozen hashes and owns the actual as/ld and
independent head-capture provenance. Matching hashes cannot prove that provenance.
This module does not replace the importer's independent instruction decoding.
"""
import hashlib
from pathlib import Path
import re
import struct
import sys
import types

if sys.flags.optimize:
    raise SystemExit('assertions required')

CAP = 1048576
PROFILE = 'offline-whole-authored-null-jumps-v1'
LIMITS = '1048576 32 32 131072 128 2097152 1048576 128 16777216'
CORPUS_SHA = '007e529b3716061d8b7f11f3e33541ee80292027165703663db2f72a81e35b07'
TARGET_SHA = 'de1028fa9b590a6f1ba37627ac5ff78470c9f3b225eed794f7c32959c1a1c00c'
BASES = {'.text.start': 0x401000, '.text.kernel': 0x402000,
         '.text.hook': 0x403000, '.data.buffers': 0x404000}
ROLES = ('start', 'kernel', 'hook')
COUNTS = {'checksum': (80, 16), 'rle-roundtrip': (107, 26)}
INPUTS = ('source', 'linker', 'object', 'original', 'heads', 'target')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def authenticated_module(path, expected):
    with path.open('rb') as stream:
        raw = stream.read(CAP + 1)
    assert len(raw) <= CAP and sha(raw) == expected, 'dependency source identity'
    module = types.ModuleType('_authored_' + path.stem)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


HERE = Path(__file__).resolve().parent
C = authenticated_module(HERE / 'corpus.py', CORPUS_SHA)
T = authenticated_module(HERE.parent / 'elf-exec/render_selection.py', TARGET_SHA)


def uint(text):
    assert re.fullmatch(r'0|[1-9][0-9]*', text), 'canonical integer'
    value = int(text)
    assert value <= (1 << 64) - 1, 'integer overflow'
    return value


def text_rows(raw):
    assert type(raw) is bytes and 0 < len(raw) <= CAP and raw.endswith(b'\n')
    assert re.fullmatch(rb'[\x20-\x7e\n]+', raw), 'ASCII/LF'
    rows = [line.split(' ') for line in raw.decode('ascii')[:-1].split('\n')]
    assert all(row and all(row) for row in rows), 'single spaces/nonempty rows'
    return rows


class Elf:
    """Bounded ELF64 structures; no tool text and no instruction inference."""
    def __init__(self, raw, kind):
        assert type(raw) is bytes and 64 <= len(raw) <= CAP
        h = struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
        assert h[:4] == (b'\x7fELF\x02\x01\x01' + bytes(9), kind, 62, 1)
        _, _, _, _, self.entry, phoff, shoff, flags, eh, pw, pn, sw, sn, names = h
        assert flags == 0 and eh == 64 and sw == 64 and 1 < sn <= 64
        assert 0 < names < sn and 64 <= shoff <= len(raw) - sn * 64
        assert (kind == 1 and self.entry == phoff == pn == pw == 0) or (
            kind == 2 and phoff == 64 and pw == 56 and pn == 6)
        self.raw = raw
        self.ph = [struct.unpack_from('<IIQQQQQQ', raw, phoff + i * 56) for i in range(pn)]
        self.sec = [struct.unpack_from('<IIQQQQIIQQ', raw, shoff + i * 64) for i in range(sn)]
        assert self.sec[0] == (0,) * 10
        occupied = [(0, 64 + pn * 56), (shoff, shoff + sn * 64)]
        assert occupied[0][1] <= occupied[1][0]
        for section in self.sec[1:]:
            _, typ, _, _, off, size, _, _, align, _ = section
            assert typ in (1, 2, 3, 4, 7, 8, 9), 'unauthored section kind'
            assert align == 0 or align & (align - 1) == 0
            assert align <= 1 or off % align == 0, 'section file alignment'
            if typ != 8 and size:
                assert off <= len(raw) - size and all(off >= b or off + size <= a for a, b in occupied), 'section overlap/bounds'
                occupied.append((off, off + size))
        assert self.sec[names][1] == 3
        strings = self.data(names)
        self.by_name = {}
        for i, section in enumerate(self.sec[1:], 1):
            name = self.string(strings, section[0])
            assert name and name not in self.by_name, 'section names'
            self.by_name[name] = i
        tabs = [i for i, s in enumerate(self.sec) if s[1] == 2]
        assert len(tabs) == 1
        self.symtab = tabs[0]
        table = self.sec[self.symtab]
        assert table[9] == 24 and table[5] % 24 == 0 and 0 < table[5] // 24 <= 512
        assert 0 < table[7] <= table[5] // 24, 'local symbol boundary'
        assert 0 < table[6] < sn and self.sec[table[6]][1] == 3
        strings = self.data(table[6])
        self.symbols = []
        self.named = {}
        for pos in range(0, table[5], 24):
            name, info, other, section, value, size = struct.unpack_from('<IBBHQQ', self.data(self.symtab), pos)
            assert (info >> 4 == 0) == (pos // 24 < table[7]), 'symbol binding order'
            assert section == 0 or section < sn or section == 0xfff1
            name = self.string(strings, name)
            row = (info, other, section, value, size)
            if name:
                assert name not in self.named and section != 0, 'duplicate/undefined named symbol'
                self.named[name] = row
            self.symbols.append(row)
        assert self.symbols[0] == (0, 0, 0, 0, 0)

    @staticmethod
    def string(table, off):
        assert off < len(table)
        end = table.find(b'\0', off)
        assert end >= off
        return table[off:end].decode('ascii')

    def data(self, index):
        s = self.sec[index]
        assert s[1] != 8 or s[5] == 0, 'nonempty NOBITS not authored'
        return self.raw[s[4]:s[4] + s[5]]

    def section(self, name):
        return self.sec[self.by_name[name]]

    def owned(self, va, size, flags):
        assert 0 < size and va <= (1 << 64) - size
        matches = [p for p in self.ph if p[0] == 1 and p[3] <= va and va + size <= p[3] + p[5]]
        assert len(matches) == 1 and matches[0][1] == flags, 'unique LOAD owner'
        p = matches[0]
        off = p[2] + va - p[3]
        assert off <= len(self.raw) - size
        return off, self.raw[off:off + size]


def source_roster():
    instructions, labels = [], {}
    for line in C.START.splitlines():
        line = line.strip()
        if not line or line.startswith('.'):
            continue
        if line.endswith(':'):
            assert line[:-1] not in labels
            labels[line[:-1]] = len(instructions)
        else:
            instructions.append(line)
    assert len(instructions) == 61 and sum(i.startswith('j') for i in instructions) == 14
    return instructions, labels


def head_transport(program, raw, original, obj, sizes):
    rows = text_rows(raw)
    assert rows[:4] == [['LI2AUTHORED-HEADS', '1'], ['program', program],
                       ['original', sha(original)], ['object', sha(obj)]]
    result = {}
    at = 4
    for role, count in zip(ROLES, (61, len(C.instructions(program)), 1)):
        heads, offset = [], 0
        for index in range(count):
            row = rows[at]; at += 1
            assert len(row) == 5 and row[:2] == ['head', role]
            assert uint(row[2]) == index and uint(row[3]) == offset
            assert re.fullmatch(r'(?:[0-9a-f]{2}){1,15}', row[4])
            code = bytes.fromhex(row[4])
            heads.append((offset, code)); offset += len(code)
        assert offset == sizes[role], 'complete region extent'
        result[role] = heads
    assert at == len(rows), 'extra or reordered head'
    return result


def ownership(original, obj, program):
    image, reloc = Elf(original, 2), Elf(obj, 1)
    assert image.entry == 0x401000
    assert [p[0] for p in image.ph] == [6, 1, 1, 1, 4, 0x6474e551]
    loads = [p for p in image.ph if p[0] == 1]
    assert [(p[3], p[5], p[6], p[1]) for p in loads] == [
        (0x400000, 4096, 4096, 4), (0x401000, 12288, 12288, 5),
        (0x404000, 335872, 335872, 6)]
    for i, ph in enumerate(loads):
        assert ph[2] % 4096 == ph[3] % 4096 and ph[7] == 4096 and ph[2] <= len(original) - ph[5]
        assert all(ph[2] >= q[2] + q[5] or ph[2] + ph[5] <= q[2] for q in loads[:i]), 'LOAD file alias'
    assert image.ph[-1][1] == 6 and image.ph[-1][5:7] == (0, 0)
    assert image.ph[0][1:7] == (4, 64, 0x400040, 0x400040, 336, 336)
    assert {n for n, i in image.by_name.items() if image.sec[i][2] & 2 and image.sec[i][5]} == {'.note.fixture', '.header_pad', '.text', '.data'}
    assert {n for n, i in image.by_name.items() if image.sec[i][2] & 4 and image.sec[i][5]} == {'.text'}
    text = image.section('.text')
    assert text[1:6] == (1, 6, 0x401000, loads[1][2], 12288)
    nonempty = {n for n, i in reloc.by_name.items() if reloc.sec[i][2] & 2 and reloc.sec[i][5]}
    assert nonempty == set(BASES) | {'.note.fixture'}, 'complete object allocation set'
    assert {n for n in nonempty if reloc.section(n)[2] & 4} == {'.text.' + r for r in ROLES}
    assert all(s[1] not in (4, 9) or s[5] == 0 for s in image.sec), 'final relocation section'
    for name in BASES:
        s = reloc.section(name)
        assert s[1] == 1 and s[2] == (3 if name == '.data.buffers' else 6) and s[3] == 0
    expected_data = bytes(69632 + 200704) + bytes([0x5a]) * 65536
    assert reloc.data(reloc.by_name['.data.buffers']) == expected_data
    assert image.owned(0x404000, len(expected_data), 6)[1] == expected_data
    note = struct.pack('<III', 4, 4, 1) + b'LI2\0' + struct.pack('<I', 1)
    assert reloc.section('.note.fixture')[1:4] == (7, 2, 0)
    assert reloc.data(reloc.by_name['.note.fixture']) == note
    assert image.ph[4][5:7] == (len(note), len(note))
    assert image.owned(image.ph[4][3], len(note), 4) == (image.ph[4][2], note)
    for name, va, size, flags in [('.note.fixture', image.ph[4][3], len(note), 4),
                                  ('.header_pad', image.ph[4][3] + len(note), 0x401000 - image.ph[4][3] - len(note), 4),
                                  ('.data', 0x404000, len(expected_data), 6)]:
        section = image.section(name)
        assert section[3] == va and section[5] == size
        assert image.owned(va, size, flags) == (section[4], image.data(image.by_name[name]))
    assert not any(image.data(image.by_name['.header_pad'])), 'authored header padding'
    expected_kernel = b''.join(h['code'] for h in C.instructions(program))
    assert reloc.data(reloc.by_name['.text.kernel']) == expected_kernel
    assert reloc.data(reloc.by_name['.text.hook']) == b'\xc3'
    sizes = {r: reloc.section('.text.' + r)[5] for r in ROLES}
    assert all(0 < sizes[r] < 4096 for r in ROLES)
    functions = {'_start': 'start', 'kernel': 'kernel', 'null_hook': 'hook'}
    assert {n for n, s in image.named.items() if s[0] & 15 == 2} == set(functions)
    assert {n for n, s in reloc.named.items() if s[0] & 15 == 2} == set(functions)
    for name, role in functions.items():
        a, b = reloc.named[name], image.named[name]
        assert a == (18, 0, reloc.by_name['.text.' + role], 0, sizes[role])
        assert b == (18, 0, image.by_name['.text'], BASES['.text.' + role], sizes[role])
    for name, s in reloc.named.items():
        source = next((n for n, i in reloc.by_name.items() if i == s[2] and n in BASES), None)
        if source is not None:
            assert s[3] + s[4] <= reloc.section(source)[5]
            actual = image.named[name]
            assert actual[:2] == s[:2] and actual[3:] == (BASES[source] + s[3], s[4]), 'linked symbol translation'
            section = image.sec[actual[2]]
            assert section[3] <= actual[3] <= section[3] + section[5]
    return image, reloc, sizes


def code_and_relocations(image, obj, heads, program):
    instructions, labels = source_roster()
    start = heads['start']
    expected_relocations = {}
    lea = {'lea input(%rip),%rsi': ('488d35', 0x404000),
           'lea stack_end-256(%rip),%rsp': ('488d25', 0x404000 + 335872 - 256),
           'lea input(%rip),%rdi': ('488d3d', 0x404000),
           'lea output(%rip),%rdx': ('488d15', 0x404000 + 69632),
           'lea output(%rip),%r15': ('4c8d3d', 0x404000 + 69632),
           'call kernel': ('e8', 0x402000)}
    branches = {'jne': 5, 'js': 8, 'je': 4, 'jbe': 6, 'jle': 14}
    for instruction, (off, code) in zip(instructions, start):
        pc = 0x401000 + off
        op = instruction.split()[0]
        if op.startswith('j'):
            label = instruction.split()[1]
            target = 0x401000 + start[labels[label]][0]
            if op == 'jmp':
                assert (len(code), code[0]) in ((2, 0xeb), (5, 0xe9))
            else:
                cc = branches[op]
                assert len(code) == 2 and code[0] == 0x70 + cc or len(code) == 6 and code[:2] == bytes([15, 0x80 + cc])
            assert pc + len(code) + int.from_bytes(code[-(1 if len(code) == 2 else 4):], 'little', signed=True) == target
        if instruction in lea:
            prefix, target = lea[instruction]
            assert len(code) == len(bytes.fromhex(prefix)) + 4 and code[:-4] == bytes.fromhex(prefix)
            assert pc + len(code) + int.from_bytes(code[-4:], 'little', signed=True) == target
            expected_relocations[off + len(code) - 4] = (target, instruction == 'call kernel')
    assert len(expected_relocations) == 6
    patched = {role: bytearray(obj.data(obj.by_name['.text.' + role])) for role in ROLES}
    seen = set()
    for section in obj.sec:
        if section[1] not in (4, 9) or not section[5]:
            continue
        assert section[1] == 4 and section[9] == 24 and section[5] % 24 == 0
        assert section[6:8] == (obj.symtab, obj.by_name['.text.start'])
        assert section[5] // 24 <= 6
        for pos in range(section[4], section[4] + section[5], 24):
            off, info, addend = struct.unpack_from('<QQq', obj.raw, pos)
            assert off in expected_relocations and off not in seen
            seen.add(off)
            target, call = expected_relocations[off]
            kind, symbol = info & 0xffffffff, info >> 32
            assert kind in ((2, 4) if call else (2,)) and symbol < len(obj.symbols)
            s = obj.symbols[symbol]
            owners = [name for name, index in obj.by_name.items() if index == s[2] and name in BASES]
            assert len(owners) == 1 and s[1] == 0
            assert s[3] <= obj.section(owners[0])[5]
            value = BASES[owners[0]] + s[3] + addend - (0x401000 + off)
            assert 0x401000 + off + 4 + value == target and -(1 << 31) <= value < (1 << 31)
            assert patched['start'][off:off + 4] == bytes(4)
            patched['start'][off:off + 4] = struct.pack('<i', value)
    assert seen == set(expected_relocations), 'every relocation exactly once'
    for role in ROLES:
        code = bytes(patched[role])
        assert b''.join(b for _, b in heads[role]) == code
        assert image.owned(BASES['.text.' + role], len(code), 5)[1] == code, 'whole source bytes after relocations'
    assert [b for _, b in heads['kernel']] == [h['code'] for h in C.instructions(program)]
    assert heads['hook'] == [(0, b'\xc3')]


def attempt(program, inputs, expected):
    """One pure material attempt; caller retains all raw inputs on every outcome.

    Expected hashes come from independent source/build/capture ownership, never
    from this return value. No candidate, importer, or runtime success is minted.
    """
    assert program in COUNTS and type(inputs) is dict and type(expected) is dict
    assert set(inputs) == set(expected) == set(INPUTS)
    files = {}
    result = dict(profile=PROFILE, program=program, status='MATERIALS_REFUSED',
                  source_expected_heads=COUNTS[program][0], source_expected_jumps=COUNTS[program][1],
                  roster_checked_heads=None, roster_checked_jumps=None,
                  qualification_complete=False, importer_verified=False, files=files)
    stage = 'inputs'
    try:
        for key in INPUTS:
            assert type(inputs[key]) is bytes and 0 < len(inputs[key]) <= CAP, 'input bound'
            assert type(expected[key]) is str and re.fullmatch('[0-9a-f]{64}', expected[key])
            assert sha(inputs[key]) == expected[key], 'frozen input digest'
        assert inputs['source'] == C.assembly(program) and inputs['linker'] == C.LINKER.encode(), 'exact authored source'
        stage = 'object-elf-ownership'
        image, obj, sizes = ownership(inputs['original'], inputs['object'], program)
        stage = 'head-transport'
        heads = head_transport(program, inputs['heads'], inputs['original'], inputs['object'], sizes)
        stage = 'relocations-and-code'
        code_and_relocations(image, obj, heads, program)
        stage = 'ledger'
        ledger = ['LI2DISASM 1', 'original ' + sha(inputs['original']),
                  'contract complete-code no-overlap no-code-as-data private-image']
        inventory = ['role\tindex\tpc\tfile_offset\tlength\tselected_jump']
        startup, _ = source_roster()
        jumps = []
        for role in ROLES:
            base = BASES['.text.' + role]
            offset = image.owned(base, sizes[role], 5)[0]
            ledger.append(f'region {base} {offset} {sizes[role]}')
            for index, (off, code) in enumerate(heads[role]):
                selected = (startup[index].startswith('j') if role == 'start' else
                            C.instructions(program)[index]['target'] is not None if role == 'kernel' else False)
                if selected:
                    jumps.append((base + off, len(code), offset + off))
                ledger.append(f'head {base + off} {code.hex()}')
                inventory.append(f'{role}\t{index}\t{base + off}\t{offset + off}\t{len(code)}\t{int(selected)}')
        count = sum(len(v) for v in heads.values())
        assert (count, len(jumps)) == COUNTS[program]
        files['ledger.txt'] = ('\n'.join(ledger) + '\n').encode()
        files['source-inventory.tsv'] = ('\n'.join(inventory) + '\n').encode()
        result.update(roster_checked_heads=count, roster_checked_jumps=len(jumps))
        stage = 'policy'
        target = T.target_record(inputs['target']).rstrip('\n')
        policy = ['LI2DISASM-POLICY 1', 'original ' + sha(inputs['original']),
                  'ledger ' + sha(files['ledger.txt']), target, 'domain 1', 'carrier 4718592',
                  'limits ' + LIMITS, 'null-hook 4206592']
        for sid in range(1, len(jumps) + 1):
            a, b = 0x500000 + (sid - 1) * 4096, 0x600000 + (sid - 1) * 4096
            policy += [f'search {sid} auto 64 256 64 none 256 4096',
                       f'allocation {sid} selected {a} 1 4096 {a}:4096',
                       f'allocation {sid} victim {b} 1 4096 {b}:4096']
        files['policy.txt'] = ('\n'.join(policy) + '\n').encode()
        assert all(len(v) <= CAP for v in files.values())
        result.update(status='MATERIALS_READY')
    except (AssertionError, ValueError, KeyError, IndexError, struct.error) as error:
        result['failure'] = dict(stage=stage, error=type(error).__name__)
    result['observed_input_sha256'] = {k: sha(v) if type(v) is bytes and len(v) <= CAP else None for k, v in inputs.items()}
    result['observed_input_bytes'] = {k: len(v) if type(v) is bytes else None for k, v in inputs.items()}
    result['expected_input_sha256'] = dict(expected)
    return result
