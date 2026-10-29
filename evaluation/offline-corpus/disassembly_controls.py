#!/usr/bin/env python3
"""Source-authenticated pure controls, UNRUN in the proposal.

Synthetic ELF/object/head fixtures test the real adapter's structural joins.
They do NOT attest a compiler run or the adapter's external source-build premise.
No assembler, disassembler, planner, candidate, or process owner is invoked.
"""
import hashlib
from pathlib import Path
import struct
import sys
import types
import unittest

if sys.flags.optimize:
    raise SystemExit('assertions required')
ADAPTER_SHA = 'cf16eecabfa6d9d1bbf26812fcac3097f82447287db2b23fab46a127974c83bf'
path = Path(__file__).resolve().with_name('disassembly.py')
with path.open('rb') as stream:
    raw = stream.read(1048577)
assert len(raw) <= 1048576 and hashlib.sha256(raw).hexdigest() == ADAPTER_SHA
D = types.ModuleType('authenticated_authored_disassembly')
D.__file__ = str(path)
exec(compile(raw, str(path), 'exec'), D.__dict__)


def section(name, data, typ=1, flags=0, va=0, **other):
    return dict(name=name, data=data, typ=typ, flags=flags, va=va,
                link=other.get('link', 0), info=other.get('info', 0),
                align=other.get('align', 1), entsize=other.get('entsize', 0),
                off=other.get('off'))


def elf(kind, sections, ph=()):
    # Build tables only. Zero RX gaps are deliberately synthetic, not tool output.
    sections = [dict(s) for s in sections]
    strings = b'\0'
    for s in sections + [dict(name='.shstrtab')]:
        s['nameoff'] = len(strings)
        strings += s['name'].encode() + b'\0'
    sections.append(section('.shstrtab', strings, 3))
    names = {s['name']: i for i, s in enumerate(sections, 1)}
    cursor = 64 + 56 * len(ph)
    raw = bytearray(cursor)
    for s in sections:
        if s['off'] is None:
            s['off'] = (cursor + 7) & ~7
        end = s['off'] + len(s['data'])
        if end > len(raw):
            raw.extend(bytes(end - len(raw)))
        raw[s['off']:end] = s['data']
        cursor = max(cursor, end)
    shoff = (cursor + 7) & ~7
    raw.extend(bytes(shoff + 64 * (len(sections) + 1) - len(raw)))
    shstrings = sections[-1]['data']
    for i, s in enumerate(sections, 1):
        nameoff = shstrings.index(s['name'].encode() + b'\0')
        struct.pack_into('<IIQQQQIIQQ', raw, shoff + i * 64, nameoff, s['typ'],
                         s['flags'], s['va'], s['off'], len(s['data']),
                         s['link'], s['info'], s['align'], s['entsize'])
    struct.pack_into('<16sHHIQQQIHHHHHH', raw, 0, b'\x7fELF\x02\x01\x01' + bytes(9),
                     kind, 62, 1, 0 if kind == 1 else 0x401000,
                     0 if kind == 1 else 64, shoff, 0, 64,
                     0 if kind == 1 else 56, len(ph), 64, len(sections) + 1, names['.shstrtab'])
    for i, row in enumerate(ph):
        struct.pack_into('<IIQQQQQQ', raw, 64 + i * 56, *row)
    return bytes(raw)


def symbols(rows):
    strings, table = b'\0', bytearray()
    for name, info, index, value, size in rows:
        offset = len(strings) if name else 0
        if name:
            strings += name.encode() + b'\0'
        table.extend(struct.pack('<IBBHQQ', offset, info, 0, index, value, size))
    return bytes(table), strings


def fixture(program='checksum'):
    instructions, labels = D.source_roster()
    prefixes = {'lea input(%rip),%rsi': '488d35', 'lea stack_end-256(%rip),%rsp': '488d25',
                'lea input(%rip),%rdi': '488d3d', 'lea output(%rip),%rdx': '488d15',
                'lea output(%rip),%r15': '4c8d3d', 'call kernel': 'e8'}
    targets = {'lea input(%rip),%rsi': 0, 'lea stack_end-256(%rip),%rsp': 335872 - 256,
               'lea input(%rip),%rdi': 0, 'lea output(%rip),%rdx': 69632,
               'lea output(%rip),%r15': 69632}
    branches = {'jne': 5, 'js': 8, 'je': 4, 'jbe': 6, 'jle': 14}
    codes, offsets = [], []
    for instruction in instructions:
        offsets.append(sum(map(len, codes)))
        op = instruction.split()[0]
        if instruction in prefixes:
            code = bytes.fromhex(prefixes[instruction]) + bytes(4)
        elif op == 'jmp':
            code = b'\xe9' + bytes(4)
        elif op in branches:
            code = bytes([15, 0x80 + branches[op]]) + bytes(4)
        else:
            code = b'\x90'  # No assertion of source/compiler correspondence.
        codes.append(code)
    relocations = bytearray()
    linked = list(codes)
    for i, instruction in enumerate(instructions):
        op = instruction.split()[0]
        end = offsets[i] + len(codes[i])
        if op.startswith('j'):
            displacement = offsets[labels[instruction.split()[1]]] - end
            codes[i] = codes[i][:-4] + struct.pack('<i', displacement)
            linked[i] = codes[i]
        if instruction in prefixes:
            call = instruction == 'call kernel'
            symbol, addend = (6, -4) if call else (4, targets[instruction] - 4)
            relocations.extend(struct.pack('<QQq', end - 4, symbol << 32 | (4 if call else 2), addend))
            target = 0x402000 if call else 0x404000 + targets[instruction]
            linked[i] = codes[i][:-4] + struct.pack('<i', target - (0x401000 + end))
    start = b''.join(codes)
    kernel_heads = D.C.instructions(program)
    kernel = b''.join(h['code'] for h in kernel_heads)
    data = bytes(69632 + 200704) + bytes([0x5a]) * 65536
    note = struct.pack('<III', 4, 4, 1) + b'LI2\0' + struct.pack('<I', 1)
    obj_symbols = [('', 0, 0, 0, 0)] + [('', 3, i, 0, 0) for i in range(1, 5)] + [
        ('_start', 18, 1, 0, len(start)), ('kernel', 18, 2, 0, len(kernel)), ('null_hook', 18, 3, 0, 1)]
    sym, names = symbols(obj_symbols)
    object_ = elf(1, [section('.text.start', start, flags=6), section('.text.kernel', kernel, flags=6),
        section('.text.hook', b'\xc3', flags=6), section('.data.buffers', data, flags=3),
        section('.note.fixture', note, 7, 2), section('.rela.text.start', bytes(relocations), 4, link=7, info=1, entsize=24),
        section('.symtab', sym, 2, link=8, info=5, entsize=24), section('.strtab', names, 3)])
    body = bytearray(12288)
    body[:len(start)] = b''.join(linked)
    body[4096:4096 + len(kernel)] = kernel
    body[8192] = 0xc3
    image_symbols = [('', 0, 0, 0, 0)] + [('', 3, 3 if i < 4 else 4, 0x401000 + (i - 1) * 4096 if i < 4 else 0x404000, 0) for i in range(1, 5)] + [
        ('_start', 18, 3, 0x401000, len(start)), ('kernel', 18, 3, 0x402000, len(kernel)), ('null_hook', 18, 3, 0x403000, 1)]
    sym, names = symbols(image_symbols)
    ph = [(6, 4, 64, 0x400040, 0x400040, 336, 336, 8),
          (1, 4, 0, 0x400000, 0x400000, 4096, 4096, 4096),
          (1, 5, 4096, 0x401000, 0x401000, 12288, 12288, 4096),
          (1, 6, 16384, 0x404000, 0x404000, len(data), len(data), 4096),
          (4, 4, 400, 0x400190, 0x400190, len(note), len(note), 4),
          (0x6474e551, 6, 0, 0, 0, 0, 0, 16)]
    original = elf(2, [section('.note.fixture', note, 7, 2, 0x400190, off=400),
        section('.header_pad', bytes(4096 - 420), flags=2, va=0x4001a4, off=420),
        section('.text', bytes(body), flags=6, va=0x401000, off=4096),
        section('.data', data, flags=3, va=0x404000, off=16384),
        section('.symtab', sym, 2, link=6, info=5, entsize=24), section('.strtab', names, 3)], ph)
    lines = ['LI2AUTHORED-HEADS 1', 'program ' + program, 'original ' + D.sha(original), 'object ' + D.sha(object_)]
    for role, values in [('start', linked), ('kernel', [h['code'] for h in kernel_heads]), ('hook', [b'\xc3'])]:
        cursor = 0
        for index, code in enumerate(values):
            lines.append(f'head {role} {index} {cursor} {code.hex()}'); cursor += len(code)
    return dict(source=D.C.assembly(program), linker=D.C.LINKER.encode(), object=object_, original=original,
                heads=('\n'.join(lines) + '\n').encode(), target=b'target xsave64 3\n')


def run(inputs, program='checksum'):
    # These are synthetic first pins, not build/native authority.
    return D.attempt(program, inputs, {k: D.sha(v) for k, v in inputs.items()})


def rebind(inputs):
    rows = inputs['heads'].splitlines()
    rows[2] = b'original ' + D.sha(inputs['original']).encode()
    rows[3] = b'object ' + D.sha(inputs['object']).encode()
    inputs['heads'] = b'\n'.join(rows) + b'\n'
    return inputs


def mutate_section(inputs, key, name, field, value):
    image = D.Elf(inputs[key], 1 if key == 'object' else 2)
    raw = bytearray(inputs[key]); shoff = struct.unpack_from('<Q', raw, 40)[0]
    section_ = list(image.section(name)); section_[field] = value
    struct.pack_into('<IIQQQQIIQQ', raw, shoff + image.by_name[name] * 64, *section_)
    inputs[key] = bytes(raw)
    return rebind(inputs)


class AuthoredDisassemblyControls(unittest.TestCase):
    def refused(self, inputs, program='checksum'):
        result = run(inputs, program)
        self.assertEqual(result['status'], 'MATERIALS_REFUSED')
        self.assertFalse(result['qualification_complete'])
        self.assertFalse(result['importer_verified'])
        self.assertEqual(result['observed_input_sha256'], {k: D.sha(v) if len(v) <= D.CAP else None for k, v in inputs.items()})
        return result

    def test_complete_two_program_source_rosters(self):
        total_heads = total_jumps = 0
        for program, counts in D.COUNTS.items():
            inputs = fixture(program); result = run(inputs, program)
            self.assertEqual(result['status'], 'MATERIALS_READY')
            self.assertEqual((result['roster_checked_heads'], result['roster_checked_jumps']), counts)
            self.assertEqual(len(result['files']['source-inventory.tsv'].splitlines()) - 1, counts[0])
            self.assertEqual(sum(line.startswith(b'head ') for line in result['files']['ledger.txt'].splitlines()), counts[0])
            self.assertEqual(sum(line.startswith(b'search ') for line in result['files']['policy.txt'].splitlines()), counts[1])
            self.assertEqual(run(inputs, program), result)
            self.assertFalse(result['importer_verified'])
            total_heads += counts[0]; total_jumps += counts[1]
        self.assertEqual((total_heads, total_jumps), (187, 42))

    def test_first_pins_and_authored_sources_are_exact(self):
        for key in D.INPUTS:
            inputs = fixture(); expected = {k: D.sha(v) for k, v in inputs.items()}
            inputs[key] += b'x'
            self.assertEqual(D.attempt('checksum', inputs, expected)['status'], 'MATERIALS_REFUSED')
        for key in ('source', 'linker'):
            inputs = fixture(); inputs[key] += b'\n'
            self.refused(inputs)

    def test_complete_sections_and_unique_file_owners(self):
        for key, name, field, value in [('object', '.note.fixture', 2, 6),
                ('object', '.text.kernel', 4, 64), ('original', '.data', 2, 7),
                ('original', '.text', 3, 0x401001), ('object', '.text.hook', 1, 8)]:
            self.refused(mutate_section(fixture(), key, name, field, value))
        inputs = fixture(); raw = bytearray(inputs['original'])
        struct.pack_into('<Q', raw, 64 + 2 * 56 + 8, 0)
        inputs['original'] = bytes(raw)
        self.refused(rebind(inputs))

    def test_every_head_is_retained_and_canonical(self):
        for program, (count, _) in D.COUNTS.items():
            for index in range(4, count + 4):
                inputs = fixture(program); rows = inputs['heads'].splitlines(); del rows[index]
                inputs['heads'] = b'\n'.join(rows) + b'\n'; self.refused(inputs, program)
        for edit in (lambda b: b + b'head hook 1 1 90\n', lambda b: b.replace(b'head start 0 0 ', b'head start 00 0 '),
                     lambda b: b.replace(b'head start 0 0 ', b'head start 0 1 '), lambda b: b.replace(b'\n', b'\r\n'),
                     lambda b: b.replace(b'head hook 0 0 c3', b'head hook 0 0 90')):
            inputs = fixture(); inputs['heads'] = edit(inputs['heads']); self.refused(inputs)

    def test_relocations_and_linked_bytes_are_not_trusted_from_heads(self):
        for index in range(6):
            for delta in (0, 8, 16):
                inputs = fixture(); obj = D.Elf(inputs['object'], 1)
                at = obj.section('.rela.text.start')[4] + index * 24 + delta
                raw = bytearray(inputs['object']); raw[at] ^= 1; inputs['object'] = bytes(raw)
                self.refused(rebind(inputs))
        for key, at in [('original', 4096), ('original', 8192), ('original', 16384),
                        ('object', D.Elf(fixture()['object'], 1).section('.text.start')[4])]:
            inputs = fixture(); raw = bytearray(inputs[key]); raw[at] ^= 1; inputs[key] = bytes(raw)
            self.refused(rebind(inputs))
        # Coherent branch corruption changes object, original and transport, and
        # refreshes all synthetic pins. Only the independent source-label target
        # requirement can reject this otherwise byte-consistent mutation.
        inputs = fixture(); rows = inputs['heads'].splitlines()
        fields = rows[5].split(); offset = int(fields[3]); code = bytes.fromhex(fields[4].decode())
        changed = code[:-4] + struct.pack('<i', int.from_bytes(code[-4:], 'little', signed=True) + 1)
        for key, base in [('object', D.Elf(inputs['object'], 1).section('.text.start')[4]), ('original', 4096)]:
            raw = bytearray(inputs[key]); raw[base + offset:base + offset + len(changed)] = changed; inputs[key] = bytes(raw)
        fields[4] = changed.hex().encode(); rows[5] = b' '.join(fields)
        inputs['heads'] = b'\n'.join(rows) + b'\n'
        self.refused(rebind(inputs))

    def test_symbol_extent_and_relocation_completeness(self):
        for key in ('object', 'original'):
            inputs = fixture(); image = D.Elf(inputs[key], 1 if key == 'object' else 2)
            raw = bytearray(inputs[key]); at = image.sec[image.symtab][4] + 5 * 24 + 16
            raw[at] ^= 1; inputs[key] = bytes(raw)
            self.refused(rebind(inputs))
        inputs = fixture(); obj = D.Elf(inputs['object'], 1)
        self.refused(mutate_section(inputs, 'object', '.rela.text.start', 5, obj.section('.rela.text.start')[5] - 24))

    def test_target_refusal_retains_complete_roster(self):
        for target in (b'target fxsave64\n', b'target xsave64 4\n', b'target xsave64 7\n', b'target xsave64 3\n\n'):
            inputs = fixture(); inputs['target'] = target
            result = self.refused(inputs)
            self.assertEqual((result['roster_checked_heads'], result['roster_checked_jumps']), (80, 16))
            self.assertEqual(set(result['files']), {'ledger.txt', 'source-inventory.tsv'})
        policy = run(fixture())['files']['policy.txt']
        self.assertIn(('limits ' + D.LIMITS + '\n').encode(), policy)
        self.assertEqual(policy.count(b' preferred 64 256 64 none 256 4096\n'), 16)
        self.assertNotIn(b' B1 ', policy)

    def test_whole_input_failures_do_not_publish_subset(self):
        for key in D.INPUTS:
            inputs = fixture(); inputs[key] = b'x' * (D.CAP + 1)
            result = self.refused(inputs)
            self.assertEqual(result['files'], {})
            self.assertIsNone(result['roster_checked_heads'])
            self.assertEqual(result['source_expected_jumps'], 16)
        inputs = fixture(); inputs['heads'] = inputs['heads'].replace(b'head start ', b'head kernel ')
        self.assertEqual(self.refused(inputs)['files'], {})


if __name__ == '__main__':
    unittest.main()
