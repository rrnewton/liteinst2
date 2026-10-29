#!/usr/bin/env python3
"""Fabricated text/ELF controls only; no actual objdump or compiler provenance."""
import hashlib
from pathlib import Path
import struct
import sys
import types
import unittest

if sys.flags.optimize:
    raise SystemExit('assertions required')


def load(name, expected):
    path = Path(__file__).resolve().with_name(name)
    with path.open('rb') as stream:
        raw = stream.read(1048577)
    assert len(raw) <= 1048576 and hashlib.sha256(raw).hexdigest() == expected
    module = types.ModuleType('_head_control_' + path.stem)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


H = load('head_capture.py', 'a4e6b5b412c9fce99397d7966670e35b215a2b0ace802f1706abb64318b89846')
F = load('disassembly_controls.py', '39f4a517209a9269f3a7f026b1b4111fc862909ca4a6ae641148c80c90b49979')


def displays(inputs):
    outputs = {}
    for role, symbol in H.SYMBOLS.items():
        base = H.D.BASES['.text.' + role]
        lines = ['', 'synthetic:     file format elf64-x86-64', '',
                 'Disassembly of section .text:', '', f'{base:016x} <{symbol}>:']
        for line in inputs['heads'].splitlines()[4:]:
            _, item_role, _, offset, encoded = line.decode().split(' ')
            if item_role == role:
                column = ' '.join(f'{x:02x}' for x in bytes.fromhex(encoded))
                lines.append(f'  {base + int(offset):x}:\t{column:<48}\topaque operands')
        outputs[role] = ('\n'.join(lines) + '\n').encode()
    return outputs


def add_label(inputs, role, offset):
    # Add a real local NOTYPE table entry to both synthetic images. Adjust RELA
    # symbol indices when inserting before globals; no actual assembler claim.
    for key, kind in (('object', 1), ('original', 2)):
        image = H.D.Elf(inputs[key], kind)
        symbols = image.sec[image.symtab]
        boundary = symbols[7]
        table = bytearray(image.data(image.symtab))
        strings = image.data(symbols[6])
        section_index = image.by_name['.text.' + role] if kind == 1 else image.by_name['.text']
        value = offset if kind == 1 else H.D.BASES['.text.' + role] + offset
        entry = struct.pack('<IBBHQQ', len(strings), 0, 0, section_index, value, 0)
        table[boundary * 24:boundary * 24] = entry
        sections = []
        for name, index in image.by_name.items():
            if name == '.shstrtab':
                continue
            s = image.sec[index]; data = image.data(index)
            if index == image.symtab:
                data = bytes(table)
            elif index == symbols[6]:
                data = strings + b'capture_label\0'
            elif s[1] == 4:
                data = bytearray(data)
                for at in range(0, len(data), 24):
                    info = struct.unpack_from('<Q', data, at + 8)[0]
                    if info >> 32 >= boundary:
                        struct.pack_into('<Q', data, at + 8, info + (1 << 32))
                data = bytes(data)
            sections.append(F.section(name, data, s[1], s[2], s[3], link=s[6],
                info=s[7] + (index == image.symtab), align=s[8], entsize=s[9],
                off=s[4] if kind == 2 and s[2] & 2 else None))
        inputs[key] = F.elf(kind, sections, image.ph)
    return F.rebind(inputs)


class HeadCaptureControls(unittest.TestCase):
    def refused(self, inputs, outputs, program='checksum'):
        with self.assertRaises((AssertionError, ValueError, KeyError, IndexError, struct.error)):
            H.capture(program, inputs['original'], inputs['object'], outputs)

    def test_complete_two_program_transport_and_opaque_rendering(self):
        total = 0
        for program in H.D.COUNTS:
            inputs = F.fixture(program); outputs = displays(inputs)
            result = H.capture(program, inputs['original'], inputs['object'], outputs)
            self.assertEqual(result, inputs['heads'])
            total += len(result.splitlines()) - 4
            changed = {role: raw.replace(b'opaque operands', b'untrusted mnemonic text') for role, raw in outputs.items()}
            self.assertEqual(H.capture(program, inputs['original'], inputs['object'], changed), result)
        self.assertEqual(total, 187)

    def test_headers_encoding_and_capture_bounds_refuse(self):
        inputs = F.fixture(); outputs = displays(inputs)
        edits = (lambda b: b[:-1], lambda b: b.replace(b'\n', b'\r\n'),
            lambda b: b + b'\0\n', lambda b: b.replace(b'elf64-x86-64', b'elf32-i386'),
            lambda b: b.replace(b'<_start>', b'<kernel>'),
            lambda b: b.replace(b'Disassembly of section .text:', b'Disassembly of section .data:'),
            lambda b: b + b'Disassembly of section .text:\n',
            lambda b: b + b'0000000000402000 <kernel>:\n',
            lambda b: b + b'...\n', lambda b: b'x' * (H.CAP + 1),
            lambda b: b.replace(b'opaque operands', b'(bad)', 1),
            lambda b: b.replace(b'opaque operands', b'x' * 4097, 1))
        for edit in edits:
            self.refused(inputs, dict(outputs, start=edit(outputs['start'])))
        self.refused(inputs, {k: v for k, v in outputs.items() if k != 'hook'})
        self.refused(inputs, dict(outputs, extra=b'x\n'))

    def test_every_head_omission_duplicate_and_order_refuse(self):
        for program in H.D.COUNTS:
            inputs = F.fixture(program); outputs = displays(inputs)
            for role, raw in outputs.items():
                rows = raw.splitlines()
                for at in range(6, len(rows)):
                    for changed in (rows[:at] + rows[at + 1:], rows[:at] + [rows[at]] + rows[at:]):
                        self.refused(inputs, dict(outputs, **{role: b'\n'.join(changed) + b'\n'}), program)
                if len(rows) > 7:
                    changed = list(rows); changed[6], changed[7] = changed[7], changed[6]
                    self.refused(inputs, dict(outputs, **{role: b'\n'.join(changed) + b'\n'}), program)

    def test_instruction_bytes_addresses_and_width_refuse(self):
        inputs = F.fixture(); outputs = displays(inputs); rows = outputs['start'].splitlines()
        edits = (b'  401001:\t90                                              \topaque',
            b'  401000:\t91                                              \topaque',
            b'  401000:\t' + b'90 ' * 16 + b'\topaque',
            b'  401000:\t9                                               \topaque',
            b'  401000:\tGG                                              \topaque',
            b'  401000:\t90                                              \t',
            b'  401000:\t90\topaque\n\t90')
        for line in edits:
            changed = list(rows); changed[6] = line
            self.refused(inputs, dict(outputs, start=b'\n'.join(changed) + b'\n'))

    def test_verified_local_labels_and_wrong_duplicate_labels(self):
        inputs = add_label(F.fixture(), 'start', 1); outputs = displays(inputs)
        rows = outputs['start'].splitlines(); label = b'0000000000401001 <capture_label>:'
        rows.insert(7, label)
        outputs['start'] = b'\n'.join(rows) + b'\n'
        self.assertEqual(H.capture('checksum', inputs['original'], inputs['object'], outputs), inputs['heads'])
        for changed in (label.replace(b'401001', b'401002'), label.replace(b'capture_label', b'missing_label'),
                        label + b'\n' + label, b'0000000000401001 <_start>:'):
            self.refused(inputs, dict(outputs, start=outputs['start'].replace(label, changed)))
        self.refused(inputs, dict(outputs, start=outputs['start'] + label + b'\n'))

    def test_actual_ownership_and_relocation_helpers_remain_required(self):
        inputs = F.fixture(); outputs = displays(inputs)
        self.refused(F.mutate_section(dict(inputs), 'object', '.text.start', 1, 8), outputs)
        for key in ('object', 'original'):
            changed = dict(inputs); image = H.D.Elf(changed[key], 1 if key == 'object' else 2)
            raw = bytearray(changed[key]); at = image.sec[image.symtab][4] + 5 * 24 + 16
            raw[at] ^= 1; changed[key] = bytes(raw)
            self.refused(changed, outputs)
        changed = dict(inputs); obj = H.D.Elf(changed['object'], 1)
        raw = bytearray(changed['object']); raw[obj.section('.rela.text.start')[4] + 16] ^= 1
        changed['object'] = bytes(raw)
        self.refused(changed, outputs)


if __name__ == '__main__':
    unittest.main()
