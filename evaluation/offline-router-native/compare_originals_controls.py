#!/usr/bin/env python3
"""Pure synthetic comparisons; no assembler, program, or candidate dispatch."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import types
import unittest
from unittest import mock
import compare_originals as S


path = Path(__file__).resolve().parents[1]/'offline-corpus/disassembly_controls.py'
raw = path.read_bytes()
assert len(raw) <= S.CAP and hashlib.sha256(raw).hexdigest() == 'f0d7f5572017fcc8a8f14c59e2980e97e50359e7d165c2b748de99439d93346d'
C = types.ModuleType('_pinned_original_fixture'); C.__file__ = str(path)
exec(compile(raw,str(path),'exec'),C.__dict__)
D = C.D


def originals(program='checksum', short=False):
    new = C.fixture(program,short_jumps=short)
    old = copy.deepcopy(new)
    C.mutate_section(old,'original','.header_pad',2,3)
    return old,new


def material(program, inputs):
    result = C.run(inputs,program)
    assert result['status'] == 'MATERIALS_READY'
    return result['files']['source-inventory.tsv']


def compare(program, old, new, inventories=None):
    files = {}
    for index, (run,inputs) in enumerate(((Path('/old'),old),(Path('/new'),new))):
        files[run/'originals'/program/'original'] = inputs['original']
        files[run/'originals'/program/'subject.o'] = inputs['object']
        files[run/'materials'/(program+'-heads.txt')] = inputs['heads']
        files[run/'materials'/(program+'-inventory.tsv')] = material(program,inputs) if inventories is None else inventories[index]
    with mock.patch.object(S,'read',side_effect=lambda path:files[path]):
        return S.compare(D,program,Path('/old'),Path('/new'))


class CompleteInventory(unittest.TestCase):
    def test_both_programs_short_near_inventory_matches_unchanged_independent_adapter(self):
        for program in D.COUNTS:
            for short in (False,True):
                old,new = originals(program,short)
                for inputs in (old,new):
                    image,obj,sizes = D.ownership(inputs['original'],inputs['object'],program)
                    heads = D.head_transport(program,inputs['heads'],inputs['original'],inputs['object'],sizes)
                    D.code_and_relocations(image,obj,heads,program)
                    self.assertEqual(S.inventory_bytes(D,program,image,heads),material(program,inputs))

    def test_real_comparator_checks_both_complete_programs_and_retains_metadata(self):
        for program,(heads,selected) in D.COUNTS.items():
            old,new = originals(program)
            report = compare(program,old,new)
            self.assertEqual((report['heads'],report['selected']),(heads,selected))
            self.assertTrue(report['all_program_headers_equal'])
            self.assertTrue(report['all_instruction_heads_equal'])
            self.assertTrue(report['complete_text_data_note_padding_equal'])
            self.assertFalse(report['whole_file_equal'])
            self.assertEqual(report['whole_file_differences']['different_positions'],1)
            for label,inputs in (('old',old),('new',new)):
                image = D.Elf(inputs['original'],2)
                metadata = report['metadata'][label]
                self.assertEqual(metadata['e_shoff'],int.from_bytes(inputs['original'][40:48],'little'))
                self.assertEqual(metadata['section_count'],len(image.sec))
                self.assertEqual(len(metadata['sections']),len(image.sec))
                self.assertEqual(metadata['symbol_table']['entries'],len(image.symbols))
                self.assertEqual({row['index'] for row in metadata['string_tables']},
                                 {index for index,row in enumerate(image.sec) if row[1]==3})

    def test_identical_incorrect_role_index_pc_offset_and_length_rows_refuse(self):
        for program in D.COUNTS:
            old,new = originals(program); inventory = material(program,new)
            for column in range(5):
                rows = inventory.decode().splitlines(); cells = rows[1].split('\t')
                cells[column] = 'wrong' if column==0 else str(int(cells[column])+1)
                rows[1] = '\t'.join(cells); bad = ('\n'.join(rows)+'\n').encode()
                self.assertEqual(len(bad.splitlines()),len(inventory.splitlines()))
                with self.subTest(program=program,column=column), self.assertRaisesRegex(ValueError,'independently derived'):
                    compare(program,old,new,(bad,bad))

    def test_same_population_wrong_selection_and_reordered_rows_refuse(self):
        for program in D.COUNTS:
            old,new = originals(program); inventory = material(program,new)
            rows = inventory.decode().splitlines()
            yes = next(i for i in range(1,len(rows)) if rows[i].endswith('\t1'))
            no = next(i for i in range(1,len(rows)) if rows[i].endswith('\t0'))
            changed = list(rows); changed[yes] = changed[yes][:-1]+'0'; changed[no] = changed[no][:-1]+'1'
            reordered = list(rows); reordered[1],reordered[2] = reordered[2],reordered[1]
            for value in (changed,reordered):
                self.assertEqual(sum(int(row.split('\t')[-1]) for row in value[1:]),D.COUNTS[program][1])
                bad = ('\n'.join(value)+'\n').encode()
                with self.assertRaisesRegex(ValueError,'independently derived'):
                    compare(program,old,new,(bad,bad))


class MetadataRetention(unittest.TestCase):
    def test_relocated_section_table_keeps_actual_offsets_and_complete_table_hashes(self):
        old,new = originals()
        image = D.Elf(new['original'],2); raw = bytearray(new['original'])
        before = int.from_bytes(raw[40:48],'little')
        table = bytes(raw[before:before+len(image.sec)*64])
        after = (len(raw)+15)&~7
        raw.extend(bytes(after-len(raw))); raw.extend(table)
        struct.pack_into('<Q',raw,40,after); new['original'] = bytes(raw); C.rebind(new)
        report = compare('checksum',old,new)
        self.assertEqual(report['metadata']['old']['e_shoff'],before)
        self.assertEqual(report['metadata']['new']['e_shoff'],after)
        self.assertEqual(report['metadata']['new']['section_table'],dict(bytes=len(table),sha256=S.sha(table)))
        self.assertGreater(report['whole_file_differences']['different_positions'],1)
        self.assertTrue(report['all_program_headers_equal']); self.assertTrue(report['complete_text_data_note_padding_equal'])

    def test_symbol_and_string_table_changes_are_retained_without_raw_dumps(self):
        for kind in ('symbol','string'):
            old,new = originals()
            image = D.Elf(new['original'],2); raw = bytearray(new['original'])
            if kind=='symbol':
                offset = image.section('.symtab')[4]+24+8  # unnamed local section-symbol value
                struct.pack_into('<Q',raw,offset,0x401001)
            else:
                offset = image.section('.shstrtab')[4]  # unused leading NUL, not a live section name
                raw[offset] = 1
            new['original'] = bytes(raw); C.rebind(new)
            report = compare('checksum',old,new)
            left,right = report['metadata']['old'],report['metadata']['new']
            if kind=='symbol':
                self.assertNotEqual(left['symbol_table']['sha256'],right['symbol_table']['sha256'])
            else:
                self.assertNotEqual(left['string_tables'],right['string_tables'])
            self.assertGreater(report['whole_file_differences']['different_positions'],1)
            self.assertLess(len(json.dumps(report)),S.CAP)
            self.assertTrue(report['complete_text_data_note_padding_equal'])

    def test_every_differing_byte_and_length_tail_is_accounted_in_fixed_blocks(self):
        for left,right in ((b'',b'x'),(b'x',b''),(b'abc',b'aXc'),
                           (b'A'*4096+b'end',b'A'*4095+b'B'+b'en'),(b'same',b'same')):
            report = S.file_differences(left,right)
            expected = sum(a!=b for a,b in zip(left,right))+abs(len(left)-len(right))
            self.assertEqual(report['different_positions'],expected)
            self.assertEqual(sum(row['different_positions'] for row in report['blocks']),expected)
            for row in report['blocks']:
                at = row['offset']; self.assertEqual(at%4096,0)
                for label,raw in (('old',left),('new',right)):
                    self.assertEqual(row[label],dict(bytes=len(raw[at:at+4096]),sha256=S.sha(raw[at:at+4096])))
        all_changed = S.file_differences(b'A'*S.CAP,b'B'*S.CAP)
        self.assertEqual(len(all_changed['blocks']),256)
        self.assertEqual(all_changed['different_positions'],S.CAP)
        self.assertLess(len(json.dumps(all_changed)),S.CAP)
        with self.assertRaisesRegex(ValueError,'comparison bound'):
            S.file_differences(b'A'*(S.CAP+1),b'')

    def test_original_full_phdr_and_payload_guards_still_reject_coherent_mutants(self):
        old,new = originals(); raw = bytearray(new['original'])
        struct.pack_into('<Q',raw,64+5*56+48,32)  # GNU_STACK alignment, outside code proof
        new['original'] = bytes(raw); C.rebind(new)
        with self.assertRaisesRegex(ValueError,'all program headers'):
            compare('checksum',old,new)
        old,new = originals(); raw = bytearray(new['original'])
        raw[0x1fff] = 1  # unused RX padding is still part of the full .text comparator
        new['original'] = bytes(raw); C.rebind(new)
        with self.assertRaisesRegex(ValueError,'complete allocated section bytes'):
            compare('checksum',old,new)


if __name__ == '__main__':
    unittest.main()
