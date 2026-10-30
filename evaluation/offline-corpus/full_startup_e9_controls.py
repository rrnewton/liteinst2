#!/usr/bin/env python3
"""Pure preparation controls; synthetic joined objects are never W01 authority."""
import copy
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


m = load('e9_preparation', Path(__file__).with_name('full_startup_e9.py'))
a = load('e9_adapter', ROOT/'tools/elf-rewrite/e9-sites.py')
c = load('e9_corpus', ROOT/'evaluation/offline-corpus/corpus.py')


def fixture():
    complete = dict(plan=dict(profile=m.PROFILE, source_revision='1'*40), programs={},
                    reference=dict(directory='/saved',sha256='2'*64),
                    captured=dict(tools={n:dict(path='/tools/'+n,sha256='4'*64) for n in ('python','timeout','helper')}), history=[dict(pin=dict(path='/old-failure',sha256='3'*64))])
    for program, (heads, selected) in m.COUNTS.items():
        original = bytearray(4096)
        original[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
        struct.pack_into('<HHIQQQIHHHHHH', original,16,2,62,1,0x401200,64,0,0,64,56,1,0,0,0)
        struct.pack_into('<IIQQQQQQ',original,64,1,5,0,0x401000,0,4096,4096,4096)
        for i in range(selected): original[512+8*i:517+8*i] = b'\xe9\0\0\0\0'
        original = bytes(original)
        selection = ('LI2TOOL 1\noriginal '+m.sha(original)+'\n'
            'neighbor-victims short-only\nneighbor-ownership inherited-t3\n'
            'pending-selected full-instruction-ownership\n'
            'adjacent-pairs original-geometry-jcc-or-routed-jmp-v1\nadjacent-pair-budgets 2 1 2\n'
            'target fxsave64\ndomain 1\ncarrier none\nlimits 1 1 1 1 1 1 1 1 1\n'+
            ''.join('site %d %d 5 %d 0 0 0 0 0 0 0 0 0\n'%(i+1,0x401200+8*i,512+8*i) for i in range(selected))).encode()
        product = {'candidate.elf':b'synthetic-independent-candidate-'+program.encode(),
            'selection.txt':selection,'report.tsv':b'synthetic-independent-report',
            'disassembly.txt':b''.join(('head %d 90\n'%i).encode() for i in range(heads))}
        complete['programs'][program] = dict(original=original, product=product,
            row=dict(expected_heads=heads,expected_selected=selected,candidate_sha256=m.sha(product['candidate.elf'])))
    tools = {role:dict(path='/tools/'+role,sha256=h) for lane, roles in m.E9.items() for role,h in zip(roles,a.PRODUCERS[lane])}
    return complete, tools


class Preparation(unittest.TestCase):
    def test_entire_fixed_population_and_exact_bytes(self):
        complete, tools = fixture(); files, plan = m.preparation(complete,c,a,tools,Path('/new'))
        self.assertEqual(len(plan['commands']),8)
        self.assertEqual([(r['program'],r['dataset'],r['lane']) for r in plan['cases']],
            [(p,d,l) for p in m.PROGRAMS for d in m.DATASETS for l in m.LANES])
        self.assertEqual(sum(p['heads'] for p in plan['programs'].values()),187)
        self.assertEqual(sum(p['selected'] for p in plan['programs'].values()),42)
        for p in m.PROGRAMS:
            self.assertEqual(files[p+'/original.elf'],complete['programs'][p]['original'])
            self.assertEqual(files[p+'/selection.txt'],complete['programs'][p]['product']['selection.txt'])
        for d, raw in c.datasets().items():
            self.assertEqual(files['datasets/'+d],raw)
            for p in m.PROGRAMS:self.assertEqual(files[p+'/expected/'+d],c.expected(p,raw))
        self.assertTrue(all(r['status']=='UNRUN' and r['attempts']==0 for r in plan['cases']))
        self.assertTrue(all(r['limits']==[20,30,16] and r['attempts']==1 for r in plan['commands']))
        self.assertTrue(all('--start=0x401000' in r['argv'] and '--end=0x403001' in r['argv'] for r in plan['commands']))
        self.assertEqual(plan['retained_history'],[complete['history'][0]['pin']])
        for key in ('qualification_complete','application_outputs_checked','native_execution_authorized','performance_eligible'):
            self.assertIs(plan[key],False)

    def test_missing_program_refuses(self):
        complete,tools=fixture();del complete['programs']['rle-roundtrip']
        with self.assertRaisesRegex(ValueError,'both programs'):m.preparation(complete,c,a,tools,Path('/new'))

    def test_old_profile_refuses(self):
        complete,tools=fixture();complete['plan']['profile']='elf-disassembly-null-jumps-static-exec-router-bootstrap-v1'
        with self.assertRaisesRegex(ValueError,'producer class'):m.preparation(complete,c,a,tools,Path('/new'))

    def test_whole_head_population_refuses_one_omitted_head(self):
        complete,tools=fixture();p=complete['programs']['checksum']['product'];p['disassembly.txt']=b'\n'.join(p['disassembly.txt'].splitlines()[1:])+b'\n'
        with self.assertRaisesRegex(ValueError,'instruction heads'):m.preparation(complete,c,a,tools,Path('/new'))

    def test_selected_population_refuses_one_omitted_site(self):
        complete,tools=fixture();p=complete['programs']['checksum']['product'];p['selection.txt']=b'\n'.join(p['selection.txt'].splitlines()[:-1])+b'\n'
        with self.assertRaisesRegex(ValueError,'jump denominator'):m.preparation(complete,c,a,tools,Path('/new'))

    def test_current_original_cannot_be_replaced_by_historical_bytes(self):
        complete,tools=fixture();p=complete['programs']['checksum'];p['original']=p['original'][:-1]+b'X'
        with self.assertRaises(AssertionError):m.preparation(complete,c,a,tools,Path('/new'))

    def test_current_candidate_identity_is_exact(self):
        complete,tools=fixture();complete['programs']['checksum']['product']['candidate.elf']+=b'X'
        with self.assertRaisesRegex(ValueError,'independent full-program'):m.preparation(complete,c,a,tools,Path('/new'))

    def test_each_pinned_tool_is_mandatory(self):
        complete,tools=fixture()
        for name in tools:
            with self.subTest(role=name):
                changed=copy.deepcopy(tools);changed[name]['sha256']='0'*64
                with self.assertRaisesRegex(ValueError,'pinned E9 lane'):m.preparation(complete,c,a,changed,Path('/new'))

    def test_dataset_cannot_be_skipped_or_reordered(self):
        complete,tools=fixture()
        for data in (dict(list(c.datasets().items())[1:]),dict(reversed(list(c.datasets().items())))):
            substitute=type('Corpus',(),dict(PROGRAMS=c.PROGRAMS,datasets=staticmethod(lambda:data),expected=staticmethod(c.expected)))
            with self.assertRaisesRegex(ValueError,'ten original datasets'):m.preparation(complete,substitute,a,tools,Path('/new'))


if __name__ == '__main__':
    unittest.main()
