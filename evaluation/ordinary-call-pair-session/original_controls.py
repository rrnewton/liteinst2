"""Fabricated transcript controls; no subject/loaded-owner authority."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
PARSER = HERE / 'original_output.py'
assert not PARSER.is_symlink() and hashlib.sha256(PARSER.read_bytes()).hexdigest() == '9933fe3c83356ce876971313a65132cb0b0b5916b866974ffa8110c73ff13f12'
_spec = importlib.util.spec_from_file_location('_call_pair_original', PARSER)
output = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(output)


def geometry(reverse=False, multi=False):
    pv, cv = (12288, 4096) if reverse else (4096, 12288)
    body = bytearray(b'\x90' * 16); body[4] = 0xe8
    body[5:9] = (cv - pv - 9).to_bytes(4, 'little', signed=True); body[15] = 0xc3
    parent = dict(elf_va=pv, length=16, heads=[0,1,2,3,4,9,10,11,12,13,14,15], edges=11,
        returns=[15], call_offset=4, continuation_offset=9, child_delta=16, callee_entry=cv, body_hex=body.hex())
    child = dict(elf_va=cv, length=8, heads=list(range(8)), edges=6 if multi else 7, returns=[3,7] if multi else [7])
    return dict(parent=parent, child=child)


CALLER = dict(extent=20, continuation=12)
RECORDS = ((b'',1), (b'a,b',2), (b'"a,b",c',2), (b',,',3))


def transcript(records=RECORDS, g=None):
    g = geometry() if g is None else g
    bias = 0x100000
    parent, child = g['parent'], g['child']
    pe, ce = bias + parent['elf_va'], bias + child['elf_va']
    rows = [['ORIGINAL_READY', output.PROFILE, 100,100,3,pe,pe+parent['length'],ce,ce+child['length'],0x800000,len(records)]]
    for node, name in enumerate(('parent','child')):
        b = g[name]; entry = bias + b['elf_va']
        rows.append(['ORIGINAL_FUNCTION',node,b['elf_va'],b['length'],entry,entry+b['length'],len(b['returns'])])
        rows.extend(['ORIGINAL_RET',node,r] for r in b['returns'])
    rows.append(['ORIGINAL_EDGE',pe+parent['call_offset'],ce,pe+parent['continuation_offset'],parent['child_delta']])
    rows.extend(['ORIGINAL',i,len(data),output.fnv(data),fields,(len(data)<<32)|fields] for i,(data,fields) in enumerate(records,1))
    rows.append(['ORIGINAL_DONE',len(records),len(records),len(records)])
    return ('\n'.join(','.join(map(str,row)) for row in rows)+'\n').encode('ascii')


def checked(data=None, records=RECORDS, g=None, caller=None, stderr=b''):
    g = geometry() if g is None else g
    return output.check(transcript(records,g) if data is None else data,stderr,
        records=records,geometry=g,caller=CALLER if caller is None else caller,cpu=3)


class Controls(unittest.TestCase):
    def refuses(self, operation):
        with self.assertRaises((AssertionError, ValueError, UnicodeError, IndexError, KeyError)):
            operation()

    def test_parent_original_rows_values_and_same_sum_mutation(self):
        for records in ((), ((b'',1),), RECORDS, ((b'x'*64,1),)*2048):
            result = checked(records=records)
            self.assertEqual(result['status'], 'CALL_PAIR_ORIGINAL_SCALAR_PASS')
            self.assertEqual(result['totals'], dict(records=len(records),root_calls=len(records),root_returns=len(records)))
            self.assertEqual(result['results'], [[i,len(data),output.fnv(data),fields,(len(data)<<32)|fields] for i,(data,fields) in enumerate(records,1)])
            self.assertEqual(result['raw'], transcript(records))
        data = transcript(); rows = data.decode().splitlines()
        indices = [i for i,s in enumerate(rows) if s.startswith('ORIGINAL,')]
        for row in indices:
            for field in range(1,6):
                bad = rows[:]; words = bad[row].split(','); words[field] = str(int(words[field])+1); bad[row] = ','.join(words)
                self.refuses(lambda: checked(('\n'.join(bad)+'\n').encode()))
        bad = rows[:]
        for row, delta in zip(indices[1:3],(1,-1)):
            words = bad[row].split(','); words[4] = str(int(words[4])+delta); words[5] = str(int(words[5])+delta); bad[row] = ','.join(words)
        self.refuses(lambda: checked(('\n'.join(bad)+'\n').encode()))
        for record in (((b'a,b',1),), ((b'"unterminated',1),), ((b'\x00',1),), ((b'x'*65,1),)):
            self.refuses(lambda: checked(records=record))
        self.assertIn('external joins', checked()['scope'])

    def test_original_complete_elf_edge_caller_and_independent_copies(self):
        for reverse in (False, True):
            for multi in (False, True):
                g = geometry(reverse,multi); result = checked(g=g)
                self.assertEqual(result['table'][1]['returns'], tuple(g['child']['returns']))
                self.assertEqual(result['edge']['child_entry'], result['ready']['child_entry'])
        for node, key, value in [('parent','length',81),('parent','continuation_offset',10),('parent','child_delta',8),
                ('parent','callee_entry',1),('parent','returns',[14]),('parent','edges',10),('child','length',257),
                ('child','elf_va',4097),('child','heads',[0,7]),('child','returns',[8]),('child','returns',[7,7])]:
            g = geometry(); g[node][key] = value
            self.refuses(lambda: checked(transcript(),g=g))
        g = geometry(); g['parent']['body_hex'] = '90'+g['parent']['body_hex'][2:8]+'90'+g['parent']['body_hex'][10:]
        self.refuses(lambda: checked(transcript(),g=g))
        for caller in ({'extent':0,'continuation':0},{'extent':20,'continuation':20},{'extent':20,'continuation':True},{'extent':20,'continuation':12,'copied':True}):
            self.refuses(lambda: checked(caller=caller))
        rows = transcript().decode().splitlines()
        for index in range(len(rows)):
            if rows[index].startswith(('ORIGINAL_READY','ORIGINAL_FUNCTION','ORIGINAL_RET','ORIGINAL_EDGE')):
                words = rows[index].split(',')
                for field in range(2 if index == 0 else 1,len(words)):
                    bad = rows[:]; changed = words[:]; changed[field] = str(int(changed[field])+1); bad[index] = ','.join(changed)
                    # PID and caller base are independently supplied to the outer recipe.
                    if index == 0 and field == 9: continue
                    self.refuses(lambda: checked(('\n'.join(bad)+'\n').encode()))
        # Exact copied caller/full-state authority is deliberately absent from scalar wire.
        self.assertIn('No Rust-caller full-state', checked()['scope'])

    def test_original_exact_frames_refusals_and_empty_population(self):
        self.assertEqual(output.frame(()), b'MODCSV1\0'+bytes(4))
        self.assertEqual(output.frame(((b'',1),)), b'MODCSV1\0'+b'\x01'+bytes(3)+b'\x00')
        self.assertEqual(output.frame(((b'a,b',2),)), b'MODCSV1\0'+b'\x01'+bytes(3)+b'\x03a,b')
        for reason in output.ORIGINAL_REFUSALS:
            error = b'module-session-original INPUT_REFUSED: '+reason.encode()+b'\n'
            self.assertEqual(output.refusal(b'',error,2,reason)['status'],'EXPECTED_INPUT_REFUSAL')
            for code in (0,1,True,3): self.refuses(lambda: output.refusal(b'',error,code,reason))
            for extra in (b'FAILED\n',b'\n',b' '): self.refuses(lambda: output.refusal(b'',error+extra,2,reason))
            self.refuses(lambda: output.refusal(b'x',error,2,reason))
            self.refuses(lambda: checked(stderr=error))
        self.refuses(lambda: output.refusal(b'',b'',2,'unknown'))
        self.refuses(lambda: output.frame(((b'a"b',1),)))
        self.refuses(lambda: output.frame(((b'x',1),)*2049))
        self.assertEqual(checked(records=())['results'],[])

    def test_original_caps_identity_domains_and_local_optimized_refusal(self):
        data = transcript(); rows = data.decode().splitlines()
        for index in range(len(rows)):
            self.refuses(lambda: checked(('\n'.join(rows[:index]+rows[index+1:])+'\n').encode()))
            self.refuses(lambda: checked(('\n'.join(rows[:index]+[rows[index]]+rows[index:])+'\n').encode()))
        for bad in (data[:-1],data+b'\n',data.replace(b'\n',b'\r\n'),data.replace(b',100,',b',0100,',1),
                data.replace(b',100,',b',18446744073709551616,',1),b'x'*351+b'\n',b'x'*(4*1024*1024+1)):
            self.refuses(lambda: checked(bad))
        self.refuses(lambda: checked(data.replace(b'call-pair-original-v1',b'module-original-v1')))
        for bad in (True, -1, (1<<64)):
            self.refuses(lambda: output.integer(bad))
        source = PARSER.read_text()
        altered = source.replace('83f12525c59f6ad31736d82db545ddc15a3c8682c1c66b30982ed4c627c8fa67','0'*64,1)
        self.assertNotEqual(altered,source)
        self.refuses(lambda: exec(compile(altered,str(PARSER),'exec'),{'__file__':str(PARSER),'__name__':'_refuse_dependency'}))
        result = subprocess.run([sys.executable,'-O','-B',str(PARSER)],capture_output=True,timeout=5,
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C','PYTHONNOUSERSITE':'1','PYTHONDONTWRITEBYTECODE':'1'})
        self.assertEqual(result.returncode,1); self.assertEqual(result.stdout,b''); self.assertEqual(result.stderr,b'assertions required\n')


if __name__ == '__main__':
    unittest.main()
