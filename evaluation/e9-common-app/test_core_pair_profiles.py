#!/usr/bin/env python3
"""Prospective pure saved-data controls. No ptrace, application or audit main.

Generated observations are synthetic values, never a claim that a kernel
produced a signal or syscall.
"""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

P=Path(__file__).with_name('audit_core_pairs.py')
spec=importlib.util.spec_from_file_location('core_pair_audit_under_test',P)
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
COMPONENTS=[(2,576,256),(5,832,64),(6,896,512),(7,1408,1024),(9,2432,8)]
REGS='r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs'.split()
GREGS='r8 r9 r10 r11 r12 r13 r14 r15 rdi rsi rbp rbx rdx rax rcx rsp rip eflags'.split()
HEADS=json.loads(P.with_name('core-pair-heads.json').read_bytes())['heads']

def reghex(r):return struct.pack('<27Q',*(r[k] for k in REGS)).hex()
def signal(signo,code,pc):
 b=bytearray(128);struct.pack_into('<iii',b,0,signo,0,code);struct.pack_into('<Q',b,16,pc);return bytes(b)
def rows_bytes(rows):return ''.join('\t'.join(map(str,r))+'\n' for r in rows).encode()

def machine_program(base):
 # Independent synthetic assembler of this fixed program; all branches use
 # near encodings. The decoder must also prove the exact branch destinations.
 items=['f30f1efa','cc','83ff04',('jne',34),'4885f6',('je',34),'4885d2',('je',34),
 '833e04',('jne',34),'837e0802',('jne',34),'4883bac800000006',('jne',34),'4c8b82a8000000',
 '4c394610',('jne',34),('table',0x73000000),'4d85c9',('je',34),('count',0x73000008),
 '4885c9',('je',34),'4883f957',('ja',34),'4d3901',('je',31),'4983c110','48ffc9',('jne',25),
 ('jmp',34),'498b4108','488982a8000000','c3','bf7c000000','b8e7000000','0f05','0f0b',
 '48c7c00f000000','0f05','0f0b']
 length=lambda x:len(bytes.fromhex(x)) if isinstance(x,str) else 7 if x[0] in ('table','count') else 5 if x[0]=='jmp' else 6
 offsets=[];cursor=0
 for item in items:offsets.append(cursor);cursor+=length(item)
 code=[]
 for i,item in enumerate(items):
  if isinstance(item,str):b=bytes.fromhex(item)
  else:
   name,target=item
   prefix={'jne':b'\x0f\x85','je':b'\x0f\x84','ja':b'\x0f\x87','jmp':b'\xe9','table':b'\x4c\x8b\x0d','count':b'\x48\x8b\x0d'}[name]
   dest=target if name in ('table','count') else base+offsets[target]
   b=prefix+struct.pack('<i',dest-(base+offsets[i]+length(item)))
  code.append(b)
 return b''.join(code),[(base+off,b) for off,b in zip(offsets,code)]

def fixture(index=0,count=1,trap=True):
 guard,table,handler=0x70000000,0x71000000,0x72000000;usable=guard+4096
 routes=[dict(pc=0x401844+i*16,target=0x501000+i*16,lo=0x401840,hi=0x401951,fetch=b'\x06') for i in range(count)]
 pc,dest=routes[index]['pc'],routes[index]['target']
 code,ins=machine_program(handler);restorer,syscall=ins[38][0],ins[39][0]
 table_bytes=b''.join(struct.pack('<QQ',r['pc'],r['target']) for r in routes)+bytes(4096-16*count)
 before={k:i+1 for i,k in enumerate(REGS)}
 before.update(rip=pc,rsp=0x600000100008,eflags=0x202,orig_rax=(1<<64)-1,cs=0x33,ss=0x2b,fs_base=0,gs_base=0,ds=0,es=0,fs=0,gs=0)
 canonical=b'\x7f\x03'+bytes(21)+bytes(80)+struct.pack('<I',0x1f80)+bytes(256)
 canonical+=b''.join(struct.pack('<IQ',bit,n)+bytes(n) for bit,_,n in COMPONENTS)
 assert len(canonical)==2287
 state=dict(r=before,canonical=canonical)
 entered=dict(before,rax=0,rip=handler+5,rsp=usable+120000,rdi=4,rsi=usable+4096,rdx=usable+8192)
 rows=[['phase','before_pc','after_pc','bytes'],['router_bootstrap','linux-x86-64-private-altstack-v1'],
 ['router_stack',guard,usable,131072],['router_table',table,4096,table_bytes.hex()],
 ['router_action',handler,0x0c000004,restorer,0],['router_mask',0],['router_code',code.hex()],
 ['router_prior','Action { handler: 0, flags: 0, restorer: 0, mask: 0 }'],
 ['router_scope','controlled_single_thread_child_only'],['router-layout',128,968,16,40,224,296],
 ['router-observed','before',table_bytes.hex(),code.hex(),table,count]]
 walk=[]
 if trap:
  walk=[(pc,dest,b'\x06')]
  rows += [['router-fault',4,2,pc],['router-entry',entered['rip'],entered['rsp'],entered['rsi'],entered['rdx'],128],
   ['router-entry-state',(5<<8)|127,reghex(entered)]]
  order=list(range(2,25))+[i for _ in range(index) for i in (25,26,27,28,29)]+[25,26,31,32,33]
  for j,i in enumerate(order):rows.append(['router-step',ins[i][0],ins[order[j+1]][0] if j+1<len(order) else restorer,ins[i][1].hex()])
  pre=dict(entered,r8=pc,r9=table+16*index,rcx=count-index,rax=dest,rsp=entered['rsp']+8,rip=restorer,eflags=0x246)
  post=dict(pre,rax=15,rip=syscall)
  enter=dict(post,orig_rax=15,rax=(1<<64)-38,rip=syscall+2,rcx=syscall+2,r11=0x246)
  exited=dict(before,rip=dest)
  frame=bytearray(968);struct.pack_into('<Q',frame,16,usable);struct.pack_into('<Q',frame,32,131072)
  for j,k in enumerate(GREGS):struct.pack_into('<Q',frame,40+8*j,before[k])
  struct.pack_into('<Q',frame,200,6);fp_address=usable+16384;struct.pack_into('<Q',frame,224,fp_address)
  after=bytearray(frame);struct.pack_into('<Q',after,168,dest)
  fp=bytearray(2444);fp[:2]=b'\x7f\x03';struct.pack_into('<I',fp,24,0x1f80)
  # Actual signal-frame representation: PKRU present; untouched reserved bytes retain the stack fill.
  struct.pack_into('<Q',fp,512,1<<9);fp[2436:2440]=b'\xa6'*4
  struct.pack_into('<II',fp,464,0x46505853,len(fp));struct.pack_into('<I',fp,480,2440);struct.pack_into('<I',fp,len(fp)-4,0x46505845)
  rows += [['router-restorer',reghex(pre),reghex(post),ins[38][1].hex(),signal(5,2,syscall).hex()],
   ['router-syscall-entry',(133<<8)|127,reghex(enter)],['router-syscall-exit',(133<<8)|127,reghex(exited)],
   ['router',pc,dest,'06'],['router-frame',entered['rdx'],signal(4,2,pc).hex(),frame.hex(),after.hex(),fp.hex()],
   ['router-fp-after',fp_address,fp.hex()],['trap-prefix',pc,dest,'06']]
 body=dest if trap else pc
 rows += [['original',body,body+1,'90'],['router-observed','after',table_bytes.hex(),code.hex(),table,count]]
 maps=(f'{guard:x}-{usable:x} ---p 00000000 00:00 0\n{usable:x}-{usable+131072:x} rw-p 00000000 00:00 0\n'
       f'{usable+131072:x}-{usable+135168:x} ---p 00000000 00:00 0\n{table:x}-{table+4096:x} r--p 00000000 00:00 0\n'
       f'{handler:x}-{handler+4096:x} r-xp 00000000 00:00 0\n73000000-73001000 rw-p 00000000 00:00 0\n').encode()
 return dict(rows=rows,routes=routes,walk=walk,trap=trap,body=body,finish=body+1,operation=b'\x90',before=state,components=COMPONENTS,map_bytes=[maps]*3,added=[])

def check(f):
 return a.router_trace(rows_bytes(f['rows']),*(f[k] for k in ('routes','walk','trap','body','finish','operation','before','components','map_bytes','added')))
def row(f,name):return next(r for r in f['rows'] if r[0]==name)
def mutate_hex(value,offset):
 b=bytearray.fromhex(value);b[offset]^=1;return b.hex()

class TraceControls(unittest.TestCase):
 def test_signal_pkru_all_32_bits_exact(self):
  for bit in range(32):
   f=fixture();fp=bytearray.fromhex(row(f,'router-frame')[5]);fp[2432+bit//8]^=1<<(bit%8)
   row(f,'router-frame')[5]=row(f,'router-fp-after')[2]=fp.hex()
   with self.subTest(bit=bit):
    with self.assertRaises(AssertionError):check(f)
    f['before']['canonical']=f['before']['canonical'][:-8]+fp[2432:2436]+bytes(4)
    self.assertEqual(check(f),34)
 def test_signal_padding_and_present_bit_are_exact(self):
  self.assertEqual(check(fixture()),34)
  for offset in range(2436,2440):
   for wrong in (0,0xa7):
    f=fixture();fp=bytearray.fromhex(row(f,'router-frame')[5]);fp[offset]=wrong
    row(f,'router-frame')[5]=row(f,'router-fp-after')[2]=fp.hex()
    with self.assertRaises(AssertionError):check(f)
  # Retain the old all-zero synthetic representation as an explicit refusal.
  f=fixture();fp=bytearray.fromhex(row(f,'router-frame')[5]);fp[512:520]=bytes(8);fp[2436:2440]=bytes(4)
  row(f,'router-frame')[5]=row(f,'router-fp-after')[2]=fp.hex()
  with self.assertRaises(AssertionError):check(f)
 def test_signal_other_architectural_components_remain_compared(self):
  for bit,offset in ((0,0),(0,32),(1,160),(2,576),(5,832),(6,896),(7,1408)):
   f=fixture();fp=bytearray.fromhex(row(f,'router-frame')[5]);struct.pack_into('<Q',fp,512,(1<<9)|(1<<bit))
   row(f,'router-frame')[5]=row(f,'router-fp-after')[2]=fp.hex();self.assertEqual(check(f),34)
   fp[offset]^=1;row(f,'router-frame')[5]=row(f,'router-fp-after')[2]=fp.hex()
   with self.assertRaises(AssertionError):check(f)

 def test_complete_first_last_and_nontrap(self):
  self.assertEqual(check(fixture()),34)
  self.assertEqual(check(fixture(86,87)),464)
  self.assertEqual(check(fixture(trap=False)),1)
 def test_missing_duplicate_and_reordered_actual_observations(self):
  for tag in ('router-layout','router-observed','router-entry-state','router-restorer','router-syscall-entry','router-syscall-exit','router-fp-after'):
   for action in ('remove','duplicate','reorder'):
    with self.subTest(tag=tag,action=action):
     f=fixture();i=next(i for i,r in enumerate(f['rows']) if r[0]==tag)
     if action=='remove':f['rows'].pop(i)
     elif action=='duplicate':f['rows'].insert(i,copy.deepcopy(f['rows'][i]))
     else:f['rows'][i],f['rows'][i+1]=f['rows'][i+1],f['rows'][i]
     with self.assertRaises(a.ERRORS):check(f)
 def test_stop_and_full_register_mutations(self):
  for tag,field in [('router-entry-state',2),('router-restorer',1),('router-restorer',2),('router-syscall-entry',2),('router-syscall-exit',2)]:
   # The pinned Linux source rule establishes entry AX=0 and unchanged
   # nonargument GPRs; all tested values have explicit predicates.
   registers=('r15','rax','rcx','orig_rax','rip','rsp','r11')
   for register in registers:
    with self.subTest(tag=tag,field=field,register=register):
     f=fixture();r=row(f,tag);r[field]=mutate_hex(r[field],8*REGS.index(register))
     with self.assertRaises(a.ERRORS):check(f)
  for tag in ('router-entry-state','router-syscall-entry','router-syscall-exit'):
   f=fixture();row(f,tag)[1]^=256
   with self.assertRaises(a.ERRORS):check(f)
 def test_ucontext_and_both_whole_fp_images(self):
  # Changes outside RIP, inside the declared header and at the last FP byte
  # are all checked; raw reserved bytes cannot hide behind canonical masking.
  for tag,field,offset in [('router-frame',2,8),('router-frame',3,40),('router-frame',4,16),
    ('router-frame',4,168),('router-frame',5,464),('router-frame',5,480),('router-frame',5,2443),
    ('router-fp-after',2,43),('router-fp-after',2,2430)]:
   f=fixture();r=row(f,tag);r[field]=mutate_hex(r[field],offset)
   with self.assertRaises(a.ERRORS):check(f)
  f=fixture();row(f,'router-fp-after')[1]+=8
  with self.assertRaises(a.ERRORS):check(f)
 def test_code_table_route_siginfo_layout_and_maps(self):
  mutations=[('router-layout',2,969),('router-observed',4,0),('router-observed',5,2),
   ('router-fault',2,1),('router-fault',3,0x401845),('trap-prefix',2,0x501001)]
  for tag,field,value in mutations:
   f=fixture();row(f,tag)[field]=value
   with self.assertRaises(a.ERRORS):check(f)
  for tag,field,offset in [('router_code',1,0),('router-observed',2,4095),('router-observed',3,12),
    ('router-restorer',3,3),('router-restorer',4,8)]:
   f=fixture();r=row(f,tag);r[field]=mutate_hex(r[field],offset)
   with self.assertRaises(a.ERRORS):check(f)
  f=fixture();f['map_bytes'][1]=f['map_bytes'][1].replace(b'r--p',b'rw-p')
  with self.assertRaises(a.ERRORS):check(f)
 def test_source_profile_arguments_and_unactivated_execution(self):
  self.assertEqual(a.profile_arguments(dict(planning_profile='legacy',entry_router='absent')),[])
  self.assertEqual(a.profile_arguments(dict(planning_profile='owned-foreign-neighbors-v1',entry_router='linux-x86-64-private-altstack-v1')),
   ['--planning-profile=owned-foreign-neighbors-v1','--entry-router=linux-x86-64-private-altstack-v1'])
  for p in [dict(planning_profile='owned',entry_router='absent'),dict(planning_profile='legacy',entry_router='inferred')]:
   with self.assertRaises(AssertionError):a.profile_arguments(p)
  self.assertIsNone(a.PROFILE_SOURCE_BINDING_SHA);self.assertIsNone(a.PROFILE_RUNNER_SHA)
  with self.assertRaises(SystemExit):a.profile_activation(None,None,None,None)

class LedgerControls(unittest.TestCase):
 def fixture(self):
  # Full three original function byte ranges come from the fixed whole 87-head
  # descriptor; these are synthetic page objects, never a candidate ELF.
  raw={p:bytearray(4096) for p in range(0x400000,0x425000,4096)}
  for h in HEADS:
   for i,b in enumerate(bytes.fromhex(h['bytes'])):raw[(h['pc']+i)&~4095][(h['pc']+i)&4095]=b
  opages={p:(5,bytes(b)) for p,b in raw.items()};pc=0x401840;dest=pc+5+0x06000000
  ranges=a.source_ranges(HEADS);store=next(b for p,b in raw.items() if p==0x401000)[0x840:0x845]
  ledger=[['step','1','0','relocation',str(pc),str(pc),str(pc),str(pc+5)],
   ['live-prerequisites-not-receipts','1','0','true','true','true'],['step-read','1','0',str(pc),store.hex()],
   ['semantic-write','1','0',str(pc),'e900000006'],['entry-preserved','1','0',str(pc)],
   ['entry-router-required','1','0',str(pc+4),str(dest+32)],
   ['image','0','1',str(dest),'64','unused','image-0000.bin'],
   ['image','1','1',str(dest+256),'64','unused','image-0001.bin'],
   ['image','2','2',str(dest+512),'64','unused','image-0002.bin'],
   ['route','0',str(pc),str(dest)],['route','0',str(pc+4),str(dest+32)],
   ['unmet-requirement','0','6','0'],['unmet-requirement','1','6','0']]
  raw[0x401000][0x840:0x845]=bytes.fromhex('e900000006');cpages={p:(5,bytes(b)) for p,b in raw.items()}
  routes=[dict(pc=pc+4,target=dest+32,lo=pc,hi=pc+5,fetch=b'\x06')]
  return ledger,routes,opages,cpages
 def test_whole_route_grammar_marker_owner_and_profile(self):
  ledger,routes,_,pages=self.fixture();r=routes[0];target=r['target']
  pages[target&~4095]=(5,bytes(4096))
  declared=[['entry-router-required','1','0',str(r['pc']),str(target)]]
  def rows(fetch,pc=r['pc'],lo=r['lo'],hi=r['hi']):
   return [['router-profile','linux-x86-64-private-altstack-v1'],
           ['router',str(pc),str(target),str(lo),str(hi),fetch.hex()],['complete']]
  def patched(pc,fetch):
   result=copy.deepcopy(pages);flags,page=result[pc&~4095];page=bytearray(page)
   page[pc&4095:(pc&4095)+len(fetch)]=fetch;result[pc&~4095]=(flags,bytes(page));return result
  for byte in (6,7,14,22,23,30,31,39,47,55,63,96,97,206):
   cursor,accepted=a.router_routes(rows(bytes([byte])),0,True,HEADS,patched(r['pc'],bytes([byte])),declared)
   self.assertEqual(cursor,2);self.assertEqual(accepted[0]['fetch'],bytes([byte]))
  for field,value in [(1,str(r['pc']+1)),(2,str(0x401900)),(3,str(r['lo']+1)),(4,str(r['hi']-1))]:
   bad=rows(b'\x06');bad[1][field]=value
   with self.assertRaises(a.ERRORS):a.router_routes(bad,0,True,HEADS,pages,declared)
  bad=rows(b'\x06');bad.insert(2,copy.deepcopy(bad[1]))
  with self.assertRaises(a.ERRORS):a.router_routes(bad,0,True,HEADS,pages,declared)
  with self.assertRaises(a.ERRORS):a.router_routes(rows(b'\x06'),0,False,HEADS,pages,declared)
  pc=0x401850;fetch=b'\x62'+bytes(14);evex=rows(fetch,pc,pc,0x4018cf)
  evex_declared=[['entry-router-required','1','0',str(pc),str(target)]]
  cursor,accepted=a.router_routes(evex,0,True,HEADS,patched(pc,fetch),evex_declared)
  self.assertEqual(cursor,2);self.assertEqual(accepted[0]['fetch'],fetch)
  for badfetch in (fetch[:2]+b'\x04'+fetch[3:],fetch[:-1]):
   with self.assertRaises(a.ERRORS):a.router_routes(rows(badfetch,pc,pc,0x4018cf),0,True,HEADS,patched(pc,badfetch),evex_declared)
 def test_whole_current_reads_and_two_image_requirement(self):
  ledger,routes,original,candidate=self.fixture()
  a.router_ledger(ledger,routes,HEADS,original,candidate)
  for mutate in ('read','write','preserved','owner','companion','unrelated','duplicate'):
   r=copy.deepcopy(ledger)
   if mutate=='read':r[2][4]='90'+r[2][4][2:]
   elif mutate=='write':r[3][4]='e900000090'
   elif mutate=='preserved':r[4][3]=str(0x401841)
   elif mutate=='owner':r[6][2]='2'
   elif mutate=='companion':r.pop()
   elif mutate=='unrelated':r.append(['unmet-requirement','2','6','0'])
   else:r.append(copy.deepcopy(r[-1]))
   with self.subTest(mutation=mutate):
    with self.assertRaises(a.ERRORS):a.router_ledger(r,routes,HEADS,original,candidate)

if __name__=='__main__':
 if sys.flags.optimize:raise SystemExit('optimized Python is unsupported; assertions are required')
 unittest.main()
