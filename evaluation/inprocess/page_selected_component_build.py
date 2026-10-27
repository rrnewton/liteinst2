"""Exact provider compile/emitted-code checks with tracked paths and pinned tools."""
import re
import struct
from pathlib import Path
from page_selected import fact as binding
ROOT=Path(__file__).resolve().parents[2]
PROVIDER=ROOT/'tools/page-entry/selected'
HERE=PROVIDER/'tests/provider'

def symbols(path):
 b=path.read_bytes();h=struct.unpack_from('<16sHHIQQQIHHHHHH',b)
 assert h[0][:6]==b'\x7fELF\x02\x01' and h[1:3]==(2,62)
 sections=[struct.unpack_from('<IIQQQQIIQQ',b,h[6]+i*h[11]) for i in range(h[12])]
 rows=[]
 for sh in sections:
  if sh[1]!=2:continue
  names=sections[sh[6]];strings=b[names[4]:names[4]+names[5]]
  assert sh[9]==24
  for at in range(sh[4],sh[4]+sh[5],24):
   name,info,other,index,value,size=struct.unpack_from('<IBBHQQ',b,at)
   stop=strings.find(b'\0',name);assert stop>=name
   rows.append((strings[name:stop].decode(),info&15,index,value,size))
 return rows

def provider(out,invoke,tools,archive):
 cc=tools['cc'];objdump=tools['objdump'];ARCHIVE=archive
 common=['-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin',
 '-fno-tree-loop-distribute-patterns','-fno-stack-protector','-fno-pie','-mgeneral-regs-only',
 '-ffunction-sections','-fdata-sections']
 objects=[]
 for name in ('probe.c','xstate.c','support.c','machine.S'):
  dest=out/(name+'.o');flags=['-O2','-fno-pie'] if name.endswith('.S') else common
  invoke('compile-'+name,[str(cc),*flags,'-c',str(HERE/name),'-o',str(dest)],build=True);objects.append(dest)
 normal=out/'provider-normal.o'
 invoke('compile-provider',[str(cc),*common,'-c',str(PROVIDER/'provider.c'),'-o',str(normal)],build=True)
 binary=out/'provider-fixture'
 invoke('link-normal',[str(cc),'-no-pie',*(str(x) for x in objects),str(normal),str(ARCHIVE),
 '-Wl,--no-undefined,--gc-sections','-o',str(binary)],build=True)
 nested_probe=out/'probe-nested.o';nested_provider=out/'provider-nested.o'
 invoke('compile-probe-nested',[str(cc),*common,'-DNESTED_VARIANT','-c',str(HERE/'probe.c'),'-o',str(nested_probe)],build=True)
 invoke('compile-provider-nested',[str(cc),*common,'-fno-inline','-fno-ipa-cp','-fno-ipa-sra','-c',str(PROVIDER/'provider.c'),'-o',str(nested_provider)],build=True)
 second=out/'provider-nested-fixture'
 invoke('link-nested',[str(cc),'-no-pie',str(nested_probe),*(str(x) for x in objects[1:]),str(nested_provider),str(ARCHIVE),
 '-Wl,--no-undefined,--gc-sections,-T,'+str(HERE/'nested.ld'),'-o',str(second)],build=True)
 rows=symbols(second);by_name={n:(v,z) for n,_,_,v,z in rows}
 start=by_name['__li2_native_random_page'][0];end=by_name['__li2_native_random_page_end'][0]
 code_end=by_name['__li2_native_random_code_end'][0]
 assert start%4096==0 and end-start==4096 and start<code_end<=end
 occupants=[(n,v,z) for n,t,_,v,z in rows if t==2 and start<=v<end]
 assert len(occupants)==1 and occupants[0][0]=='native_random' and occupants[0][1]==start and occupants[0][2]>0 and start+occupants[0][2]<=code_end
 assembly={}
 for label,path in (('normal',binary),('nested',second)):
  full=b''
  for symbol in ('li2_selected_complete_native','native_random'):
   text=invoke('disassemble-'+label+'-'+symbol,[str(objdump),'-d','--no-show-raw-insn','--disassemble='+symbol,str(path)],build=True)[0]
   full+=text
  instructions=[]
  for line in full.decode().splitlines():
   m=re.match(r'^\s*[0-9a-f]+:\s+(\S+)\s*(.*)$',line)
   if m:instructions.append((m[1],m[2]))
  found={n:0 for n in ('rdrand','rdseed','rdpid')}
  for i,(op,args) in enumerate(instructions):
   if op in found:
    found[op]+=1
    if op!='rdpid':assert i+1<len(instructions) and instructions[i+1][0] in ('setb','setc')
  assert found=={'rdrand':3,'rdseed':3,'rdpid':1}
  assembly[label]=found
 return {'normal':str(binary),'nested':str(second),'binaries':{str(x):binding(Path(x)) for x in (binary,second)},
         'isolated_page':{'start':start,'code_end':code_end,'end':end,'functions':occupants},'actual_instruction_sites':assembly}
