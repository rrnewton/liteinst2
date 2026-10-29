"""Actual stack growth and native reference; no synthetic address/frame credit."""
import hashlib,importlib.util,re,struct
from pathlib import Path
from page_selected import need
_spec=importlib.util.spec_from_file_location('pcs_old_lease',Path(__file__).resolve().parent.parent/'tf_same_page/check.py')
old=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(old)
MAIN,BODY,TAIL,GUARD,DATA,PAGE,WORD=old.MAIN,old.BODY,old.TAIL,old.GUARD,old.DATA,old.PAGE,old.WORD
GREG,VECTORS,MASKS,q,word,put=old.GREG,old.VECTORS,old.MASKS,old.q,old.word,old.put
MAGIC=0x314b545359445443
LIMIT=(1<<64)-1

def program():
 return [(BODY+32,4,'add_rax'),(BODY+36,3,'store'),(BODY+39,4,'add_r8'),(BODY+43,1,'nop'),(BODY+44,5,'jump_guard'),
         (BODY+96,4,'add_r8'),(BODY+100,4,'add_r9'),(BODY+104,1,'nop'),(BODY+105,5,'jump_again')]

def geometry():return (BODY+32,GUARD,BODY+96,GUARD+128)

def elf(data,interpreter,case,native_policy):
 need(type(case)is int and case==0 and type(data)is bytes and len(data)>=64,'fixed finite ELF case')
 h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
 need(h[0][:7]==b'\x7fELF\x02\x01\x01'and h[1:4]==(2,62,1)and h[4]==MAIN and h[8:10]==(64,56)and h[11]==64,'actual high ET_EXEC')
 def extent(a,n):
  need(0<=a<=len(data)and 0<=n<=len(data)-a,'actual file extent');return data[a:a+n]
 ph=[struct.unpack('<IIQQQQQQ',extent(h[5]+56*i,56))for i in range(h[10])];loads=[p for p in ph if p[0]==1]
 need(len(loads)==3 and [p[1]for p in loads]==[4,5,6]and loads[0][2:4]==(0,MAIN-4096)and loads[0][5]<=4096 and
      loads[1][2:4]==(4096,MAIN)and loads[1][5:7]==(24576,24576)and loads[2][3]==DATA and loads[2][5]>=16384 and
      all(p[7]==4096 and p[5]<=p[6]for p in loads)and not any(p[0]==7 for p in ph),'three exact original ELF domains')
 ip=[p for p in ph if p[0]==3];need(len(ip)==1 and extent(ip[0][2],ip[0][5])==str(interpreter).encode()+b'\0','actual exact interpreter path')
 ss=[struct.unpack('<IIQQQQIIQQ',extent(h[6]+64*i,64))for i in range(h[12])];tables=[s for s in ss if s[1]==2]
 need(not any(s[1]in(4,9)and s[5]for s in ss)and len(tables)==1 and tables[0][9]==24,'no instruction relocations and one actual symbol table')
 t=tables[0];strings=ss[t[6]];names=extent(strings[4],strings[5]);symbols={}
 for at in range(t[4],t[4]+t[5],24):
  n,info,other,index,value,size=struct.unpack('<IBBHQQ',extent(at,24))
  if n and info&15!=4:
   name=names[n:names.index(b'\0',n)].decode();need(name not in symbols,'unique actual symbol');symbols[name]=value
 def read(a,n):
  p=next((p for p in loads if p[3]<=a and a+n<=p[3]+p[5]),None);need(p is not None,'actual mapped file bytes');return extent(p[2]+a-p[3],n)
 expected=dict(_start=MAIN,rn_seed=MAIN+4096,rn_body=BODY,rn_tail=TAIL,rn_guard=GUARD,rn_guard_write=GUARD+1,rn_data=DATA,rn_data_end=DATA+16384,
  rn_case=DATA+8,rn_mode=DATA+16,rn_active=DATA+24,rn_registration_result=DATA+32,rn_rounds=DATA+40,rn_commit=DATA+48,rn_abort_seen=DATA+56,
  rn_final_fs=DATA+64,rn_final_gs=DATA+72,rn_store=DATA+128,rn_descriptor=DATA+256,rn_vectors=DATA+512,rn_masks=DATA+2560,
  rn_live_vectors=DATA+4096,rn_live_masks=DATA+6144,rn_live_gpr=DATA+6208,rn_live_flags=DATA+6336,rn_live_selectors=DATA+6344,rn_rseq_initial=DATA+8192,rn_stack_top=DATA+16320)
 need(all(symbols[k]==v for k,v in expected.items())and symbols['rn_program']==BODY+32 and symbols['pcs_again']==BODY+96 and symbols['pcs_guard_again']==GUARD+128 and all(symbols[k]==DATA+n for k,n in dict(rn_entry_rsp=80,rn_stack_target=88,rn_query_result=96,rn_setup_pid=104,rn_next_program=112).items()),'all fixed source/data/capture identities')
 source,initial=read(MAIN,24576),read(DATA,16384)
 need(q(initial[:96])==(0x31464954414e5352,case,0,0,LIMIT,0,0,0,0,0,0,0)and initial[256:288]==bytes(32)and initial[512:2624]==VECTORS+MASKS,'literal case/descriptor/vector/mask seeds')
 seed=bytearray(16384);struct.pack_into('<5Q',seed,0,0x31464954414e5352,case,0,0,LIMIT);seed[512:2624]=VECTORS+MASKS;seed[12288:]=b'\xa5'*4096
 need(initial==seed,'every original DATA seed byte, including new metadata and stack')
 literals=dict(add_rax_rbx='4801d8',add_rax='4883c001',pxor='660fefc7',store='488907',overlap='488907',add_r8='4983c001',add_r9='4983c101',sub_eax='29c0',sub_ecx='29c9',cpuid='0fa2',nop='90')
 for pc,n,kind in program():
  if kind.startswith('jump'):
   target=GUARD+128 if kind=='jump_again'else GUARD
   need(read(pc,1)==b'\xe9'and pc+5+struct.unpack('<i',read(pc+1,4))[0]==target,'literal actual branch target')
  else:need(read(pc,n)==bytes.fromhex(literals[kind]),'complete exact real instruction '+kind)
 need(read(GUARD,1)==b'\x90'and read(GUARD+1,1)==b'\xe9'and GUARD+6+struct.unpack('<i',read(GUARD+2,4))[0]==symbols['rn_capture'],'genuine old-NOP endpoint then original full capture')
 need(read(symbols['rn_setup_syscall'],2)==b'\x0f\x05'and read(symbols['rn_restorer'],9)==bytes.fromhex('b80f0000000f050f0b'),'actual registration and signal restorer')
 need(native_policy(read(MAIN+4096-14,4096+28))==0 and native_policy(read(TAIL-14,4096+28))==0 and all(native_policy(read(p,4096))!=0 for p in(MAIN,BODY,GUARD)),
      'unchanged all-start helper+halo admission and real dirty program pages; no policy exemption')
 need(read(GUARD+128,2)==b'\x90\xe9'and GUARD+134+struct.unpack('<i',read(GUARD+130,4))[0]==symbols['rn_capture'],'second distinct old-NOP endpoint')
 need(read(symbols['pcs_query']-5,7)==bytes.fromhex('b8270000000f05'),'literal existing getpid query')
 need(read(MAIN,3)==bytes.fromhex('488925')and MAIN+7+struct.unpack('<i',read(MAIN+3,4))[0]==DATA+80,'save actual entry RSP before any stack use')
 interp=interpreter.read_bytes();ih=struct.unpack_from('<16sHHIQQQIHHHHHH',interp);entry=b'\x0f\xa2\x48\xb8'+struct.pack('<Q',MAIN)+b'\xff\xe0'
 need(len(interp)==8192 and ih[1:4]==(3,62,1)and ih[4]==4096 and interp[4096:4096+len(entry)]==entry and not any(interp[4096+len(entry):]),'unchanged first-interpreter CPUID and actual main handoff')
 return dict(case=case,symbols=symbols,entry=MAIN,source_hex=source.hex(),data_hex=initial.hex(),source_sha256=hashlib.sha256(source).hexdigest())

class Reader(old.Reader):
 def __init__(self,data,layout,record='pcs_native_record'):
  self.data,self.types,self.layout=data,layout['types'],layout;self.rt=self.types[record];self.ft=self.types['rn_frame']
  self.ucn=layout['uc_bytes'];self.go=layout['offsets']['greg'];self.fo=layout['offsets']['fp_pointer']
  need(layout['record']=='pcs_native_record'and record in('pcs_native_record','pcs_stack_proof')and len(data)==self.rt['bytes']<16<<20 and 0<self.ucn<=2048 and self.go+184<=self.ucn and self.fo+8<=self.ucn,'whole actual native/stack DWARF extent')
  need(layout['siginfo']==dict(bytes=128,offsets=dict(si_signo=0,si_errno=4,si_code=8,si_addr=16,si_pid=16,si_uid=20),widths=dict(si_signo=4,si_errno=4,si_code=4,si_addr=8,si_pid=4,si_uid=4)),'exact actual siginfo ABI')
  forms={'rn_frame':dict(h=512,uc=2048,fp=65536,source=24576,data=16384,rseq=4096),
   'pcs_maps':dict(h=128,reads=136,raw=65536),
   'pcs_stack_proof':dict(h=256,limit=16,before=65800,after=65800,adjacent_before=4096,adjacent_after=4096,grown=4096,code_before=4096,code_after=4096),
   'pcs_native_row':dict(h=256,before=113152,after=113152),
   'pcs_native_record':dict(h=512,xstate=128,rows=4*226560)}
  need(set(self.types)==set(forms),'complete fixed native layout type inventory')
  for name,fields in forms.items():
   t=self.types[name];at=0;need(set(t['fields'])==set(fields),'complete source field inventory '+name)
   for key,n in fields.items():need(t['fields'][key]==dict(offset=at,bytes=n),'full typed extent '+name+'.'+key);at+=n
   need(t['bytes']==at,'whole structure without omitted padding '+name)

def maps_data(b,layout):
 t=layout['types']['pcs_maps'];need(len(b)==t['bytes']==65800,'complete actual maps capture')
 h=q(b[:128]);calls=struct.unpack_from('<17q',b,128);raw=b[264:]
 need(h[:3]==(1,1,1)and h[3]>3 and 2<=h[4]<=17 and 0<h[5]<65536 and h[6:10]==(1,1,1,0)and not any(h[10:]),'actual open/EOF/close prefix, no inferred or partial acquisition')
 n=h[4];used=calls[:n];need(used[-1]==0 and all(0<x<=4096 for x in used[:-1])and sum(used)==h[5]and not any(calls[n:])and not any(raw[h[5]:]),'every bounded actual read/result and unused byte retained')
 rows=[];last=0
 for line in raw[:h[5]].splitlines(keepends=True):
  m=re.fullmatch(rb'([0-9a-f]+)-([0-9a-f]+) ([r-][w-][x-][ps]) ([0-9a-f]+) ([0-9a-f]+):([0-9a-f]+) ([0-9]+) *(.*)\n',line)
  need(m is not None,'complete literal Linux maps row')
  a,z,perm,off,major,minor,ino,name=m.groups();a,z,off,major,minor=(int(x,16)for x in(a,z,off,major,minor));ino=int(ino)
  need(0<=last<=a<z<=LIMIT and not(a|z)&4095 and all(0<=v<=LIMIT for v in(off,major,minor,ino)),'ordered actual map extents and exact integer domains');last=z
  rows.append(dict(first=a,end=z,perm=perm,offset=off,major=major,minor=minor,inode=ino,name=name))
 need(rows,'nonempty complete actual maps');return rows

def stack_proof(data,layout,image,pid):
 r=Reader(data,layout,'pcs_stack_proof');F=r.field;h=q(F(data,r.rt,'h'));limit=q(F(data,r.rt,'limit'))
 need(type(pid)is int and pid>0 and h[:3]==(MAGIC,1,len(data))and h[3]>0 and h[3]<1<<47 and h[4:7]==(1,0,1)and h[16:19]==(pid,1,1)and not any(h[19:]),'complete actual stack/prlimit/setup/growth prefix and parent PID')
 before,after=(maps_data(F(data,r.rt,k),layout)for k in('before','after'))
 def stack(rows):
  found=[(i,v)for i,v in enumerate(rows)if v['first']<=h[3]<v['end']]
  need(len(found)==1,'unique actual stack containing untouched entry RSP');i,s=found[0]
  need(s['perm']==b'rw-p'and s['name']==b'[stack]'and (s['offset'],s['major'],s['minor'],s['inode'])==(0,0,0,0),'genuine initial anonymous private writable stack identity')
  return s,rows[i-1]['end']if i else 0
 a,prev=stack(before);z,prev_after=stack(after)
 need((a['first'],a['end'],prev)==h[7:10]and h[10]==a['first']-4096 and h[11]==h[10]+64 and h[10]-prev>=2*1024*1024 and a['end']-h[10]<=limit[0]<=limit[1]<=LIMIT,'actual untouched one-page-below target, preceding VMA gap and real stack limit')
 need(not any(v['first']<a['first']and h[10]<v['end']for v in before),'entire target was actually unmapped')
 need(z['first']==h[10]and z['end']==a['end']and prev_after==prev,'actual stack expanded exactly one page; no absent-growth success')
 def body(rows):
  found=[v for v in rows if v['first']<=BODY and BODY+4096<=v['end']];need(len(found)==1,'one actual whole body mapping');v=found[0]
  need(v['perm']==b'r--p','actual body R after genuine native/owner close')
  return (v['major'],v['minor'],v['inode'],v['offset']+BODY-v['first'])
 need(body(before)==body(after)==h[12:16]and h[14]>0,'same file identity and per-page offset after real close')
 code=bytes.fromhex(image['source_hex'])[BODY-MAIN:BODY-MAIN+4096]
 need(F(data,r.rt,'code_before')==F(data,r.rt,'code_after')==code,'whole literal code page unchanged')
 need(F(data,r.rt,'adjacent_before')==F(data,r.rt,'adjacent_after'),'complete previously mapped adjacent stack page unchanged')
 grown=bytearray(4096);put(grown,64,DATA+257)
 need(F(data,r.rt,'grown')==grown,'whole newly mapped zero page with only the literal retired MOV result')
 return dict(entry_rsp=h[3],target=h[11],pid=pid,stack_first=a['first'],stack_end=a['end'],new_first=z['first'],query_result=pid,proof_bytes=len(data),proof_sha256=hashlib.sha256(data).hexdigest())

def states(image,context):
 need(image['case']==0 and set(context)>={'entry_rsp','target','pid','query_result'}and context['query_result']==context['pid'],'validated per-lane stack/PID authority')
 result=[]
 for episode,instructions in enumerate((program()[:5],program()[5:])):
  g=[0x1122334455667700+i for i in range(16)];g[0]=DATA+256;g[4]=DATA+16320;g[7]=context['target'];flags=0xed7
  for pc,n,kind in instructions:
   before=(tuple(g),flags,VECTORS,0)
   if kind.startswith('add_'):
    at={'add_rax':0,'add_r8':8,'add_r9':9}[kind];g[at],flags=old.add(g[at],1,flags)
   nextpc=GUARD if kind=='jump_guard'else GUARD+128 if kind=='jump_again'else pc+n
   result.append(dict(episode=episode,pc=pc,length=n,kind=kind,next=nextpc,before=before,after=(tuple(g),flags,VECTORS,0)))
 return result

def memory(image,native,page,context,endpoint_index,terminal=False):
 need(type(native)is bool and endpoint_index in range(4)and old.page_ids(page)['cpu']>=0,'typed lane and exact registered page')
 b=bytearray.fromhex(image['data_hex']);model=states(image,context);episode=endpoint_index//2
 for at,v in ((16,int(native)),(24,1),(32,0),(40,2 if terminal else episode),(80,context['entry_rsp']),(88,context['target']),(96,context['pid']if episode or terminal else 0),(104,context['pid']),(112,BODY+96 if episode else BODY+32)):
  put(b,at,v)
 b[8192:12288]=page;put(b,16312,0xed7)
 if episode or terminal:
  state=model[-1]['after']if terminal else model[4]['after'];g,flags,z,_=state
  b[4096:6144]=z;b[6144:6208]=MASKS;b[6208:6336]=struct.pack('<16Q',*g);put(b,6336,flags);b[6344:6356]=struct.pack('<6H',0x33,0x2b,0,0,0,0)
 if terminal:
  put(b,64,DATA+2048);put(b,72,DATA+2304);put(b,16312,model[-1]['after'][1])
 return bytes(b)

def output(data,layout,image,pid,native,cpu):
 n=layout['types']['pcs_stack_proof']['bytes'];need(type(data)is bytes and len(data)==20480+n,'entire DATA/rseq/actual stack-proof output')
 context=stack_proof(data[20480:],layout,image,pid);actual,page=data[:16384],data[16384:20480];ids=old.page_ids(page)
 need(type(cpu)is int and ids['cpu']==cpu and actual[8192:12288]==page,'actual reserved CPU and complete initial/final rseq page equality')
 need(actual==memory(image,native,page,context,3,True),'every live GPR/flags/32ZMM/8K/selector/data/stack byte and literal two-episode effects')
 return dict(accepted=True,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),context=context,cpu=cpu,node=ids['node'],mm_cid=ids['mm_cid'],episodes=2,grown_pages=1)

def native_frames(data,layout,image,pid,exit_status,context,cpu):
 need(type(pid)is int and pid==context['pid']and exit_status==0,'successful actual native process/PID')
 r=Reader(data,layout);F=r.field;h=q(F(data,r.rt,'h'));rows=F(data,r.rt,'rows');st=r.types['pcs_native_row'];components=r.components(F(data,r.rt,'xstate'))
 need(h[:6]==(MAGIC,1,len(data),0,4,1)and h[6:8]==(0,0)and h[8:10]==(pid,pid)and h[10]&0xe7==0xe7 and h[11]>0 and h[12]==131072 and not any(h[13:]),'whole actual four-event native prefix')
 model=states(image,context);expected=(model[0]['before'],model[4]['after'],model[5]['before'],model[-1]['after']);frames=[]
 for i,pc in enumerate(geometry()):
  row=rows[i*st['bytes']:(i+1)*st['bytes']];v=q(F(row,st,'h'));a=F(row,st,'before')
  need(a==F(row,st,'after'),'whole local UC/FP/source/data/rseq byte equality, no frame edits')
  f=r.frame(a,image);r.envelope(f,h[11],h[12],True);r.siginfo_alias(row,st,f)
  need(v[:5]==(1,i,pc,pc,1)and not any(v[5:8]+v[16:24]+v[28:]),'exact native current-PC/si_addr/prefix and unused header')
  permits=(GUARD,4096,1,0,BODY,4096,5,0)if i%2==0 else(BODY,4096,1,0,GUARD,4096,5,0)
  need(v[8:16]==permits,'real close of old page then real open of next page; no inferred protection')
  old.literal(f,expected[i],pc,0x10000,components)
  need(old.page_ids(f['page'])['cpu']==cpu and f['data']==memory(image,True,f['page'],context,i),'entire per-event literal data and reserved CPU')
  if frames:need(f['fp']==frames[0]['fp']and f['page']==frames[0]['page'],'every initialized FP/software/header byte and rseq byte remains exact across reseeding')
  frames.append(f)
 return r,frames,components

def native(data,layout,image,pid,exit_status,context,cpu):
 native_frames(data,layout,image,pid,exit_status,context,cpu)
 return dict(accepted=True,exit_status=exit_status,frames=4,episodes=2,observed_cpu=cpu,grown_pages=1)
