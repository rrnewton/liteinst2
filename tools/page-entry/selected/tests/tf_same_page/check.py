"""Strict finite lease evidence. Transfers never acquire a CLOSED label.

The old registered/boundary/chain readers are unchanged. This reader binds the
new events to actual DWARF and independent native endpoints, not supplied frames.
"""
import hashlib,importlib.util,struct
from pathlib import Path
from page_selected import need
S=importlib.util.spec_from_file_location('lso_old_boundary',Path(__file__).resolve().parent.parent/'rseq_native_boundary/check.py')
old=importlib.util.module_from_spec(S);S.loader.exec_module(old)
MAIN,BODY,TAIL,GUARD,DATA,PAGE,AREA,WORD=old.MAIN,old.BODY,old.TAIL,old.GUARD,old.DATA,old.PAGE,old.AREA,old.WORD
GREG,VECTORS,MASKS,q,word,put,page_ids=old.GREG,old.VECTORS,old.MASKS,old.q,old.word,old.put,old.page_ids
MAGIC=0x31455341454c4654
GENERIC=(6,6,5,4,4,1,1,1,1,1)
TRANSFERS=(3,2,2,1,0,0,0,0,0,0)
EXIT=(0,0,0,0,0,125,125,125,125,125)
MASK=(1<<64)-1

def program(c):
 p=TAIL-7 if c==3 else TAIL-5 if c==4 else BODY+32
 if c in(3,4):return [(p,3,'add_rax_rbx'),(p+3,4,'add_rax'),(TAIL+(2 if c==4 else 0),4,'add_r8'),(TAIL+(6 if c==4 else 4),1,'nop'),(TAIL+(7 if c==4 else 5),5,'jump_guard')]
 if c==1:return [(p,3,'add_rax_rbx'),(p+3,4,'add_rax'),(p+7,5,'jump_branch'),(BODY+64,4,'add_r8'),(BODY+68,4,'add_r9'),(BODY+72,1,'nop'),(BODY+73,5,'jump_guard')]
 if c==2:return [(p,2,'sub_eax'),(p+2,2,'sub_ecx'),(p+4,2,'cpuid'),(p+6,4,'add_r8'),(p+10,4,'add_r9'),(p+14,1,'nop'),(p+15,5,'jump_guard')]
 if c==5:return [(p,3,'add_rax_rbx'),(p+3,3,'overlap')]
 return [(p,3,'add_rax_rbx'),(p+3,4,'add_rax'),(p+7,4,'pxor'),(p+11,3,'store'),(p+14,1,'nop'),(p+15,4,'add_r8'),(p+19,5,'jump_guard')]

def elf(data,interpreter,case,native_policy):
 need(type(case)is int and 0<=case<10 and type(data)is bytes and len(data)>=64,'fixed finite ELF case')
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
 need(all(symbols[k]==v for k,v in expected.items())and symbols['rn_program']==program(case)[0][0],'all fixed source/data/capture identities')
 source,initial=read(MAIN,24576),read(DATA,16384)
 need(q(initial[:96])==(old.old.MAGIC,case,0,0,MASK,0,0,0,0,0,0,0)and initial[256:288]==bytes(32)and initial[512:2624]==VECTORS+MASKS,'literal case/descriptor/vector/mask seeds')
 literals=dict(add_rax_rbx='4801d8',add_rax='4883c001',pxor='660fefc7',store='488907',overlap='488907',add_r8='4983c001',add_r9='4983c101',sub_eax='29c0',sub_ecx='29c9',cpuid='0fa2',nop='90')
 for pc,n,kind in program(case):
  if kind.startswith('jump'):
   target=BODY+64 if kind=='jump_branch'else GUARD
   need(read(pc,1)==b'\xe9'and pc+5+struct.unpack('<i',read(pc+1,4))[0]==target,'literal actual branch target')
  else:need(read(pc,n)==bytes.fromhex(literals[kind]),'complete exact real instruction '+kind)
 need(read(GUARD,1)==b'\x90'and read(GUARD+1,1)==b'\xe9'and GUARD+6+struct.unpack('<i',read(GUARD+2,4))[0]==symbols['rn_capture'],'genuine old-NOP endpoint then original full capture')
 need(read(symbols['rn_setup_syscall'],2)==b'\x0f\x05'and read(symbols['rn_restorer'],9)==bytes.fromhex('b80f0000000f050f0b'),'actual registration and signal restorer')
 need(native_policy(read(MAIN+4096-14,4096+28))==0 and all(native_policy(read(p,4096))!=0 for p in(MAIN,BODY,TAIL,GUARD)),
      'unchanged all-start helper+halo admission and real dirty program pages; no policy exemption')
 interp=interpreter.read_bytes();ih=struct.unpack_from('<16sHHIQQQIHHHHHH',interp);entry=b'\x0f\xa2\x48\xb8'+struct.pack('<Q',MAIN)+b'\xff\xe0'
 need(len(interp)==8192 and ih[1:4]==(3,62,1)and ih[4]==4096 and interp[4096:4096+len(entry)]==entry and not any(interp[4096+len(entry):]),'unchanged first-interpreter CPUID and actual main handoff')
 return dict(case=case,symbols=symbols,entry=MAIN,source_hex=source.hex(),data_hex=initial.hex(),source_sha256=hashlib.sha256(source).hexdigest())

class Reader(old.Reader):
 def __init__(self,data,layout,record):
  self.data,self.types,self.layout=data,layout['types'],layout;self.rt=self.types[record];self.ft=self.types['rn_frame']
  self.ucn=layout['uc_bytes'];self.go=layout['offsets']['greg'];self.fo=layout['offsets']['fp_pointer']
  need(layout['record']==record and len(data)==self.rt['bytes']<16<<20 and 0<self.ucn<=2048 and self.go+184<=self.ucn and self.fo+8<=self.ucn,'complete actual record/DWARF extent')
  need(layout['siginfo']==dict(bytes=128,offsets=dict(si_signo=0,si_errno=4,si_code=8,si_addr=16,si_pid=16,si_uid=20),widths=dict(si_signo=4,si_errno=4,si_code=4,si_addr=8,si_pid=4,si_uid=4)),'actual complete signal ABI')
  fields=dict(h=512,uc=2048,fp=65536,source=24576,data=16384,rseq=4096);at=0
  need(set(self.ft['fields'])==set(fields),'whole original frame fields')
  for k,n in fields.items():need(self.ft['fields'][k]==dict(offset=at,bytes=n),'whole original frame extent '+k);at+=n
  need(self.ft['bytes']==at,'whole original frame including raw libc UC')
  sizes={k:v['bytes']for k,v in self.types.items()}
  own={'lso_native_row':dict(h=256,before=at,after=at),
       'lso_native_record':dict(h=512,xstate=128,rows=2*sizes['lso_native_row'])}
  if record=='lso_record':
   own['lso_event']=dict(h=256,counts_before=128,counts_after=128,before=at,after=at,
       owner_before=sizes['li2_tf_owner'],owner_after=sizes['li2_tf_owner'],
       fetch_before=sizes['li2_chain_fetch'],fetch_after=sizes['li2_chain_fetch'],next_fetch=sizes['li2_chain_fetch'],
       next_first_fetch=sizes['li2_chain_fetch'],next_first_decoded=sizes['li2_decoded'],next_first_release=sizes['li2_chain_release'],
       release=sizes['li2_chain_release'],query=sizes['li2_tf_continuation'],next_before=sizes['li2_step_frame'],
       lease=sizes['li2_tf_same_page'],rseq_before=sizes['li2_rseq_state'],rseq=sizes['li2_rseq_state'])
   own['lso_record']=dict(h=512,xstate=128,hardware=56,endpoints=2*sizes['lso_native_row'],events=12*sizes['lso_event'],
       cpuid_h=160,cpuid_before=at,cpuid_after=at,terminal_chain=sizes['li2_tf_chain'],terminal_rseq=sizes['li2_rseq_state'],
       fault_view=sizes['li2_fetch_rx_view'],terminal_maps=sizes['li2_fetch_map_progress'],nested=at,
       terminal_source=24576,terminal_data=16384,terminal_page=4096)
  for name,fields in own.items():
   if name not in self.types:continue
   shape=self.types[name]
   need(set(shape['fields'])==set(fields)and sorted(shape['fields'],key=lambda k:shape['fields'][k]['offset'])==list(fields)and
        all(shape['fields'][k]['bytes']==n for k,n in fields.items()),'exact complete source field order/extent '+name)
  for name,sh in self.types.items():
   last=0
   for f in sorted(sh['fields'].values(),key=lambda v:v['offset']):
    need(type(f['offset'])is int and type(f['bytes'])is int and last<=f['offset']and 0<f['bytes']<=sh['bytes']-f['offset'],'nonoverlapping complete typed fields '+name);last=f['offset']+f['bytes']
 def entry_siginfo(self,row,st,f,returned):
  if returned:return self.siginfo_alias(row,st,f)
  v=q(self.field(row,st,'h'));si=self.layout['siginfo'];o=si['offsets'];offset=v[24]-f['h'][3]
  need(v[24]>0 and v[25]==0 and v[26]==si['bytes']and v[27]==o['si_addr']and
       offset==self.layout['offsets']['mask']+8 and 0<=offset<=self.ucn-si['bytes'],
       'actual entry-only siginfo pointer and full alias extent; no invented returned pointer')
  expected=bytearray(si['bytes'])
  for key,value in(('si_signo',f['h'][5]),('si_errno',f['h'][7]),('si_code',f['h'][6])):struct.pack_into('<i',expected,o[key],value)
  put(expected,o['si_addr'],f['h'][8])
  need(f['uc'][offset:offset+si['bytes']]==expected,'entire actual entry-only siginfo including padding and unused bytes')
 def frame(self,b,image,event='nx'):
  h=q(self.field(b,self.ft,'h'));uc=self.field(b,self.ft,'uc');fp=self.field(b,self.ft,'fp')
  need(h[:2]==(1,self.ucn)and 512<=h[2]<=65536 and h[3]>0 and h[11]==0 and not any(h[12:]),'complete actual frame and observed zero word')
  need(not any(uc[self.ucn:])and not any(fp[h[2]:])and word(uc,self.fo)>0,'complete actual initialized UC/FP extent, no dirty-state truncation')
  if h[2]>512:need(struct.unpack_from('<II',fp,464)==(0x46505853,h[2])and struct.unpack_from('<I',fp,h[2]-4)[0]==0x46505845 and word(fp,520)==0,'actual standard signal FP envelope')
  g=q(uc[self.go:self.go+184]);need(g[18]==0x002b000000000033 and h[9:11]==(0,0),'actual selectors and full packed selector slots')
  if event=='nx':need(h[4:8]==(11,11,2,0)and g[20]==14 and g[19]==21 and g[22]==h[8]and g[17]&0x10100==0x10000,'genuine exact fetch-NX frame')
  elif event=='trace':need(h[4:8]==(5,5,2,0)and g[20]==1 and g[19]==0 and g[16]==h[8]and g[17]&0x10100==0x100,'genuine TRACE with TF still set and no RF')
  elif event=='committed':need(h[4:8]==(11,11,2,0)and g[20]==14 and g[19]==21 and g[17]&0x10100==0,'same actual NX frame after explicit selected commit')
  elif event=='returned':need(h[4:8]==(5,5,2,0)and g[20]==1 and g[19]==0 and g[16]==h[8]and not g[17]&0x10000,'actual original TRACE after close/rearm')
  else:need(event=='nested'and h[4:8]==(5,5,(1<<32)-6,0),'genuine nested SI_TKILL event, no invented TRACE')
  source,memory,page=(self.field(b,self.ft,k)for k in('source','data','rseq'))
  need(source==bytes.fromhex(image['source_hex'])and word(page,72)==0 and memory[512:2624]==VECTORS+MASKS,'complete unchanged source and original seed domains');page_ids(page)
  return dict(h=h,uc=uc,fp=fp,data=memory,page=page,greg=g,raw=b)
 def step_frame(self,b,f,flags=None):
  t='li2_step_frame';n=self.integer(b,t,'fp_bytes')
  expected=list(f['greg']);expected[17]=f['greg'][17]if flags is None else flags
  need(q(self.field(b,t,'greg'))==tuple(expected)and self.integer(b,t,'mask')==word(f['uc'],self.layout['offsets']['mask'])and
       self.integer(b,t,'fp_address')==word(f['uc'],self.fo)and self.integer(b,t,'initialized')==n==f['h'][2]and
       self.field(b,t,'fp')[:n]==f['fp'][:n],'all actual step-frame GPR/mask/pointer/initialized FP bytes, exact TF meaning')

def add(a,b,flags,bits=64):
 m=(1<<bits)-1;v=(a+b)&m;sign=1<<(bits-1);changed=1|4|16|64|128|2048
 f=flags&~changed;f|=int(a+b>m);f|=int((v&255).bit_count()%2==0)*4;f|=((a^b^v)&16);f|=int(v==0)*64;f|=int(bool(v&sign))*128;f|=int(bool((~(a^b)&(a^v))&sign))*2048
 return v,f

def states(image,cpuid=None):
 c=image['case'];g=[0x1122334455667700+i for i in range(16)];g[0]=DATA+256;g[4]=DATA+16320;g[7]=WORD if c==5 else DATA+128
 flags=0xed7;z=bytearray(VECTORS);store=0;rows=[]
 for pc,n,kind in program(c):
  before=(tuple(g),flags,bytes(z),store)
  if kind=='add_rax_rbx':g[0],flags=add(g[0],g[3],flags)
  elif kind.startswith('add_'):
   i={'add_rax':0,'add_r8':8,'add_r9':9}[kind];g[i],flags=add(g[i],1,flags)
  elif kind in('sub_eax','sub_ecx'):g[int(kind=='sub_ecx')]=0;flags=(flags&~(1|4|16|64|128|2048))|4|64
  elif kind=='pxor':z[:16]=bytes(a^b for a,b in zip(z[:16],z[7*64:7*64+16]))
  elif kind=='store':store=g[0]
  elif kind=='overlap':break # never execute the failed publication operation
  elif kind=='cpuid':
   need(cpuid is not None and len(cpuid)==4 and all(type(v)is int and 0<=v<1<<32 for v in cpuid),'separate actual same-input native/raw CPUID authority')
   g[0],g[3],g[1],g[2]=cpuid
  nextpc=BODY+64 if kind=='jump_branch'else GUARD if kind=='jump_guard'else pc+n
  rows.append(dict(pc=pc,length=n,kind=kind,next=nextpc,before=before,after=(tuple(g),flags,bytes(z),store)))
 return rows

def memory(image,native,page,state,terminal=False):
 g,flags,z,store=state;b=bytearray.fromhex(image['data_hex']);put(b,16,int(native));put(b,24,1);put(b,32,0);put(b,128,store);b[8192:12288]=page;put(b,16312,0xed7)
 if terminal:
  put(b,40,1);put(b,64,DATA+2048);put(b,72,DATA+2304);b[4096:6144]=z;b[6144:6208]=MASKS;b[6208:6336]=struct.pack('<16Q',*g);put(b,6336,flags);b[6344:6356]=struct.pack('<6H',0x33,0x2b,0,0,0,0);put(b,16312,flags)
 return bytes(b)

def vector_bytes(fp,components):
 result=bytearray()
 for reg in range(32):
  if reg<16:
   z=fp[160+reg*16:176+reg*16];o=components[2][0]+reg*16;z+=fp[o:o+16];o=components[6][0]+reg*32;z+=fp[o:o+32]
  else:o=components[7][0]+(reg-16)*64;z=fp[o:o+64]
  result+=z
 return bytes(result)

def literal(f,state,pc,flags_extra,components):
 g,flags,z,store=state
 need(tuple(f['greg'][n]for n in GREG)==g and f['greg'][16]==pc and f['greg'][17]==flags|flags_extra,'all literal GPR/PC/flags; no unspecified flag mask')
 need(word(f['fp'],512)&0xe7==0xe7 and all(o+n<=f['h'][2]-4 for o,n in components.values())and vector_bytes(f['fp'],components)==z,'complete real 32-ZMM state')
 o,n=components[5];need(f['fp'][o:o+n]==MASKS,'all eight actual opmasks')

def endpoint(r,b,st,image,native,index,components):
 h=q(r.field(b,st,'h'));a=r.field(b,st,'before');need(a==r.field(b,st,'after'),'every local raw UC/FP/source/data/page byte unchanged')
 f=r.frame(a,image);pc=GUARD if index else program(image['case'])[0][0]
 need(h[:5]==(1,index,pc,pc,1)and f['greg'][16]==pc and f['h'][8]==pc,'genuine literal first/endpoint NX event')
 r.siginfo_alias(b,st,f);return f

def native(data,layout,image,pid,exit_status):
 need(image['case']<5 and type(pid)is int and pid>0 and exit_status==0,'actual successful independent native process')
 r=Reader(data,layout,'lso_native_record');h=q(r.field(data,r.rt,'h'));st=r.types['lso_native_row'];rows=r.field(data,r.rt,'rows')
 need(h[:6]==(MAGIC,1,len(data),image['case'],2,1)and h[6:8]==(0,0)and h[8:10]==(pid,pid)and h[10]&0xe7==0xe7 and h[11]>0 and h[12]==131072 and not any(h[13:])and len(rows)==2*st['bytes'],'complete genuine native prefix')
 components=r.components(r.field(data,r.rt,'xstate'));fs=[]
 for i in range(2):
  row=rows[i*st['bytes']:(i+1)*st['bytes']];f=endpoint(r,row,st,image,True,i,components);r.envelope(f,h[11],h[12],True);v=q(r.field(row,st,'h'))
  calls=(BODY,4096,5,0,TAIL,4096,5,0)if i==0 else(GUARD,4096,5,0)
  need(v[8:8+len(calls)]==calls and not any(v[5:8]+v[8+len(calls):24]+v[28:]),'only actual complete native mprotect calls');fs.append(f)
 cpuid=tuple(fs[1]['greg'][i]for i in(13,11,14,12))if image['case']==2 else None
 model=states(image,cpuid)
 for i,f in enumerate(fs):
  state=model[-1]['after']if i else model[0]['before'];literal(f,state,GUARD if i else model[0]['pc'],0x10000,components)
  need(f['data']==memory(image,True,f['page'],state),'complete independent native data/stack')
 expected=bytearray(fs[0]['fp']);expected[160:176]=model[-1]['after'][2][:16]
 need(bytes(expected)==fs[1]['fp']and fs[0]['page']==fs[1]['page'],'whole native FP envelope and rseq page, only literal PXOR bytes differ')
 return dict(case=image['case'],exit_status=0,events=2,observed_cpus=[page_ids(f['page'])['cpu']for f in fs],cpuid=cpuid)

def gated(data,layout,image,pid,exit_status,lease=True):
 c=image['case'];need(type(lease)is bool and type(pid)is int and pid>0 and type(exit_status)is int and exit_status==EXIT[c],'actual fixed gated outcome')
 r=Reader(data,layout,'lso_record');I,F=r.integer,r.field;h=q(F(data,r.rt,'h'));et=r.types['lso_event'];rows=F(data,r.rt,'events')
 need(h[:6]==(MAGIC,2,len(data),c,r.ucn,et['bytes'])and h[6]&0xe7==0xe7 and h[7:11]==(1,0,1,EXIT[c])and h[13:15]==(GENERIC[c],1)and
      h[15]>0 and h[16]==512*1024 and h[17]==h[18]>0 and h[19:21]==(pid,pid)and not any(h[22:32]+h[40:41]+h[50:]),'complete actual terminal record, no partial success')
 need(len(rows)==12*et['bytes']and not any(rows[GENERIC[c]*et['bytes']:]),'bounded fixed event capacity and zero unused rows')
 hw=struct.unpack('<14I',F(data,r.rt,'hardware'));need(hw[:2]==(1,0)and hw[2]>=13 and hw[8]&0x18000000==0x18000000 and hw[11]&0x40010000==0x40010000,'actual pre-arm CPUID capability')
 components=r.components(F(data,r.rt,'xstate'));cpuid=None;ch=q(F(data,r.rt,'cpuid_h'))
 if c==2:
  need(ch[:3]==(1,1,3)and ch[3]==ch[4]==ch[5]==2 and ch[6:10]==(BODY+36,BODY+38,0,0)and ch[10:14]==ch[14:18]and not any(ch[18:]),'exact interpreter plus one program CPUID; actual raw sample equals committed result')
  cpuid=ch[10:14];cb=r.frame(F(data,r.rt,'cpuid_before'),image);ca=r.frame(F(data,r.rt,'cpuid_after'),image,'committed')
  changed=bytearray(cb['uc'])
  for reg,value in zip((13,11,14,12),cpuid):put(changed,r.go+8*reg,value)
  put(changed,r.go+16*8,BODY+38);put(changed,r.go+17*8,cb['greg'][17]&~0x10000)
  need(bytes(changed)==ca['uc']and cb['h']==ca['h']and cb['fp']==ca['fp']and cb['data']==ca['data']and cb['page']==ca['page'],'complete exact builtin frame commit and unchanged FP/source/data/mask')
 else:need(not any(F(data,r.rt,'cpuid_h')+F(data,r.rt,'cpuid_before')+F(data,r.rt,'cpuid_after')),'no fabricated program CPUID')
 model=states(image,cpuid);executed=[x for x in model if x['kind']not in('nop','cpuid')]
 if c>=5:executed=executed[:1]
 need(len(executed)==GENERIC[c],'source-fixed generic execution count')
 ep=F(data,r.rt,'endpoints');nt=r.types['lso_native_row'];ends=[]
 for i in range(2 if c<5 else 1):
  row=ep[i*nt['bytes']:(i+1)*nt['bytes']];f=endpoint(r,row,nt,image,False,i,components);v=q(F(row,nt,'h'))
  need(not any(v[5:24]+v[28:]),'endpoint has actual native-fetch READY return and no invented permission calls')
  r.envelope(f,h[15],h[16],False);state=model[-1]['after']if i else model[0]['before'];literal(f,state,GUARD if i else model[0]['pc'],0x10000,components)
  need(f['data']==memory(image,False,f['page'],state),'complete actual endpoint data/stack');ends.append(f)
 if c>=5:need(not any(ep[nt['bytes']:]),'failed operation has no endpoint')
 baseline=ends[0]['fp'];previous=None;active_opening=None;actual_transfers=closed=0;observed_cpus=[page_ids(f['page'])['cpu']for f in ends]
 def sub(b,t,k):return F(b,t,k)
 def step(owner):return F(owner,'li2_tf_owner','step')
 def request(p):return F(p,'li2_step_owner','request')
 def initialized(a,b):
  t='li2_step_frame';n=I(a,t,'fp_bytes');need(n==I(b,t,'fp_bytes')and I(a,t,'initialized')==I(b,t,'initialized')==n and 512<=n<=65536,'same entire initialized frame extent')
  off=r.types[t]['fields']['fp']['offset'];need(a[:off+n]==b[:off+n],'all initialized metadata/FP bytes exact')
 def opening(lr,expected=None):
  t='li2_tf_same_page';actual=(F(lr,t,'opening'),F(lr,t,'opening_frame'),
       *(I(lr,t,k)for k in('slot','owner_generation','origin_event','origin_borrow')))
  if expected is None:
   need(actual[0]==rq and actual[2:]==(v[2],v[3],v[17],seq),'original request/slot/generation/event/borrow from the actual pre-transfer owner')
   initialized(actual[1],saved)
  else:need(actual==expected,'entire original opening proof persists through transfer and actual final close')
  return actual
 def maps_receipt(b,direct=False):
  mt='li2_fetch_map_progress';ot='li2_maps_observation';o=F(b,mt,'observation')
  need(I(b,mt,'fd')>3 and I(b,mt,'last_read')==I(b,mt,'close_result')==0 and
       0<I(b,mt,'bytes')<=256*1024 and 0<I(b,mt,'rows')<=2048 and
       all(I(b,mt,k)==1 for k in('opened','close_started','closed')),'actual complete maps acquisition with EOF and closed descriptor')
  if direct:need(not any(o),'separate direct post-failure observation does not invent a phase receipt')
  else:need(I(o,ot,'acquisition_id')>0 and I(o,ot,'handler_id')>0 and I(o,ot,'mutation_epoch')>0 and
       I(o,ot,'kind')==I(o,ot,'io_performed')==1,'fresh actual RX acquisition in this handler, no inherited validity')
 def borrow(b,pc,pages,held):
  t='li2_chain_fetch';ref=F(b,t,'ref');pr=F(b,t,'progress');seq=I(ref,'li2_fetch_ref','sequence')
  need(I(ref,'li2_fetch_ref','owner')>0 and seq>0 and I(pr,'li2_fetch_progress','sequence')==seq and I(pr,'li2_fetch_progress','held')==held and
       I(pr,'li2_fetch_progress','complete')==I(pr,'li2_fetch_progress','identity_observed')==1 and I(pr,'li2_fetch_progress','first_error')==I(pr,'li2_fetch_progress','first_detail')==0 and
       I(b,t,'pc')==pc and I(b,t,'page_count')==pages and I(b,t,'pid')==I(b,t,'tid')==pid and I(b,t,'identity_observed')==1,'complete live held/released fetch identity')
  n=I(b,t,'length');need(1<=n<=15 and F(b,t,'bytes')[:n]==bytes.fromhex(image['source_hex'])[pc-MAIN:pc-MAIN+n],'every borrowed source byte')
  return seq
 for i,m in enumerate(executed):
  row=rows[i*et['bytes']:(i+1)*et['bytes']];v=q(F(row,et,'h'));bcount=q(F(row,et,'counts_before'));acount=q(F(row,et,'counts_after'))
  need(v[:2]==(1,i)and v[2]in(0,1)and v[3]>0 and 0<v[17]<bcount[0]and v[18]in(1,2)and v[19]==3 and not any(v[20:24]+v[28:]),'actual ordered event and original owner event identity')
  before=r.frame(F(row,et,'before'),image,'trace');r.envelope(before,h[15],h[16],False);r.entry_siginfo(row,et,before,v[4]==1)
  literal(before,m['after'],m['next'],0x100,components);need(before['data']==memory(image,False,before['page'],m['after']),'complete per-instruction state and disjoint store')
  expected_fp=bytearray(baseline);expected_fp[160:176]=m['after'][2][:16]
  need(before['fp']==bytes(expected_fp),'entire hardware FP image; only literal PXOR bytes change')
  observed_cpus.append(page_ids(before['page'])['cpu'])
  ob,oa=F(row,et,'owner_before'),F(row,et,'owner_after');pb,pa=step(ob),step(oa);rq=request(pb);d=F(rq,'li2_step_request','decoded')
  pages=1+int((m['pc']&~4095)!=((m['pc']+m['length']-1)&~4095))
  need(I(pb,'li2_step_owner','phase')==3 and I(pb,'li2_step_owner','first_error')==0 and I(pb,'li2_step_owner','in_handler')==I(pb,'li2_step_owner','trace_seen')==0 and
       I(d,'li2_decoded','pc')==m['pc']and I(d,'li2_decoded','next_pc')==m['pc']+m['length']and I(d,'li2_decoded','length')==m['length']and
       I(rq,'li2_step_request','page_count')==pages and I(rq,'li2_step_request','original_flags')==m['before'][1],'actual running instruction and original logical flags')
  for k in('open_started','opened'):need(struct.unpack('<2I',F(pb,'li2_step_owner',k))==(1,int(pages==2)),'only actual original opens')
  for k in('revoke_started','revoked','revoke_result'):need(not any(F(pb,'li2_step_owner',k)),'no invented pre-effect revocation')
  need(not any(F(pb,'li2_step_owner','open_result'))and I(pb,'li2_step_owner','open_sync')==0,'actual successful original opening')
  saved=F(pb,'li2_step_owner','before');sg=q(F(saved,'li2_step_frame','greg'))
  need(tuple(sg[n]for n in GREG)==m['before'][0]and sg[16]==m['pc'],'literal complete saved execution input')
  from_lease=previous is not None and previous['result']==2
  need(sg[17]==(m['before'][1]|(0x100 if from_lease else 0x10000 if sg[20]==14 else 0)),'genuine TF-set transfer before-frame versus actual old NX/TRACE armed frame')
  if i==0:r.step_frame(saved,ends[0])
  if from_lease:need(ob==previous['owner_after']and v[17]==previous['event'],'same actual permission owner and committed event survive application retirement')
  bf,af=F(row,et,'fetch_before'),F(row,et,'fetch_after');seq=borrow(bf,m['pc'],pages,1)
  need(bcount[10:13]==(v[2],1,0)and bcount[15]==301,'one real pending chain and continuously held fetch interlock')
  rb,ra=F(row,et,'rseq_before'),F(row,et,'rseq');rt='li2_rseq_state'
  for state in(rb,ra):
   need(tuple(I(state,rt,k)for k in('initialized','registered','held','phase','pid','tid','address','page','length','signature','epoch'))==
        (1,1,1,3,pid,pid,AREA,PAGE,32,0x53053053,1)and
        tuple(I(state,rt,k)for k in('tls_attempted','tls_complete','fs_result','gs_result','fs_base','gs_base'))==
        (1,1,0,0,DATA+2048,DATA+2304),'same real ACTIVE registration and fresh completed TLS authority at every transfer')
  checked_next=(v[4]==1 and v[5]in(1,2))or c in(5,7,9)
  need(I(ra,rt,'instruction_checks')==I(rb,rt,'instruction_checks')+int(checked_next),'every actual admitted successor performs one fresh instruction guard')
  if checked_next:
   successor=next(x for x in program(c)if x[0]==m['next']);pc,n,kind=successor
   is_store=kind in('store','overlap');first=(WORD if c==5 else DATA+128)if is_store else 0;end=first+8 if is_store else 0
   footprint=F(ra,rt,'last_footprint');ft='li2_write_footprint'
   need(tuple(I(footprint,ft,k)for k in('pc','next_pc','first','end','abi_version','policy','length'))==
        (pc,pc+n,first,end,1,2 if is_store else 1,n)and I(footprint,ft,'code')==I(ra,rt,'last_code')and
        tuple(I(ra,rt,k)for k in('last_pc','last_first','last_end','last_policy'))==(pc,first,end,2 if is_store else 1)and
        I(ra,rt,'range_checks')==I(rb,rt,'range_checks')+int(is_store),
        'actual fresh typed successor footprint including exact disjoint/publication write range')
  expected_rseq=bytearray(rb)
  changed=('instruction_checks','range_checks','last_pc','last_code','last_first','last_end','last_policy','last_footprint')if checked_next else()
  if c==5:changed+=('first_error','first_detail')
  for key in changed:
   f=r.types[rt]['fields'][key];a=f['offset'];expected_rseq[a:a+f['bytes']]=ra[a:a+f['bytes']]
  need(bytes(expected_rseq)==ra and I(rb,rt,'first_error')==0 and I(ra,rt,'first_error')==(1205 if c==5 else 0)and I(ra,rt,'first_detail')==0,
       'complete registration/pin/TLS state unchanged outside the exact new guard observations')
  if c>=5:
   need(v[4:6]==(0,0)and not any(F(row,et,'after')),'terminal prefix never invents a returned trace or state')
   need(I(pa,'li2_step_owner','phase')==6 and I(pa,'li2_step_owner','first_error')>0 and struct.unpack('<2I',F(pa,'li2_step_owner','revoke_started'))==(1,0)and
        struct.unpack('<2Q',F(pa,'li2_step_owner','revoke_result'))==(0,0)and I(pa,'li2_step_owner','revoke_sync_started')==1 and I(pa,'li2_step_owner','revoke_sync')==0 and
        not any(F(row,et,'release'))and I(oa,'li2_tf_owner','continuation_started')==0,'failed operation attempted actual original-page revoke and sync; no close/release claim')
   need(request(pa)==rq and I(pa,'li2_step_owner','session')==I(pb,'li2_step_owner','session')and F(pa,'li2_step_owner','hooks')==F(pb,'li2_step_owner','hooks'),'same original permission cleanup owner through failure')
   need(v[6:10]==(v[2],v[3],7,v[18])and v[10:12]==(0,0), 'failed staged transfer retains its original active slot; no successor publication')
   need(tuple(struct.unpack('<2I',F(pa,'li2_step_owner','revoked')))==(1,0),
        'actual successful mprotect is retained even when subsequent authentication fails; phase remains FAILED')
   lr=F(row,et,'lease');lt='li2_tf_same_page'
   need(I(lr,lt,'origin_active')==int(c in(7,9)),'only the actual commit prefixes install an original opening proof')
   if c in(7,9):
    need(I(lr,lt,'phase')==2,'failed commit prefix remains TRANSFERRING, never CLOSED')
    active_opening=opening(lr)
   continue
  need(v[4]==1 and v[5]in(0,1,2)and(lease or v[5]!=2),'actual completed strict result discriminator')
  after=r.frame(F(row,et,'after'),image,'returned');r.envelope(after,h[15],h[16],False)
  ua=bytearray(before['uc']);put(ua,r.go+17*8,after['greg'][17])
  need(bytes(ua)==after['uc']and before['fp']==after['fp']and before['h']==after['h']and before['data']==after['data']and before['page']==after['page'],
       'every real local byte preserved except exact owner TF transition')
  r.step_frame(F(pa,'li2_step_owner','after'),before)
  if v[5]==2:
   actual_transfers+=1;need(F(row,et,'before')==F(row,et,'after')and after['greg'][17]&0x100,'no transfer frame normalization')
   need(v[6:10]==(v[2],v[3],3,v[18])and v[10:12]==(0,0),'same actual opening slot/generation, no invented retry or fallback')
   need(acount[:2]==bcount[:2]and acount[2:10]==bcount[2:10]and acount[10:13]==bcount[10:13]and acount[15]==301,'no synthetic preparation/open/step/close/release accounting')
   lr=F(row,et,'lease');lt='li2_tf_same_page';vtx=F(lr,lt,'transfer');vt='li2_fetch_rx_view';nextpc=m['next']
   need(I(lr,lt,'phase')==3 and I(lr,lt,'origin_active')==1 and I(lr,lt,'slot')==v[2]and I(lr,lt,'owner_generation')==v[3]and
        I(lr,lt,'completed_event')==bcount[0]and I(vtx,vt,'phase')==4 and I(vtx,vt,'complete')==1 and I(vtx,vt,'result')==0 and
        I(vtx,vt,'before_sequence')==seq and I(vtx,vt,'pc')==nextpc and I(vtx,vt,'pid')==I(vtx,vt,'tid')==pid,'complete same-slot same-generation transfer receipt')
   active_opening=opening(lr,active_opening)
   nextseq=borrow(af,nextpc,1,1);need(nextseq==I(vtx,vt,'after_sequence')==seq+1,'actual singleton replacement followed by exact ref publication')
   n=I(vtx,vt,'length');need(n==min(15,4096-(nextpc&4095))and F(vtx,vt,'bytes')[:n]==bytes.fromhex(image['source_hex'])[nextpc-MAIN:nextpc-MAIN+n],'complete clipped fresh RX source window')
   maps_receipt(F(vtx,vt,'maps'))
   p=F(vtx,vt,'page');pt='li2_fetch_page';original_page=F(rq,'li2_step_request','pages')[:r.types['li2_step_page']['bytes']]
   need(tuple(I(p,pt,k)for k in('address','allocation','generation','offset'))==
        tuple(I(original_page,'li2_step_page',k)for k in('address','object','generation','offset'))and
        I(p,pt,'logical')==5 and I(p,pt,'closed_prot')==1 and I(p,pt,'backing')==1 and
        I(p,pt,'vma_first')<=I(p,pt,'address')and I(p,pt,'vma_end')>=I(p,pt,'address')+4096,
        'fresh observed mapping retains the exact original opening allocation/generation/page/source offset')
   backing=F(vtx,vt,'backing');bt='li2_fetch_backing'
   need(I(backing,bt,'retained_fd')>3 and I(backing,bt,'seals')&15==15 and I(backing,bt,'stat_result')==0 and
        I(backing,bt,'seals_observed')==I(backing,bt,'stat_observed')==1 and
        F(af,'li2_chain_fetch','backing')[:r.types[bt]['bytes']]==backing,
        'actual sealed backing queries retained in the committed singleton')
   need(F(lr,lt,'previous')==rq and F(lr,lt,'previous_fetch')==F(bf,'li2_chain_fetch','progress'),'exact predecessor request and held fetch')
   initialized(F(lr,lt,'previous_before'),saved);r.step_frame(F(pa,'li2_step_owner','before'),before)
   need(F(request(pa),'li2_step_request','decoded')==F(lr,lt,'next')and F(oa,'li2_tf_owner','classification')==F(lr,lt,'classification')and
        tuple(I(pa,'li2_step_owner',k)for k in('signal_number','signal_code','signal_errno','signal_address'))==(5,2,0,m['next']),
        'new request/classification and actual entry fields match the authenticated transfer')
   need(I(pa,'li2_step_owner','phase')==3 and I(pa,'li2_step_owner','trace_seen')==0 and I(pa,'li2_step_owner','in_handler')==0 and
        F(request(pa),'li2_step_request','pages')==F(rq,'li2_step_request','pages')and I(request(pa),'li2_step_request','page_count')==1 and
        I(pa,'li2_step_owner','session')==I(pb,'li2_step_owner','session')and F(pa,'li2_step_owner','hooks')==F(pb,'li2_step_owner','hooks')and
        not any(F(row,et,'release')+F(row,et,'query'))and I(oa,'li2_tf_owner','continuation_started')==0,'original actual permission owner; no invented CLOSED continuation')
   for k in('open_started','opened','open_result','open_sync','revoke_started','revoked','revoke_result','revoke_sync_started','revoke_sync'):
    need(F(pa,'li2_step_owner',k)==F(pb,'li2_step_owner',k),'all actual permission-call fields unchanged on transfer '+k)
   original=bytearray(ob);sf=r.types['li2_tf_owner']['fields']['step'];pt=r.types['li2_step_owner'];qt=r.types['li2_step_request']
   # These are the only fields assigned by the real completed transfer. Keep
   # every other owner byte, including hooks, opening results and padding.
   for key in('before','after','signal_number','signal_code','signal_errno','signal_address'):
    field=pt['fields'][key];a=sf['offset']+field['offset'];original[a:a+field['bytes']]=oa[a:a+field['bytes']]
   for key in('decoded','original_flags'):
    field=qt['fields'][key];a=sf['offset']+pt['fields']['request']['offset']+field['offset'];original[a:a+field['bytes']]=oa[a:a+field['bytes']]
   for key in('classification','actual_post_pc','actual_post_flags'):
    field=r.types['li2_tf_owner']['fields'][key];a=field['offset'];original[a:a+field['bytes']]=oa[a:a+field['bytes']]
   need(bytes(original)==oa,'complete same permission-owner bytes outside explicit authenticated transfer fields')
  else:
   closed+=1;need(I(pa,'li2_step_owner','phase')==5 and I(pa,'li2_step_owner','first_error')==0 and I(pa,'li2_step_owner','trace_seen')==1 and
        I(pa,'li2_step_owner','revoke_sync_started')==1 and I(pa,'li2_step_owner','revoke_sync')==0 and
        I(oa,'li2_tf_owner','continuation_started')==I(oa,'li2_tf_owner','continuation_complete')==1 and I(oa,'li2_tf_owner','continuation_result')==0,'actual old complete trace/revoke/sync/continuation route')
   for k in('revoke_started','revoked'):need(struct.unpack('<2I',F(pa,'li2_step_owner',k))==(1,int(pages==2)),'all original pages actually revoked')
   need(not any(F(pa,'li2_step_owner','revoke_result'))and F(request(pa),'li2_step_request','pages')==F(rq,'li2_step_request','pages'),'real final revoke keeps original opening page identity')
   need(tuple(I(F(row,et,'release'),'li2_chain_release',k)for k in('started','complete','result'))==(1,1,0),'actual complete release')
   need(borrow(af,m['pc'],pages,0)==seq and acount[3]==bcount[3]+1 and acount[8]>bcount[8]and acount[7]>bcount[7],'one actual old completed step, release and successor preparation')
   if active_opening is not None:
    lr=F(row,et,'lease');opening(lr,active_opening)
    need(I(lr,'li2_tf_same_page','phase')==5 and I(lr,'li2_tf_same_page','origin_active')==0,'original opening proof reaches its actual CLOSED receipt')
    active_opening=None
   nq=F(row,et,'query');need(tuple(I(nq,'li2_tf_continuation',k)for k in('pc','attempted','page_observed','complete','result'))==(m['next'],1,1,1,0),'actual closed continuation at exact next PC')
   nf=F(row,et,'next_fetch');need(I(F(nf,'li2_chain_fetch','ref'),'li2_fetch_ref','sequence')>seq,'strictly new ordinary borrow after final lease close')
   need(v[6]==(v[2]^1)and v[7]>0 and v[8]==(3 if v[5]==1 else 6)and v[9]==2 and v[12:14]==(1,1)and v[16]==m['next'],
        'actual ordinary successor preparation after the original owner closes')
   need(v[11]==(0 if v[5]==1 else 3 if c==2 and m['next']==BODY+36 else 4),'exact selected/old-NOP fallback; no invented domain refusal')
   retry=(c==4 and i==0)
   need(v[10]==int(retry),'only the actual clipped cross-page preparation retries')
   if retry:
    ff=F(row,et,'next_first_fetch');fd=F(row,et,'next_first_decoded');fr=F(row,et,'next_first_release')
    fs=borrow(ff,TAIL-2,1,0)
    need(I(ff,'li2_chain_fetch','length')==2 and I(fd,'li2_decoded','decode_status')==2 and I(fd,'li2_decoded','available')==2 and
         tuple(I(fr,'li2_chain_release',k)for k in('started','complete','result'))==(1,1,0)and
         fs>seq and I(F(nf,'li2_chain_fetch','ref'),'li2_fetch_ref','sequence')==fs+1 and I(nf,'li2_chain_fetch','page_count')==2,
         'real clipped first borrow/release precedes a new two-page borrow; no relaxed coverage')
   else:need(not any(F(row,et,'next_first_fetch')+F(row,et,'next_first_decoded')+F(row,et,'next_first_release')),'no invented cross-page retry')
   if lease and m['kind']not in('jump_branch','jump_guard')and pages==1 and (m['pc']>>12)==(m['next']>>12):
    lr=F(row,et,'lease');tx=F(lr,'li2_tf_same_page','transfer')
    need(I(tx,'li2_fetch_rx_view','phase')==5 and I(tx,'li2_fetch_rx_view','result')==0 and
         I(tx,'li2_fetch_rx_view','before_sequence')==seq and I(tx,'li2_fetch_rx_view','after_sequence')==0,
         'clean classification/domain miss cancels staging before the unchanged actual close')
   if v[5]==1:r.step_frame(F(row,et,'next_before'),after,after['greg'][17]&~0x100)
   need(after['greg'][17]==m['after'][1]|(0x100 if v[5]==1 else 0),'exact real old close/rearm TF transition')
  previous=dict(result=v[5],owner_after=oa,event=bcount[0])
 need(actual_transfers==(TRANSFERS[c]if lease and c<5 else 0)and closed==(GENERIC[c]-actual_transfers if c<5 else 0),'literal transfer versus real old-close counts')
 tc=F(data,r.rt,'terminal_chain');rs=F(data,r.rt,'terminal_rseq');rt='li2_rseq_state'
 need(I(rs,rt,'initialized')==I(rs,rt,'registered')==I(rs,rt,'held')==1 and I(rs,rt,'pid')==I(rs,rt,'tid')==pid and
      tuple(I(rs,rt,k)for k in('address','page','length','signature'))==(AREA,PAGE,32,0x53053053)and I(rs,rt,'epoch')==1 and
      I(rs,rt,'tls_attempted')==I(rs,rt,'tls_complete')==1 and I(rs,rt,'fs_result')==I(rs,rt,'gs_result')==0 and
      I(rs,rt,'fs_base')==DATA+2048 and I(rs,rt,'gs_base')==DATA+2304 and I(rs,rt,'phase')==3,
      'retained real registration and full actual TLS authority')
 page=F(data,r.rt,'terminal_page');page_ids(page);observed_cpus.append(page_ids(page)['cpu'])
 need(F(data,r.rt,'terminal_source')==bytes.fromhex(image['source_hex'])and all(f['page']==page for f in ends),'complete unchanged source and slot page')
 sender_uid=None
 if c<5:
  need(active_opening is None,'every observed transfer reaches an observed actual final close')
  need(h[11:13]==(0,0)and h[21]==0 and not any(h[32:50])and I(tc,'li2_tf_chain','pending')==I(tc,'li2_tf_chain','first_error')==0 and
       I(rs,rt,'first_error')==0 and F(data,r.rt,'terminal_data')==memory(image,False,page,model[-1]['after'],True),'actual successful terminal full data and no pending/failed owner')
  if lease:
   l=F(tc,'li2_tf_chain','lease');need(I(l,'li2_tf_same_page','origin_active')==0 and I(l,'li2_tf_same_page','transfers')>=actual_transfers and I(l,'li2_tf_same_page','closed_leases')>=int(actual_transfers>0),'all leases really closed, no fabricated release')
 else:
  if active_opening is not None:
   l=F(tc,'li2_tf_chain','lease');opening(l,active_opening)
   need(I(l,'li2_tf_same_page','phase')==2 and I(l,'li2_tf_same_page','origin_active')==1,'terminal failed prefix retains original cleanup authority without verified close')
  expected_error=1205 if c==5 else 903 if c in(6,7)else 7
  detail=307 if c==7 else 5 if c>=8 else 0
  need(h[11:13]==(expected_error,detail)and I(tc,'li2_tf_chain','first_error')==expected_error and I(tc,'li2_tf_chain','first_detail')==detail and
       h[43:47]==(1,0,1,1),'retained exact required operation failure plus independent actual R observation')
  maps_receipt(F(data,r.rt,'terminal_maps'),True)
  need(F(data,r.rt,'terminal_data')==memory(image,False,page,model[0]['after']),'failed effect did not write any application byte')
  need(h[32]==max(0,c-5)and h[33]==(2 if c==9 else 1 if c>=6 else 0),'exact finite failure seam selection')
  slot=F(tc,'li2_tf_chain','slots')[r.types['li2_tf_chain_slot']['bytes']*I(tc,'li2_tf_chain','active'):][:r.types['li2_tf_chain_slot']['bytes']]
  final_fetch=F(slot,'li2_tf_chain_slot','fetch');final_ref=F(final_fetch,'li2_chain_fetch','ref');progress=F(final_fetch,'li2_chain_fetch','progress')
  if c>=6:
   fv=F(data,r.rt,'fault_view');vt='li2_fetch_rx_view'
   need(I(fv,vt,'phase')==(3 if c==9 else 2)and I(fv,vt,'complete')==1 and I(fv,vt,'result')==0 and
        I(fv,vt,'before_sequence')==h[34]and I(fv,vt,'after_sequence')==0 and I(fv,vt,'pc')==BODY+35 and I(fv,vt,'length')==15 and
        F(fv,vt,'bytes')==bytes.fromhex(image['source_hex'])[BODY+35-MAIN:BODY+50-MAIN],
        'complete actual staged/committing prefix precedes the explicit control')
   maps_receipt(F(fv,vt,'maps'))
   need(I(progress,'li2_fetch_progress','held')==1 and I(final_ref,'li2_fetch_ref','sequence')==(h[34]+1 if c==6 else h[34])and
        I(progress,'li2_fetch_progress','sequence')==(h[34]+1 if c==9 else h[34])and
        I(progress,'li2_fetch_progress','first_error')==(307 if c==7 else 0),
        'exact occupied singleton/chain-ref prefix distinguishes stale before/after replacement and backing failure')
  if c==5:need(I(rs,rt,'first_error')==1205 and word(page,72)==0 and not any(h[32:43]),'unchanged rseq publication overlap guard')
  if c==6:need(h[36]==h[34]+1 and h[37:43]==(0,0,0,0,0,0),'explicit supplied stale ref, no invented actual syscall')
  if c==7:need(h[36]>3 and h[37:40]==(1,0,1)and h[41:43]==(0,0),'actual retained backing close result precedes authentication refusal')
  if c>=8:
   need(h[37]==1 and h[38]==h[39]==0 and h[41:43]==(1,5),'genuine nested delivery before tgkill returned; no returned-call claim')
   nested=r.frame(F(data,r.rt,'nested'),image,'nested');observed_cpus.append(page_ids(nested['page'])['cpu'])
   r.step_frame(F(slot,'li2_tf_chain_slot','unexpected'),nested)
   need(I(slot,'li2_tf_chain_slot','unexpected_frame_observed')==1 and I(slot,'li2_tf_chain_slot','unexpected_signal')==5 and
        I(slot,'li2_tf_chain_slot','unexpected_code')==(1<<32)-6,'actual owner retains the same genuine nested signal/frame')
   offset=h[47]-nested['h'][3];need(h[48:50]==(128,16)and offset==r.layout['offsets']['mask']+8 and offset+128<=r.ucn,'actual nested siginfo pointer/extent/typed sender alias')
   payload=bytearray(128);struct.pack_into('<iii',payload,0,5,0,-6);sender_uid=nested['h'][8]>>32
   struct.pack_into('<II',payload,16,pid,sender_uid)
   need(nested['h'][8]&0xffffffff==pid and nested['uc'][offset:offset+128]==payload,'whole genuine self-tgkill siginfo and actual sender PID, including padding')
  else:need(not any(h[47:50])and not any(F(data,r.rt,'nested')),'no fabricated nested signal')
  need(h[35]==301 if c>=6 else True,'original singleton remained held at injected prefix')
 return dict(case=c,exit_status=exit_status,operation_status='passed'if c<5 else'failed',events=GENERIC[c],transfers=actual_transfers,real_closes=closed,
             observed_cpus=observed_cpus,cpuid=cpuid,nested_sender_uid=sender_uid,accepted=True)

def output(data,image,native_lane,cpuid=None):
 need(len(data)==20480,'complete independently emitted data and rseq page')
 memory_bytes,page=data[:16384],data[16384:];ids=page_ids(page);state=states(image,cpuid)[-1]['after']
 need(memory_bytes==memory(image,native_lane,page,state,True),'every actual live GPR/flag/ZMM/K/selector/stack/data byte')
 return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),cpu=ids['cpu'],node=ids['node'],live_gprs=16,live_vectors=32,live_masks=8,flags=state[1])

def pair(nrec,grec,nout,gout,layouts,image,npid,gpid,cpu,lease=True):
 need(type(cpu)is int and cpu>=0 and npid!=gpid,'independent actual subjects and allocated CPU')
 n=native(nrec,layouts['native'],image,npid,0);g=gated(grec,layouts['gated'],image,gpid,0,lease)
 need(n['cpuid']==g['cpuid'],'same-input native CPUID results equal actual raw/committed gated results')
 no=output(nout,image,True,n['cpuid']);go=output(gout,image,False,g['cpuid'])
 need(all(x==cpu for x in n['observed_cpus']+g['observed_cpus']+[no['cpu'],go['cpu']]),'every actual frame and output CPU joins the allocated CPU')
 nr=Reader(nrec,layouts['native'],'lso_native_record');gr=Reader(grec,layouts['gated'],'lso_record')
 need(layouts['native']['offsets']==layouts['gated']['offsets']and layouts['native']['siginfo']==layouts['gated']['siginfo']and nr.ucn==gr.ucn,'same complete signal ABI')
 ns,gs=nr.types['lso_native_row'],gr.types['lso_native_row'];nb=nr.field(nrec,nr.rt,'rows');gb=gr.field(grec,gr.rt,'endpoints')
 for i in range(2):
  nf=nr.frame(nr.field(nb[i*ns['bytes']:(i+1)*ns['bytes']],ns,'before'),image);gf=gr.frame(gr.field(gb[i*gs['bytes']:(i+1)*gs['bytes']],gs,'before'),image)
  need(nf['fp']==gf['fp'],'whole native/gated FP bytes without flag/component exemptions')
  nu,gu=bytearray(nf['uc']),bytearray(gf['uc'])
  for k in('stack_sp','stack_size','fp_pointer'):put(nu,nr.layout['offsets'][k],0);put(gu,gr.layout['offsets'][k],0)
  need(nu==gu,'all remaining raw UC bytes exact after separately validated actual pointer extents')
  nd,gd=bytearray(nf['data']),bytearray(gf['data']);put(nd,16,0)
  np,gp=bytearray(nf['page']),bytearray(gf['page']);ni,gi=page_ids(np),page_ids(gp);need(ni['cpu']==gi['cpu']and ni['node']==gi['node'],'actual singleton CPU/node identities')
  for b,at in((nd,8192+88),(gd,8192+88),(np,88),(gp,88)):struct.pack_into('<I',b,at,0)
  need(nd==gd and np==gp,'whole lane memory/page with only independently typed mode/mm_cid differences')
 return dict(case=image['case'],successful_pair=1,native=n,gated=g,native_output=no,gated_output=go)
