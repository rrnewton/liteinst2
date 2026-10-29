"""Fixed N=1/256 interval evidence; endpoint FP is full, TRACE FP is not.

The enclosing driver authenticates source/build/ELF/layout inputs and separately
qualifies both release profiles. No absence of a record selects a weaker lane.
"""
import hashlib,importlib.util,json,struct
from pathlib import Path
from page_selected import ENV,need
S=importlib.util.spec_from_file_location('tfi_existing_full_state',Path(__file__).resolve().parent.parent/'tf_same_page/check.py')
old=importlib.util.module_from_spec(S);S.loader.exec_module(old)
S=importlib.util.spec_from_file_location('tfi_existing_full_reports',Path(__file__).resolve().parent.parent/'tf_same_page/reports.py')
reports=importlib.util.module_from_spec(S);S.loader.exec_module(reports)
MAIN,WAIT,BODY,GUARD,DATA,PAGE,AREA,WORD=old.MAIN,old.BODY,old.TAIL,old.GUARD,old.DATA,old.PAGE,old.AREA,old.WORD
READ=WAIT+4094;MAGIC=0x314c415652495446;MASK64=(1<<64)-1
GREG,VECTORS,MASKS,q,word,put,page_ids=old.GREG,old.VECTORS,old.MASKS,old.q,old.word,old.put,old.page_ids
SELECTED_MASK=old.old.old.SELECTED_MASK
PROFILES={'native-reference':'reference','gated-observed':'gated','native-timing':'native','gated-timing':'gated'}

def add64(a,b,flags):
 """Independent architectural ADD carry/parity/AF/ZF/SF/OF calculation."""
 need(all(type(v)is int and 0<=v<=MASK64 for v in(a,b,flags)),'typed 64-bit arithmetic inputs')
 wide=a+b;v=wide&MASK64;f=flags&~0x8d5
 f|=int(wide>MASK64)|int((v&255).bit_count()%2==0)<<2|((a^b^v)&16)
 f|=int(v==0)<<6|((v>>63)&1)<<7|int(bool((~(a^b)&(a^v))&(1<<63)))<<11
 return v,f

def fixed(count,go,notify,cpu):
 need(type(count)is int and count in(1,256)and all(type(v)is int and 3<v<=1000000 for v in(go,notify))and go!=notify and type(cpu)is int and cpu>=0,'fixed count and actual separately bound pipe/CPU inputs')

def states(image,go):
 n=image['count'];g=[0x1122334455667700+i for i in range(16)]
 g[0]=1;g[1]=BODY;g[2]=1;g[4]=DATA+16320;g[6]=DATA+56;g[7]=go;g[11]=0x646
 result=[(tuple(g),0x646)]
 for _ in range(n):g[8],f=add64(g[8],1,result[-1][1]);result.append((tuple(g),f))
 need(result[-1][1]==(0x606 if n==1 else 0x602),'independent fixed final ADD flags')
 return result

def memory(image,mode,go,notify,page,completed=False,before_read=False):
 need(mode in('gated','reference','native'),'literal application mode');page_ids(page)
 b=bytearray.fromhex(image['data_hex'])
 for at,value in((16,{'gated':0,'reference':1,'native':2}[mode]),(24,1),(32,0),(56,0 if before_read else 0x47),(80,go),(88,notify)):put(b,at,value)
 b[8192:12288]=page;put(b,16312,0xed7)
 if completed:
  g,f=states(image,go)[-1]
  for at,value in((40,1),(64,DATA+2048),(72,DATA+2304),(6336,f),(16312,f)):put(b,at,value)
  b[4096:6144]=VECTORS;b[6144:6208]=MASKS;b[6208:6336]=struct.pack('<16Q',*g)
  b[6344:6356]=struct.pack('<6H',0x33,0x2b,0,0,0,0)
 return bytes(b)

def elf(data,interpreter,count,native_policy):
 need(type(count)is int and count in(1,256)and type(data)is bytes and len(data)>=64,'fixed complete interval ELF')
 h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
 need(h[0][:7]==b'\x7fELF\x02\x01\x01'and h[1:4]==(2,62,1)and h[4]==MAIN and h[8:10]==(64,56)and h[11]==64,'actual original-PC ET_EXEC')
 def extent(a,n):
  need(0<=a<=len(data)and 0<=n<=len(data)-a,'complete actual ELF extent');return data[a:a+n]
 ph=[struct.unpack('<IIQQQQQQ',extent(h[5]+56*i,56))for i in range(h[10])];loads=[p for p in ph if p[0]==1]
 need(len(loads)==3 and [p[1]for p in loads]==[4,5,6]and loads[0][2:4]==(0,MAIN-4096)and loads[0][5]<=4096 and loads[1][2:4]==(4096,MAIN)and loads[1][5:7]==(24576,24576)and loads[2][3]==DATA and loads[2][5]>=16384 and all(p[7]==4096 and p[5]<=p[6]for p in loads)and not any(p[0]==7 for p in ph),'exact immutable code/data domains and no TLS')
 ip=[p for p in ph if p[0]==3];need(len(ip)==1 and extent(ip[0][2],ip[0][5])==str(interpreter).encode()+b'\0','actual interpreter filename')
 ss=[struct.unpack('<IIQQQQIIQQ',extent(h[6]+64*i,64))for i in range(h[12])];tables=[s for s in ss if s[1]==2]
 need(not any(s[1]in(4,9)and s[5]for s in ss)and len(tables)==1 and tables[0][9]==24,'no code relocation and one actual symbol table')
 t=tables[0];strings=ss[t[6]];names=extent(strings[4],strings[5]);symbols={}
 for at in range(t[4],t[4]+t[5],24):
  n,info,other,index,value,size=struct.unpack('<IBBHQQ',extent(at,24))
  if n and info&15!=4:
   name=names[n:names.index(b'\0',n)].decode();need(name not in symbols,'unique actual named symbol');symbols[name]=value
 def read(a,n):
  p=next((p for p in loads if p[3]<=a and a+n<=p[3]+p[5]),None);need(p is not None,'actual file-backed range');return extent(p[2]+a-p[3],n)
 expected=dict(_start=MAIN,rn_seed=MAIN+4096,rn_body=WAIT,tfi_wait=WAIT,tfi_wait_tail=READ-1,tfi_read=READ,rn_tail=BODY,rn_program=BODY,tfi_body_end=BODY+4*count,rn_guard=GUARD,rn_guard_write=GUARD+1,rn_data=DATA,rn_data_end=DATA+16384,rn_case=DATA+8,rn_mode=DATA+16,rn_active=DATA+24,rn_registration_result=DATA+32,rn_rounds=DATA+40,tfi_control=DATA+48,tfi_go_byte=DATA+56,rn_final_fs=DATA+64,rn_final_gs=DATA+72,tfi_go_fd=DATA+80,tfi_notify_fd=DATA+88,rn_store=DATA+128,rn_descriptor=DATA+256,rn_vectors=DATA+512,rn_masks=DATA+2560,rn_live_vectors=DATA+4096,rn_live_masks=DATA+6144,rn_live_gpr=DATA+6208,rn_live_flags=DATA+6336,rn_live_selectors=DATA+6344,rn_rseq_initial=DATA+8192,rn_stack_top=DATA+16320)
 need(all(symbols[k]==v for k,v in expected.items()),'all literal entry/body/record/pipe symbols')
 source,initial=read(MAIN,24576),read(DATA,16384)
 seed=bytearray(16384);struct.pack_into('<12Q',seed,0,old.old.old.MAGIC,count,0,0,MASK64,0,0,0,0,0,0,0);seed[512:2624]=VECTORS+MASKS;seed[12288:]=b'\xa5'*4096
 need(initial==seed,'whole fixed initial data including unused bytes and stack canary')
 def rip(pc,opcode,target):
  need(read(pc,len(opcode))==opcode and pc+len(opcode)+4+struct.unpack('<i',read(pc+len(opcode),4))[0]==target,'actual literal RIP-relative operand')
 rip(WAIT,b'\x48\x8b\x3d',DATA+88);rip(WAIT+7,b'\x48\x8d\x35',symbols['tfi_ready'])
 need(read(WAIT+14,3)==b'\x48\x83\x3d'and WAIT+22+struct.unpack('<i',read(WAIT+17,4))[0]==DATA+48 and read(WAIT+21,3)==b'\x01\x75\x07','actual normal READY selection')
 rip(WAIT+24,b'\x48\x8d\x35',symbols['tfi_bad_ready'])
 need(read(WAIT+31,12)==bytes.fromhex('ba08000000b8010000000f05')and read(WAIT+43,6)==bytes.fromhex('4883f8080f85')and WAIT+53+struct.unpack('<i',read(WAIT+49,4))[0]==symbols['rn_fail'],'actual READY write and exact-result branch')
 rip(WAIT+53,b'\x48\x8b\x3d',DATA+80);rip(WAIT+60,b'\x48\x8d\x35',DATA+56)
 need(read(WAIT+67,10)==bytes.fromhex('ba01000000b800000000')and read(WAIT+77,1)==b'\xe9'and WAIT+82+struct.unpack('<i',read(WAIT+78,4))[0]==READ-1 and read(WAIT+82,4093-82)==b'\x90'*(4093-82)and read(READ-1,3)==b'\x90\x0f\x05','real old NOP then read ending precisely at BODY; no destination prefetch')
 end=BODY+4*count;need(read(BODY,4*count)==bytes.fromhex('4983c001')*count and read(end,2)==b'\x90\xe9'and end+6+struct.unpack('<i',read(end+2,4))[0]==GUARD and read(end+6,3072-(end+6-BODY))==b'\x90'*(3072-(end+6-BODY))and read(BODY+3072,2)==b'\x0f\xa2'and read(BODY+3074,1022)==b'\x90'*1022,'literal N additions, old NOP close and direct GUARD branch, untouched barrier')
 need(read(GUARD,2)==b'\x90\xe9'and GUARD+6+struct.unpack('<i',read(GUARD+2,4))[0]==symbols['rn_capture']and read(GUARD+3072,2)==b'\x0f\xa2','genuine old-NOP endpoint and full capture target')
 need(read(symbols['tfi_ready'],8)==b'TFI-RDY\n'and read(symbols['tfi_bad_ready'],8)==b'TFI-BAD\n'and read(symbols['tfi_done'],16)==b'TFI-DON\nTFI-DON\n'and read(symbols['rn_setup_syscall'],2)==b'\x0f\x05'and read(symbols['rn_restorer'],9)==bytes.fromhex('b80f0000000f050f0b'),'actual protocol, registration and native signal return')
 need(native_policy(read(MAIN+4096-14,4096+28))==0 and all(native_policy(read(p,4096))!=0 for p in(MAIN,WAIT,BODY,GUARD)),'unchanged whole helper/halos and genuine dirty WAIT/BODY/GUARD; no exemption')
 interp=interpreter.read_bytes();ih=struct.unpack_from('<16sHHIQQQIHHHHHH',interp);entry=b'\x0f\xa2\x48\xb8'+struct.pack('<Q',MAIN)+b'\xff\xe0'
 need(len(interp)==8192 and ih[1:4]==(3,62,1)and ih[4]==4096 and interp[4096:4096+len(entry)]==entry and not any(interp[4096+len(entry):]),'actual original first-interpreter CPUID/main handoff')
 return dict(count=count,symbols=symbols,entry=MAIN,source_hex=source.hex(),data_hex=initial.hex(),elf_bytes=len(data),elf_sha256=hashlib.sha256(data).hexdigest(),interpreter_sha256=hashlib.sha256(interp).hexdigest())

class Reader(old.Reader):
 def __init__(self,data,layout,record):
  need(type(data)is bytes and type(layout)is dict and set(layout)=={'types','record','offsets','siginfo','uc_bytes'}and layout['record']==record,'exact actual layout schema and record lane')
  self.data,self.layout,self.types=data,layout,layout['types'];self.rt=self.types[record];self.ft=self.types['rn_frame'];self.ucn=layout['uc_bytes'];self.go=layout['offsets']['greg'];self.fo=layout['offsets']['fp_pointer']
  names={'rn_frame','tfi_endpoint',record}
  if record=='tfi_record':names.update('tfi_event tfi_trace_frame tfi_owner li2_tf_chain li2_tf_trace_entry li2_tf_chain_slot li2_tf_owner li2_step_owner li2_step_request li2_step_page li2_step_frame li2_chain_fetch li2_chain_release li2_tf_continuation li2_tf_same_page li2_fetch_rx_view li2_fetch_ref li2_fetch_progress li2_fetch_page li2_fetch_backing stat li2_fetch_map_progress li2_maps_observation li2_lifecycle_page_view li2_rseq_state li2_rseq_transaction li2_rseq_data li2_write_footprint li2_decoded li2_tf_classification'.split())
  need(set(self.types)==names,'exact source-defined emitted layout type inventory')
  need(type(self.ucn)is int and 0<self.ucn<=2048 and len(data)==self.rt['bytes']<16<<20 and layout['offsets']==dict(greg=40,fp_pointer=224,mask=296,stack_sp=16,stack_flags=24,stack_size=32),'exact complete native x86-64 UC/DWARF layout')
  need(layout['siginfo']==dict(bytes=128,offsets=dict(si_signo=0,si_errno=4,si_code=8,si_addr=16,si_pid=16,si_uid=20),widths=dict(si_signo=4,si_errno=4,si_code=4,si_addr=8,si_pid=4,si_uid=4)),'actual complete signal ABI')
  z=lambda n:self.types[n]['bytes'];frame=512+2048+65536+24576+16384+4096
  forms={'rn_frame':dict(h=512,uc=2048,fp=65536,source=24576,data=16384,rseq=4096),'tfi_endpoint':dict(h=256,before=frame,after=frame)}
  if record=='tfi_native_record':forms[record]=dict(h=512,xstate=128,endpoints=2*z('tfi_endpoint'))
  else:
   need(record=='tfi_record','literal gated record type')
   forms['tfi_trace_frame']=dict(h=128,greg=184,mask=8,siginfo=128)
   forms['tfi_owner']=dict(h=256,request=z('li2_step_request'),ref=z('li2_fetch_ref'),progress=z('li2_fetch_progress'),release=z('li2_chain_release'))
   forms['tfi_event']=dict(h=128,counts_before=128,counts_after=128,before=z('tfi_trace_frame'),after=z('tfi_trace_frame'),owner_before=z('tfi_owner'),owner_after=z('tfi_owner'),transfer=z('li2_fetch_rx_view'),rseq_before=z('li2_rseq_state'),rseq_after=z('li2_rseq_state'))
   forms['stat']=dict(st_dev=8,st_ino=8,st_nlink=8,st_mode=4,st_uid=4,st_gid=4,__pad0=4,st_rdev=8,st_size=8,st_blksize=8,st_blocks=8,st_atim=16,st_mtim=16,st_ctim=16,__glibc_reserved=24)
   forms[record]=dict(h=512,xstate=128,hardware=56,endpoints=2*z('tfi_endpoint'),read=z('tfi_endpoint'),read_decoded=z('li2_decoded'),read_fetch=z('li2_chain_fetch'),read_released=z('li2_fetch_progress'),read_maps=z('li2_fetch_map_progress'),read_page=z('li2_lifecycle_page_view'),read_rseq=z('li2_rseq_state'),opening=z('li2_tf_chain_slot'),closing=z('li2_tf_chain_slot'),body_lease_before=z('li2_tf_same_page'),closed_lease=z('li2_tf_same_page'),opened=frame,last_before=frame,last_after=frame,events=256*z('tfi_event'),terminal_chain=z('li2_tf_chain'),terminal_rseq=z('li2_rseq_state'),terminal_source=24576,terminal_data=16384,terminal_page=4096)
  for name,shape in self.types.items():
   need(type(shape)is dict and set(shape)=={'bytes','fields'}and type(shape['bytes'])is int and shape['bytes']>0,'actual typed shape')
   last=0
   for f in sorted(shape['fields'].values(),key=lambda f:f['offset']):
    need(set(f)=={'offset','bytes'}and type(f['offset'])is type(f['bytes'])is int and last<=f['offset']and 0<f['bytes']<=shape['bytes']-f['offset'],'disjoint complete actual typed fields');last=f['offset']+f['bytes']
  for name,fields in forms.items():
   shape=self.types[name];need(list(sorted(shape['fields'],key=lambda k:shape['fields'][k]['offset']))==list(fields)and all(shape['fields'][k]['bytes']==n for k,n in fields.items()),'complete source-defined observation fields '+name)
  need(self.ft['bytes']==frame and all(self.ft['fields'][k]['offset']==sum(list(forms['rn_frame'].values())[:i])for i,k in enumerate(forms['rn_frame'])),'exact complete original raw frame')
  if record=='tfi_record':need(z('stat')==144 and all(self.types['stat']['fields'][k]['offset']==sum(list(forms['stat'].values())[:i])for i,k in enumerate(forms['stat'])),'complete fixed x86-64 stat layout and every field extent')
  self.padding_tree(data,record)
 def padding(self,b,t):
  t=self.types[t]if isinstance(t,str)else t;at=0
  for f in sorted(t['fields'].values(),key=lambda f:f['offset']):
   need(not any(b[at:f['offset']]),'zero initialized observation padding');at=f['offset']+f['bytes']
  need(not any(b[at:t['bytes']]),'zero initialized observation trailing padding')
 def padding_tree(self,b,t):
  """Only the fixed retained C children; raw kernel/source arrays stay exact."""
  self.padding(b,t)
  children={
   'tfi_native_record':dict(endpoints='tfi_endpoint'),
   'tfi_record':dict(endpoints='tfi_endpoint',read='tfi_endpoint',read_decoded='li2_decoded',read_fetch='li2_chain_fetch',read_released='li2_fetch_progress',read_maps='li2_fetch_map_progress',read_page='li2_lifecycle_page_view',read_rseq='li2_rseq_state',opening='li2_tf_chain_slot',closing='li2_tf_chain_slot',body_lease_before='li2_tf_same_page',closed_lease='li2_tf_same_page',opened='rn_frame',last_before='rn_frame',last_after='rn_frame',events='tfi_event',terminal_chain='li2_tf_chain',terminal_rseq='li2_rseq_state'),
   'tfi_endpoint':dict(before='rn_frame',after='rn_frame'),
   'tfi_event':dict(before='tfi_trace_frame',after='tfi_trace_frame',owner_before='tfi_owner',owner_after='tfi_owner',transfer='li2_fetch_rx_view',rseq_before='li2_rseq_state',rseq_after='li2_rseq_state'),
   'tfi_owner':dict(request='li2_step_request',ref='li2_fetch_ref',progress='li2_fetch_progress',release='li2_chain_release'),
   'li2_tf_chain':dict(entry='li2_tf_trace_entry',slots='li2_tf_chain_slot',lease='li2_tf_same_page'),
   'li2_tf_chain_slot':dict(owner='li2_tf_owner',decoded='li2_decoded',first_decoded='li2_decoded',descriptive_classification='li2_tf_classification',fetch='li2_chain_fetch',first_fetch='li2_chain_fetch',release='li2_chain_release',first_release='li2_chain_release',query='li2_tf_continuation',unexpected='li2_step_frame'),
   'li2_tf_owner':dict(step='li2_step_owner',classification='li2_tf_classification'),
   'li2_step_owner':dict(request='li2_step_request',before='li2_step_frame',after='li2_step_frame'),
   'li2_step_request':dict(decoded='li2_decoded',pages='li2_step_page'),
   'li2_tf_same_page':dict(opening='li2_step_request',previous='li2_step_request',opening_frame='li2_step_frame',previous_before='li2_step_frame',previous_fetch='li2_fetch_progress',transfer='li2_fetch_rx_view',next='li2_decoded',classification='li2_tf_classification'),
   'li2_chain_fetch':dict(ref='li2_fetch_ref',progress='li2_fetch_progress',pages='li2_fetch_page',backing='li2_fetch_backing',last_backing='li2_fetch_backing'),
   'li2_fetch_progress':dict(preparation='li2_fetch_map_progress',validation='li2_fetch_map_progress'),
   'li2_fetch_backing':dict(stat='stat'),
   'li2_fetch_map_progress':dict(observation='li2_maps_observation'),
   'li2_fetch_rx_view':dict(page='li2_fetch_page',backing='li2_fetch_backing',maps='li2_fetch_map_progress'),
   'li2_tf_continuation':dict(page='li2_fetch_page',backing='li2_fetch_backing',maps='li2_fetch_map_progress'),
   'li2_rseq_state':dict(last_footprint='li2_write_footprint',data='li2_rseq_data',transaction='li2_rseq_transaction'),
   'li2_rseq_transaction':dict(before='li2_rseq_data',after='li2_rseq_data'),
   'li2_rseq_data':dict(maps='li2_fetch_map_progress'),
  }.get(t,{})
  for field,child in children.items():
   raw=self.field(b,t,field);n=self.types[child]['bytes'];need(len(raw)>0 and len(raw)%n==0,'complete fixed retained child/array extent')
   for at in range(0,len(raw),n):self.padding_tree(raw[at:at+n],child)
 def full(self,b,image,kind):
  h=q(self.field(b,self.ft,'h'));uc=self.field(b,self.ft,'uc');fp=self.field(b,self.ft,'fp')
  need(h[:2]==(1,self.ucn)and 580<=h[2]<=65536 and h[3]>0 and h[9:12]==(0,0,0)and not any(h[12:])and not any(uc[self.ucn:])and not any(fp[h[2]:]),'whole actual frame and clean unused bytes')
  need(struct.unpack_from('<II',fp,464)==(0x46505853,h[2])and 576<=struct.unpack_from('<I',fp,480)[0]<=h[2]-4 and struct.unpack_from('<I',fp,h[2]-4)[0]==0x46505845 and word(fp,520)==0,'full standard signal XSAVE envelope')
  g=q(uc[self.go:self.go+184]);need(g[18]==0x002b000000000033,'complete packed CS/SS and reserved zero FS/GS')
  if kind in('nx','armed','commit'):
   need(h[4:8]==(11,11,2,0)and g[19:21]==(21,14)and g[22]==h[8],'genuine exact fetch-fault tuple')
   need(g[17]&0x10100=={'nx':0x10000,'armed':0x10100,'commit':0}[kind],'exact real owner RF/TF state')
  else:
   need(kind in('trace','returned')and h[4:8]==(5,5,2,0)and g[19:21]==(0,1)and g[16]==h[8]and g[17]&0x10100==(0x100 if kind=='trace'else 0),'genuine actual TRACE and exact returned TF transition')
  source,memory_bytes,page=(self.field(b,self.ft,k)for k in('source','data','rseq'))
  need(source==bytes.fromhex(image['source_hex']),'whole immutable actual source');page_ids(page)
  return dict(h=h,uc=uc,fp=fp,data=memory_bytes,page=page,greg=g,raw=b)
 def compact(self,b,state,pc,tf,lo,cap,fp_bytes):
  self.padding(b,'tfi_trace_frame');h=q(self.field(b,'tfi_trace_frame','h'));g=q(self.field(b,'tfi_trace_frame','greg'));mask=self.integer(b,'tfi_trace_frame','mask')
  need(h[:6]==(1,5,5,2,0,pc)and h[6]==h[7]+self.layout['offsets']['mask']+8 and h[9:16]==(fp_bytes,128,16,0,0,0,0)and lo<=h[7]<=lo+cap-self.ucn and lo<=h[8]<=lo+cap-fp_bytes and h[8]%16==0,'complete genuine compact TRACE tuple/actual signal and FP addresses')
  need(g[16]==pc and g[17]==state[1]|tf and g[18]==0x002b000000000033 and g[19:23]==(0,1,SELECTED_MASK,BODY)and mask==SELECTED_MASK and tuple(g[i]for i in GREG)==state[0],'all retained TRACE GPR/PC/flags/mask/trap fields')
  si=bytearray(128);struct.pack_into('<iii',si,0,5,0,2);put(si,16,pc)
  need(self.field(b,'tfi_trace_frame','siginfo')==si,'complete actual TRACE siginfo including padding')
  return dict(h=h,greg=g,raw=b)
 def decoded(self,b,image,pc,length,available,code,kind=0,disposition=0):
  expected=struct.pack('<QQ10I16s',pc,pc+length,1,0,code,kind,16,0,disposition,available,length,0,bytes.fromhex(image['source_hex'])[pc-MAIN:pc-MAIN+available].ljust(16,b'\0'))
  need(b==expected,'entire original decoded ABI/code/source/PC/nextPC/length')
 def literal(self,f,state,pc,extra,components):
  need(tuple(f['greg'][i]for i in GREG)==state[0]and f['greg'][16:18]==(pc,state[1]|extra),'complete independent literal GPR/PC/flags')
  need(word(f['fp'],512)&0xe7==0xe7 and all(o+n<=f['h'][2]-4 for o,n in components.values())and old.vector_bytes(f['fp'],components)==VECTORS,'all32 actual complete ZMM values')
  at,n=components[5];need(f['fp'][at:at+n]==MASKS,'all8 complete actual K masks')
 def maps(self,b,direct=False):
  I=self.integer;mt='li2_fetch_map_progress';o=self.field(b,mt,'observation');ot='li2_maps_observation'
  self.padding(b,mt);self.padding(o,ot)
  need(I(b,mt,'fd')>3 and I(b,mt,'last_read')==I(b,mt,'close_result')==0 and 0<I(b,mt,'bytes')<=256*1024 and 0<I(b,mt,'rows')<=2048 and all(I(b,mt,k)==1 for k in('opened','close_started','closed')),'actual complete maps acquisition/EOF/close')
  if direct:need(not any(o),'direct fresh read-return observation does not invent scoped reuse')
  else:need(all(I(o,ot,k)>0 for k in('acquisition_id','handler_id','mutation_epoch'))and I(o,ot,'kind')in(1,2)and I(o,ot,'io_performed')==int(I(o,ot,'kind')==1),'actual valid acquisition/handler/mutation receipt')
 def progress(self,b,ref,pc,n,held,fresh=False):
  I=self.integer;t='li2_fetch_progress';seq=I(ref,'li2_fetch_ref','sequence')
  self.padding(b,t);self.padding(ref,'li2_fetch_ref')
  need(type(fresh)is bool and I(ref,'li2_fetch_ref','owner')>0 and seq>0 and I(b,t,'sequence')==seq and tuple(I(b,t,k)for k in('held','complete','first_error','identity_observed','first_detail','pages_copied','bytes_copied'))==(held,1,0,1,0,1,n)and I(b,t,'last_backing_page')==0,'actual held/released singleton and complete copied source')
  self.maps(self.field(b,t,'preparation'))
  if fresh:need(held==1 and I(b,t,'validation_calls')==I(b,t,'last_backing_observed')==0 and not any(self.field(b,t,'validation')),'exact new prepare/transfer progress before any later validation')
  else:
   need(I(b,t,'validation_calls')>0 and I(b,t,'last_backing_observed')==1,'actual positive original/released validation prefix');self.maps(self.field(b,t,'validation'))
  return seq
 def backing(self,b,carrier,anchor=None):
  import stat
  I,F=self.integer,self.field;t='li2_fetch_backing';self.padding(b,t);s=F(b,t,'stat');self.padding(s,'stat')
  need(type(carrier)is dict and set(carrier)=={'bytes','sha256'}and type(carrier['bytes'])is int and carrier['bytes']>0 and type(carrier['sha256'])is str and len(carrier['sha256'])==64 and bytes.fromhex(carrier['sha256']).hex()==carrier['sha256'],'independently source/command-bound complete carrier identity')
  need(I(b,t,'retained_fd')>=200 and I(b,t,'seals')==15 and tuple(I(b,t,k)for k in('stat_result','seals_observed','stat_observed'))==(0,1,1),'actual retained sealed descriptor and complete F_GET_SEALS/fstat')
  # Linux shmem uses i_blocksize (PAGE_SIZE) unless huge policy selects
  # HPAGE_PMD_SIZE. This fixed x86-64/4KiB profile admits only those two
  # source-defined values; the complete first stat still anchors every byte.
  need(I(s,'stat','st_dev')>0 and I(s,'stat','st_ino')>0 and I(s,'stat','st_nlink')==0 and stat.S_ISREG(I(s,'stat','st_mode'))and not I(s,'stat','st_mode')&0o7000 and I(s,'stat','st_rdev')==0 and I(s,'stat','st_size')==carrier['bytes']and I(s,'stat','st_blksize')in(4096,1<<21) and 0<I(s,'stat','st_blocks')<=((carrier['bytes']+4095)//4096)*8 and not any(F(s,'stat','__pad0')+F(s,'stat','__glibc_reserved')),'whole actual memfd stat, exact carrier extent and clean reserved fields')
  for key in('st_atim','st_mtim','st_ctim'):
   sec,nsec=struct.unpack('<qq',F(s,'stat',key));need(sec>=0 and 0<=nsec<10**9,'complete typed actual stat timestamp')
  actual=(I(b,t,'retained_fd'),s)
  if anchor is not None:need(actual==anchor,'every retained stat byte and descriptor equals the first actual same-object observation')
  return actual
 def page(self,b,address,backing,identity=None):
  import os
  I=self.integer;t='li2_fetch_page';self.padding(b,t);s=backing[1];dev=I(s,'stat','st_dev');ino=I(s,'stat','st_ino')
  v=tuple(I(b,t,k)for k in('address','allocation','generation','offset','initial_extent','backing','object','logical','closed_prot'))
  need(v[0]==address and v[1]>0 and v[2]>0 and v[3:6]==(4096+address-MAIN,0,1)and v[6]<34 and v[7:]==(5,1),'actual initial-image page identity and exact source offset; no loader-envelope extent')
  first,end,major,minor,inode,offset=(I(b,t,k)for k in('vma_first','vma_end','vma_major','vma_minor','vma_inode','vma_offset'))
  need(MAIN-4096<=first<=address and address+4096<=end<=MAIN+24576 and first%4096==end%4096==0 and (major,minor,inode)==(os.major(dev),os.minor(dev),ino)and offset==4096+first-MAIN and offset+address-first==v[3],'whole actual maps row geometry and exact sealed fstat identity/offset')
  key=(v[1],v[2],v[6])
  if identity is not None:need(key==identity,'same actual initial-main allocation/generation/object across pages')
  return key
 def fetch(self,b,image,pc,n,pid,held,anchor=None,identity=None,fresh=False):
  I,F=self.integer,self.field;t='li2_chain_fetch';self.padding(b,t);ref=F(b,t,'ref');pr=F(b,t,'progress');seq=self.progress(pr,ref,pc,n,held,fresh)
  need(tuple(I(b,t,k)for k in('pc','length','page_count','pid','tid','identity_observed'))==(pc,n,1,pid,pid,1)and F(b,t,'bytes')==bytes.fromhex(image['source_hex'])[pc-MAIN:pc-MAIN+n].ljust(15,b'\0'),'whole exact singleton source window and process identity')
  pages=F(b,t,'pages');backs=F(b,t,'backing');pn=self.types['li2_fetch_page']['bytes'];bn=self.types['li2_fetch_backing']['bytes']
  need(len(pages)==2*pn and len(backs)==2*bn and not any(pages[pn:]+backs[bn:]),'all unused source page/backing bytes remain zero')
  actual=self.backing(backs[:bn],image['backing'],anchor);key=self.page(pages[:pn],pc&~4095,actual,identity)
  last=F(b,t,'last_backing')
  if fresh:need(not any(last),'fresh original acquisition has no invented last-validation backing')
  else:self.backing(last,image['backing'],actual)
  return seq,actual,key
 def step_frame(self,b,f,flags=None):
  super().step_frame(b,f,flags);self.padding(b,'li2_step_frame');n=self.integer(b,'li2_step_frame','fp_bytes')
  need(not any(self.field(b,'li2_step_frame','fp')[n:]),'complete initialized stored FP plus zero unused frame capacity')
 def compact_step(self,b,compact,baseline):
  I,F=self.integer,self.field;t='li2_step_frame';self.padding(b,t);h=q(F(compact,'tfi_trace_frame','h'))
  need(F(b,t,'greg')==F(compact,'tfi_trace_frame','greg')and I(b,t,'mask')==I(compact,'tfi_trace_frame','mask')and I(b,t,'fp_address')==h[8]and I(b,t,'fp_bytes')==I(b,t,'initialized')==h[9]and F(b,t,'fp')==baseline,'entire retained predecessor frame joins its genuine compact TRACE metadata and full endpoint FP baseline')

def endpoint(r,b,image,index,mode,go,notify,cpu,components,lo,cap):
 r.padding(b,'tfi_endpoint');h=q(r.field(b,'tfi_endpoint','h'));raw=r.field(b,'tfi_endpoint','before')
 need(raw==r.field(b,'tfi_endpoint','after'),'every local endpoint UC/FP/source/data/page byte preserved')
 f=r.full(raw,image,'nx');pc=GUARD if index else BODY
 need(h[:5]==(1,index,pc,pc,1)and not any(h[5:8]+h[12:24]+h[28:]),'complete literal endpoint and unused fields')
 need(h[8:12]==((pc,4096,5,0)if mode=='reference'else(0,0,0,0)),'actual native mprotect versus gated native-fetch READY; no invented permission call')
 r.siginfo_alias(b,'tfi_endpoint',f);r.envelope(f,lo,cap,mode=='reference')
 r.literal(f,states(image,go)[-1 if index else 0],pc,0x10000,components)
 need(f['data']==memory(image,mode,go,notify,f['page'])and page_ids(f['page'])['cpu']==cpu,'whole endpoint memory/stack and reserved CPU')
 return f

def _native(data,layout,image,pid,exit_status,go,notify,cpu):
 fixed(image['count'],go,notify,cpu);need(type(pid)is int and pid>0 and type(exit_status)is int and exit_status==0,'actual reaped successful native reference')
 r=Reader(data,layout,'tfi_native_record');F=r.field;h=q(F(data,r.rt,'h'))
 need(h[:6]==(MAGIC,1,len(data),image['count'],2,1)and h[6:8]==(0,0)and h[8:10]==(pid,pid)and h[10]&0xe7==0xe7 and h[11]>0 and h[12]==131072 and not any(h[13:]),'complete actual native prefix/count/PID/XCR0')
 components=r.components(F(data,r.rt,'xstate'));rows=F(data,r.rt,'endpoints');n=r.types['tfi_endpoint']['bytes']
 ends=[endpoint(r,rows[i*n:(i+1)*n],image,i,'reference',go,notify,cpu,components,h[11],h[12])for i in range(2)]
 need(ends[0]['fp']==ends[1]['fp']and ends[0]['page']==ends[1]['page'],'every native FP/rseq byte unchanged across real ADD interval')
 return r,ends,dict(accepted=True,operation_status='completed',count=image['count'],exit=0,nx_endpoints=2,read_ingress_frames=0,full_fp_endpoints=2,trace_records=0,cpu=cpu)

def native(data,layout,image,pid,exit_status,go_fd,notify_fd,cpu):
 return _native(data,layout,image,pid,exit_status,go_fd,notify_fd,cpu)[2]

def output(data,image,mode,go_fd,notify_fd,cpu):
 fixed(image['count'],go_fd,notify_fd,cpu);need(type(data)is bytes and len(data)==20480,'entire emitted data and rseq page; no trailing/truncated bytes')
 memory_bytes,page=data[:16384],data[16384:];ids=page_ids(page)
 need(ids['cpu']==cpu and memory_bytes==memory(image,mode,go_fd,notify_fd,page,True),'every literal live GPR/flags/32ZMM/8K/selectors/data/stack byte and actual CPU')
 return dict(accepted=True,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),count=image['count'],flags=states(image,go_fd)[-1][1],cpu=cpu,node=ids['node'],mm_cid=ids['mm_cid'])

def control_output(data,image,control,go_fd,notify_fd,cpu):
 """Complete output for the two fixed failed protocols whose target completes.

 This accepts output only, never a timing sample or a successful protocol.
 The enclosing negative reader must retain the actual failed transcript.
 """
 need(type(control)is int and control in(2,3)and image['count']==1,'only literal extra-DONE/missing-DONE controls')
 fixed(image['count'],go_fd,notify_fd,cpu);need(type(data)is bytes and len(data)==20480,'complete failed-protocol target output')
 page=data[16384:];ids=page_ids(page);expected=bytearray(memory(image,'gated',go_fd,notify_fd,page,True));put(expected,48,control)
 need(ids['cpu']==cpu and data[:16384]==expected,'every complete controlled output byte, with only its independently supplied literal control input')
 return dict(output_validated=True,protocol_accepted=False,control=control,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),count=1,flags=states(image,go_fd)[-1][1],cpu=cpu,node=ids['node'],mm_cid=ids['mm_cid'])

def _gated(data,layout,image,pid,exit_status,go,notify,cpu):
 fixed(image['count'],go,notify,cpu);need(type(pid)is int and pid>0 and type(exit_status)is int and exit_status==0,'actual reaped successful observed gated process')
 r=Reader(data,layout,'tfi_record');I,F=r.integer,r.field;h=q(F(data,r.rt,'h'));N=image['count'];states_=states(image,go)
 need(h[:6]==(MAGIC,2,len(data),N,r.ucn,r.types['tfi_event']['bytes'])and h[6]&0xe7==0xe7 and h[7:15]==(1,0,1,0,0,0,N,0)and h[15]>0 and h[16]==512*1024 and h[17:22]==(1,1,pid,pid,0)and not any(h[22:]),'complete original gated record and exact N rows/terminal success')
 hw=struct.unpack('<14I',F(data,r.rt,'hardware'));need(hw[:2]==(1,0)and hw[2]>=13 and hw[8]&0x18000000==0x18000000 and hw[11]&0x40010000==0x40010000,'actual pre-arm complete required hardware')
 components=r.components(F(data,r.rt,'xstate'));nt=r.types['tfi_endpoint']['bytes'];endbytes=F(data,r.rt,'endpoints')
 ends=[endpoint(r,endbytes[i*nt:(i+1)*nt],image,i,'gated',go,notify,cpu,components,h[15],h[16])for i in range(2)]
 baseline=ends[0]['fp'];page=ends[0]['page'];need(ends[1]['fp']==baseline and ends[1]['page']==page,'entire gated endpoint FP/rseq invariant')
 def framed(b,kind,state,pc,extra):
  f=r.full(b,image,kind);r.envelope(f,h[15],h[16],False);r.literal(f,state,pc,extra,components)
  need(f['fp']==baseline and f['page']==page and f['data']==memory(image,'gated',go,notify,page),'whole frame FP/data/page matches literal body state');return f
 read=F(data,r.rt,'read');r.padding(read,'tfi_endpoint');rh=q(F(read,'tfi_endpoint','h'))
 need(rh[:15]==(1,0,READ,READ,1,1,1,0,1,0,1,1,0,0,0)and not any(rh[15:24]+rh[28:]),'actual read ingress/commit and fresh BODY R/NX observation with no pending owner')
 before=r.full(F(read,'tfi_endpoint','before'),image,'nx');after=r.full(F(read,'tfi_endpoint','after'),image,'commit')
 r.envelope(before,h[15],h[16],False);r.envelope(after,h[15],h[16],False);r.siginfo_alias(read,'tfi_endpoint',before)
 input_g=list(states_[0][0]);input_g[0]=0;input_g[1]=WAIT+43;input_g[11]=0x697
 r.literal(before,(tuple(input_g),0x646),READ,0x10000,components);r.literal(after,states_[0],BODY,0,components)
 need(before['data']==memory(image,'gated',go,notify,page,before_read=True)and after['data']==memory(image,'gated',go,notify,page)and before['page']==after['page']==page and before['fp']==after['fp']==baseline,'read writes exactly one GO byte; complete FP/source/rseq/other memory retained')
 expected=bytearray(before['uc'])
 for reg,value in((13,1),(14,BODY),(3,0x646),(16,BODY),(17,0x646)):put(expected,r.go+reg*8,value)
 need(bytes(expected)==after['uc']and before['h']==after['h'],'entire syscall UC commit limited to actual RAX/RCX/R11/PC/logical flags')
 r.decoded(F(data,r.rt,'read_decoded'),image,READ,2,2,870,7,5)
 rf=F(data,r.rt,'read_fetch');ref=F(rf,'li2_chain_fetch','ref');pr=F(rf,'li2_chain_fetch','progress')
 readseq,backing_anchor,read_identity=r.fetch(rf,image,READ,2,pid,1,fresh=True)
 need(tuple(I(rf,'li2_chain_fetch',k)for k in('pc','length','page_count','pid','tid','identity_observed'))==(READ,2,1,pid,pid,1)and F(rf,'li2_chain_fetch','bytes')==b'\x0f\x05'+bytes(13),'actual final two-byte single-page borrow, never BODY')
 r.progress(F(data,r.rt,'read_released'),ref,READ,2,0);r.maps(F(data,r.rt,'read_maps'),True)
 rp=F(data,r.rt,'read_page');need(tuple(I(rp,'li2_lifecycle_page_view',k)for k in('backing','logical','actual','admitted'))==(1,5,1,0),'BODY actual R/NX, never pre-admitted at read return')
 opening=F(data,r.rt,'opening');closing=F(data,r.rt,'closing');st='li2_tf_chain_slot';pt='li2_step_owner';ot='li2_tf_owner';qt='li2_step_request';ft='li2_chain_fetch'
 oo=F(opening,st,'owner');op=F(oo,ot,'step');oq=F(op,pt,'request');of=F(opening,st,'fetch')
 opened=framed(F(data,r.rt,'opened'),'armed',states_[0],BODY,0x10100)
 expected=bytearray(ends[0]['uc']);put(expected,r.go+17*8,0x10746)
 need(bytes(expected)==opened['uc']and ends[0]['h']==opened['h'],'genuine first BODY NX before original arm; only TF is added and NX RF is preserved')
 need(I(opening,st,'phase')==3 and I(opening,st,'origin')==1 and I(opening,st,'fallback')==0 and I(opening,st,'index')in(0,1)and I(opening,st,'generation')>0 and I(opening,st,'event_id')>0,'first BODY owner is real NX origin, not TRACE destination')
 r.step_frame(F(op,pt,'before'),ends[0]);need(not any(F(op,pt,'after')),'first real owner has no fabricated after frame')
 r.decoded(F(oq,qt,'decoded'),image,BODY,4,15,249)
 origpages=F(oq,qt,'pages');psz=r.types['li2_step_page']['bytes'];pg=origpages[:psz]
 need(not any(origpages[psz:])and I(oq,qt,'page_count')==1 and I(oq,qt,'original_flags')==0x646 and tuple(I(pg,'li2_step_page',k)for k in('address','closed_prot','open_prot'))==(BODY,1,5),'one original BODY permission owner')
 need(tuple(I(pg,'li2_step_page',k)for k in('object','generation','offset'))==tuple(I(rp,'li2_lifecycle_page_view',k)for k in('allocation','generation','offset'))and I(pg,'li2_step_page','object')>0 and I(pg,'li2_step_page','generation')>0,'actual read-return BODY allocation/generation/offset equals first opening')
 need(I(F(of,ft,'ref'),'li2_fetch_ref','sequence')>readseq,'fresh BODY fetch follows fully released syscall borrow')
 _,body_anchor,body_identity=r.fetch(of,image,BODY,15,pid,1)
 # Between the released read borrow and first BODY fetch, native admission
 # preads this sealed source before rejecting its dirty policy bytes. Linux
 # shmem_file_read_iter calls file_accessed, so only this transition permits
 # changed atime. Both raw stats already passed every typed timestamp check;
 # all other bytes and the descriptor remain exact. Later BODY stats must
 # equal the complete new anchor, including atime.
 at=r.types['stat']['fields']['st_atim'];a,z=at['offset'],at['bytes']
 need(z==16 and body_anchor[0]==backing_anchor[0]and body_anchor[1][:a]==backing_anchor[1][:a]and body_anchor[1][a+z:]==backing_anchor[1][a+z:],'same READ/BODY descriptor and every raw stat byte except source-mutable atime')
 backing_anchor=body_anchor
 need(body_identity==(read_identity[0],read_identity[1]+1,read_identity[2]),'adjacent initial WAIT/BODY pages retain exact append generations in one main allocation')
 identity=None
 def registration(b):
  nonlocal identity
  t='li2_rseq_state';need(tuple(I(b,t,k)for k in('initialized','registered','held','first_error','phase','first_detail','pid','tid','address','page','length','signature','epoch'))==(1,1,1,0,3,0,pid,pid,AREA,PAGE,32,0x53053053,1),'actual ACTIVE zero/error-free registration identity')
  need(tuple(I(b,t,k)for k in('fs_base','gs_base','fs_result','gs_result','tls_attempted','tls_complete','registrations','unregistrations','kernel_errors'))==(DATA+2048,DATA+2304,0,0,1,1,1,0,0),'complete actual TLS/registration success')
  pin=F(b,t,'data');dt='li2_rseq_data';values=tuple(I(pin,dt,k)for k in('address','page','allocation','generation','offset','pid','tid'))
  need(values[:2]==(AREA,PAGE)and values[2]>0 and values[3]>0 and values[4]%4096==0 and values[5:]==(pid,pid)and tuple(I(pin,dt,k)for k in('attempted','complete','error','detail'))==(1,1,0,0),'same actual complete anonymous data pin')
  if identity is None:identity=values
  need(values==identity,'one actual registered allocation/generation survives every sampled boundary')
 registration(F(data,r.rt,'read_rseq'))
 def owner(b,pc,flags,held,phase,event_id,post_pc,post_flags):
  r.padding(b,'tfi_owner');v=q(F(b,'tfi_owner','h'));rq=F(b,'tfi_owner','request');rr=F(b,'tfi_owner','ref');progress=F(b,'tfi_owner','progress')
  need(v[:7]==(I(opening,st,'index'),I(opening,st,'generation'),event_id,phase,3 if phase==3 else 5,0,int(phase==5))and v[7:13]==(1,0,1,0,0,0),'same actual slot/generation and opening state')
  need(v[13:22]==((0,0,0,0,0,0,0,0,0)if phase==3 else(1,0,1,0,0,0,0,1,0))and v[22:30]==(1,0,pc,15,1,pid,pid,1)and v[30:]==(post_pc,post_flags),'actual only original open/final revoke and complete source/process identity')
  r.decoded(F(rq,qt,'decoded'),image,pc,4,15,249)
  need(F(rq,qt,'pages')==origpages and I(rq,qt,'page_count')==1 and I(rq,qt,'original_flags')==flags,'original permission identity and actual decoded instruction flags')
  seq=r.progress(progress,rr,pc,15,held,fresh=phase==3 and pc>BODY);release=F(b,'tfi_owner','release');r.padding(rq,qt);r.padding(release,'li2_chain_release')
  need(tuple(I(release,'li2_chain_release',k)for k in('started','complete','result'))==((1,1,0)if phase==5 else(0,0,0)),'only genuine completed final release')
  return v,seq,rq,rr,progress
 def compact_from_slot(slot):
  p=F(F(slot,st,'owner'),ot,'step');rq=F(p,pt,'request');fetch=F(slot,st,'fetch');o=F(slot,st,'owner')
  v=[I(slot,st,k)for k in('index','generation','event_id','phase')]+[I(p,pt,k)for k in('phase','first_error','trace_seen')]
  for k in('open_started','opened','open_result','revoke_started','revoked','revoke_result'):v+=list(struct.unpack('<2'+('Q'if k.endswith('result')else'I'),F(p,pt,k)))
  v += [I(p,pt,k)for k in('open_sync','revoke_sync_started','revoke_sync')]
  v += [I(slot,st,k)for k in('origin','fallback')]+[I(fetch,ft,k)for k in('pc','length','page_count','pid','tid','identity_observed')]+[I(o,ot,k)for k in('actual_post_pc','actual_post_flags')]
  return tuple(v),rq,F(fetch,ft,'ref'),F(fetch,ft,'progress'),F(slot,st,'release')
 rows=F(data,r.rt,'events');et=r.types['tfi_event'];need(not any(rows[N*et['bytes']:]),'all unused event bytes are zero')
 previous=None;first_counts=None;last_counts=None;first_before=None;last_before_owner=None;total_transfers=0
 for i in range(N):
  row=rows[i*et['bytes']:(i+1)*et['bytes']];r.padding(row,et);v=q(F(row,et,'h'));bc=q(F(row,et,'counts_before'));ac=q(F(row,et,'counts_after'));pc=BODY+4*i;nextpc=pc+4;transfer=i+1<N
  need(v[:6]==(1,i,I(opening,st,'index'),I(opening,st,'generation'),1,2 if transfer else 0)and v[6]==(v[2]if transfer else v[2]^1)and not any(v[7:]),'every actual returned row/order/same slot or final fallback')
  bf=r.compact(F(row,et,'before'),states_[i+1],nextpc,0x100,h[15],h[16],ends[0]['h'][2]);af=r.compact(F(row,et,'after'),states_[i+1],nextpc,0x100 if transfer else 0,h[15],h[16],ends[0]['h'][2])
  changed=bytearray(bf['raw']);tf=r.types['tfi_trace_frame'];put(changed,tf['fields']['greg']['offset']+17*8,states_[i+1][1]|(0x100 if transfer else 0))
  need(bytes(changed)==af['raw'],'entire retained local TRACE bytes unchanged except actual final TF clear')
  ob,oa=F(row,et,'owner_before'),F(row,et,'owner_after');old_event=I(opening,st,'event_id')if i==0 else previous[0]
  bv,bseq,brq,bref,bpr=owner(ob,pc,states_[i][1],1,3,old_event,0 if i==0 else pc,0 if i==0 else states_[i][1]|0x100)
  av,aseq,arq,aref,apr=owner(oa,nextpc if transfer else pc,states_[i+1 if transfer else i][1],int(transfer),3 if transfer else 5,bc[0]if transfer else old_event,nextpc,states_[i+1][1]|0x100)
  if i==0:
   first_counts=bc;first_before=ob
   need((bv,brq,bref,bpr,F(ob,'tfi_owner','release'))==compact_from_slot(opening),'whole first compact owner joins actual full opening')
  else:need(ob==previous[1]and bc[0]==previous[0]+1 and bc[1:]==previous[2][1:],'same held compact owner and counters across each genuine next instruction')
  need(bc[0]==old_event+1 and bc[14:]==(2,301),'one genuine TRACE per ADD and held single-step routing interlock')
  want=list(bc);want[8]+=1
  if transfer:want[10]+=1;want[12:14]=[3,1];total_transfers+=1
  else:
   want[3]+=1;want[6]+=1;want[7]+=2;want[9]+=1;want[11]+=int(N==256);want[12:14]=[5 if N==256 else 4,0];want[15]=0
  need(ac==tuple(want),'exact body-local candidate/transfer versus genuine final close/release counters')
  tx=F(row,et,'transfer');vt='li2_fetch_rx_view'
  need(tuple(I(tx,vt,k)for k in('phase','complete','result','before_sequence','after_sequence','pc','length','pid','tid'))==(4 if transfer else 5,1,0,bseq,bseq+1 if transfer else 0,nextpc,15,pid,pid)and I(tx,vt,'serial')>0 and F(tx,vt,'bytes')==bytes.fromhex(image['source_hex'])[nextpc-MAIN:nextpc-MAIN+15],'actual complete same-page staging/commit or cancel and full source window')
  need(aseq==bseq+int(transfer)and I(aref,'li2_fetch_ref','owner')==I(bref,'li2_fetch_ref','owner'),'exact single-use borrow sequence; no fabricated owner turnover')
  r.maps(F(tx,vt,'maps'));o=F(F(tx,vt,'maps'),'li2_fetch_map_progress','observation')
  need(I(o,'li2_maps_observation','kind')==I(o,'li2_maps_observation','io_performed')==1,'actual fresh RX acquisition at each body trace')
  r.padding(tx,vt);tpg=F(tx,vt,'page');backing=r.backing(F(tx,vt,'backing'),image['backing'],backing_anchor);r.page(tpg,BODY,backing,body_identity)
  rb,ra=F(row,et,'rseq_before'),F(row,et,'rseq_after');registration(rb);registration(ra);rt='li2_rseq_state'
  checked_next=transfer
  need(I(ra,rt,'instruction_checks')==I(rb,rt,'instruction_checks')+int(checked_next),'every transferred instruction has its own original pre-effect guard')
  expected=bytearray(rb)
  if checked_next:
   foot=F(ra,rt,'last_footprint');wf='li2_write_footprint'
   need(foot==struct.pack('<4Q4I',nextpc,nextpc+4,0,0,1,1,249,4)and tuple(I(ra,rt,k)for k in('last_pc','last_code','last_first','last_end','last_policy'))==(nextpc,249,0,0,1),'complete fresh ADD no-write footprint')
   for key in('instruction_checks','last_pc','last_code','last_first','last_end','last_policy','last_footprint'):
    f=r.types[rt]['fields'][key];at=f['offset'];expected[at:at+f['bytes']]=ra[at:at+f['bytes']]
  need(bytes(expected)==ra,'every other registered pin/TLS/transaction/range field unchanged')
  previous=(bc[0],oa,ac);last_counts=ac;last_before_owner=ob
  if i+1==N:need((av,arq,aref,apr,F(oa,'tfi_owner','release'))==compact_from_slot(closing),'whole final compact owner joins the full genuine closed owner')
 need(total_transfers==N-1 and last_counts[10]-first_counts[10]==N-1 and last_counts[11]-first_counts[11]==int(N==256)and last_counts[3]-first_counts[3]==1,'exact0/255 transfers, zero/one established lease closure and one actual permission-owner close')
 last=framed(F(data,r.rt,'last_before'),'trace',states_[-1],BODY+4*N,0x100);returned=framed(F(data,r.rt,'last_after'),'returned',states_[-1],BODY+4*N,0)
 expected=bytearray(last['uc']);put(expected,r.go+17*8,states_[-1][1]);need(bytes(expected)==returned['uc']and last['h']==returned['h'],'whole final local UC only clears TF; complete endpoint FP/source/data remain exact')
 for full,compact in((last,F(rows[(N-1)*et['bytes']:N*et['bytes']],et,'before')),(returned,F(rows[(N-1)*et['bytes']:N*et['bytes']],et,'after'))):
  ch=q(F(compact,'tfi_trace_frame','h'));need(q(F(compact,'tfi_trace_frame','greg'))==full['greg']and ch[7:10]==(full['h'][3],word(full['uc'],r.fo),full['h'][2])and F(compact,'tfi_trace_frame','siginfo')==full['uc'][r.layout['offsets']['mask']+8:r.layout['offsets']['mask']+136],'complete compact last TRACE joins its genuine full raw frame')
 cp=F(F(closing,st,'owner'),ot,'step');r.step_frame(F(cp,pt,'after'),last)
 need(F(F(cp,pt,'request'),qt,'pages')==origpages and I(cp,pt,'phase')==5 and I(cp,pt,'first_error')==I(cp,pt,'in_handler')==0 and I(cp,pt,'trace_seen')==I(cp,pt,'revoke_sync_started')==1 and I(cp,pt,'revoke_sync')==0,'actual old complete permission close, no renamed transfer')
 lease=F(data,r.rt,'closed_lease');lt='li2_tf_same_page'
 prior_lease=F(data,r.rt,'body_lease_before');r.padding(prior_lease,lt);r.padding(lease,lt)
 need(I(prior_lease,lt,'phase')in(0,4,5)and I(prior_lease,lt,'origin_active')==0 and tuple(I(prior_lease,lt,k)for k in('candidates','misses','transfers','closed_leases','phase','origin_active'))==first_counts[8:14],'actual inactive pre-BODY lease and all counters join the first genuine TRACE')
 need(I(lease,lt,'phase')==(5 if N==256 else 4)and I(lease,lt,'origin_active')==0 and I(lease,lt,'transfers')==last_counts[10]and I(lease,lt,'closed_leases')==last_counts[11]and F(lease,lt,'transfer')==F(rows[(N-1)*et['bytes']:N*et['bytes']],et,'transfer'),'actual final stage cancellation and lease state')
 r.decoded(F(lease,lt,'next'),image,BODY+4*N,1,15,300,disposition=1)
 if N==256:
  need(F(lease,lt,'opening')==oq and tuple(I(lease,lt,k)for k in('slot','owner_generation','origin_event','origin_borrow'))==(I(opening,st,'index'),I(opening,st,'generation'),I(opening,st,'event_id'),I(F(of,ft,'ref'),'li2_fetch_ref','sequence')),'retained original opening authority across all255 transfers')
  r.step_frame(F(lease,lt,'opening_frame'),ends[0])
  penultimate=rows[(N-2)*et['bytes']:(N-1)*et['bytes']];pob=F(penultimate,et,'owner_before')
  need(F(lease,lt,'previous')==F(pob,'tfi_owner','request')and F(lease,lt,'previous_fetch')==F(pob,'tfi_owner','progress'),'actual predecessor entry progress, never normalized to later validation')
  r.compact_step(F(lease,lt,'previous_before'),F(rows[(N-3)*et['bytes']:(N-2)*et['bytes']],et,'after'),baseline)
  need(I(lease,lt,'completed_event')==q(F(penultimate,et,'counts_before'))[0]and F(lease,lt,'classification')==struct.pack('<QQ6I',BODY+4*(N-1),BODY+4*N,1,1,249,4,1,1),'last successful ADD classification/event survives the final old-NOP miss')
 else:
  for key in('slot','owner_generation','origin_event','origin_borrow','completed_event','opening','previous','opening_frame','previous_before','previous_fetch','classification'):
   need(F(lease,lt,key)==F(prior_lease,lt,key),'N1 preserves complete actual pre-BODY setup authority '+key)
 # Reconstruct only the source-defined writes to the actual pre-BODY object.
 # For N1 this also checks every byte of all inherited setup payloads. N256
 # replaces those payloads with the independently joined body authority above.
 expected_lease=bytearray(prior_lease)
 scalar_writes=dict(phase=5 if N==256 else 4,origin_active=0,candidates=first_counts[8]+N,misses=first_counts[9]+1,transfers=first_counts[10]+N-1,closed_leases=first_counts[11]+int(N==256))
 for key,value in scalar_writes.items():
  f=r.types[lt]['fields'][key];expected_lease[f['offset']:f['offset']+f['bytes']]=value.to_bytes(f['bytes'],'little')
 changed_payloads=['transfer','next']
 if N==256:changed_payloads+=['slot','owner_generation','origin_event','origin_borrow','completed_event','opening','previous','opening_frame','previous_before','previous_fetch','classification']
 for key in changed_payloads:
  f=r.types[lt]['fields'][key];expected_lease[f['offset']:f['offset']+f['bytes']]=F(lease,lt,key)
 need(bytes(expected_lease)==lease,'every remaining retained lease byte and padding preserves actual pre-BODY state')
 # Whole retained original opening/closing slots: every field is either a
 # literal transition, the real full frame, a checked fetch/query, or a typed
 # persistent callback/session pointer. No opaque owner payload is discarded.
 tc=F(data,r.rt,'terminal_chain');chain_address=I(opening,st,'chain');session=I(tc,'li2_tf_chain','session')
 need(0<chain_address<1<<47 and chain_address%8==0 and 0<session<1<<47 and session%8==0,'actual canonical private chain/session identities')
 def classify(pc):return struct.pack('<QQ6I',pc,pc+4,1,1,249,4,1,1)
 def full_slot(slot,closed):
  r.padding(slot,st);pc=BODY+4*(N-1)if closed else BODY;owner_=F(slot,st,'owner');p=F(owner_,ot,'step');r.padding(owner_,ot);r.padding(p,pt)
  scalar=dict(chain=chain_address,phase=5 if closed else 3,index=I(opening,st,'index'),origin=1,fallback=0,prepare_attempted=0,prepare_complete=1,decode_attempted=1,decode_complete=1,retry=0,unexpected_frame_observed=0,unexpected_signal=0,unexpected_code=0,unexpected_errno=0,unexpected_address=0,generation=I(opening,st,'generation'),event_id=q(F(last_before_owner,'tfi_owner','h'))[2]if closed else I(opening,st,'event_id'),prepare_result=0,decode_result=0,classify_result=0)
  need(all(I(slot,st,k)==v for k,v in scalar.items()),'all retained original slot scalars and actual final event')
  need(F(slot,st,'decoded')==F(F(p,pt,'request'),qt,'decoded')and F(slot,st,'descriptive_classification')==(classify(pc)if closed and N==256 else bytes(r.types['li2_tf_classification']['bytes'])),'complete original decoded/classification state')
  for key in('first_decoded','first_fetch','first_release','unexpected'):need(not any(F(slot,st,key)),'no fabricated retry/unexpected slot bytes '+key)
  r.fetch(F(slot,st,'fetch'),image,pc,15,pid,int(not closed),backing_anchor,body_identity)
  step_scalars=dict(phase=5 if closed else 3,first_error=0,in_handler=0,self_test=0,trace_seen=int(closed),revoke_sync_started=int(closed),first_detail=0,session=session,open_sync=0,revoke_sync=0,signal_number=5 if closed else 11,signal_code=2,signal_errno=0,signal_address=BODY+4*N if closed else BODY,destination=0,width=0,immediate=0,effect=0,source=0)
  need(all(I(p,pt,k)==v for k,v in step_scalars.items()),'all retained original step scalars/error/signal/effect state')
  slot_address=chain_address+r.types['li2_tf_chain']['fields']['slots']['offset']+I(slot,st,'index')*r.types[st]['bytes']
  hooks=q(F(p,pt,'hooks'));owner_hooks=q(F(owner_,ot,'hooks'))
  need(len(hooks)==3 and hooks[0]==slot_address and all(0<x<1<<47 for x in hooks[1:])and len(owner_hooks)==4 and owner_hooks[:3]==hooks and 0<owner_hooks[3]<1<<47,'complete actual source-owned callback/context identities')
  need(F(owner_,ot,'classification')==classify(pc)and tuple(I(owner_,ot,k)for k in('actual_post_pc','actual_post_flags','continuation_started','continuation_complete','unexpected_frame_observed','continuation_result'))==((BODY+4*N,states_[-1][1]|0x100,1,1,0,0)if closed else(0,0,0,0,0,0)),'exact original classification/continuation observations')
  for key in('rdssp_query_attempted','rdssp_query_complete','rdssp_query_result','rdssp_features','rdssp_observation','bnd_xcr0_attempted','bnd_xcr0_complete','bnd_xcr0'):need(not any(F(owner_,ot,key)),'no unrelated owner evidence '+key)
  if closed:
   if N==1:r.step_frame(F(p,pt,'before'),ends[0])
   else:r.compact_step(F(p,pt,'before'),F(rows[(N-2)*et['bytes']:(N-1)*et['bytes']],et,'after'),baseline)
   r.step_frame(F(p,pt,'after'),last);query=F(slot,st,'query');r.padding(query,'li2_tf_continuation')
   need(tuple(I(query,'li2_tf_continuation',k)for k in('pc','attempted','page_observed','complete','result'))==(BODY+4*N,1,1,1,0),'real complete original closed continuation')
   r.maps(F(query,'li2_tf_continuation','maps'));qb=r.backing(F(query,'li2_tf_continuation','backing'),image['backing'],backing_anchor);r.page(F(query,'li2_tf_continuation','page'),BODY,qb,body_identity)
  else:need(not any(F(slot,st,'query')),'no invented pre-execution continuation query')
  return hooks,owner_hooks
 need(full_slot(opening,False)==full_slot(closing,True),'complete original callbacks/context/session survive every transfer and final close')
 rs=F(data,r.rt,'terminal_rseq');registration(rs)
 need(I(tc,'li2_tf_chain','initialized')==1 and all(I(tc,'li2_tf_chain',k)==0 for k in('pending','in_handler','first_error','first_detail','unexpected_events'))and F(data,r.rt,'terminal_source')==bytes.fromhex(image['source_hex'])and F(data,r.rt,'terminal_data')==memory(image,'gated',go,notify,page,True)and F(data,r.rt,'terminal_page')==page,'complete successful terminal/no pending owner/source/full data/rseq page')
 terminal_lease=F(tc,'li2_tf_chain','lease');need(I(terminal_lease,lt,'origin_active')==0 and I(terminal_lease,lt,'transfers')>=last_counts[10]and I(terminal_lease,lt,'closed_leases')>=last_counts[11],'every later actual lease also terminates under the unchanged owner contract')
 return r,ends,dict(accepted=True,operation_status='completed',count=N,exit=0,nx_endpoints=2,read_ingress_frames=1,read_return_body_protection=1,trace_records=N,body_transfers=N-1,body_real_closes=1,body_established_lease_closes=int(N==256),full_fp_endpoints=2,full_fp_per_trace=False,cpu=cpu)

def gated(data,layout,image,pid,exit_status,go_fd,notify_fd,cpu):
 return _gated(data,layout,image,pid,exit_status,go_fd,notify_fd,cpu)[2]

def pair(nrec,grec,nout,gout,layouts,image,npid,gpid,cpu,native_fds,gated_fds):
 need(type(layouts)is dict and set(layouts)=={'native','gated'}and type(npid)is type(gpid)is int and npid!=gpid and all(type(x)in(tuple,list)and len(x)==2 for x in(native_fds,gated_fds)),'two independent actual subjects and exact paired layout inputs')
 nr,nf,n=_native(nrec,layouts['native'],image,npid,0,*native_fds,cpu)
 gr,gf,g=_gated(grec,layouts['gated'],image,gpid,0,*gated_fds,cpu)
 no=output(nout,image,'reference',*native_fds,cpu);go=output(gout,image,'gated',*gated_fds,cpu)
 need(layouts['native']['offsets']==layouts['gated']['offsets']and layouts['native']['siginfo']==layouts['gated']['siginfo']and nr.ucn==gr.ucn and nr.field(nrec,nr.rt,'xstate')==gr.field(grec,gr.rt,'xstate')and word(nr.field(nrec,nr.rt,'h'),80)==word(gr.field(grec,gr.rt,'h'),48),'actual same UC/FP layout/XCR0 in both independently executed lanes')
 for a,b in zip(nf,gf):
  need(a['fp']==b['fp'],'every native/gated initialized and retained FP byte, not just selected vectors')
  au,bu=bytearray(a['uc']),bytearray(b['uc'])
  for key in('stack_sp','stack_size','fp_pointer'):put(au,nr.layout['offsets'][key],0);put(bu,gr.layout['offsets'][key],0)
  # Both actual descriptor values have already been independently bound to the
  # parent and checked in every complete literal frame; only these inputs vary.
  put(au,nr.go+GREG[7]*8,0);put(bu,gr.go+GREG[7]*8,0)
  need(au==bu,'all remaining raw UC bytes equal after separately validated actual stack/FP pointers and input FD')
  am,bm=bytearray(a['data']),bytearray(b['data']);ap,bp=bytearray(a['page']),bytearray(b['page'])
  ai,bi=page_ids(ap),page_ids(bp);need(ai['cpu']==bi['cpu']==cpu and ai['node']==bi['node'],'actual same reserved CPU and node, separately typed mm_cid')
  for buf in(am,bm):
   for offset in(16,80,88):put(buf,offset,0)
   struct.pack_into('<I',buf,8192+88,0)
  for buf in(ap,bp):struct.pack_into('<I',buf,88,0)
  need(am==bm and ap==bp,'every remaining native/gated data/stack/rseq byte; exact per-lane mode/FD/mm_cid only')
 return dict(accepted=True,operations=image['count'],native=n,gated=g,native_output=no,gated_output=go,full_endpoint_fp_pair=True,per_trace_fp_claim=False)

def semantic_counts(parsed):
 """Actual global report counters. They include setup and are not BODY counts."""
 need(type(parsed)is dict and type(parsed.get('chain'))is dict and type(parsed.get('lease'))is dict,'complete actual original reports')
 c=parsed['chain'];l=parsed['lease']
 keys=('attempts','steps','nx_entries','trace_entries','fallbacks','preparations','releases','unexpected')
 result={k:c[k]for k in keys};result.update(l)
 need(all(type(v)is int and 0<=v<1<<64 for v in result.values()),'typed actual global semantic report counters')
 return result

def capture_identity(snapshot,size,child=False):
 """Replay retained normal-open/dup observations; no pathname-derived claim."""
 import os,stat
 fields={'parent_fd','open_route','identity','statx_hex'}
 if child:fields.update(('fd','query_duplicate','statfs_result','statfs_hex','query_duplicate_closed'))
 need(type(snapshot)is dict and set(snapshot)==fields and type(snapshot['parent_fd'])is int and snapshot['parent_fd']>3 and snapshot['open_route']=='exclusive-normal-open/Popen-stdout-dup2-exec','complete actual normal-open stdout observation')
 ids=snapshot['identity'];need(type(ids)is list and len(ids)==7 and all(type(x)is int and x>=0 for x in ids),'typed actual stdout identity')
 dev,ino,mnt,major,minor,mode,flags=ids
 need(ino>0 and mnt>0 and stat.S_ISREG(mode)and flags&os.O_ACCMODE==os.O_WRONLY and not flags&os.O_PATH and (major,minor)==(os.major(dev),os.minor(dev)),'actual ordinary mount/regular writable capture identity')
 raw=bytes.fromhex(snapshot['statx_hex']);need(len(raw)==256 and raw.hex()==snapshot['statx_hex']and struct.unpack_from('<I',raw)[0]&0x1103==0x1103 and not struct.unpack_from('<I',raw)[0]&0x4000 and struct.unpack_from('<H',raw,28)[0]==mode and word(raw,32)==ino and word(raw,40)==size and struct.unpack_from('<IIQ',raw,136)==(major,minor,mnt),'complete actual statx payload, normal mount ID and exact capture extent')
 if child:
  fs=bytes.fromhex(snapshot['statfs_hex'])
  need(type(snapshot['fd'])is int and snapshot['fd']==1 and type(snapshot['query_duplicate'])is int and snapshot['query_duplicate']==snapshot['parent_fd']>=100 and snapshot['query_duplicate_closed']is True and type(snapshot['statfs_result'])is int and snapshot['statfs_result']==0 and len(fs)==120 and fs.hex()==snapshot['statfs_hex']and word(fs,0)==0x9123683e,'actual closed same-OFD query and full Btrfs statfs result')
 return ids

def terminal(row,stdout,stderr,record,preparation,*,image,layout,cpu,expected_command,profile):
 """Strict callback for pipe_run.invoke, with an explicitly bound profile.

 expected_command is the immutable original command(...) template retained
 before invoke resolves its five placeholders. The enclosing helper separately
 pins its original ELF, exact observed/unobserved bridge, source and namespace.
 """
 need(profile in PROFILES and type(profile)is str and type(row)is dict and type(preparation)is dict and type(stdout)is type(stderr)is type(record)is bytes,'explicit fixed terminal profile and raw captures')
 mode=PROFILES[profile]
 need(type(expected_command)is tuple and all(type(x)is str for x in expected_command)and len(expected_command)==(22 if mode=='gated'else 18)and expected_command[3]==mode,'exact independently bound immutable launcher command/profile')
 need(row['control']=='normal'and row['bounds']==[5,512<<20,16<<20,15]and all(type(v)is int for v in row['bounds'])and type(row['pid'])is int and row['pid']>0 and type(row['exit'])is int and row['exit']==0 and row['reaped']is True and row['timed_out']is False and row['error']is None and row['cleanup_errors']==[]and row['protocol_complete']is True,'actual complete successful process, never failure relabelling')
 need(set(preparation)=={'previous_mask','mask','dispositions','argv','environment','observer','pipes','stdout','mode','control','affinity'}and preparation['mode']==mode and type(preparation['control'])is int and preparation['control']==0 and preparation['affinity']==[cpu]and preparation['mask']==0,'complete actual preparation/profile/CPU schema')
 need(type(preparation['previous_mask'])is int and 0<=preparation['previous_mask']<=MASK64 and preparation['environment']=={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'},'actual fixed launcher environment and typed previous mask')
 need(type(preparation['dispositions'])is list and [x['signal']for x in preparation['dispositions']]==[i for i in range(1,65)if i not in(9,19)]and all(set(x)=={'signal','before','after'}and type(x['before'])is int and x['before']>=0 and type(x['after'])is int and x['after']==0 for x in preparation['dispositions']),'all actual reserved/default signal dispositions')
 pipes=preparation['pipes'];need(type(pipes)is list and len(pipes)==2 and all(type(x)is dict and set(x)=={'fd','device','inode','mode','flags','inheritable'}for x in pipes),'exact two inherited application pipe ends')
 go,notify=(x['fd']for x in pipes);fixed(image['count'],go,notify,cpu)
 need(row['pass_fds']==[3,go,notify]and preparation['argv']==[expected_command[5],mode,str(go),str(notify),'0'],'exact record plus only two explicit pipe ends and actual target argv')
 names=('record','go_read','go_write','notify_read','notify_write');descriptors=row['descriptors']
 need(type(descriptors)is list and len(descriptors)==5 and [x['name']for x in descriptors]==list(names)and all(set(x)=={'name','fd','closed'}and type(x['fd'])is int and x['closed']is True for x in descriptors)and len({x['fd']for x in descriptors})==5 and descriptors[0]['fd']==3 and descriptors[1]['fd']==go and descriptors[4]['fd']==notify,'every exact parent descriptor closed once; no omitted descriptor rows')
 parent=row['pipe_before'];need(type(parent)is list and len(parent)==4 and [x['fd']for x in parent]==[x['fd']for x in descriptors[1:]],'all four actual parent pipe endpoints')
 import os,stat
 for i,x in enumerate(parent):
  need(type(x)is dict and set(x)==set(pipes[0])and all(type(x[k])is int for k in('fd','device','inode','mode','flags'))and stat.S_ISFIFO(x['mode'])and x['flags']&os.O_ACCMODE==(0 if i in(0,2)else 1)and not x['flags']&(os.O_NONBLOCK|os.O_PATH)and x['inheritable']is False,'actual parent blocking FIFO kind/access/custody')
 need((parent[0]['device'],parent[0]['inode'])==(parent[1]['device'],parent[1]['inode'])and(parent[2]['device'],parent[2]['inode'])==(parent[3]['device'],parent[3]['inode'])and(parent[0]['device'],parent[0]['inode'])!=(parent[2]['device'],parent[2]['inode']),'two distinct pipe objects, not relabelled endpoints')
 for a,b in zip((parent[0],parent[3]),pipes):need(b==dict(a,inheritable=True),'actual child descriptor identity joins the exact parent endpoint')
 rb=row['record_before'];need(set(rb)=={'fd','device','inode','mode','flags'}and rb['fd']==3 and stat.S_ISREG(rb['mode'])and rb['flags']&os.O_ACCMODE==os.O_WRONLY and preparation['observer']=={k:rb[k]for k in('fd','device','inode')},'actual fresh regular FD3 identity')
 before=row['stdout_before'];after=row['stdout_after'];child=preparation['stdout']
 need(capture_identity(before,0)==capture_identity(child,0,True)==capture_identity(after,len(stdout))and before['parent_fd']==after['parent_fd'],'all actual parent/child normal-open stdout identities and retained before/after extents')
 need(set(row['captures'])=={'stdout','stderr','record','preparation'},'all four actual capture facts')
 for name,payload in(('stdout',stdout),('stderr',stderr),('record',record),('preparation',json.dumps(preparation,sort_keys=True).encode())):
  c=row['captures'][name];need(set(c)=={'sha256','bytes','file'}and c['bytes']==len(payload)<=16<<20 and c['sha256']==hashlib.sha256(payload).hexdigest()and c['file']==row['name']+'.'+name,'exact supplied raw capture custody '+name)
 argv=row['argv'];need(type(argv)is list and len(argv)==len(expected_command),'complete actual invocation argv')
 replacements={'{record_fd}':'3','{go_fd}':str(go),'{notify_fd}':str(notify),'{control}':'0','{preparation}':argv[9]}
 need(all(expected_command.count(k)==1 for k in replacements)and argv==[replacements.get(x,x)for x in expected_command]and Path(argv[9]).name==row['captures']['preparation']['file']==row['name']+'.preparation','exact fixed argv with only actual five placeholder resolutions')
 need(type(row['start_ns'])is int and type(row['deadline_ns'])is int and row['deadline_ns']==row['start_ns']+15*10**9,'one original absolute IPC deadline')
 transcript=row['transcript'];need(type(transcript)is list and 4<=len(transcript)<=32,'bounded complete actual IPC transcript')
 received=bytearray();write_seen=False;eof=False;last_time=row['start_ns'];go_time=None;done_time=None
 for entry in transcript:
  need(type(entry)is dict and type(entry.get('time_ns'))is int and last_time<=entry['time_ns']<=row['deadline_ns']and not eof,'ordered actual IPC events within one deadline');last_time=entry['time_ns']
  if entry.get('kind')=='write':
   need(set(entry)=={'kind','time_ns','hex','result'}and not write_seen and bytes(received)==b'TFI-RDY\n'and entry['hex']=='47'and type(entry['result'])is int and entry['result']==1,'one actual GO byte after complete READY')
   write_seen=True;go_time=entry['time_ns']
  else:
   need(set(entry)=={'kind','time_ns','hex'}and entry['kind']=='read'and type(entry['hex'])is str and len(entry['hex'])<=18,'actual bounded pipe read')
   b=bytes.fromhex(entry['hex']);need(b.hex()==entry['hex'],'canonical retained actual bytes')
   if not b:need(write_seen and bytes(received)==b'TFI-RDY\nTFI-DON\n','EOF only after exact DONE');eof=True
   else:
    received+=b;want=b'TFI-RDY\nTFI-DON\n';need(len(received)<=len(want)and want.startswith(received)and(write_seen or len(received)<=8),'no partial, duplicate, extra, wrong-order or relabelled IPC byte')
    if len(received)==16:done_time=entry['time_ns']
 need(eof and write_seen and bytes(received)==b'TFI-RDY\nTFI-DON\n'and row['candidate_go_ns']==go_time and type(row['candidate_done_ns'])is int and done_time<=row['candidate_done_ns']<=row['deadline_ns']and go_time<row['candidate_done_ns'],'complete exact transcript+EOF and provisional actual timestamp')
 out=output(stdout,image,mode,go,notify,cpu);parsed=None;counts=None
 if profile=='native-reference':
  need(not stderr and layout is not None,'native reference has only actual full endpoint record')
  result=native(record,layout,image,row['pid'],0,go,notify,cpu)
 elif profile=='gated-observed':
  need(layout is not None,'explicit observed gated layout')
  result=gated(record,layout,image,row['pid'],0,go,notify,cpu)
 else:
  need(layout is None and record==b'','explicit unobserved timing profile has no invented binary observation')
  if profile=='native-timing':need(stderr==b'','native timing stderr empty')
  result=dict(accepted=True,operation_status='completed',endpoint_frame_claim=False,body_transfer_claim=False)
 if mode=='gated':
  parsed=reports.reports(stderr);reports.completed(parsed,row['pid']);counts=semantic_counts(parsed)
  if profile=='gated-observed':reports.join(parsed,Reader(record,layout,'tfi_record'),record)
 result.update(profile=profile,operations=image['count'],pid=row['pid'],cpu=cpu,output=out,output_bytes=out['bytes'],output_sha256=out['sha256'])
 if parsed is not None:
  result.update(reports=parsed,global_semantic_counts=counts,global_semantic_sha256=hashlib.sha256(json.dumps(counts,sort_keys=True,separators=(',',':')).encode()).hexdigest())
 return result
