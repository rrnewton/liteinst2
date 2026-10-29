"""Finite actual TCGETS frames; original full signal/FP predicates are reused."""
import hashlib,importlib.util,json,struct
from pathlib import Path
from page_selected import need
_SPEC=importlib.util.spec_from_file_location('rtc_original_frames',Path(__file__).resolve().parent.parent/'rseq_native_boundary/check.py')
boundary=importlib.util.module_from_spec(_SPEC);_SPEC.loader.exec_module(boundary)
old=boundary.old
MAIN,BODY,TAIL,GUARD,DATA=old.MAIN,old.BODY,old.TAIL,old.GUARD,old.DATA
ARENA,PAGE,AREA,WORD=old.ARENA,old.PAGE,old.AREA,old.WORD
MAGIC=0x3153544547435452
GREG,VECTORS,MASKS=old.GREG,old.VECTORS,old.MASKS
q,word,put,page_ids=old.q,old.word,old.put,old.page_ids
U64=(1<<64)-1
NATIVE_EXIT=(0,)*20
GATED_EXIT=(0,)*7+(125,)*13
RESULT=(-25,)*7+(-9,-25,-25,-25,-25,-25,-9,-25,None,-9,-25,-25,-25)

def elf(data,interpreter,case,native_policy,injected=0,request_profile=False):
    need(type(request_profile)is bool,'fixed TCGETS or TIOCGWINSZ fixture request')
    need(type(injected)is int and 0<=injected<=16 and (not injected or case==0),'fixed literal refusal-control selector')
    need(type(case)is int and 0<=case<20 and type(data)is bytes and len(data)>=64,'fixed real fixture ELF')
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    need(h[0][:7]==b'\x7fELF\x02\x01\x01' and h[1:4]==(2,62,1) and h[4]==MAIN and h[8:10]==(64,56) and h[11]==64,'actual high ET_EXEC entry')
    def extent(a,n):
        need(0<=a<=len(data) and 0<=n<=len(data)-a,'actual file extent');return data[a:a+n]
    ph=[struct.unpack('<IIQQQQQQ',extent(h[5]+56*i,56))for i in range(h[10])]
    loads=[p for p in ph if p[0]==1]
    need(len(loads)==3 and [p[1]for p in loads]==[4,5,6] and loads[0][2:4]==(0,MAIN-4096) and loads[0][5]<=4096 and
         loads[1][2:4]==(4096,MAIN) and loads[1][5:7]==(24576,24576) and loads[2][3]==DATA and loads[2][5]>=16384 and
         all(p[7]==4096 and p[5]<=p[6]for p in loads) and not any(p[0]==7 for p in ph),'three real nonoverlapping domains/no TLS')
    ip=[p for p in ph if p[0]==3]
    need(len(ip)==1 and extent(ip[0][2],ip[0][5])==str(interpreter).encode()+b'\0','actual custom interpreter string')
    ss=[struct.unpack('<IIQQQQIIQQ',extent(h[6]+64*i,64))for i in range(h[12])]
    need(not any(s[1]in(4,9) and s[5]for s in ss),'no instruction relocations or per-lane byte fixups')
    tables=[s for s in ss if s[1]==2];need(len(tables)==1 and tables[0][9]==24,'one actual full symbol table')
    t=tables[0];strings=ss[t[6]];names=extent(strings[4],strings[5]);symbols={}
    for at in range(t[4],t[4]+t[5],24):
        n,info,other,index,value,size=struct.unpack('<IBBHQQ',extent(at,24))
        if n and info&15!=4:
            name=names[n:names.index(b'\0',n)].decode();need(name not in symbols,'unique named actual symbol');symbols[name]=value
    def read(a,n):
        p=next((p for p in loads if p[3]<=a and a+n<=p[3]+p[5]),None)
        need(p is not None,'retained mapped file bytes');return extent(p[2]+a-p[3],n)
    expected={'_start':MAIN,'rn_seed':MAIN+4096,'rn_body':BODY,'rn_tail':TAIL,'rn_guard':GUARD,'rn_finish':GUARD,
      'rn_fault':TAIL-2,'rn_data':DATA,'rn_data_end':DATA+16384,'rn_case':DATA+8,'rn_mode':DATA+16,
      'rn_active':DATA+24,'rn_registration_result':DATA+32,'rn_rounds':DATA+40,'rn_commit':DATA+48,
      'rn_abort_seen':DATA+56,'rn_final_fs':DATA+64,'rn_final_gs':DATA+72,'rn_vdso':DATA+80,
      'rn_unmapped':DATA+88,'rn_closed':DATA+96,'rn_restored':DATA+104,'rn_startup':DATA+112,'rn_injected':DATA+120,
      'rn_store':DATA+128,'rn_descriptor':DATA+256,'rn_vectors':DATA+512,'rn_masks':DATA+2560,
      'rn_live_vectors':DATA+4096,'rn_live_masks':DATA+6144,'rn_live_gpr':DATA+6208,
      'rn_live_flags':DATA+6336,'rn_live_selectors':DATA+6344,'rn_rseq_initial':DATA+8192,'rn_stack_top':DATA+16320}
    need(all(symbols[k]==v for k,v in expected.items()),'complete actual fixture symbol geometry')
    source=read(MAIN,24576);initial=read(DATA,16384)
    if request_profile:
        need(symbols.get('rn_request_profile')==DATA+160 and q(initial[160:168])==(1,),
             'actual ELF literal TIOCGWINSZ fixture profile')
    else:
        need('rn_request_profile'not in symbols and initial[160:168]==bytes(8),
             'original TCGETS fixture has no alternate profile literal')
    need(q(initial[:128])==(old.MAGIC,case,0,0,U64,0,0,0,0,0,0,0,0,0,0,injected) and
         initial[128:160]==b'\x5a'*32 and initial[256:288]==bytes(32) and initial[512:2624]==VECTORS+MASKS,
         'literal independent case/data/rseq/vector/mask seeds')
    need(read(TAIL-2,3)==b'\x0f\x05\x90' and read(TAIL+1,1)==b'\xe9' and
         TAIL+6+struct.unpack('<i',read(TAIL+2,4))[0]==GUARD and read(TAIL+256,2)==b'\x0f\xa2' and
         read(symbols['rn_setup_syscall'],2)==b'\x0f\x05','one exact original syscall and genuine next-NX boundary')
    need(native_policy(read(MAIN+4096-14,4096+28))==0 and
         all(native_policy(read(p,4096))!=0 for p in (MAIN,BODY,TAIL,GUARD)),
         'whole helper/halo accepted and every effect/setup/terminal page blocked under unchanged policy')
    need(read(MAIN,3)==b'\x48\x89\x25' and MAIN+7+struct.unpack('<i',read(MAIN+3,4))[0]==DATA+112,
         'first instruction stores the actual unchanged startup RSP')
    need(read(symbols['rn_restorer'],9)==bytes.fromhex('b80f0000000f050f0b'),'real rt_sigreturn restorer')
    interp=interpreter.read_bytes();ih=struct.unpack_from('<16sHHIQQQIHHHHHH',interp)
    entry=bytes.fromhex('0fa248b8')+struct.pack('<Q',MAIN)+bytes.fromhex('ffe0')
    need(len(interp)==8192 and ih[1:4]==(3,62,1) and ih[4]==4096 and
         interp[4096:4096+len(entry)]==entry and not any(interp[4096+len(entry):]),
         'unchanged genuine first-interpreter CPUID and main handoff')
    image=dict(case=case,injected=injected,entry=MAIN,symbols=symbols,source_hex=source.hex(),data_hex=initial.hex(),
                source_sha256=hashlib.sha256(source).hexdigest(),data_sha256=hashlib.sha256(initial).hexdigest())
    if request_profile:image['request_profile']=True
    return image


class Reader(old.Reader):
    siginfo_alias=boundary.Reader.siginfo_alias
    def __init__(self,data,layout,record):
        self.data,self.types,self.layout=data,layout['types'],layout
        self.rt=self.types[record];self.ft=self.types['rn_frame'];self.ucn=layout['uc_bytes']
        self.go=layout['offsets']['greg'];self.fo=layout['offsets']['fp_pointer']
        need(layout['record']==record and len(data)==self.rt['bytes']<16<<20 and
             0<self.ucn<=2048 and self.go+23*8<=self.ucn and self.fo+8<=self.ucn,'complete actual DWARF record')
        si=layout['siginfo']
        need(all(type(x)is int for x in (si['bytes'],*si['offsets'].values(),*si['widths'].values())) and
             si==dict(bytes=128,offsets=dict(si_signo=0,si_errno=4,si_code=8,si_addr=16),
                      widths=dict(si_signo=4,si_errno=4,si_code=4,si_addr=8)),'complete actual x86-64 siginfo ABI')
        frame=self.ft['bytes'];row=self.types['rtc_native_row']['bytes']
        forms={'rn_frame':dict(h=512,uc=2048,fp=65536,source=24576,data=16384,rseq=4096),
               'rtc_native_row':dict(h=256,before=frame,after=frame,siginfo_before=128,siginfo_after=128,
                                     private_before=65536,private_after=65536)}
        if record=='rtc_native_record':forms[record]=dict(h=512,xstate=128,startup=2048,rows=2*row)
        else:
            ns=self.types['li2_rseq_native_state']['bytes'];ts=self.types['li2_tcgets_state']['bytes']
            forms['rtc_row']=dict(frame=row,permits=64,native_before=ns,native_after=ns,
                                 close=self.types['li2_native_close']['bytes'])
            forms[record]=dict(h=512,xstate=128,startup=2048,hardware=56,rows=2*self.types['rtc_row']['bytes'],
                effect_before=frame,effect_after=frame,stages=7*ts,owners=7*self.types['li2_rseq_state']['bytes'],
                terminal_close=self.types['li2_native_close']['bytes'],query=20480,injection=128,injection_before=2*ts,injection_after=2*ts,
                terminal_source=24576,terminal_data=16384,terminal_page=4096)
        for name,fields in forms.items():
            shape=self.types[name];at=0
            need(set(shape['fields'])==set(fields),'complete observation field inventory '+name)
            for key,size in fields.items():
                need(shape['fields'][key]==dict(offset=at,bytes=size),'contiguous actual field '+name+'.'+key);at+=size
            need(shape['bytes']==at,'complete record without ignored padding '+name)

    def startup(self,h,native):
        s=q(self.field(self.data,self.rt,'startup'));n=h[23];argc=2 if native else 1
        need(h[22]>0 and h[22]%16==0 and type(n)is int and argc+5<=n<=256 and
             s[0]==argc and all(s[i]>0 for i in range(1,argc+1)) and s[argc+1]==0 and not any(s[n:]),
             'actual bounded startup words and argument extent')
        at=argc+2
        while at<n and s[at]:at+=1
        need(at<n,'actual environment terminator');at+=1
        aux={}
        while at+1<n and s[at]:
            need(s[at] not in aux,'unique actual auxiliary-vector key');aux[s[at]]=s[at+1];at+=2
        need(at+2==n and s[at:at+2]==(0,0) and aux.get(9)==MAIN and
             aux.get(33,0)>0 and aux[33]%4096==0,'complete actual auxv/entry/vDSO authority')
        return aux

    def rows(self):
        b=self.field(self.data,self.rt,'rows');t=self.types['rtc_native_row'if self.layout['record']=='rtc_native_record'else'rtc_row']
        return [b[i*t['bytes']:(i+1)*t['bytes']]for i in range(2)],t

    def event(self,row,t,image,components,lo,cap,native,i,aux,startup):
        if not native:row=self.field(row,t,'frame')
        t=self.types['rtc_native_row'];v=q(self.field(row,t,'h'))
        f=self.unchanged(self.field(row,t,'before'),self.field(row,t,'after'),image)
        pc=TAIL if i else TAIL-2
        need(v[:5]==(1,i,pc,pc,1) and v[5:8]==(0,0,0) and not any(v[12:24]+v[30:]) and
             f['greg'][16]==pc and f['h'][8]==pc and f['greg'][19]==21,'exact genuine syscall/next NX frame')
        self.envelope(f,lo,cap,native);f['si_addr_alias']=self.siginfo_alias(row,t,f)
        si=self.field(row,t,'siginfo_before');need(si==self.field(row,t,'siginfo_after')==
            f['uc'][v[24]-f['h'][3]:v[24]-f['h'][3]+128],'complete separate actual siginfo and owned raw UC alias')
        need(v[8:12]==((pc&~4095,4096,5,0)if native and image['case']!=15 else(0,0,0,0)),
             'only actual native mprotect call or no invented runtime query')
        seeded(self,f,components,image['case'],i,aux,image.get('request_profile',False))
        need(f['data']==memory(image,native,f['page'],aux,startup),'complete exact data/stack around original operation')
        pb=self.field(row,t,'private_before');pa=self.field(row,t,'private_after')
        need(pb==pa,'complete locally unchanged private output domain')
        if image['case']==4:
            need(v[28]==aux[33] and 0<v[29]<=65536 and v[29]%4096==0 and not any(pb[v[29]:]),'actual auxv-bound private vDSO extent')
            vh=struct.unpack_from('<16sHHIQQQIHHHHHH',pb)
            need(vh[0][:7]==b'\x7fELF\x02\x01\x01' and vh[1:4]==(3,62,1) and vh[9]==56 and
                 0<vh[10]<=16 and vh[5]+56*vh[10]<=4096,'complete actual private vDSO header')
            loads=[struct.unpack_from('<IIQQQQQQ',pb,vh[5]+56*j)for j in range(vh[10])]
            loads=[p for p in loads if p[0]==1]
            need(len(loads)==1 and loads[0][1:4]==(5,0,0) and
                 0<loads[0][5]==loads[0][6]<=65536 and (loads[0][6]+4095)&~4095==v[29],
                 'one complete unchanged RX vDSO mapping')
        else:need(v[28:30]==(0,0) and not any(pb),'no invented private domain')
        return f


def registers(c,i,aux,request_profile=False):
    need(type(request_profile)is bool,'fixed register request profile')
    r=[0x1122334455667700+n for n in range(16)]
    r[0]=16;r[4]=DATA+16320;r[6]={9:0x5400,10:0x5402,11:0x100005401,15:0x541b}.get(c,0x5401)
    if request_profile:r[6]={9:0x5412,10:0x5414,11:0x100005413,15:0x541b}.get(c,0x5413)
    r[7]={12:3,13:U64,14:0x100000001}.get(c,1)
    r[2]={1:0,2:ARENA,3:WORD,4:aux[33],15:WORD}.get(c,DATA+128)
    if i:r[0]=RESULT[c]&U64;r[1]=TAIL;r[11]=0xed7
    return r


def memory(image,native,page,aux,startup):
    page_ids(page);c=image['case'];b=bytearray.fromhex(image['data_hex'])
    for at,v in((16,int(native)),(24,1),(32,0),(80,aux[33]if c==4 else 0),(88,int(c==2)),
                (96,int(c in(7,8))),(104,int(c==8)),(112,startup),(16312,0xed7)):put(b,at,v)
    b[8192:12288]=page;return bytes(b)


def seeded(r,f,components,c,i,aux,request_profile=False):
    need(f['h'][9:11]==(0,0) and tuple(f['greg'][k]for k in GREG)==tuple(registers(c,i,aux,request_profile)) and
         f['greg'][17]==0x10ed7,'all exact actual GPR/flags/live selectors and original syscall inputs/result')
    fp=f['fp'];need(word(fp,512)&0xe7==0xe7 and all(o+n<=f['h'][2]-4 for o,n in components.values()),'complete actual seeded xstate')
    for reg in range(32):
        if reg<16:
            z=fp[160+reg*16:176+reg*16];o=components[2][0]+reg*16;z+=fp[o:o+16];o=components[6][0]+reg*32;z+=fp[o:o+32]
        else:o=components[7][0]+(reg-16)*64;z=fp[o:o+64]
        need(z==VECTORS[reg*64:reg*64+64],'all32 actual ZMM seeds')
    o,n=components[5];need(fp[o:o+n]==MASKS,'all8 actual K seeds')


def transition(r,b,a,c):
    expected=bytearray(b['uc'])
    for index,value in((13,RESULT[c]&U64),(14,TAIL),(3,0xed7),(16,TAIL),(22,TAIL)):
        put(expected,r.go+8*index,value)
    need(b['si_addr_alias']==a['si_addr_alias'],'same completely authenticated typed signal alias')
    put(expected,b['si_addr_alias'],TAIL)
    need(bytes(expected)==a['uc'] and b['fp']==a['fp'] and b['data']==a['data'] and b['page']==a['page'] and
         b['h'][:8]==a['h'][:8] and b['h'][9:]==a['h'][9:],
         'whole native syscall state: only exact RAX/RCX/R11/RIP/CR2/si_addr change')


def native(data,layout,image,pid,exit_status):
    c=image['case'];need(type(pid)is int and pid>0 and type(exit_status)is int and exit_status==0,'exact native subject exit')
    r=Reader(data,layout,'rtc_native_record');h=q(r.field(data,r.rt,'h'));count=1 if c==15 else 2
    need(h[:6]==(MAGIC,1,len(data),c,count,1) and h[6:8]==(0,0) and h[8:10]==(pid,pid) and
         h[10]&0xe7==0xe7 and h[11]>0 and h[12:14]==(131072,int(c==15)) and not any(h[14:22]+h[24:]),
         'complete native operation or explicitly before-operation-only FIONREAD prefix')
    aux=r.startup(h,True);rows,t=r.rows();components=r.components(r.field(data,r.rt,'xstate'))
    need(all(not any(x)for x in rows[count:]),'complete unused native rows')
    fs=[r.event(row,t,image,components,h[11],h[12],True,i,aux,h[22])for i,row in enumerate(rows[:count])]
    if count==2:transition(r,*fs,c)
    return dict(case=c,exit_status=0,events=count,actual_syscalls=int(c!=15),before_operation_prefix=int(c==15),
                result=RESULT[c],observed_cpus=[page_ids(f['page'])['cpu']for f in fs])


def _module(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

gate=_module('rtc_gate_prefixes','gate.py')


def gated(data,layout,image,pid,exit_status,capture):
    c=image['case'];injected=image['injected'];success=c<7 and not injected;count=2 if success else 0 if c>=16 else 1
    need(type(pid)is int and pid>0 and type(exit_status)is int and exit_status==(0 if success else 125),'exact gated subject outcome; required refusals stay125')
    r=Reader(data,layout,'rtc_record');h=q(r.field(data,r.rt,'h'));rows,t=r.rows()
    need(h[:6]==(MAGIC,1,len(data),c,r.ucn,t['bytes'])and h[6]&0xe7==0xe7 and
         h[7:15]==(1,0,1,exit_status,0 if success else 1207,0 if success else 16,count,injected)and
         h[15]>0 and h[16]==512*1024 and h[17]==h[18]and (h[17]>0 if c<16 else h[17]==0)and
         h[43:45]==(pid,pid)and h[45:48]==((0,1,0)if success else(1207,4,16))and not any(h[21:22]+h[48:]),'complete actual terminal/event/owner prefix, without completion from counts alone')
    hw=struct.unpack('<14I',r.field(data,r.rt,'hardware'))
    need(hw[:2]==(1,0)and hw[2]>=13 and hw[8]&0x18000000==0x18000000 and hw[11]&0x40010000==0x40010000,
         'actual required pre-arm CPUID/XSTATE hardware')
    aux=r.startup(h,False);image=dict(image,args=tuple(registers(c,0,aux,image.get('request_profile',False))[i]for i in(7,6,2,10,8,9)))
    need(all(not any(x)for x in rows[count:]),'unreached target rows remain completely empty')
    components=r.components(r.field(data,r.rt,'xstate'))
    fs=[r.event(row,t,image,components,h[15],h[16],False,i,aux,h[22])for i,row in enumerate(rows[:count])]
    if count==2:transition(r,*fs,c)
    ns='li2_rseq_native_state';I=r.integer;F=r.field;closed=None
    counts=('attempts','admissions','preentries','entries','closed','tls_refreshes')
    def pin(b):
        pt='li2_rseq_data';v=tuple(I(b,pt,k)for k in('address','page','allocation','generation','offset','pid','tid'))
        need(v[:2]==(AREA,PAGE)and v[2]>0 and v[3]>0 and v[4]%4096==0 and v[5:]==(pid,pid)and
             tuple(I(b,pt,k)for k in('attempted','complete','error','detail'))==(1,1,0,0),'actual complete pinned registration')
        m=F(b,pt,'maps');mt='li2_fetch_map_progress';o=F(m,mt,'observation');ot='li2_maps_observation'
        need(I(m,mt,'fd')<1<<31 and I(m,mt,'last_read')==I(m,mt,'close_result')==0 and
             I(m,mt,'bytes')>0 and I(m,mt,'rows')>0 and all(I(m,mt,k)==1 for k in('opened','close_started','closed'))and
             I(o,ot,'acquisition_id')>0 and I(o,ot,'mutation_epoch')>0 and I(o,ot,'handler_id')==I(o,ot,'kind')==0 and I(o,ot,'io_performed')==1,
             'complete fresh actual pin maps observation')
        return v,I(o,ot,'acquisition_id')
    for i,row in enumerate(rows[:count]):
        p=q(F(row,t,'permits'));b=F(row,t,'native_before');a=F(row,t,'native_after')
        need(p[:3]==p[4:7]==(0,0,0)and p[3]==p[7]>0,'no pending step/borrow/new admission at either observation seam')
        for state,phase in((b,2 if i==0 else 0),(a,0)):
            need(tuple(I(state,ns,k)for k in('phase','checking','first_error','unsafe_terminal','entry_checked','first_detail'))==(phase,0,0,0,1,0)and
                 tuple(I(state,ns,k)for k in('pid','tid','pc','address','page','registration_epoch','length','signature'))==
                 (pid,pid,MAIN+4096,AREA,PAGE,1,32,0x53053053)and
                 all(I(state,ns,k)==0 for k in('word_before','word_entry','word_after','fs_selector_entry','gs_selector_entry','fs_selector_after','gs_selector_after'))and
                 I(state,ns,'fs_before')==DATA+2048 and I(state,ns,'gs_before')==DATA+2304 and
                 I(state,ns,'native_admissions_before')==I(state,ns,'native_closed_before'),
                 'real helper native epoch has exact entry/zero/pin/TLS/phase provenance')
            values=tuple(I(state,ns,k)for k in counts);before_pin,acq=pin(F(state,ns,'before'))
            if phase==2:
                need(values[0]==values[1]==values[2]>0 and values[3]==values[4]==values[5]==values[0]-1 and
                     I(state,ns,'fs_after')==I(state,ns,'gs_after')==0 and not any(F(state,ns,'after')),
                     'one actual outstanding helper epoch before close')
            else:
                after_pin,after_acq=pin(F(state,ns,'after'))
                need(len(set(values))==1 and values[0]>0 and after_pin==before_pin and after_acq>acq and
                     I(state,ns,'fs_after')==DATA+2048 and I(state,ns,'gs_after')==DATA+2304,
                     'one verified native close and fresh TLS before old syscall owner')
        if i==0:
            need(F(b,ns,'before')==F(a,ns,'before')and I(a,ns,'closed')==I(b,ns,'closed')+1,'same retained native input and one actual close');closed=a
        else:need(b==a==closed,'no duplicate native owner during the second selected boundary')
        cl=F(row,t,'close');ct='li2_native_close';pages=1 if i==0 else 0
        need(I(cl,ct,'complete')==1 and I(cl,ct,'busy')==I(cl,ct,'first_error')==I(cl,ct,'first_detail')==0 and
             all(I(cl,ct,k)==pages for k in('pages','attempted','returned','closed','verified','sync_started','sync_returned'))and
             I(cl,ct,'last_address')==(MAIN+4096 if i==0 else 0)and I(cl,ct,'pid')==I(cl,ct,'tid')==pid and
             I(cl,ct,'sequence')>0 and all(I(cl,ct,k)==0 for k in('last_result','sync_result','first_error_address','cleanup_started','cleanup_complete','cleanup_attempted','cleanup_returned','cleanup_first_result','cleanup_sync_result')),
             'actual one-page entry close or later zero-page syscall close')
    cl=F(data,r.rt,'terminal_close');ct='li2_native_close'
    need(I(cl,ct,'sequence')>0 and I(cl,ct,'pid')==I(cl,ct,'tid')==pid and I(cl,ct,'complete')==1 and
         all(I(cl,ct,k)==0 for k in('pages','attempted','returned','closed','verified','last_address','busy','first_error','first_detail',
             'last_result','sync_result','first_error_address','sync_started','sync_returned','cleanup_started','cleanup_complete',
             'cleanup_attempted','cleanup_returned','cleanup_first_result','cleanup_sync_result')),
         'actual terminal zero-page verified close; failure is not relabelled completion')
    eb=F(data,r.rt,'effect_before');ea=F(data,r.rt,'effect_after')
    need(tuple(h[40:42])==((1,int(success))if count else(0,0)),'actual effect entry and separately completed frame commit')
    if count:
        need(eb==fs[0]['raw'],'effect entered with complete exact original NX frame/source/memory')
        if success:
            expected=bytearray(eb);uc=r.ft['fields']['uc']['offset']
            for index,value in((13,(-25)&U64),(14,TAIL),(3,0xed7),(16,TAIL),(17,0xed7)):
                put(expected,uc+r.go+8*index,value)
            need(bytes(expected)==ea,'same actual committed frame changes only original syscall ABI and logical RF removal')
        else:need(not any(ea),'refusal has no invented postcommit frame')
    else:need(not any(eb+ea),'initialization refusal never reaches source operation')
    terminal_source=F(data,r.rt,'terminal_source');terminal_data=F(data,r.rt,'terminal_data');page=F(data,r.rt,'terminal_page')
    need(terminal_source==bytes.fromhex(image['source_hex']),'entire actual source remains original through terminal')
    if count:
        page_ids(page);need(all(f['page']==page for f in fs)and terminal_data==memory(image,False,page,aux,h[22]),
             'whole terminal application output/stack/registration page unchanged by refused or ENOTTY ioctl')
    else:need(not any(page)and terminal_data==bytes.fromhex(image['data_hex']),'initial failure before all application writes/registration')
    prefix=gate.check(r,data,h,image,pid,capture,injected)
    gate.injections(r,data,h,image,injected)
    return dict(case=c,exit_status=exit_status,events=count,actual_syscalls=prefix['issued'],frame_commits=int(success),
                initial_refusal=int(c>=16),before_operation_refusal=int(c<16 and not success and not injected),
                observed_cpus=[page_ids(f['page'])['cpu']for f in fs],gate=prefix)


def pair(native_record,gated_record,native_output,gated_output,layout,image,npid,gpid,cpu,capture):
    need(type(cpu)is int and cpu>=0 and npid!=gpid and not image['injected'],'independent actual same-ELF pair')
    n=native(native_record,layout['native'],image,npid,0)
    g=gated(gated_record,layout['gated'],image,gpid,GATED_EXIT[image['case']],capture)
    need(native_output==gated_output==b'','no application output or changed capture-file data')
    compare(native_record,gated_record,layout,image,image,npid,gpid,cpu,n,g)
    return dict(case=image['case'],native=n,gated=g,qualified_pair=1,forwarded_pair=int(image['case']<7),
                required_refusal=int(image['case']>=7),full_frame_pairs=min(n['events'],g['events']))


def compare(native_record,gated_record,layout,nimage,gimage,npid,gpid,cpu,n,g):
    need(all(x==cpu for x in n['observed_cpus']+g['observed_cpus']),'every observed rseq CPU joins the sole allocated CPU')
    nr=Reader(native_record,layout['native'],'rtc_native_record');gr=Reader(gated_record,layout['gated'],'rtc_record')
    need(layout['native']['offsets']==layout['gated']['offsets']and layout['native']['siginfo']==layout['gated']['siginfo']and nr.ucn==gr.ucn,
         'same actual complete native/gated signal ABI')
    nrows,nt=nr.rows();grows,gt=gr.rows();o=nr.layout['offsets']
    for i in range(min(n['events'],g['events'])):
        nf=nr.frame(nr.field(nrows[i],nt,'before'),nimage)
        grow=gr.field(grows[i],gt,'frame');gf=gr.frame(gr.field(grow,'rtc_native_row','before'),gimage)
        need(nf['fp']==gf['fp'],'every actual FP byte equal across independent native/gated operation')
        nu,gu=bytearray(nf['uc']),bytearray(gf['uc'])
        for offset in(o['stack_sp'],o['stack_size'],o['fp_pointer']):put(nu,offset,0);put(gu,offset,0)
        if nimage['case']==4:put(nu,nr.go+12*8,0);put(gu,gr.go+12*8,0)
        need(nu==gu,'all UC bytes after only separately proven pointer/extent and auxv-vDSO argument joins')
        nd,gd=bytearray(nf['data']),bytearray(gf['data']);put(nd,16,0)
        for b in(nd,gd):
            put(b,112,0) # Each independently bound to its complete actual startup record.
            if nimage['case']==4:put(b,80,0)
            if gimage['injected']:put(b,120,0) # Exact source literal, never an expected runtime effect.
            struct.pack_into('<I',b,8192+88,0)
        ni,gi=page_ids(nf['page']),page_ids(gf['page']);need(ni['cpu']==gi['cpu']==cpu and ni['node']==gi['node'],'actual same-CPU/node kernel observations')
        np,gp=bytearray(nf['page']),bytearray(gf['page']);struct.pack_into('<I',np,88,0);struct.pack_into('<I',gp,88,0)
        need(nd==gd and np==gp,'complete cross-lane memory/page equality after only independent launch/kernel identities')
        ntp=nr.field(nrows[i],nt,'private_before');gtp=gr.field(grow,'rtc_native_row','private_before')
        need(ntp==gtp,'whole private argument mapping bytes, without address-based content exemption')


def control(native_record,gated_record,layout,nimage,image,npid,gpid,cpu,capture):
    need(nimage['case']==image['case']==0 and not nimage['injected']and 1<=image['injected']<=16 and
         nimage['source_hex']==image['source_hex'],'injected control uses exact same original case0 code')
    n=native(native_record,layout['native'],nimage,npid,0);g=gated(gated_record,layout['gated'],image,gpid,125,capture)
    compare(native_record,gated_record,layout,nimage,image,npid,gpid,cpu,n,g)
    return dict(injected=image['injected'],operation_status='failed',exit_status=125,before_frames=g['events'],
                actual_syscalls=g['actual_syscalls'],frame_commits=0,gate=g['gate'])
