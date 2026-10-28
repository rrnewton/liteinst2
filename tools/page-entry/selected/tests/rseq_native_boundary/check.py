"""Four fixed real native/registered-boundary pairs; no synthetic signal credit."""
import hashlib,importlib.util,struct
from pathlib import Path
from page_selected import need
_SPEC=importlib.util.spec_from_file_location('rnb_old_full_frame',Path(__file__).resolve().parent.parent/'rseq_native/check.py')
old=importlib.util.module_from_spec(_SPEC);_SPEC.loader.exec_module(old)
MAIN,BODY,TAIL,GUARD,DATA=old.MAIN,old.BODY,old.TAIL,old.GUARD,old.DATA
ARENA,PAGE,AREA,WORD=old.ARENA,old.PAGE,old.AREA,old.WORD
MAGIC=0x31444e424e535252
GREG,VECTORS,MASKS=old.GREG,old.VECTORS,old.MASKS
q,word,put,page_ids=old.q,old.word,old.put,old.page_ids
NATIVE_EXIT=GATED_EXIT=(0,0,0,0)
EVENTS=(3,4,2,3)
RETRIES=(1,1,0,1)

def elf(data,interpreter,case,native_policy):
    need(type(case)is int and 0<=case<4 and type(data)is bytes and len(data)>=64,'fixed real fixture ELF')
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
    expected={'_start':MAIN,'rn_seed':MAIN+4096,'rn_body':BODY,'rn_tail':TAIL,'rn_guard':GUARD,'rn_guard_write':GUARD+1,
      'rn_data':DATA,'rn_data_end':DATA+16384,'rn_case':DATA+8,'rn_mode':DATA+16,'rn_active':DATA+24,
      'rn_registration_result':DATA+32,'rn_rounds':DATA+40,'rn_commit':DATA+48,'rn_abort_seen':DATA+56,
      'rn_final_fs':DATA+64,'rn_final_gs':DATA+72,'rn_store':DATA+128,'rn_descriptor':DATA+256,
      'rn_vectors':DATA+512,'rn_masks':DATA+2560,'rn_live_vectors':DATA+4096,'rn_live_masks':DATA+6144,
      'rn_live_gpr':DATA+6208,'rn_live_flags':DATA+6336,'rn_live_selectors':DATA+6344,'rn_rseq_initial':DATA+8192,'rn_stack_top':DATA+16320}
    expected.update(rn_call_return=DATA+80,rn_call_rsp=DATA+88)
    need(all(symbols[k]==v for k,v in expected.items()),'exact emitted source/data/capture geometry')
    source=read(MAIN,24576);initial=read(DATA,16384)
    need(q(initial[:96])==(old.MAGIC,case,0,0,(1<<64)-1,0,0,0,0,0,0,0) and initial[512:2624]==VECTORS+MASKS,'literal independent scalar/vector/mask seeds')
    need(read(symbols['rn_setup_syscall'],2)==bytes.fromhex('0f05') and read(TAIL+256,2)==bytes.fromhex('0fa2'),'actual registration and dirty boundary barrier')
    need(native_policy(read(MAIN+4096-14,4096+28))==0 and native_policy(read(BODY-14,4096+28))==0,'unchanged whole-page and halo policy without exemptions')
    need(all(native_policy(read(p,4096))!=0 for p in(MAIN,TAIL,GUARD)),'setup/continuation/callee remain genuinely dirty')
    fault=TAIL-(5 if case==2 else 2);ret=TAIL+(3 if case==1 else 0 if case==2 else 1)
    start=TAIL-6 if case==3 else fault;abort=TAIL-14 if case==3 else BODY+256
    need(symbols['rn_fault']==fault and symbols['rn_return']==ret and symbols['rn_cs_start']==start and
         symbols['rn_cs_end']==ret and symbols['rn_abort']==abort and
         struct.unpack_from('<IIQQQ',initial,256)==(0,0,start,ret-start,abort) and not start<=abort<ret,
         'literal emitted descriptor and outside-CS abort target')
    need(read(abort-4,4)==bytes.fromhex('53300553') and read(abort,1)==b'\xe9' and
         abort+5+struct.unpack('<i',read(abort+1,4))[0]==GUARD,'actual registered signature and direct abort JMP')
    encoding=bytes.fromhex('e8fd0f0000'if case==1 else'e800100000'if case==2 else'4889c3')
    need(read(fault,len(encoding))==encoding,'fixed real split/ending instruction bytes')
    if case==3:need(read(start,4)==bytes.fromhex('48894708') and ret-start==7 and TAIL-abort==14,'publication in actual interval and current-PC boundary limit')
    target=GUARD if case in(0,3)else symbols['rn_capture']
    need(read(GUARD,1)==b'\x90','exact one-byte old-step NOP at the required callee/continuation NX PC')
    jump=ret+int(case in(1,2))
    if case in(1,2):need(read(ret,1)==b'\x90','exact one-byte old-step NOP at the unchanged CALL return PC')
    need(read(jump,1)==b'\xe9' and jump+5+struct.unpack('<i',read(jump+1,4))[0]==target,'exact original return continuation after the identity NOP')
    if case in(1,2):
        callee=GUARD+1
        need(read(callee,7)==bytes.fromhex('4c8b1c244c891d') and callee+11+struct.unpack('<i',read(callee+7,4))[0]==DATA+80 and
             read(callee+11,3)==bytes.fromhex('488925') and callee+18+struct.unpack('<i',read(callee+14,4))[0]==DATA+88 and
             read(callee+18,1)==b'\xc3','actual callee observes one pushed word/RSP then genuine RET')
    need(read(symbols['rn_restorer'],9)==bytes.fromhex('b80f0000000f050f0b'),'actual rt_sigreturn restorer')
    interp=interpreter.read_bytes();ih=struct.unpack_from('<16sHHIQQQIHHHHHH',interp)
    entry=bytes.fromhex('0fa248b8')+struct.pack('<Q',MAIN)+bytes.fromhex('ffe0')
    need(len(interp)==8192 and ih[1:4]==(3,62,1) and ih[4]==4096 and interp[4096:4096+len(entry)]==entry and not any(interp[4096+len(entry):]),'unchanged real first-interpreter CPUID and handoff')
    return dict(case=case,entry=MAIN,symbols=symbols,source_hex=source.hex(),data_hex=initial.hex(),source_sha256=hashlib.sha256(source).hexdigest(),data_sha256=hashlib.sha256(initial).hexdigest())

def geometry(c):
    p=TAIL-14 if c==3 else TAIL-2
    prefix=[]if c==2 else[(p,TAIL),(p,p)]
    return prefix+[(GUARD,GUARD)]+([(TAIL+(3 if c==1 else 0),TAIL+(3 if c==1 else 0))]if c in(1,2)else[])

class Reader(old.Reader):
    def __init__(self,data,layout,record):
        self.data,self.types,self.layout=data,layout['types'],layout
        self.rt=self.types[record];self.ft=self.types['rn_frame'];self.ucn=layout['uc_bytes'];self.go=layout['offsets']['greg'];self.fo=layout['offsets']['fp_pointer']
        need(layout['record']==record and len(data)==self.rt['bytes']<16<<20 and 0<self.ucn<=2048 and self.go+23*8<=self.ucn and self.fo+8<=self.ucn,'complete actual DWARF/record extent')
        si=layout['siginfo']
        need(all(type(x)is int for x in (si['bytes'],*si['offsets'].values(),*si['widths'].values())) and
             si==dict(bytes=128,offsets=dict(si_signo=0,si_errno=4,si_code=8,si_addr=16),widths=dict(si_signo=4,si_errno=4,si_code=4,si_addr=8)),
             'actual complete native x86-64 siginfo ABI')
        frame=self.ft['bytes'];forms={'rn_frame':dict(h=512,uc=2048,fp=65536,source=24576,data=16384,rseq=4096)}
        if record=='rnb_native_record':
            forms['rnb_native_row']=dict(h=256,before=frame,after=frame)
            forms[record]=dict(h=512,xstate=128,rows=4*self.types['rnb_native_row']['bytes'])
        else:
            ns=self.types['li2_rseq_native_state']['bytes'];bs=self.types['li2_rseq_native_boundary_state']['bytes'];rs=self.types['li2_rseq_state']['bytes']
            forms['rnb_row']=dict(h=256,permits=384,before=frame,after=frame,guard_before=frame,guard_after=frame,
                native_before=ns,native_after=ns,boundary_before=bs,boundary_after=bs,guard_state=rs,close=self.types['li2_native_close']['bytes'])
            forms[record]=dict(h=512,xstate=128,hardware=56,rows=4*self.types['rnb_row']['bytes'],terminal_native=ns,
                terminal_boundary=bs,terminal_rseq=rs,terminal_source=24576,terminal_data=16384,terminal_page=4096)
        for name,fields in forms.items():
            shape=self.types[name];at=0
            need(set(shape['fields'])==set(fields),'exact complete observation field inventory '+name)
            for key,size in fields.items():
                need(shape['fields'][key]==dict(offset=at,bytes=size),'contiguous actual field '+name+'.'+key);at+=size
            need(shape['bytes']==at,'complete record extent without ignored padding '+name)

    def siginfo_alias(self,row,st,f):
        v=q(self.field(row,st,'h'));si=self.layout['siginfo'];offsets=si['offsets']
        need(v[24]==v[25]>0 and v[26]==si['bytes'] and v[27]==offsets['si_addr'],
             'actual entry/return siginfo pointer and sizeof/offsetof identity')
        offset=v[24]-f['h'][3]
        # The retained native x86-64 kernel ucontext ends after its 8-byte mask;
        # its following siginfo overlaps the larger libc ucontext_t copy.
        need(offset==self.layout['offsets']['mask']+8 and 0<=offset<=self.ucn-si['bytes'],
             'actual complete siginfo follows the kernel mask inside retained libc UC')
        expected=bytearray(si['bytes'])
        for key,value in (('si_signo',f['h'][5]),('si_errno',f['h'][7]),('si_code',f['h'][6])):
            struct.pack_into('<i',expected,offsets[key],value)
        put(expected,offsets['si_addr'],f['h'][8])
        need(f['uc'][offset:offset+si['bytes']]==expected,
             'entire actual siginfo alias including header padding and unused union bytes')
        return offset+offsets['si_addr']

def registers(c,i,terminal=False):
    r=[0x1122334455667700+n for n in range(16)];r[0]=DATA+256;r[4]=DATA+16320;r[7]=AREA
    if c==0 and (i==2 or terminal):r[3]=DATA+256
    if c in(1,2):
        callee=2 if c==1 else 0
        if i==callee and not terminal:r[4]-=8
        if i>callee or terminal:r[11]=TAIL+(3 if c==1 else 0)
    return r

def memory(image,native,page,i,terminal=False):
    c=image['case'];page_ids(page);b=bytearray.fromhex(image['data_hex'])
    for at,value in((16,int(native)),(24,1),(32,0),(40,int(terminal))):put(b,at,value)
    b[8192:12288]=page;put(b,16312,0xed7)
    if c in(1,2):
        callee=2 if c==1 else 0;ret=TAIL+(3 if c==1 else 0)
        if i>=callee and not terminal:put(b,16312,ret)
        if i>callee or terminal:put(b,80,ret);put(b,88,DATA+16312)
    if terminal:
        if c==3:put(b,56,0x44556677)
        put(b,64,DATA+2048);put(b,72,DATA+2304)
        b[4096:6208]=VECTORS+MASKS;b[6208:6336]=struct.pack('<16Q',*registers(c,i,True));put(b,6336,0xed7)
        b[6344:6356]=struct.pack('<6H',0x33,0x2b,0,0,0,0)
    return bytes(b)

def seeded(r,f,components,c,i):
    need(f['h'][9:11]==(0,0) and tuple(f['greg'][n]for n in GREG)==tuple(registers(c,i)) and f['greg'][17]==0x10ed7,'literal all-GPR/flags/live-selector state')
    fp=f['fp'];need(word(fp,512)&0xe7==0xe7 and all(o+n<=f['h'][2]-4 for o,n in components.values()),'complete actual seeded components')
    for reg in range(32):
        if reg<16:
            z=fp[160+reg*16:176+reg*16];o=components[2][0]+reg*16;z+=fp[o:o+16];o=components[6][0]+reg*32;z+=fp[o:o+32]
        else:o=components[7][0]+(reg-16)*64;z=fp[o:o+64]
        need(z==VECTORS[reg*64:reg*64+64],'all actual seeded ZMM bytes')
    o,n=components[5];need(fp[o:o+n]==MASKS,'all eight actual mask seeds')

def frames(r,rows,st,image,components,lo,cap,native):
    c=image['case'];result=[]
    need(len(rows)==4*st['bytes'] and not any(rows[EVENTS[c]*st['bytes']:]),'complete fixed row capacity and unused tails')
    for i,(pc,address)in enumerate(geometry(c)):
        row=rows[i*st['bytes']:(i+1)*st['bytes']]
        f=r.unchanged(r.field(row,st,'before'),r.field(row,st,'after'),image)
        need(f['greg'][16]==pc and f['h'][8]==address and f['greg'][19]==21,'actual exact sequential current-PC/CR2 geometry')
        r.envelope(f,lo,cap,native);seeded(r,f,components,c,i)
        f['si_addr_alias']=r.siginfo_alias(row,st,f)
        need(f['data']==memory(image,native,f['page'],i),'complete literal data and stack before/after event')
        result.append(f)
    need(all(f['fp']==result[0]['fp'] for f in result),'whole actual FP state conserved through all original operations')
    if c!=2:
        a,b=result[:2];ua,ub=bytearray(a['uc']),bytearray(b['uc'])
        put(ua,r.go+22*8,0);put(ub,r.go+22*8,0)
        need(a['si_addr_alias']==b['si_addr_alias'],'same authenticated cross-event siginfo alias field')
        put(ua,a['si_addr_alias'],0);put(ub,b['si_addr_alias'],0)
        need(ua==ub and a['fp']==b['fp'] and a['data']==b['data'] and a['page']==b['page'] and
             a['h'][:8]==b['h'][:8] and a['h'][9:]==b['h'][9:],
             'two genuine frames identical except actual CR2/siginfo address; no intervening operation')
    return result

def native(data,layout,image,pid,exit_status):
    c=image['case'];need(type(pid)is int and pid>0 and type(exit_status)is int and exit_status==0,'actual successful native subject')
    r=Reader(data,layout,'rnb_native_record');h=q(r.field(data,r.rt,'h'));st=r.types['rnb_native_row'];rows=r.field(data,r.rt,'rows')
    need(h[:6]==(MAGIC,2,len(data),c,EVENTS[c],1) and h[6:8]==(0,0) and h[8:10]==(pid,pid) and
         h[10]&0xe7==0xe7 and h[11]>0 and h[12]==131072 and not any(h[13:]),'exact complete native identity and no partial success')
    fs=frames(r,rows,st,image,r.components(r.field(data,r.rt,'xstate')),h[11],h[12],True)
    for i,(pc,a)in enumerate(geometry(c)):
        row=rows[i*st['bytes']:(i+1)*st['bytes']];v=q(r.field(row,st,'h'));calls=[]
        if c!=2 and i==0:calls=[(BODY,4096,1,0)]
        elif c!=2 and i==1:calls=[(BODY,4096,5,0),(TAIL,4096,5,0)]
        elif (c==1 and i==2)or(c==2 and i==0):calls=[(TAIL if c==1 else BODY,4096,1,0),(GUARD,4096,5,0)]
        elif c in(1,2):calls=[(TAIL,4096,5,0)]
        else:calls=[(GUARD,4096,5,0)]
        need(v[:5]==(1,i,pc,a,1) and not any(v[5:8]) and v[8:8+4*len(calls)]==sum(calls,()) and
             not any(v[8+4*len(calls):24]+v[28:]),'exact successful native close/reopen calls and complete unused prefix')
    return dict(case=c,exit_status=0,events=len(fs),genuine_refaults=RETRIES[c],observed_cpus=[page_ids(f['page'])['cpu']for f in fs])

def gated(data,layout,image,pid,exit_status):
    c=image['case'];need(type(pid)is int and pid>0 and type(exit_status)is int and exit_status==0,'actual successful gated subject')
    r=Reader(data,layout,'rnb_record');h=q(r.field(data,r.rt,'h'));st=r.types['rnb_row'];rows=r.field(data,r.rt,'rows')
    need(h[:6]==(MAGIC,2,len(data),c,r.ucn,st['bytes']) and h[6]&0xe7==0xe7 and h[7:15]==(1,0,1,0,0,0,EVENTS[c],1) and
         h[15]>0 and h[16]==512*1024 and h[17]==h[18]>0 and not any(h[19:]),'complete actual successful terminal and balanced lifecycle counts')
    hw=struct.unpack('<14I',r.field(data,r.rt,'hardware'))
    need(hw[:2]==(1,0) and hw[2]>=13 and hw[8]&0x18000000==0x18000000 and hw[11]&0x40010000==0x40010000,'actual required pre-arm hardware')
    fs=frames(r,rows,st,image,r.components(r.field(data,r.rt,'xstate')),h[15],h[16],False)
    I=r.integer;identity=None
    def maps(b):
        t='li2_fetch_map_progress'
        need(I(b,t,'fd')<1<<31 and I(b,t,'last_read')==I(b,t,'close_result')==0 and I(b,t,'bytes')>0 and I(b,t,'rows')>0 and
             all(I(b,t,k)==1 for k in('opened','close_started','closed')),'complete actual direct maps descriptor custody')
        o=r.field(b,t,'observation');ot='li2_maps_observation'
        need(I(o,ot,'acquisition_id')>0 and I(o,ot,'handler_id')==0 and I(o,ot,'mutation_epoch')>0 and
             I(o,ot,'kind')==0 and I(o,ot,'io_performed')==1,'fresh direct observation, no inferred phase reuse')
        return I(o,ot,'acquisition_id')
    def pin(b):
        nonlocal identity
        t='li2_rseq_data';v=tuple(I(b,t,k)for k in('address','page','allocation','generation','offset','pid','tid'))
        need(v[:2]==(AREA,PAGE) and v[2]>0 and v[3]>0 and v[4]%4096==0 and v[5:]==(pid,pid) and
             I(b,t,'attempted')==I(b,t,'complete')==1 and I(b,t,'error')==I(b,t,'detail')==0,'complete exact registered data pin')
        if identity is None:identity=v
        need(v==identity,'same actual registration allocation/generation/offset')
        return maps(r.field(b,t,'maps'))
    def registration(b,t):
        need(tuple(I(b,t,k)for k in('pid','tid','address','page','length','signature'))==(pid,pid,AREA,PAGE,32,0x53053053),
             'actual fixed registration and singleton process identity')
    def close(b,pages,address):
        t='li2_native_close'
        need(I(b,t,'sequence')>0 and I(b,t,'allocation_epoch')>0 and I(b,t,'generation_epoch')>0 and I(b,t,'records_epoch')>0 and
             I(b,t,'pid')==I(b,t,'tid')==pid and all(I(b,t,k)==pages for k in('pages','attempted','returned','closed','verified')) and
             I(b,t,'last_address')==address and I(b,t,'complete')==1 and
             I(b,t,'sync_started')==I(b,t,'sync_returned')==pages and
             all(I(b,t,k)==0 for k in('busy','first_error','first_error_address','last_result','sync_result','first_detail',
                 'cleanup_started','cleanup_complete','cleanup_attempted','cleanup_returned','cleanup_first_result','cleanup_sync_result')),
             'complete exact verified close, not best-effort cleanup')
        before=maps(r.field(b,t,'before'));after=maps(r.field(b,t,'after'))
        need(after>before,'actual distinct fresh before/after close observations')
    counts=('attempts','admissions','preentries','entries','closed','tls_refreshes')
    def ns(b,phase):
        t='li2_rseq_native_state';registration(b,t);pin(r.field(b,t,'before'))
        need(I(b,t,'registration_epoch')==1 and I(b,t,'phase')==phase and I(b,t,'entry_checked')==1 and
             all(I(b,t,k)==0 for k in('checking','first_error','unsafe_terminal','first_detail','word_before','word_entry','word_after',
                 'fs_selector_entry','gs_selector_entry','fs_selector_after','gs_selector_after')) and
             I(b,t,'native_admissions_before')==I(b,t,'native_closed_before') and
             I(b,t,'fs_before')==DATA+2048 and I(b,t,'gs_before')==DATA+2304,'exact registered native phase/word/TLS prefix')
        values=tuple(I(b,t,k)for k in counts)
        if phase==2:
            need(values[0]==values[1]==values[2]>0 and values[3]==values[4]==values[5]==values[0]-1 and
                 I(b,t,'fs_after')==I(b,t,'gs_after')==0 and not any(r.field(b,t,'after')),'one outstanding native epoch, no invented post-observation')
        else:
            need(len(set(values))==1 and values[0]>0 and I(b,t,'fs_after')==DATA+2048 and I(b,t,'gs_after')==DATA+2304,'one counted complete native epoch and fresh actual TLS')
            pin(r.field(b,t,'after'))
        return values
    bc=('attempts','preentries','entries','observations','tls_refreshes','completed')
    retained=None;closed_ns=None;last_close=None
    for i,(pc,a)in enumerate(geometry(c)):
        row=rows[i*st['bytes']:(i+1)*st['bytes']];v=q(r.field(row,st,'h'));p=q(r.field(row,st,'permits'))
        epoch=i==0 or(c!=2 and i==1);refault=c!=2 and i==0;guard=c!=2 and i==1
        need(v[:8]==(1,i,pc,a,1,int(refault),int(epoch),int(refault)) and v[8:11]==(int(guard),int(guard),0) and not any(v[11:24]+v[28:]),
             'actual fetch and epoch READY/REFAULT returns; no fabricated owner call')
        need(p[:3]==p[12:15]==(0,0,0) and p[3:10]==p[15:22] and p[10]==p[22] and p[23]>=p[11],
             'no old execution permit or new native admission while returning the unchanged frame')
        before=r.field(row,st,'native_before');after=r.field(row,st,'native_after')
        vb=ns(before,2 if i==0 else 3 if guard else 0);va=ns(after,3 if refault else 0)
        need(I(before,'li2_rseq_native_state','pc')==I(after,'li2_rseq_native_state','pc')==BODY and
             r.field(before,'li2_rseq_native_state','before')==r.field(after,'li2_rseq_native_state','before'),'same original admitted BODY and complete input pin')
        if i==0:
            need(va[0]==vb[0] and va[4]==vb[4]+1 and p[10]==p[11]+1 and p[22]==p[23],
                 'actual first event closes the one outstanding native page once')
            closed_ns=after
        elif guard:
            changed=bytearray(before);f=r.types['li2_rseq_native_state']['fields']['phase']
            changed[f['offset']:f['offset']+f['bytes']]=bytes(f['bytes'])
            need(before==closed_ns and bytes(changed)==after and p[10]==p[11]==p[22]==p[23],
                 'second genuine event only consumes original CLOSING state; no duplicate epoch count')
        else:need(before==after==closed_ns and p[10]==p[11]==p[22]==p[23],'no second native admission or duplicated epoch count')
        bb=r.field(row,st,'boundary_before');ba=r.field(row,st,'boundary_after');bt='li2_rseq_native_boundary_state'
        cl=r.field(row,st,'close')
        if c==2:
            need(not any(bb+ba),'CALL ending at boundary never creates a retry token')
            if i==0:close(cl,1,BODY);last_close=cl
            else:need(cl==last_close,'no invented second native close on ordinary continuation')
        else:
            if i==0:need(not any(bb),'first boundary attempt has no prior token')
            for token,phase,cs in((ba,2,(1,0,0,0,0,0)),)if i==0 else((bb,2,(1,1,0,0,0,0)),(ba,0,(1,1,1,1,1,1)))if i==1 else((bb,0,(1,1,1,1,1,1)),(ba,0,(1,1,1,1,1,1))):
                registration(token,bt)
                need(I(token,bt,'phase')==phase and I(token,bt,'first_error')==I(token,bt,'first_detail')==0 and
                     I(token,bt,'entry_checked')==int(i!=0) and tuple(I(token,bt,k)for k in bc)==cs and
                     tuple(I(token,bt,k)for k in('pc','fault_address','admitted_page','registration_epoch'))==(geometry(c)[0][0],TAIL,BODY,1) and
                     all(I(token,bt,k)==0 for k in('word_first','word_entry','word_after','fs_selector_first','gs_selector_first',
                         'fs_selector_entry','gs_selector_entry','fs_selector_after','gs_selector_after')) and
                     I(token,bt,'fs_first')==DATA+2048 and I(token,bt,'gs_first')==DATA+2304 and
                     I(token,bt,'native_admissions')==I(token,bt,'native_closed')==p[10],
                     'exact retained retry token/current kernel PC/registration/zero and actual one-page count')
                pin(r.field(token,bt,'first_data'));first=r.field(token,bt,'first_close');close(first,1,BODY)
                if cs[-1]:
                    need(I(token,bt,'fs_second')==DATA+2048 and I(token,bt,'gs_second')==DATA+2304,'fresh actual unchanged second TLS')
                    need(pin(r.field(token,bt,'second_data'))>pin(r.field(token,bt,'first_data')),'separate actual second data observation')
                    second=r.field(token,bt,'second_close');close(second,0,0)
                    need(I(second,'li2_native_close','sequence')==I(first,'li2_native_close','sequence')+1 and
                         all(I(second,'li2_native_close',k)==I(first,'li2_native_close',k)for k in('allocation_epoch','generation_epoch','transactions_epoch','records_epoch')),
                         'zero-page second close follows exact one-page close without lifecycle mutation')
                else:need(not any(r.field(token,bt,'second_data')+r.field(token,bt,'second_close')) and I(token,bt,'fs_second')==I(token,bt,'gs_second')==0,
                          'pending token has no invented second observation')
            need(cl==r.field(ba,bt,'first_close'if i==0 else'second_close'),'row close is actual first/second retained owner close')
            if i==1:
                retained=ba;closed_ns=after
                # The second pure entry changes only its three documented fields.
                prior=r.field(rows[:st['bytes']],st,'boundary_after');changed=bytearray(prior)
                for key,value in(('preentries',1),('entry_checked',1)):
                    f=r.types[bt]['fields'][key];changed[f['offset']:f['offset']+f['bytes']]=value.to_bytes(f['bytes'],'little')
                need(bytes(changed)==bb,'actual pending token carried unchanged across genuine signal return')
            if i>1:need(bb==ba==retained,'consumed token remains exact; no duplicate retry')
        if guard:
            gf=r.unchanged(r.field(row,st,'guard_before'),r.field(row,st,'guard_after'),image)
            need(gf['raw']==fs[i]['raw'] and p[24:36]==p[36:48] and p[24:27]==(0,0,301),
                 'unchanged full actual pre-instruction frame/source/stack with held borrow and no execution permit')
            gs=r.field(row,st,'guard_state');gt='li2_rseq_state';registration(gs,gt);pin(r.field(gs,gt,'data'))
            code,length,policy=(693,5,2)if c==1 else(282,3,1)if c==0 else(696,5,1)
            first,end=(DATA+16312,DATA+16320)if c==1 else(0,0)
            need(I(gs,gt,'initialized')==I(gs,gt,'registered')==I(gs,gt,'held')==1 and I(gs,gt,'phase')==3 and
                 I(gs,gt,'first_error')==I(gs,gt,'first_detail')==0 and I(gs,gt,'epoch')==1 and
                 I(gs,gt,'tls_attempted')==I(gs,gt,'tls_complete')==1 and I(gs,gt,'fs_result')==I(gs,gt,'gs_result')==0 and
                 I(gs,gt,'fs_base')==DATA+2048 and I(gs,gt,'gs_base')==DATA+2304 and
                 tuple(I(gs,gt,k)for k in('last_pc','last_code','last_policy','last_first','last_end'))==(pc,code,policy,first,end) and
                 struct.unpack('<4Q4I',r.field(gs,gt,'last_footprint'))==(pc,pc+length,first,end,1,policy,code,length),
                 'actual original typed NONE/RANGE8 guard before promoted MOV/CALL/JMP execution')
        else:need(not any(r.field(row,st,'guard_before')+r.field(row,st,'guard_after')+r.field(row,st,'guard_state')) and not any(p[24:]),'no invented footprint call or frame')
    terminal=r.field(data,r.rt,'terminal_native');ns(terminal,0)
    need(tuple(I(terminal,'li2_rseq_native_state',k)for k in counts)[0]>=va[0] and
         I(terminal,'li2_rseq_native_state','pc')//4096==(MAIN+4096)//4096,'final real capture-page epoch is completely closed')
    token=r.field(data,r.rt,'terminal_boundary')
    need(token==(retained if c!=2 else bytes(len(token))),'terminal pending token consumed exactly once or never created')
    rs=r.field(data,r.rt,'terminal_rseq');registration(rs,'li2_rseq_state');pin(r.field(rs,'li2_rseq_state','data'))
    need(tuple(I(rs,'li2_rseq_state',k)for k in('initialized','registered','held','phase','first_error','first_detail','epoch'))==(1,1,1,3,0,0,1) and
         I(rs,'li2_rseq_state','tls_attempted')==I(rs,'li2_rseq_state','tls_complete')==1 and
         I(rs,'li2_rseq_state','fs_result')==I(rs,'li2_rseq_state','gs_result')==0 and
         I(rs,'li2_rseq_state','fs_base')==DATA+2048 and I(rs,'li2_rseq_state','gs_base')==DATA+2304,'complete terminal registration and actual refreshed TLS')
    page=r.field(data,r.rt,'terminal_page');page_ids(page)
    need(r.field(data,r.rt,'terminal_source')==bytes.fromhex(image['source_hex']) and
         r.field(data,r.rt,'terminal_data')==memory(image,False,page,EVENTS[c],True),'complete terminal source/data/stack ownership')
    need(all(f['page']==page for f in fs),'same-process complete rseq page remains exact')
    return dict(case=c,exit_status=0,events=len(fs),registered_retries=RETRIES[c],pending=0,
                observed_cpus=[page_ids(f['page'])['cpu']for f in fs]+[page_ids(page)['cpu']])

def output(data,image,native):
    need(len(data)==20480,'complete actual data and registered-page output')
    actual,page=data[:16384],data[16384:];ids=page_ids(page)
    need(actual[8192:12288]==page and actual==memory(image,native,page,EVENTS[image['case']],True),
         'complete independent live state/stack/CALL/abort result and same initial/final page')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),kernel_ids=ids,live_gprs=16,live_vectors=32,live_masks=8,flags=0xed7)

def pair(native_record,gated_record,native_output,gated_output,layout,image,native_pid,gated_pid,cpu):
    need(type(cpu)is int and cpu>=0 and native_pid!=gated_pid,'independent actual subjects and reserved CPU')
    n=native(native_record,layout['native'],image,native_pid,0);g=gated(gated_record,layout['gated'],image,gated_pid,0)
    no=output(native_output,image,True);go=output(gated_output,image,False)
    need(all(x==cpu for x in n['observed_cpus']+g['observed_cpus']) and no['kernel_ids']['cpu']==go['kernel_ids']['cpu']==cpu,
         'every actual recorded and output CPU equals independent affinity authority')
    nr=Reader(native_record,layout['native'],'rnb_native_record');gr=Reader(gated_record,layout['gated'],'rnb_record')
    need(layout['native']['offsets']==layout['gated']['offsets'] and layout['native']['siginfo']==layout['gated']['siginfo'] and nr.ucn==gr.ucn,'same real complete signal ABI')
    nrows=nr.field(native_record,nr.rt,'rows');grows=gr.field(gated_record,gr.rt,'rows')
    nt=nr.types['rnb_native_row'];gt=gr.types['rnb_row'];o=nr.layout['offsets']
    for i in range(EVENTS[image['case']]):
        nf=nr.frame(nr.field(nrows[i*nt['bytes']:(i+1)*nt['bytes']],nt,'before'),image)
        gf=gr.frame(gr.field(grows[i*gt['bytes']:(i+1)*gt['bytes']],gt,'before'),image)
        need(nf['fp']==gf['fp'],'complete native/gated FP equality including x87/MXCSR and all extended bytes')
        nu,gu=bytearray(nf['uc']),bytearray(gf['uc'])
        for offset in(o['stack_sp'],o['stack_size'],o['fp_pointer']):put(nu,offset,0);put(gu,offset,0)
        need(nu==gu,'all UC bytes equal after three separately validated pointer/extent identities')
        nd,gd=bytearray(nf['data']),bytearray(gf['data']);put(nd,16,0)
        ni,gi=page_ids(nf['page']),page_ids(gf['page']);need(ni['cpu']==gi['cpu'] and ni['node']==gi['node'],'actual kernel CPU/node join')
        struct.pack_into('<I',nd,8192+88,0);struct.pack_into('<I',gd,8192+88,0)
        np,gp=bytearray(nf['page']),bytearray(gf['page']);struct.pack_into('<I',np,88,0);struct.pack_into('<I',gp,88,0)
        need(nd==gd and np==gp,'complete lane memory/page equality with only actual mode/mm_cid differences')
    return dict(case=image['case'],native=n,gated=g,native_output=no,gated_output=go,successful_pair=1,
                genuine_refault_pairs=RETRIES[image['case']],call_single_push=int(image['case']in(1,2)))
