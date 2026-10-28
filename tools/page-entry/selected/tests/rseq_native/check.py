"""Literal native/registered-native semantics and complete real-frame records.

No reader derives expected register/vector/store values from captured after
state. Kernel-owned ID words are typed per-process observations, not wildcards.
"""
import hashlib,struct
from page_selected import need
MAIN=0x200401000
BODY,TAIL,GUARD,DATA=MAIN+8192,MAIN+12288,MAIN+16384,MAIN+24576
ARENA=0x300000000
PAGE,AREA,WORD=ARENA+4096,ARENA+4160,ARENA+4168
MAGIC=0x31464954414e5352
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
NATIVE_EXIT=(0,0,0,0,0,125,0,125,0,0,0,0,-11,-11,125,-4)
GATED_EXIT=(0,0,0,0,0,125,0,125,0,125,0,125,-11,-11,125,-4)
ERROR={5:1458,7:1473,9:1205,11:1205,14:1458}
VECTORS=bytes(1+(r*17+i*13)%255 for r in range(32)for i in range(64))
MASKS=b''.join(struct.pack('<Q',0x1020304050607080+r*0x0101010101010101)for r in range(8))
SELECTED_MASK=((1<<64)-1)&~sum(1<<(s-1)for s in(11,5,31,9,19))
def q(b):
    need(len(b)%8==0,'complete qword payload');return struct.unpack('<'+'Q'*(len(b)//8),b)
def word(b,at):return struct.unpack_from('<Q',b,at)[0]
def put(b,at,x):struct.pack_into('<Q',b,at,x)

def elf(data,interpreter,case,native_policy):
    need(type(case)is int and 0<=case<16 and type(data)is bytes and len(data)>=64,'fixed real fixture ELF')
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
    expected={'_start':MAIN,'rn_seed':MAIN+4096,'rn_body':BODY,'rn_tail':TAIL,'rn_guard':GUARD,'rn_guard_write':GUARD,
      'rn_data':DATA,'rn_data_end':DATA+16384,'rn_case':DATA+8,'rn_mode':DATA+16,'rn_active':DATA+24,
      'rn_registration_result':DATA+32,'rn_rounds':DATA+40,'rn_commit':DATA+48,'rn_abort_seen':DATA+56,
      'rn_final_fs':DATA+64,'rn_final_gs':DATA+72,'rn_store':DATA+128,'rn_descriptor':DATA+256,
      'rn_vectors':DATA+512,'rn_masks':DATA+2560,'rn_live_vectors':DATA+4096,'rn_live_masks':DATA+6144,
      'rn_live_gpr':DATA+6208,'rn_live_flags':DATA+6336,'rn_live_selectors':DATA+6344,'rn_rseq_initial':DATA+8192,'rn_stack_top':DATA+16320}
    need(all(symbols[k]==v for k,v in expected.items()),'exact emitted source/data/capture geometry')
    source=read(MAIN,24576);initial=read(DATA,16384)
    need(q(initial[:80])==(MAGIC,case,0,0,(1<<64)-1,0,0,0,0,0) and initial[512:2624]==VECTORS+MASKS,'literal independent case/vector/mask seeds')
    need(read(symbols['rn_setup_syscall'],2)==bytes.fromhex('0f05') and read(TAIL+256,2)==bytes.fromhex('0fa2'),'actual registration syscall/dirty boundary core')
    need(native_policy(read(MAIN+4096-14,4096+28))==0 and native_policy(read(BODY-14,4096+28))==0,'whole real helper/body plus halos admissible without exemptions')
    need(native_policy(read(MAIN,4096))!=0 and native_policy(read(TAIL,4096))!=0 and native_policy(read(GUARD,4096))!=0,'real setup/boundary/guard dirty pages remain blocked')
    start,end,abort=symbols['rn_cs_start'],symbols['rn_cs_end'],symbols['rn_abort']
    descriptor=struct.unpack_from('<IIQQQ',initial,256)
    need(descriptor==(0,0,start,end-start,TAIL if case==6 else abort) and read(abort-4,4)==bytes.fromhex('53300553'),'actual source-bound descriptor and signature')
    if case in(5,6,7,12,13):
        need(start==symbols['rn_fault']==TAIL-2 and end==TAIL+(case!=6) and read(TAIL-4,5)==bytes.fromhex('90904889c3'),'exact real two-page MOV and coincident RET bytes')
    if case in(8,9,10,11):
        need(read(start,2)==bytes.fromhex('8ee8'if case<10 else'8ee0') and read(GUARD,4)==bytes.fromhex('654c8917'if case<10 else'644c8917'),'real segment load and segmented RANGE8 store')
    if case==14:need(read(symbols['rn_fault'],3)==bytes.fromhex('488b1e'),'real guarded data read')
    if case==15:need(read(symbols['rn_fault'],2)==bytes.fromhex('0f0b'),'real native UD2')
    if case==4:need(start==BODY and read(start,6)==bytes.fromhex('48894708f390'),'CS includes publication itself before real scheduling loop')
    interp=interpreter.read_bytes();ih=struct.unpack_from('<16sHHIQQQIHHHHHH',interp)
    entry=bytes.fromhex('0fa248b8')+struct.pack('<Q',MAIN)+bytes.fromhex('ffe0')
    need(len(interp)==8192 and ih[1:4]==(3,62,1) and ih[4]==4096 and interp[4096:4096+len(entry)]==entry and not any(interp[4096+len(entry):]),'unchanged genuine first-interpreter CPUID then main handoff')
    return dict(case=case,entry=MAIN,symbols=symbols,source_hex=source.hex(),data_hex=initial.hex(),source_sha256=hashlib.sha256(source).hexdigest(),data_sha256=hashlib.sha256(initial).hexdigest())

class Reader:
    def __init__(self,data,layout,record):
        self.data,self.types,self.layout=data,layout['types'],layout
        self.rt=self.types[record];self.ft=self.types['rn_frame'];self.ucn=layout['uc_bytes'];self.go=layout['offsets']['greg'];self.fo=layout['offsets']['fp_pointer']
        need(layout['record']==record and len(data)==self.rt['bytes']<16<<20 and 0<self.ucn<=2048 and self.go+23*8<=self.ucn and self.fo+8<=self.ucn,'complete actual DWARF/record extent')
        forms={'rn_frame':dict(h=512,uc=2048,fp=65536,source=24576,data=16384,rseq=4096)}
        if record=='rn_native_record':forms[record]=dict(h=512,xstate=128,before=self.ft['bytes'],after=self.ft['bytes'])
        else:
            frame=self.ft['bytes'];ns=self.types['li2_rseq_native_state']['bytes'];rs=self.types['li2_rseq_state']['bytes']
            forms['rn_row']=dict(h=256,permits=192,before=frame,after=frame,guard_before=frame,guard_after=frame,
              native_before=ns,native_after=ns,guard_state=rs,close=self.types['li2_native_close']['bytes'])
            forms[record]=dict(h=512,xstate=128,hardware=56,rows=4*self.types['rn_row']['bytes'],publication_frame=frame,
              terminal_native=ns,terminal_rseq=rs,terminal_source=24576,terminal_data=16384,terminal_page=4096)
        for name,fields in forms.items():
            shape=self.types[name];at=0
            need(set(shape['fields'])==set(fields),'exact complete observation field inventory '+name)
            for key,size in fields.items():
                need(shape['fields'][key]==dict(offset=at,bytes=size),'actual contiguous observation field '+name+'.'+key);at+=size
            need(shape['bytes']==at,'complete observation extent without ignored padding '+name)
    def field(self,b,t,n):
        t=self.types[t]if isinstance(t,str)else t;f=t['fields'][n]
        need(0<=f['offset']<=len(b) and 0<f['bytes']<=len(b)-f['offset'],'actual field bounds '+n)
        return b[f['offset']:f['offset']+f['bytes']]
    def integer(self,b,t,n):
        x=self.field(b,t,n);need(len(x)in(2,4,8),'typed scalar extent '+n);return int.from_bytes(x,'little')
    def frame(self,b,image):
        h=q(self.field(b,self.ft,'h'));uc=self.field(b,self.ft,'uc');fp=self.field(b,self.ft,'fp')
        need(h[0:2]==(1,self.ucn) and 512<=h[2]<=65536 and h[3]>0 and h[4:8]==(11,11,2,0) and h[11]==0 and not any(h[12:]),'genuine observed SEGV/zero publication word/clean retained prefix')
        need(uc[self.ucn:]==bytes(2048-self.ucn) and not any(fp[h[2]:]) and word(uc,self.fo)>0,'complete actual UC/FP and unused tails')
        if h[2]>512:need(struct.unpack_from('<I',fp,464)[0]==0x46505853 and struct.unpack_from('<I',fp,468)[0]==h[2] and struct.unpack_from('<I',fp,h[2]-4)[0]==0x46505845 and word(fp,520)==0,'actual standard signal XSAVE envelope')
        source=self.field(b,self.ft,'source');memory=self.field(b,self.ft,'data');page=self.field(b,self.ft,'rseq')
        need(source==bytes.fromhex(image['source_hex']),'complete unchanged actual source image')
        page_ids(page);need(word(page,72)==0 and memory[512:2624]==VECTORS+MASKS,'full real slot page and independent vector/mask seed')
        g=q(uc[self.go:self.go+23*8]);need(g[20]==14 and g[22]==h[8] and g[18]==0x002b000000000033 and g[17]&0x10000 and not g[17]&0x100,'real kernel page-fault frame/selectors/RF/no TF')
        return dict(h=h,uc=uc,fp=fp,data=memory,page=page,greg=g,raw=b)
    def envelope(self,f,lo,cap,native):
        need(type(lo)is int and lo>0 and cap==(131072 if native else 512*1024) and lo<=f['h'][3]<=lo+cap-self.ucn and
          lo<=word(f['uc'],self.fo)<=lo+cap-f['h'][2],'actual UC/FP pointers in the observed installed altstack')
        o=self.layout['offsets'];mask=SELECTED_MASK
        need(word(f['uc'],o['stack_sp'])==lo and word(f['uc'],o['stack_size'])==cap and struct.unpack_from('<I',f['uc'],o['stack_flags'])[0]==0 and
          word(f['uc'],o['mask'])==mask and f['greg'][21]==mask,'actual altstack and exact pre-delivery application mask')
    def components(self,x):
        rows=q(x);need(len(rows)==16,'four actual CPUID layout rows');out={}
        for i,(bit,size)in enumerate(((2,256),(5,64),(6,512),(7,1024))):
            r=rows[i*4:i*4+4];need(r[0]==bit and r[2]==size and r[1]>=576 and r[1]+size<=65532 and not r[3]&1,'actual standard user xstate layout');out[bit]=(r[1],size)
        spans=sorted((o,o+n)for o,n in out.values());need(all(a[1]<=b[0]for a,b in zip(spans,spans[1:])),'disjoint actual xstate components');return out
    def seeded(self,f,components,case,pc):
        expected=registers(case,pc)
        selectors=(0x2b if case in(10,11) and pc!=BODY else 0,0x2b if case in(8,9) and pc!=BODY else 0)
        need(f['h'][9:11]==selectors,'actual live FS/GS selectors at the literal body stage, distinct from reserved zero UC slots')
        need(tuple(f['greg'][i]for i in GREG)==tuple(expected) and f['greg'][17]==0x10ed7,'all actual seeded GPR/DF/flags')
        fp=f['fp'];need(word(fp,512)&0xe7==0xe7 and all(o+n<=f['h'][2]-4 for o,n in components.values()),'all seeded components retained in complete real signal FP')
        for reg in range(32):
            if reg<16:
                z=fp[160+reg*16:176+reg*16];o=components[2][0]+reg*16;z+=fp[o:o+16];o=components[6][0]+reg*32;z+=fp[o:o+32]
            else:o=components[7][0]+(reg-16)*64;z=fp[o:o+64]
            need(z==VECTORS[reg*64:reg*64+64],'all actual seeded ZMM bytes')
        o,n=components[5];need(fp[o:o+n]==MASKS,'all eight actual seeded masks')
    def unchanged(self,b,a,image):
        before,after=self.frame(b,image),self.frame(a,image)
        need(before['raw']==after['raw'],'entire original UC/FP/source/data/rseq/selector observation unchanged across real owner call')
        return before

def page_ids(page):
    need(len(page)==4096 and not any(page[:64]) and not any(page[96:]),'complete page outside exact registered32B unchanged')
    cpu0,cpu,cs,flags,node,cid,reserved=struct.unpack_from('<IIQIIII',page,64)
    need(cpu0==cpu<1<<31 and cs==0 and flags==0 and node<1<<31 and cid<1<<31 and reserved==0,'typed actual kernel CPU/node/mm_cid observations and zero private fields')
    return dict(cpu=cpu,node=node,mm_cid=cid)

def registers(case,pc):
    r=[0x1122334455667700+i for i in range(16)]
    r[0]=0x2b if 8<=case<=11 else ARENA if case==13 else DATA+256
    r[4]=DATA+16320-(8 if case==6 and pc!=GUARD else 0)
    if case==14:r[6]=ARENA
    r[7]=DATA+128 if case in(8,10)else WORD if case in(9,11)else AREA
    if case in(9,11):r[10]=0
    return r

def memory(image,native,page,stage,rounds=0):
    """Complete independent data image at a named, fixed execution boundary."""
    c=image['case'];page_ids(page);b=bytearray.fromhex(image['data_hex'])
    for at,value in ((16,int(native)),(24,1),(32,0),(40,rounds)):
        put(b,at,value)
    if (stage!='body' or rounds) and c in(0,1,2,3):put(b,48,0x11223344)
    if stage!='body' and c==4:put(b,56,0x44556677)
    b[8192:12288]=page
    put(b,16312,GUARD if c==6 and stage!='terminal' else 0xed7)
    if c==6:put(b,16304,0xed7)
    if rounds or stage=='terminal':
        b[4096:6208]=VECTORS+MASKS;b[6208:6336]=struct.pack('<16Q',*registers(c,GUARD));put(b,6336,0xed7)
        b[6344:6356]=struct.pack('<6H',0x33,0x2b,0,0,0x2b if c in(10,11)else 0,0x2b if c in(8,9)else 0)
    if stage=='terminal':
        put(b,64,0 if c in(10,11)else DATA+2048);put(b,72,0 if c in(8,9)else DATA+2304)
        if c in(8,10):put(b,128,0x112233445566770a)
    return bytes(b)

def output(data,image,native):
    case=image['case'];need(len(data)==20480,'complete real stdout data/page images')
    actual,page=data[:16384],data[16384:];ids=page_ids(page);initial_page=actual[8192:12288]
    need(initial_page==page,'complete initial and final rseq page equality on one CPU')
    need(actual==memory(image,native,initial_page,'terminal',2 if case==1 else 1),'complete literal live GPR/flags/32ZMM/8K/selectors/memory/stack effects')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),kernel_ids=ids,live_vectors=32,live_masks=8,live_gprs=16,flags=0xed7)

def native(data,layout,image,pid,exit_status):
    c=image['case'];need(type(pid)is int and pid>0 and type(exit_status)is int and exit_status==NATIVE_EXIT[c],'exact native reference exit')
    fatal=c in(12,13,15)
    r=Reader(data,layout,'rn_native_record');h=q(r.field(data,r.rt,'h'))
    expected=1
    need(h[:6]==(MAGIC,1,len(data),c,expected,1) and h[6]==int(c<=4 or c in(6,8,9,10,11) or fatal) and h[7]==(125 if c in(5,7,14)else 0) and h[8:10]==(pid,pid) and h[10]&0xe7==0xe7 and h[11]>0 and h[12]==131072 and h[13]==int(fatal) and not any(h[14:]),'actual native observer/prefix and PID')
    components=r.components(r.field(data,r.rt,'xstate'))
    b,a=r.field(data,r.rt,'before'),r.field(data,r.rt,'after')
    if expected:
        f=r.unchanged(b,a,image);pc=BODY if fatal else TAIL if c==6 else image['symbols']['rn_abort']if c==5 else image['symbols']['rn_fault']if c in(7,14)else GUARD
        address=BODY if fatal else ARENA if c==14 else TAIL if c in(5,6,7)else GUARD
        need(f['greg'][16]==pc and f['h'][8]==address and f['greg'][19]==(4 if c==14 else 21),'actual native current-PC/abort/fetch/data-fault geometry')
        r.seeded(f,components,c,pc)
        r.envelope(f,h[11],h[12],True)
        need(f['data']==memory(image,True,f['page'],'body'if fatal else'exit'),'complete native before/after data and stack at actual fault')
    else:need(not any(b+a),'no invented native event on no-fault lane')
    return dict(case=c,exit_status=exit_status,frames=expected,kernel_fatal=int(fatal),pre_operation_prefix=int(fatal),observed_cpu=page_ids(f['page'])['cpu'])

def gated(data,layout,image,pid,exit_status):
    c=image['case'];need(type(pid)is int and pid>0 and type(exit_status)is int and exit_status==GATED_EXIT[c],'exact gated operation exit')
    fatal=c in(12,13,15)
    r=Reader(data,layout,'rn_record');h=q(r.field(data,r.rt,'h'));rows=r.field(data,r.rt,'rows');st=r.types['rn_row']
    expected=1 if fatal else 4 if c==1 else 2
    need(h[:6]==(MAGIC,2,len(data),c,r.ucn,st['bytes']) and h[6]&0xe7==0xe7 and h[7:12]==(1,0,int(not fatal),125 if c in ERROR else 0,ERROR.get(c,0)) and h[12]==(11 if c in(5,7,14)else 0) and h[13:15]==(expected,1) and h[15]>0 and h[16]==512*1024 and h[17]>=h[18] and h[19]==int(fatal) and not any(h[20:]),'exact complete observation/error/preeffect prefix; required failures remain failures')
    need(len(rows)==4*st['bytes'] and not any(rows[expected*st['bytes']:]),'fixed complete row capacity and unused tails')
    components=r.components(r.field(data,r.rt,'xstate'))
    hw=struct.unpack('<14I',r.field(data,r.rt,'hardware'));need(hw[:2]==(1,0) and hw[2]>=13 and hw[8]&0x18000000==0x18000000 and hw[11]&0x40010000==0x40010000,'actual required pre-arm hardware')
    def integer(b,t,n):return r.integer(b,t,n)
    identity=None
    def pin_identity(b):
        nonlocal identity
        t='li2_rseq_data'
        keys=('address','page','allocation','generation','offset','pid','tid')
        v=tuple(integer(b,t,k)for k in keys)
        need(v[:2]==(AREA,PAGE) and v[2]>0 and v[3]>0 and v[4]%4096==0 and v[5:]==(pid,pid) and
          integer(b,t,'attempted')==integer(b,t,'complete')==1 and integer(b,t,'error')==integer(b,t,'detail')==0,
          'actual complete registered data pin and process identity')
        if identity is None:identity=v
        need(v==identity,'same actual allocation/generation/offset across every retained registration observation')
        return v
    def registration(b,t):
        need(integer(b,t,'pid')==integer(b,t,'tid')==pid and integer(b,t,'address')==AREA and integer(b,t,'page')==PAGE and
          integer(b,t,'length')==32 and integer(b,t,'signature')==(0x89489090 if c==6 else 0x53053052 if c==12 else 0x53053053),
          'literal registration address/page/length/signature and actual process')
    def state(b,phase,error=0):
        registration(b,'li2_rseq_native_state')
        pin_identity(r.field(b,'li2_rseq_native_state','before'))
        need(integer(b,'li2_rseq_native_state','phase')==phase and integer(b,'li2_rseq_native_state','checking')==0 and
          integer(b,'li2_rseq_native_state','unsafe_terminal')==0 and integer(b,'li2_rseq_native_state','entry_checked')==1 and
          integer(b,'li2_rseq_native_state','pid')==integer(b,'li2_rseq_native_state','tid')==pid and
          integer(b,'li2_rseq_native_state','address')==AREA and integer(b,'li2_rseq_native_state','page')==PAGE and
          integer(b,'li2_rseq_native_state','registration_epoch')==1 and integer(b,'li2_rseq_native_state','length')==32 and
          integer(b,'li2_rseq_native_state','signature')==(0x89489090 if c==6 else 0x53053052 if c==12 else 0x53053053) and
          all(integer(b,'li2_rseq_native_state',n)==0 for n in ('word_before','word_entry','word_after')) and
          integer(b,'li2_rseq_native_state','first_error')==error and integer(b,'li2_rseq_native_state','first_detail')==(11 if error==1473 else 0),'actual trusted singleton registration/zero/epoch/error state')
        return {n:integer(b,'li2_rseq_native_state',n)for n in ('attempts','admissions','preentries','entries','closed','tls_refreshes','fs_before','gs_before','fs_after','gs_after','first_error')}
    first_fp=None;initial_fp=None;observed_cpus=[]
    for i in range(expected):
        row=rows[i*st['bytes']:(i+1)*st['bytes']];v=q(r.field(row,st,'h'))
        pc=BODY if i%2==0 else TAIL if c==6 else image['symbols']['rn_abort']if c==5 else image['symbols']['rn_fault']if c in(7,14)else GUARD
        addr=ARENA if i%2 and c==14 else TAIL if i%2 and c in(5,6,7)else pc
        result=ERROR.get(c,0)if i%2 and c in(5,7,14)else 0
        need(v[:6]==(1,i,pc,addr,1,result) and not any(v[9:]),'actual ordered entry/current-PC/owner return prefix')
        f=r.unchanged(r.field(row,st,'before'),r.field(row,st,'after'),image)
        need(f['greg'][16]==pc and f['h'][8]==addr and f['greg'][19]==(4 if i%2 and c==14 else 21),'genuine saved-PC/si_addr/CR2 join')
        r.seeded(f,components,c,pc)
        observed_cpus.append(page_ids(f['page'])['cpu'])
        r.envelope(f,h[15],h[16],False)
        need(f['data']==memory(image,False,f['page'],'exit'if i%2 else'body',i//2),'complete independently expected entry/exit data and stack')
        if i%2==0:
            first_fp=f['fp']
            if initial_fp is None:initial_fp=first_fp
            else:need(first_fp==initial_fp,'second complete native body starts from the same full initialized FP state')
        else:need(f['fp']==first_fp,'entire actual kernel FP image conserved across native body execution')
        before=r.field(row,st,'native_before');after=r.field(row,st,'native_after');sb=state(before,2);sa=state(after,4 if result==1473 else 2 if result else 0,1473 if result==1473 else 0)
        live=f['h'][9:11]
        need(tuple(integer(before,'li2_rseq_native_state',k)for k in('fs_selector_entry','gs_selector_entry'))==live and
          tuple(integer(after,'li2_rseq_native_state',k)for k in('fs_selector_entry','gs_selector_entry'))==live and
          all(integer(before,'li2_rseq_native_state',k)==0 for k in('fs_selector_after','gs_selector_after','fs_after','gs_after')) and
          tuple(integer(after,'li2_rseq_native_state',k)for k in('fs_selector_after','gs_selector_after'))==((0,0)if result else live),
          'actual native entry/close live selectors match genuine frame observation')
        need(sb['fs_before']==sa['fs_before']==DATA+2048 and sb['gs_before']==sa['gs_before']==DATA+2304,
          'body and seed admissions retain the prior actual TLS authority')
        need(r.field(before,'li2_rseq_native_state','before')==r.field(after,'li2_rseq_native_state','before') and
          not any(r.field(before,'li2_rseq_native_state','after')),'unchanged full pre-admission pin and empty unperformed post-observation')
        if result:need(not any(r.field(after,'li2_rseq_native_state','after')) and sa['fs_after']==sa['gs_after']==0,'failed ingress has no fabricated data/TLS refresh')
        else:pin_identity(r.field(after,'li2_rseq_native_state','after'))
        owned_pc=integer(before,'li2_rseq_native_state','pc')
        need(owned_pc==BODY if i%2 else MAIN+4096<=owned_pc<MAIN+8192,'actual admitted body versus seed/capture predecessor page')
        need(sb['attempts']==sb['admissions']==sb['preentries'] and sb['closed']+1==sb['admissions'] and sb['entries']==sb['closed']==sb['tls_refreshes'],'outstanding original native epoch before actual close')
        if not result:
            need(sa['attempts']==sa['admissions']==sa['preentries']==sa['entries']==sa['closed']==sa['tls_refreshes'] and sa['closed']==sb['closed']+1 and not sa['first_error'],'complete one-page registered close and fresh TLS observation')
            close=r.field(row,st,'close')
            need(integer(close,'li2_native_close','complete')==1 and integer(close,'li2_native_close','busy')==integer(close,'li2_native_close','first_error')==0 and integer(close,'li2_native_close','pages')==integer(close,'li2_native_close','verified')==1,'actual full native close receipt')
            wanted_fs=0 if i%2 and c in(10,11)else DATA+2048;wanted_gs=0 if i%2 and c in(8,9)else DATA+2304
            need(sa['fs_after']==wanted_fs and sa['gs_after']==wanted_gs,'fresh actual FS/GS authority including selector-base change')
        else:need(sa['closed']==sb['closed'] and sa['tls_refreshes']==sb['tls_refreshes'],'refused frame has no completed close or refreshed-authority claim')
        if i%2 and 8<=c<=11:
            need(v[6:9]==(1,1205 if c in(9,11)else 0,1),'actual unchanged old instruction-guard return')
            r.unchanged(r.field(row,st,'guard_before'),r.field(row,st,'guard_after'),image)
            need(r.field(row,st,'guard_before')==r.field(row,st,'after'),'guard observes the exact original closed-entry frame/data/FP prefix')
            permits=q(r.field(row,st,'permits'));need(permits[:12]==permits[12:] and permits[:3]==(0,0,301),'no execution permit or TF-open change across actual guard')
            gs=r.field(row,st,'guard_state');fp=r.field(gs,'li2_rseq_state','last_footprint')
            first=WORD if c in(9,11)else DATA+128
            need(integer(gs,'li2_rseq_state','first_error')==(1205 if c in(9,11)else 0) and integer(gs,'li2_rseq_state','last_pc')==GUARD and
              integer(gs,'li2_rseq_state','last_first')==first and integer(gs,'li2_rseq_state','last_end')==first+8 and
              integer(gs,'li2_rseq_state','last_policy')==2 and integer(gs,'li2_rseq_state','last_code')==282 and
              r.field(gs,'li2_rseq_state','last_footprint')==struct.pack('<QQQQIIII',GUARD,GUARD+4,first,first+8,1,2,282,4),
              'entire actual-before typed Code282/RANGE8 identity with refreshed base; zero store still refused on overlap')
        else:need(v[6:9]==(0,0,0) and not any(r.field(row,st,'permits')+r.field(row,st,'guard_before')+r.field(row,st,'guard_after')+r.field(row,st,'guard_state')),'no fabricated guard observation')
    terminal=r.field(data,r.rt,'terminal_rseq')
    registration(terminal,'li2_rseq_state');pin_identity(r.field(terminal,'li2_rseq_state','data'))
    need(integer(terminal,'li2_rseq_state','pid')==integer(terminal,'li2_rseq_state','tid')==pid and integer(terminal,'li2_rseq_state','registered')==integer(terminal,'li2_rseq_state','held')==1 and integer(terminal,'li2_rseq_state','phase')==3 and integer(terminal,'li2_rseq_state','epoch')==1,'actual still-registered terminal prefix')
    need(r.field(data,r.rt,'terminal_source')==bytes.fromhex(image['source_hex']),'all original source bytes terminal unchanged')
    page=r.field(data,r.rt,'terminal_page');observed_cpus.append(page_ids(page)['cpu'])
    need(r.field(data,r.rt,'terminal_data')==memory(image,False,page,'body'if fatal else'exit'if c in ERROR else'terminal',0 if fatal or c in ERROR else 2 if c==1 else 1),'complete terminal or safe-prefix data/stack including failed operations with no stdout')
    tn=r.field(data,r.rt,'terminal_native')
    if fatal:
        registration(tn,'li2_rseq_native_state');pin_identity(r.field(tn,'li2_rseq_native_state','before'))
        need(integer(tn,'li2_rseq_native_state','registration_epoch')==1 and not any(r.field(tn,'li2_rseq_native_state','after')) and
          all(integer(tn,'li2_rseq_native_state',k)==0 for k in('fs_selector_entry','gs_selector_entry','fs_selector_after','gs_selector_after','fs_after','gs_after')) and
          integer(tn,'li2_rseq_native_state','fs_before')==sa['fs_after']==DATA+2048 and
          integer(tn,'li2_rseq_native_state','gs_before')==sa['gs_after']==DATA+2304,'new fatal BODY admission binds the actual just-closed registration/pin/TLS authority')
        pf=r.field(data,r.rt,'publication_frame');need(pf==r.field(row,st,'after'),'actual original BODY frame survives completed close and fresh admission')
        n=integer(tn,'li2_rseq_native_state','admissions');closed=integer(tn,'li2_rseq_native_state','closed')
        need(integer(tn,'li2_rseq_native_state','phase')==2 and integer(tn,'li2_rseq_native_state','pc')==BODY and
          all(integer(tn,'li2_rseq_native_state',k)==0 for k in('checking','first_error','unsafe_terminal','entry_checked','first_detail','word_before','word_entry','word_after')) and
          n==closed+1==integer(tn,'li2_rseq_native_state','attempts') and
          all(integer(tn,'li2_rseq_native_state',k)==closed for k in('preentries','entries','tls_refreshes')) and
          h[17]==h[18]+1 and integer(tn,'li2_rseq_native_state','native_admissions_before')==h[18] and
          integer(tn,'li2_rseq_native_state','native_closed_before')==h[18],'actual safely retained pre-operation BODY admission, no terminal close claim')
    elif c in ERROR:
        need(tn==after,'failed terminal retains the complete actual native-owner prefix, no invented closure')
        if c in(9,11):need(terminal==r.field(row,st,'guard_state'),'terminal preserves entire failing original overlap-guard state')
    else:
        sn=state(tn,0);n=sn['admissions'];pin_identity(r.field(tn,'li2_rseq_native_state','after'))
        need(n==sn['attempts']==sn['preentries']==sn['entries']==sn['closed']==sn['tls_refreshes'] and n>=sa['closed'] and not sn['first_error'] and
          h[17]==h[18]==integer(tn,'li2_rseq_native_state','native_admissions_before')+1 and
          integer(tn,'li2_rseq_native_state','native_closed_before')+1==h[18],'terminal complete registered/native count identities')
    if not fatal:need(not any(r.field(data,r.rt,'publication_frame')),'no invented fatal pre-operation frame')
    return dict(case=c,exit_status=exit_status,rows=expected,kernel_fatal=int(fatal),pre_operation_prefix=int(fatal),accepted_failed_operation=int(GATED_EXIT[c]!=0),full_frame_pairs=expected,segment_guard=int(8<=c<=11),observed_cpus=observed_cpus)

def pair(native_record,gated_record,native_output,gated_output,layout,image,native_pid,gated_pid,cpu):
    need(type(cpu)is int and cpu>=0,'actual independently reserved CPU authority')
    c=image['case'];n=native(native_record,layout['native'],image,native_pid,NATIVE_EXIT[c]);g=gated(gated_record,layout['gated'],image,gated_pid,GATED_EXIT[c])
    no=output(native_output,image,True)if NATIVE_EXIT[c]==0 else None
    go=output(gated_output,image,False)if GATED_EXIT[c]==0 else None
    if no is None:need(native_output==b'','failed native operation emits no success output')
    if go is None:need(gated_output==b'','failed gated operation emits no success output')
    if no and go:need(no['kernel_ids']['cpu']==go['kernel_ids']['cpu'] and no['kernel_ids']['node']==go['kernel_ids']['node'],'native/gated actual kernel CPU/node equality')
    need(n['observed_cpu']==cpu and all(x==cpu for x in g['observed_cpus']),'every observed native/gated frame and terminal CPU equals reserved CPU')
    for value in (no,go):
        if value:need(value['kernel_ids']['cpu']==cpu,'actual output/initial rseq CPU equals reserved CPU')
    nr=Reader(native_record,layout['native'],'rn_native_record');gr=Reader(gated_record,layout['gated'],'rn_record')
    nf=nr.frame(nr.field(native_record,nr.rt,'before'),image);rows=gr.field(gated_record,gr.rt,'rows');st=gr.types['rn_row']
    index=0 if c in(12,13,15)else 1
    gf=gr.frame(gr.field(rows[index*st['bytes']:(index+1)*st['bytes']],st,'before'),image)
    need(layout['native']['offsets']==layout['gated']['offsets'] and nr.ucn==gr.ucn and nf['fp']==gf['fp'],'complete actual native/gated kernel FP bytes including x87/MXCSR')
    nu,gu=bytearray(nf['uc']),bytearray(gf['uc']);o=nr.layout['offsets']
    # These are actual, separately validated signal-envelope identities;
    # every remaining ucontext byte, including all 23 gregs, stays exact.
    for offset in (o['stack_sp'],o['stack_size'],o['fp_pointer']):
        put(nu,offset,0);put(gu,offset,0)
    need(nu==gu,'complete cross-lane actual ucontext after three explicit pointer/extent identities; full masks remain equal')
    nd,gd=bytearray(nf['data']),bytearray(gf['data']);put(nd,16,0)
    ni,gi=page_ids(nf['page']),page_ids(gf['page']);need(ni['cpu']==gi['cpu'] and ni['node']==gi['node'],'actual native/gated rseq CPU/node identities')
    # Distinct processes may have distinct kernel mm_cid. No other byte
    # is excluded; each full page and data image already matched literals.
    struct.pack_into('<I',nd,8192+88,0);struct.pack_into('<I',gd,8192+88,0)
    np,gp=bytearray(nf['page']),bytearray(gf['page']);struct.pack_into('<I',np,88,0);struct.pack_into('<I',gp,88,0)
    need(nd==gd and np==gp,'complete native/gated memory and rseq page with only actual mode/mm_cid identity differences')
    return dict(case=c,native=n,gated=g,native_output=no,gated_output=go,successful_pair=int(no is not None and go is not None),required_failed_operation=int(GATED_EXIT[c]!=0))
