"""Distinct resident owner: one active70-head epoch, internal register JMP and genuine exit.
Old fixed/dynamic/group267 profiles remain separate mandatory prerequisites."""
import hashlib,struct,importlib.util
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
HERE=Path(__file__).resolve().parent
wire=load('persistent_resident_wire',HERE/'wire.py');plan=load('persistent_resident_plan',HERE/'plan.py')
old=wire.old
need,zero,q,canonical=old.need,old.zero,old.q,old.canonical
U64,PAGE,FP,TF,RF,MASK=old.U64,old.PAGE,old.FP,old.TF,old.RF,old.MASK
DATA,STACK,RSP=old.DATA,old.STACK,old.RSP
RSEQ=0x500000200000
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)

def elf_symbols(data):
    registered=wire.REGISTERED
    h,loads=old.elf(data)
    need(h[11]==64 and h[12]>0 and h[6]+h[12]*64<=len(data),'whole actual bridge section table')
    sections=[struct.unpack_from('<IIQQQQIIQQ',data,h[6]+64*i)for i in range(h[12])]
    symbols={}
    for s in sections:
        if s[1]!=2:continue
        need(s[9]==24 and s[5]%24==0 and s[6]<len(sections) and s[4]+s[5]<=len(data),'actual complete ELF symbol table')
        tab=sections[s[6]];need(tab[1]==3 and tab[4]+tab[5]<=len(data),'actual symbol string table');strings=data[tab[4]:tab[4]+tab[5]]
        for at in range(s[4],s[4]+s[5],24):
            name,info,other,section,address,size=struct.unpack_from('<IBBHQQ',data,at)
            if not section or not name:continue
            end=strings.find(b'\0',name);need(0<=name<end<len(strings),'bounded symbol name')
            name=strings[name:end].decode('ascii')
            if name in registered or name in ('li2_raw6','li2_gateway_start','li2_gateway_end','span_transfer','selected_chain','protected'):
                need(name not in symbols,'unique actual bridge symbol');symbols[name]=(address,size)
    need(set(symbols)==set(registered)|{'li2_raw6','li2_gateway_start','li2_gateway_end','span_transfer','selected_chain','protected'},'whole required compiled object inventory')
    ph=[struct.unpack_from('<IIQQQQQQ',data,h[5]+56*i)for i in range(h[10])]
    return h,ph,symbols

class Check(old.Check):
    def layout(self,b,base=None):
        values=q(b)
        need(len(values)==5,'whole distinct group layout')
        a,c,stubs,slots,spill=values
        need(PAGE<=a<1<<47 and a%PAGE==0 and values==(a,a+32768,a+65536,a+69632,a+73728)and canonical(a,77824),'exact contiguous two-image stub/slots/spill bank')
        if base is not None:need(a==base,'actual selected bank layout')
        return values

    def query3(self,b,prot):
        rows=[b[i*self.r.types['li2_private_code_query']['bytes']:(i+1)*self.r.types['li2_private_code_query']['bytes']]for i in range(3)]
        need(len(b)==3*self.r.types['li2_private_code_query']['bytes'],'three exact code queries')
        for i,row in enumerate(rows):self.query(row,self.geometry[i],prot,pages=8 if i<2 else 1)

    def proof_query(self,b,address,prot):
        rows=self.r.items(b,'pg_proof_query','part','li2_private_code_query')
        need(len(rows)==2,'exact two actual proof query chunks')
        for row,offset,pages in zip(rows,(0,64*PAGE),(64,25),strict=True):
            self.query(row,address+offset,prot,pages=pages)

    def proof_permission(self,b,address,prot):
        t='pg_proof_permission'
        self.eq(b,t,started=1,returned=1,sync_started=1,sync_returned=1,complete=1,prot=prot,result=0,sync_result=0)
        self.proof_query(self.f(b,t,'query'),address,prot)

    def permission3(self,b,prot):
        n=self.r.types['le_permission']['bytes'];need(len(b)==3*n,'three exact permission transitions')
        for i in range(3):self.permission(b[i*n:(i+1)*n],self.geometry[i],prot,8 if i<2 else 1)

    def decoded(self,b,pc,kind):
        off=pc-self.page
        code,length,step=(299,2,1)if off==0xdfe else(765,2,0)
        need(off in(0xdfe,0xf18),'one actual resident ordinary boundary')
        self.eq(b,'li2_decoded',pc=pc,next_pc=pc+length,abi_version=1,decode_status=0,code=code,kind=0,destination=16,width_bits=0,step_disposition=step,available=15,length=length,reserved=0)
        need(self.f(b,'li2_decoded','bytes')==self.app['source'][off:off+15]+b'\0','whole actual ordinary group decoder window')
        return code,length

    def source(self,b,serial,entry,key,ref,terminal=False,cancel=False):
        t='li2_pg_source_progress';phase=(8 if cancel else 6)if terminal else(3 if cancel else 4)
        self.eq(b,t,initialized=1,phase=phase,first_error=0,pages_copied=2,release_started=int(terminal),release_complete=int(terminal),aborted=0,first_detail=0,serial=serial,
                opened_extents=0 if cancel else 3,opened_pages=0 if cancel else 17,closed_extents=3 if terminal and not cancel else 0,closed_pages=17 if terminal and not cancel else 0,
                cancel_started=int(terminal and cancel),cancel_complete=int(terminal and cancel),cancel_extents=3 if terminal and cancel else 0,cancel_pages=17 if terminal and cancel else 0)
        need(self.layout(self.f(b,t,'layout'))==self.geometry and struct.unpack('<2I',self.f(b,t,'bytes_copied'))==(4096,4096),'actual group source layout/full copies')
        s=self.f(b,t,'source');self.eq(s,'li2_pg_sources',complete=1,reserved=0,serial=serial)
        for name in('allocation_epoch','generation_epoch','records_epoch'):need(self.i(s,'li2_pg_sources',name)>0,'actual lifecycle generation epochs')
        actual=self.f(s,'li2_pg_sources','key');self.source_key(actual,entry);self.key_identity(actual,key)
        need(self.f(s,'li2_pg_sources','anchor')==ref,'actual group source anchor')
        self.maps(self.f(b,t,'preparation'))
        if cancel:
            self.eq(b,t,validations=int(terminal))
            zero(self.f(b,t,'opened'),'cancel does not invent RX');zero(self.f(b,t,'closed'),'cancel does not invent revoke')
            if terminal:
                self.maps(self.f(b,t,'validation'));prot=struct.unpack('<3I',self.f(b,t,'cancel_expected_prot'))
                need(prot[0]in(1,3)and prot==(prot[0],)*3,'three actual closed or virgin cancel extents');self.query3(self.f(b,t,'cancel_code'),prot[0]);self.observation(self.f(b,t,'cancelled_fetch'),entry,False,ref)
            else:
                for k in('validation','cancel_expected_prot','cancel_code','cancelled_fetch'):zero(self.f(b,t,k),'no premature group cancel evidence')
        else:
            self.eq(b,t,validations=3 if terminal else 2);self.maps(self.f(b,t,'validation'));self.query3(self.f(b,t,'opened'),5)
            if terminal:self.query3(self.f(b,t,'closed'),1)
            else:zero(self.f(b,t,'closed'),'no premature group close')
            for k in('cancel_expected_prot','cancel_code','cancelled_fetch'):zero(self.f(b,t,k),'accepted group has no cancellation')
        for row in self.r.items(b,t,'last_backing','li2_fetch_backing'):
            if cancel and not terminal:zero(row,'no invented prevalidation backing')
            else:self.backing(row)
        return self.i(b,t,'validations')

    def compact(self,payload):
        c=self.f(payload,'pe_payload','plan');t='li2_pg_compact'
        self.eq(c,t,version=2,bytes=353600,ready=1,result=0,heads=70,exits=1,stores=0,source_bytes=280,source_mask=3,decoder_result=0,guard_result=0,reserved=0,links=2,reserved2=0,entry=self.head)
        need(struct.unpack('<2I',self.f(c,t,'member_heads'))==(64,6)and q(self.f(c,t,'page'))==(self.page,self.page+PAGE)and self.layout(self.f(c,t,'layout'))==self.geometry and self.f(c,t,'source')==self.app['source'],'whole independent resident source and deterministic64/6 partition')
        expected=plan.loop(self.app['source'],self.page,self.geometry,self.table)
        for k in('image','stub_image','head','original','frontier','edge','instruction','guard'):
            need(self.f(c,t,k)==expected[k],'whole independent resident '+k)
        need(q(self.f(c,t,'exit_pc'))==(self.page+0xf18,0,0,0,0,0,0,0),'one actual before-JMP unknown-target exit')
        instruction=self.r.items(c,t,'instruction','li2_pg_instruction')[69]
        record=self.r.items(c,t,'guard','li2_pg_guard_record')[69]
        self.r.walk(self.f(instruction,'li2_pg_instruction','dispatch'),'li2_jd_descriptor')
        self.r.walk(self.f(record,'li2_pg_guard_record','dispatch'),'li2_jd_record')
        table=plan.table(self.ranges+[(self.page,self.page+PAGE),(self.page+PAGE,self.page+2*PAGE),(RSEQ+8,RSEQ+16)],self.table)
        need(self.f(c,t,'table')==table,'whole independent exclusion table including both source pages and registered word')
        need(self.table-64576==self.proof+self.r.types['pe_payload']['fields']['plan']['offset']+self.r.types[t]['fields']['original']['offset'],'actual immutable row address and common full/compact table relation')
        return expected

    def cell(self,b,generation,serial,before):
        t='pg_dispatch_cell_transition'
        self.eq(b,t,generation=generation,serial=serial,started=1,complete=1,before=before,after=0)
        self.query(self.f(b,t,'mapping'),self.geometry[4],3)

    def continuation_page(self,b,pc):
        if self.page<=pc<self.page+2*PAGE:
            return self.page_row(b,(pc-self.page)//PAGE)
        page=pc&-PAGE;obj,_,loads=self.objects[self.image['main_object']];bias=self.bases[self.image['main_object']]
        owners=[p for p in loads if p[1]==5 and bias+(p[3]&-PAGE)<=page<=((bias+p[3]+p[5]-1)&-PAGE)]
        need(len(owners)==1,'one actual original suffix executable load')
        owner=owners[0];offset=(owner[2]&-PAGE)+page-bias-(owner[3]&-PAGE)
        t='li2_fetch_page';self.eq(b,t,address=page,backing=1,object=self.image['main_object'],logical=5,closed_prot=1,offset=offset,initial_extent=0)
        need(self.i(b,t,'allocation')>0 and self.i(b,t,'generation')>0,'actual suffix allocation/generation')
        a,z,major,minor,inode,off=self.v(b,t,'vma_first vma_end vma_major vma_minor vma_inode vma_offset')
        st=self.stat(self.f(self.main_backing,'li2_fetch_backing','stat'));dev=st['dev']
        need(a%PAGE==z%PAGE==off%PAGE==0 and a<=page<page+PAGE<=z and off+page-a==offset and
             (major,minor,inode)==(((dev>>8)&0xfff)|((dev>>32)&0xfffff000),(dev&255)|((dev>>12)&0xffffff00),st['ino']),'exact suffix VMA/device/inode/offset')
        need((major,minor,inode)==self.main_vma_identity,'suffix and focal source share actual sealed-carrier VMA identity')


    def slots_transition(self,b,linked):
        t='pg_slot_transition';self.eq(b,t,started=1,linked=int(linked),complete=1,copied=4096,verified=4096)
        self.query3(self.f(b,t,'code'),1)
        self.permission(self.f(b,t,'write'),self.geometry[3],3,1);self.permission(self.f(b,t,'seal'),self.geometry[3],1,1)

    def permit(self,b,g,source=None,pin=None,fetch=None):
        t='ped_permit';gt='li2_pg_generation'
        self.eq(b,t,valid=1,generation=self.i(g,gt,'generation'),generated=self.i(g,gt,'generated'),proof=self.i(g,gt,'proof'))
        serial=self.i(b,t,'serial');seq=self.i(b,t,'ref_sequence');need(serial>0 and seq>0,'actual completed group permit serial/borrow')
        saved=self.geometry;self.geometry=self.layout(self.f(b,t,'layout'))
        need(self.f(b,t,'layout')==self.f(g,gt,'layout')and self.f(b,t,'member_generation')==self.f(g,gt,'member_generation')and self.f(b,t,'close')==self.f(g,gt,'close'),'permit binds actual complete member identities and17-page close')
        self.permission3(self.f(b,t,'close'),1);self.proof_query(self.f(b,t,'proof_query'),self.i(b,t,'proof'),1);self.query(self.f(b,t,'reset_slots'),self.geometry[3],1)
        n=self.r.types['pg_slot_transition']['bytes'];reset=self.f(g,gt,'slots')[2*n:3*n]
        need(self.f(b,t,'reset_slots')==self.f(self.f(reset,'pg_slot_transition','seal'),'le_permission','query'),'permit slot reset query from actual completed transition')
        f=self.f(b,t,'fetch');self.progress(f,seq,False)
        s=self.f(b,t,'source');self.eq(s,'li2_pg_source_progress',serial=serial,phase=6,first_error=0,release_started=1,release_complete=1,cancel_started=0,cancel_complete=0,aborted=0,opened_extents=3,opened_pages=17,closed_extents=3,closed_pages=17)
        need(self.f(s,'li2_pg_source_progress','layout')==self.f(g,gt,'layout'),'permit source binds the actual complete generation layout')
        src=self.f(s,'li2_pg_source_progress','source');self.eq(src,'li2_pg_sources',complete=1,serial=serial,reserved=0)
        need(self.i(self.f(src,'li2_pg_sources','anchor'),'li2_fetch_ref','sequence')==seq,'actual group released borrow owns permit')
        self.key_identity(self.f(src,'li2_pg_sources','key'),self.f(b,t,'generation_source'))
        r=self.f(b,t,'rseq');self.eq(r,'li2_pg_rseq_progress',active=0,checking=0,first_error=0,unsafe_terminal=0,seed_complete=1,entry_complete=1,close_complete=1,cancel_started=0,cancel_complete=0,word_before=0,word_entry=0,word_after=0,registration_epoch=1,address=RSEQ,length=32,signature=0x53053053)
        self.eq(self.f(r,'li2_pg_rseq_progress','token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
        for actual,expected,name in((s,source,'source'),(r,pin,'rseq'),(f,fetch,'fetch')):
            if expected is not None:need(actual==expected,'whole actual group completion permit '+name)
        cell=self.r.items(g,gt,'cell','pg_dispatch_cell_transition')[2]
        self.cell(cell,self.i(g,gt,'generation'),serial,self.i(cell,'pg_dispatch_cell_transition','before'))
        self.geometry=saved

    def prior_completed(self,b,g,counts):
        gt='li2_pg_generation';generation=self.i(g,gt,'generation');serial=self.i(b,'ped_permit','serial')
        self.eq(g,gt,installed=1,complete=1,proof_complete=1,generation=counts['next_generation'],ready_generation=generation,plan_proofs=2,none_proofs=1,active_refs=0,linked=0,proof=self.h[27],code_copied=69632,code_verified=69632,proof_zeroed=364544,proof_copied=362624,proof_verified=364544)
        need(0<self.i(g,gt,'build_serial')<=serial<=counts['next_serial']and 0<generation<U64//2,'actual completed prior publication serial/generation')
        need(q(self.f(g,gt,'member_generation'))==(2*generation,2*generation+1),'prior exact member generations')
        zero(self.f(g,gt,'incoming'),'prior incoming references drained');zero(self.f(g,gt,'member_refs'),'prior member references drained');zero(self.f(g,gt,'cleanup'),'prior success has no failure cleanup')
        saved=self.geometry;self.geometry=self.layout(self.f(g,gt,'layout'))
        need(self.geometry[0]in(self.h[26],self.h[29])and self.i(g,gt,'generated')==self.geometry[0]and self.i(g,gt,'spill')==self.geometry[4],'prior actual registered bank identity')
        self.query3(self.f(g,gt,'code_writable'),3);self.proof_query(self.f(g,gt,'proof_writable'),self.h[27],3);self.query(self.f(g,gt,'spill_query'),self.geometry[4],3);zero(self.f(g,gt,'slot_query'),'prior unused aggregate slots query')
        self.permission3(self.f(g,gt,'code_sealed'),1);self.proof_permission(self.f(g,gt,'proof_sealed'),self.h[27],1);self.permission3(self.f(g,gt,'open'),5);self.permission3(self.f(g,gt,'close'),1)
        transitions=self.r.items(g,gt,'slots','pg_slot_transition')
        for row,linked in zip(transitions,(False,True,False),strict=True):self.slots_transition(row,linked)
        cells=self.r.items(g,gt,'cell','pg_dispatch_cell_transition')
        for i,row in enumerate(cells):
            actual_serial=self.i(row,'pg_dispatch_cell_transition','serial')
            need(actual_serial==(self.i(g,gt,'build_serial')if i==0 else serial),'prior cell transition serials')
            self.cell(row,generation,actual_serial,0 if i<2 else self.i(row,'pg_dispatch_cell_transition','before'))
        self.permit(b,g)
        source=self.f(b,'ped_permit','source');self.query3(self.f(source,'li2_pg_source_progress','opened'),5);self.query3(self.f(source,'li2_pg_source_progress','closed'),1)
        self.maps(self.f(source,'li2_pg_source_progress','preparation'));self.maps(self.f(source,'li2_pg_source_progress','validation'))
        self.geometry=saved

    def progress(self,b,sequence,held,validated=True):
            t='li2_fetch_progress';self.eq(b,t,held=int(held),complete=1,first_error=0,identity_observed=1,first_detail=0,pages_copied=1,bytes_copied=15,sequence=sequence,last_backing_page=0,last_backing_observed=int(validated))
            self.maps(self.f(b,t,'preparation'))
            if validated:need(self.i(b,t,'validation_calls')>0,'actual positive full validation count');self.maps(self.f(b,t,'validation'))
            else:self.eq(b,t,validation_calls=0);zero(self.f(b,t,'validation'),'no invented source validation')

    def observation(self,b,pc,held,ref=None):
            t='li2_span_fetch_observation';self.eq(b,t,complete=1,pc=pc,length=15,page_count=1,pid=self.pid,tid=self.pid)
            actual=self.f(b,t,'ref');a,n=self.v(actual,'li2_fetch_ref','owner sequence');need(canonical(a)and n>0,'actual protected singleton identity')
            if ref is not None:need(actual==ref,'exact real ref, not caller sequence assertion')
            self.progress(self.f(b,t,'progress'),n,held)
            off=pc-self.page;need(0<=off<=PAGE-15 and self.f(b,t,'bytes')==self.app['source'][off:off+15],'all actual requested15 bytes')
            pages=self.r.items(b,t,'pages','li2_fetch_page');backs=self.r.items(b,t,'backing','li2_fetch_backing');self.page_row(pages[0]);self.backing(backs[0]);self.backing(self.f(b,t,'last_backing'));zero(pages[1],'unused singleton page');zero(backs[1],'unused singleton backing')
            return a,n

    def trace(self,f,pc,flags):
            need(f['sig']==5 and struct.unpack_from('<iii',f['si'])==(5,0,2)and int.from_bytes(f['si'][16:24],'little')==pc and f['greg'][16]==pc and f['greg'][17]==flags and f['greg'][18]==0x2b000000000033 and f['greg'][19:22]==(0,1,MASK)and f['mask']==MASK,'exact genuine TRACE signal, full mask and flags')

    def normalized(self,b,origin=None):
            f=self.frame(b,origin is None)
            if origin is not None:f.update(fs=origin['fs'],gs=origin['gs'])
            return f

    def same_event(self,a,b,flags):
            # Neither raw UC nor its glibc mask/siginfo alias is relaxed.
            want=bytearray(a['raw']);fields=self.r.types['le_frame']['fields'];step=self.r.types['li2_step_frame']['fields']
            struct.pack_into('<Q',want,fields['uc']['offset']+40+17*8,flags)
            struct.pack_into('<Q',want,fields['frame']['offset']+step['greg']['offset']+17*8,flags)
            for key in ('fs','gs','fs_result','gs_result','tls_complete'):
                f=fields[key];want[f['offset']:f['offset']+f['bytes']]=b['raw'][f['offset']:f['offset']+f['bytes']]
            need(bytes(want)==b['raw'],'entire same-event captured frame except actual TF edit and observed TLS fields')

    def step_frame(self,b,actual,flags=None):
            want=list(actual['greg'])
            if flags is not None:want[17]=flags
            need(q(self.f(b,'li2_step_frame','greg'))==tuple(want)and self.f(b,'li2_step_frame','fp')==actual['fp'],'all actual owner GREG/FP bytes')
            self.eq(b,'li2_step_frame',mask=MASK,fp_address=int.from_bytes(actual['uc'][224:232],'little'),fp_bytes=actual['fp_bytes'],initialized=actual['fp_bytes'])

    def chain_fetch(self,b,pc,held):
            t='li2_chain_fetch';self.eq(b,t,pc=pc,length=15,page_count=1,pid=self.pid,tid=self.pid,identity_observed=1)
            ref=self.f(b,t,'ref');a,n=self.v(ref,'li2_fetch_ref','owner sequence');need(canonical(a)and n>0,'actual ordinary fetch origin')
            self.progress(self.f(b,t,'progress'),n,held)
            need(self.f(b,t,'bytes')==self.app['source'][pc-self.page:pc-self.page+15],'whole actual ordinary window')
            pages=self.r.items(b,t,'pages','li2_fetch_page');back=self.r.items(b,t,'backing','li2_fetch_backing')
            self.page_row(pages[0]);self.backing(back[0]);self.backing(self.f(b,t,'last_backing'));zero(pages[1],'unused ordinary page');zero(back[1],'unused ordinary backing')
            return ref

    def page_row(self,b,index=0):
        t='li2_fetch_page';page=self.page+index*PAGE
        self.eq(b,t,address=page,backing=1,object=self.image['main_object'],logical=5,closed_prot=1,offset=self.source_offset+index*PAGE,initial_extent=0)
        need(self.i(b,t,'allocation')>0 and self.i(b,t,'generation')>0,'actual positive source allocation/generation')
        a,z,major,minor,inode,off=self.v(b,t,'vma_first vma_end vma_major vma_minor vma_inode vma_offset')
        st=self.stat(self.f(self.main_backing,'li2_fetch_backing','stat'));dev=st['dev']
        need(a%PAGE==z%PAGE==off%PAGE==0 and a<=page<page+PAGE<=z and off+page-a==self.source_offset+index*PAGE and
             (major,minor,inode)==(((dev>>8)&0xfff)|((dev>>32)&0xfffff000),(dev&255)|((dev>>12)&0xffffff00),st['ino']),'exact source VMA/device/inode/offset')

    def permission(self,b,address,prot,pages):
        self.eq(b,'le_permission',started=1,returned=1,sync_started=1,sync_returned=1,complete=1,prot=prot,result=0,sync_result=0)
        self.query(self.f(b,'le_permission','query'),address,prot,pages=pages)

    def live_rseq(self,b,state,frame):
        t='li2_link_rseq_live';self.eq(b,t,attempted=1,complete=1,result=0,session=self.symbol('selected_session'),epoch=1,registered=1)
        regs=self.f(b,t,'registers');self.eq(regs,'li2_write_registers',fs_base=self.i(state,'li2_rseq_state','fs_base'),gs_base=self.i(state,'li2_rseq_state','gs_base'))
        need(q(self.f(regs,'li2_write_registers','gpr'))==tuple(frame['greg'][i]for i in GREG),'every actual live rseq GPR')
        need(self.v(regs,'li2_write_registers','fs_base gs_base')==(frame['fs'],frame['gs']),'registered current TLS bound to actual frame')

    def registry(self,b):
            t='pro_registry';self.eq(b,t,complete=1,table=self.symbol('protected'));count=self.i(b,t,'count');need(0<count<=128,'bounded actual registration table')
            rows=self.r.items(b,t,'ranges','li2_fork_range');ranges=[self.v(x,'li2_fork_range','first end')for x in rows[:count]]
            for row in rows[count:]:zero(row,'whole unused protected range')
            need(all(canonical(a,z-a)for a,z in ranges),'whole actual protected byte intervals')
            kinds=self.f(b,t,'initial_code');need(not any(kinds[count:])and all(x in(0,1)for x in kinds),'literal initial-code classification')
            im=self.f(b,t,'bridge');self.eq(im,'image',bias=self.bias,entry=self.bias+self.eh[4],n=len(self.ph),source=0,source_size=0,backing_fd=(1<<32)-1,kind=3)
            zero(self.f(im,'image','source_hash'),'no invented original bridge hash');need(canonical(self.i(im,'image','ph'),56*len(self.ph)),'actual program header pointer')
            need(self.f(b,t,'ph')==b''.join(struct.pack('<IIQQQQQQ',*p)for p in self.ph)+bytes((32-len(self.ph))*56),'all actual bridge program headers')
            objects=[];decl=self.r.layout['registrations'];need(set(decl)==set(self.r.registered),'all exact byte-registration source witnesses')
            headers=self.image['headers'];need(type(headers)is dict and headers,'actual complete compiler-M header closure')
            for name,(source,tag)in self.r.registered.items():
                d=decl[name];at,n=self.symbols[name];a,z=self.bias+at,self.bias+at+n
                need(set(d)=={'address','bytes','alignment','tag','source'}and(d['address'],d['bytes'],d['tag'])==(at,n,tag)and type(d['alignment'])is int and 0<d['alignment']<=PAGE and not d['alignment']&(d['alignment']-1)and a%d['alignment']==0 and d['source'].endswith('/tools/page-entry/selected/'+source),'actual symbol/DWARF/source-selected registration '+name)
                need(d['source']in headers and type(headers[d['source']])is dict and set(headers[d['source']])=={'bytes','sha256'},'every actual DWARF origin belongs to the complete compiler-M closure')
                if name not in self.r.lifetime:need(ranges.count((a,z))==1 and kinds[ranges.index((a,z))]==0,'whole strict registered object extent')
                loads=[p for p in self.ph if p[0]==1 and p[6]and self.bias+p[3]<z and a<self.bias+p[3]+p[6]]
                need(len(loads)==1 and loads[0][1]==6 and self.bias+loads[0][3]<=a<z<=self.bias+loads[0][3]+loads[0][6],'whole registered object in one RW/NX load')
                p=loads[0];rounded=((self.bias+p[3])&-PAGE,(self.bias+p[3]+p[6]+PAGE-1)&-PAGE)
                need(ranges.count(rounded)==1 and kinds[ranges.index(rounded)]==0,'whole bridge load strict protection');objects.append((a,z))
            need(all(a%PAGE==z%PAGE==0 or(a,z)in objects for a,z in ranges),'every non-page interval is an exact source registration')
            for i,kind in enumerate(kinds[:count]):
                if not kind:continue
                a,z=ranges[i];matches=[]
                for key in ('main_object','interpreter_object'):
                    obj,_,loads=self.objects[self.image[key]];bias=self.bases[self.image[key]]
                    matches += [p for p in loads if p[1]&1 and ((bias+p[3])&-PAGE,(bias+p[3]+p[6]+PAGE-1)&-PAGE)==(a,z)]
                need(len(matches)==1,'initial protection exception names one original executable load')
            return ranges,kinds[:count]

    def memory(self,b,failed):
        t='li2_pro_memory';self.eq(b,t,attempted=1,complete=1,after_abort=int(failed),rows_checked=6,data_copied=8192,stack_copied=224,result=0,detail=0,rsp=RSP,data_first=DATA,stack_first=RSP-128)
        m=self.maps(self.f(b,t,'maps'),0)
        before,after=(self.f(b,t,k)for k in('before','after'));mt='li2_maps_stats'
        self.eq(before,mt,active=0,poisoned=0,reserved=0);self.eq(after,mt,active=0,poisoned=0,reserved=0,valid=1)
        self.r.change(before,after,mt,values=dict(fresh_calls=self.i(before,mt,'fresh_calls')+1,acquisitions=self.i(before,mt,'acquisitions')+1),observed=('valid','invalidations','mutation_epoch'))
        invalidations=self.i(after,mt,'invalidations')-self.i(before,mt,'invalidations')
        need(invalidations>=1 and self.i(after,mt,'mutation_epoch')-self.i(before,mt,'mutation_epoch')==invalidations,'actual explicit fresh invalidation and every gateway invalidation')
        need(m[:3]==(self.i(after,mt,'acquisitions'),0,self.i(after,mt,'mutation_epoch')),'memory acquisition actual stats join')
        rows=self.r.items(b,t,'rows','li2_pro_map_row')
        for i,row in enumerate(rows):
            self.eq(row,'li2_pro_map_row',offset=0,major=0,minor=0,inode=0,private=1)
            a,z,prot=self.v(row,'li2_pro_map_row','first end prot');need(a%PAGE==z%PAGE==0 and a<z,'actual page-aligned memory extent')
            if i<2:need((a,z,prot)==(DATA,DATA+8192,3),'actual two-page writable data')
            elif i==4:need((a,z,prot)==(STACK+4096,STACK+4096+131072,3),'actual fixed writable guest stack')
            else:
                point=(DATA+8192,STACK,STACK+4096+131072)[(2,3,5).index(i)]
                need(a<=point and point+PAGE<=z and prot==0,'actual inaccessible data/stack guard')
        return dict(data=self.f(b,t,'data'),stack=self.f(b,t,'stack'))

    def __init__(self,r,image,app,pid,cpu):
        self.r,self.image,self.app,self.pid,self.cpu=r,image,app,pid,cpu
        self.b=r.data[:-64];self.h=q(self.f(self.b,'pro_wire','h'));self.bias=self.h[9]-r.layout['symbols']['li2_raw6']
        self.page=app['head']&-PAGE;self.head=app['head'];self.objects={};self.bases={};self.backings={};self.maps_seen={};self.source_ids={}
        for key,obj in image['objects'].items():
            need(type(key)is int and type(obj)is dict,'actual complete object inventory');h,loads=old.elf(obj['data']);self.objects[key]=(obj,h,loads)
        need(image['main_object']in self.objects and image['interpreter_object']in self.objects,'actual source object identities')
        self.eh,self.ph,self.symbols=elf_symbols(image['bridge'])
        need(set(r.layout['symbols'])==set(self.symbols)|{'span_progress'}and all(r.layout['symbols'][k]==v[0]for k,v in self.symbols.items()),'same actual bridge/DWARF symbols')
        first=r.items(self.b,'pro_wire','epochs','pro_epoch')[0];payload=self.f(first,'pro_epoch','initial_payload')
        key=self.f(payload,'pe_payload','source');row=r.items(key,'li2_pg_source_key','page','li2_pg_source_page')[0]
        self.main_backing=self.f(row,'li2_pg_source_page','backing');self.source_offset=self.i(self.f(row,'li2_pg_source_page','identity'),'li2_fetch_page','offset')
        self.main_vma_identity=self.v(self.f(row,'li2_pg_source_page','identity'),'li2_fetch_page','vma_major vma_minor vma_inode')

    def registry_prefix(self,a,b):
        t='pro_registry';n,m=self.i(a,t,'count'),self.i(b,t,'count');need(0<n<=m<=128,'startup registry population is an exact predecessor')
        need(all(self.f(a,t,k)==self.f(b,t,k)for k in('complete','table','bridge','ph')),'startup registry keeps exact table, bridge and program headers')
        need(self.f(a,t,'ranges')[:n*16]==self.f(b,t,'ranges')[:n*16]and self.f(a,t,'initial_code')[:n]==self.f(b,t,'initial_code')[:n],'startup registry retains every original range and classification')
        rows=[self.v(x,'li2_fork_range','first end')for x in self.r.items(b,t,'ranges','li2_fork_range')[:m]];kinds=self.f(b,t,'initial_code')
        for i,(first,end)in enumerate(rows[n:],n):need(first%PAGE==0 and end-first==PAGE and not kinds[i]and all(end<=x or y<=first for x,y in rows[:i]),'startup additions are distinct strict PAGE intervals')
        self.registry(a);return self.registry(b)

    def source_key(self,key,entry):
        self.eq(key,'li2_pg_source_key',entry=entry)
        for i,row in enumerate(self.r.items(key,'li2_pg_source_key','page','li2_pg_source_page')):
            self.page_row(self.f(row,'li2_pg_source_page','identity'),i);self.backing(self.f(row,'li2_pg_source_page','backing'))
            need(self.f(row,'li2_pg_source_page','bytes')==self.app['source'][i*PAGE:(i+1)*PAGE],'whole immutable two-source bytes')

    def backing_identity(self,b):
        # Exact span_source_backing_equal fields across distinct fstat calls.
        # Every stat byte remains in the typed wire; stat() validates kernel
        # padding/nanoseconds. Timestamps are observations, not source identity.
        t='li2_fetch_backing';self.eq(b,t,seals_observed=1,stat_observed=1,seals=15,stat_result=0)
        st=self.stat(self.f(b,t,'stat'));fd=self.i(b,t,'retained_fd')
        need(200<=fd<1<<31 and st['mode']&0xf000==0x8000 and st['size']>0,'actual sealed backing identity')
        return fd,self.i(b,t,'seals'),st['dev'],st['ino'],st['mode'],st['size']

    def backing(self,b):
        identity=self.backing_identity(b)
        need(identity==self.backing_identity(self.main_backing)and
             identity[-1]==self.image['objects'][self.image['main_object']]['carrier_bytes'],'actual sealed main carrier stable identity')
        return identity

    def key_identity(self,a,b):
        t='li2_pg_source_key';need(self.i(a,t,'entry')==self.i(b,t,'entry'),'current and immutable entry identity')
        for x,y in zip(self.r.items(a,t,'page','li2_pg_source_page'),self.r.items(b,t,'page','li2_pg_source_page'),strict=True):
            for k in('identity','bytes'):need(self.f(x,'li2_pg_source_page',k)==self.f(y,'li2_pg_source_page',k),'actual current/immutable complete source identity '+k)
            need(self.backing_identity(self.f(x,'li2_pg_source_page','backing'))==self.backing_identity(self.f(y,'li2_pg_source_page','backing')),'actual source-owned stable backing identity')

    def counts(self,b):
        t='pro_counts';names='next_serial next_generation offers publications hits cold_attempts cancelled retirements permit_claims entries completed unexpected'.split()
        d={k:self.i(b,t,k)for k in names};d['misses']=q(self.f(b,t,'misses'));need(len(d['misses'])==18 and d['misses'][0]==0,'exact eighteen descriptive reason buckets')
        need(all(0<=x<U64 for x in d.values()if type(x)is int)and all(0<=x<U64 for x in d['misses']),'bounded exact dynamic counters')
        return d

    def delta(self,a,b,**increments):
        x,y=self.counts(a),self.counts(b)
        for k in x:
            if k=='misses':need(y[k]==tuple(v+(1 if i==increments.get('miss_reason',-1)else 0)for i,v in enumerate(x[k])),'exact classified miss bucket delta')
            else:need(y[k]==x[k]+increments.get(k,0),'exact focal dynamic counter delta '+k)

    def pin(self,b,state,serial,heads,stores,stubs=0,terminal=False,failed=False,cancel=False):
        t='li2_pg_rseq_progress';self.eq(b,t,active=int(not terminal or failed),checking=0,first_error=0,unsafe_terminal=0,seed_complete=1,entry_complete=int(not cancel),close_complete=int(terminal and not failed and not cancel),first_detail=0,pid=self.pid,tid=self.pid,fs_result=0,gs_result=0,registration_epoch=1,address=RSEQ,page=RSEQ,length=32,signature=0x53053053,fs=self.app['machine'][1],gs=self.app['machine'][2],word_before=0,word_entry=0,word_after=0,cold_heads=heads,cold_stores=stores,cold_stubs=stubs,fs_selector=0,gs_selector=0,session=self.symbol('selected_session'),cancel_started=int(terminal and cancel),cancel_complete=int(terminal and cancel))
        self.eq(self.f(b,t,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial);need(self.i(b,t,'raw_checks')>0,'actual positive zero-word raw checks')
        rt='li2_rseq_state';self.eq(state,rt,initialized=1,registered=1,held=1,first_error=0,phase=3,first_detail=0,pid=self.pid,tid=self.pid,address=RSEQ,page=RSEQ,length=32,signature=0x53053053,epoch=1,fs_base=self.app['machine'][1],gs_base=self.app['machine'][2],fs_result=0,gs_result=0,tls_complete=1,registrations=1,unregistrations=0,kernel_errors=0,calls=1)
        need(self.f(state,rt,'data')==self.f(b,t,'before'),'whole original registered mapping receipt')
        identity=None
        for k in('before','observed')+('after',)*(terminal and not failed):
            d=self.f(b,t,k);dt='li2_rseq_data';self.eq(d,dt,address=RSEQ,page=RSEQ,pid=self.pid,tid=self.pid,attempted=1,complete=1,error=0,detail=0)
            ids=self.v(d,dt,'address page allocation generation offset pid tid');need(ids[2]>0 and ids[3]>0 and ids[4]==0,'actual registered data allocation/generation')
            if identity is None:identity=ids
            else:need(ids==identity,'whole unchanged registered page identity')
            self.maps(self.f(d,dt,'maps'))
        if not terminal or failed:zero(self.f(b,t,'after'),'no invented closing registration observation')
        return self.i(b,t,'raw_checks')

    def predecessor(self,slot,pc,ingress,closed=True):
        t='li2_tf_chain_slot';index=self.i(slot,t,'index');need(index in(0,1),'actual predecessor slot index')
        self.eq(slot,t,chain=self.symbol('selected_chain'),phase=5 if closed else 3,fallback=0,prepare_complete=1,decode_attempted=1,decode_complete=1,retry=0,unexpected_frame_observed=0,unexpected_signal=0,unexpected_code=0,unexpected_errno=0,unexpected_address=0,prepare_result=0,decode_result=0,classify_result=0)
        need(self.i(slot,t,'generation')>0 and self.i(slot,t,'event_id')>0,'actual predecessor generation/event')
        origin=self.i(slot,t,'origin');need(origin in(1,2)and self.i(slot,t,'prepare_attempted')==int(origin==2),'actual predecessor NX/TRACE preparation')
        for k in('first_decoded','first_fetch','first_release','unexpected'):zero(self.f(slot,t,k),'no unused predecessor '+k)
        kind='nop'if pc==self.page+0xdfe else'jmp';code,length=self.decoded(self.f(slot,t,'decoded'),pc,kind)
        ref=self.chain_fetch(self.f(slot,t,'fetch'),pc,not closed);o=self.f(slot,t,'owner');st=self.f(o,'li2_tf_owner','step');qt='li2_step_owner'
        flags=ingress['greg'][17]&~TF
        self.eq(st,qt,phase=5 if closed else 3,first_error=0,in_handler=0,self_test=0,trace_seen=int(closed),revoke_sync_started=int(closed),first_detail=0,session=self.symbol('selected_session'),open_sync=0,revoke_sync=0,destination=0,width=0,immediate=0,effect=0,source=0)
        request=self.f(st,qt,'request');self.eq(request,'li2_step_request',page_count=1,original_flags=flags);self.decoded(self.f(request,'li2_step_request','decoded'),pc,kind)
        cl=self.f(o,'li2_tf_owner','classification');self.eq(cl,'li2_tf_classification',pc=pc,next_pc=pc+length,abi_version=1,policy=1,code=code,length=length,flow=1 if kind=='nop'else 2,family=1 if kind=='nop'else 3)
        desc=self.f(slot,t,'descriptive_classification')
        if origin==2:need(desc==cl,'actual TRACE descriptive classification')
        else:zero(desc,'NX origin has no separate descriptive classification')
        address=self.symbol('selected_chain')+self.r.types['li2_tf_chain']['fields']['slots']['offset']+index*self.r.types[t]['bytes']
        hooks=self.f(st,qt,'hooks');self.eq(hooks,'li2_step_hooks',context=address)
        for k in('authenticate','failure'):need(canonical(self.i(hooks,'li2_step_hooks',k)),'actual predecessor callback')
        oh=self.f(o,'li2_tf_owner','hooks');need(self.f(oh,'li2_tf_hooks','step')==hooks and canonical(self.i(oh,'li2_tf_hooks','continue_closed')),'actual typed continuation hook')
        pages=self.r.items(request,'li2_step_request','pages','li2_step_page');src=self.r.items(self.f(slot,t,'fetch'),'li2_chain_fetch','pages','li2_fetch_page')[0]
        self.eq(pages[0],'li2_step_page',address=self.page,object=self.i(src,'li2_fetch_page','allocation'),generation=self.i(src,'li2_fetch_page','generation'),offset=self.source_offset,closed_prot=1,open_prot=5);zero(pages[1],'unused predecessor permission page')
        for k in('open_started','opened'):need(struct.unpack('<2I',self.f(st,qt,k))==(1,0),'actual original page open')
        for k in('revoke_started','revoked'):need(struct.unpack('<2I',self.f(st,qt,k))==(int(closed),0),'actual original page revoke')
        for k in('open_result','revoke_result'):zero(self.f(st,qt,k),'actual successful page operations')
        self.eq(o,'li2_tf_owner',unexpected_frame_observed=0,continuation_started=int(closed),continuation_complete=int(closed),continuation_result=0,rdssp_query_attempted=0,rdssp_query_complete=0,rdssp_query_result=0,rdssp_features=0,bnd_xcr0_attempted=0,bnd_xcr0_complete=0,bnd_xcr0=0)
        zero(self.f(o,'li2_tf_owner','rdssp_observation'),'no unrelated SHSTK observation')
        before=self.f(st,qt,'before');g=q(self.f(before,'li2_step_frame','greg'));n=self.i(before,'li2_step_frame','fp_bytes')
        need(self.i(before,'li2_step_frame','mask')==MASK and self.i(before,'li2_step_frame','initialized')==n and n==ingress['fp_bytes']and self.f(before,'li2_step_frame','fp')==ingress['fp'],'whole real predecessor FP and mask')
        need(g[16]==pc and g[18]==0x2b000000000033 and g[21]==MASK and g[17]==flags|(RF if origin==1 else 0),'original real NX/TRACE predecessor frame')
        need(g[19:21]==((21,14)if origin==1 else(0,1)),'actual predecessor event class')
        if origin==1:need(g[22]==pc,'original predecessor NX CR2')
        if closed:
            self.step_frame(self.f(st,qt,'after'),ingress);self.eq(st,qt,signal_number=5,signal_code=2,signal_errno=0,signal_address=ingress['greg'][16])
            self.eq(o,'li2_tf_owner',actual_post_pc=ingress['greg'][16],actual_post_flags=ingress['greg'][17])
            query=self.f(slot,t,'query');self.eq(query,'li2_tf_continuation',pc=ingress['greg'][16],attempted=1,page_observed=1,complete=1,result=0);self.maps(self.f(query,'li2_tf_continuation','maps'));self.continuation_page(self.f(query,'li2_tf_continuation','page'),ingress['greg'][16]);self.backing(self.f(query,'li2_tf_continuation','backing'))
            self.eq(self.f(slot,t,'release'),'li2_chain_release',started=1,complete=1,result=0)
        else:
            for k in('query','release'):zero(self.f(slot,t,k),'no premature predecessor '+k)
            zero(self.f(st,qt,'after'),'no future predecessor frame');self.eq(o,'li2_tf_owner',actual_post_pc=0,actual_post_flags=0)
            self.eq(st,qt,signal_number=11 if origin==1 else 5,signal_code=2,signal_errno=0,signal_address=pc)
        return dict(greg=g,mask=MASK,fp=self.f(before,'li2_step_frame','fp'),fp_bytes=n,fs=ingress['fs'],gs=ingress['gs']),ref

    def transfer(self,tr,slot,ingress,before,ref,consumed=True):
        t='li2_span_transfer_progress';oldref=self.f(self.f(slot,'li2_tf_chain_slot','fetch'),'li2_chain_fetch','ref');seq=self.i(ref,'li2_fetch_ref','sequence');oldseq=self.i(oldref,'li2_fetch_ref','sequence')
        self.eq(tr,t,phase=3 if consumed else 2,issued=1,consume_attempted=int(consumed),consumed=int(consumed),resume_attempted=0,resumed=0,previous=self.i(slot,'li2_tf_chain_slot','index'),next=0,successor_installed=0,first_error=0,first_detail=0,previous_generation=self.i(slot,'li2_tf_chain_slot','generation'),previous_borrow=oldseq,fresh_borrow=seq if consumed else 0,pc=before['greg'][16],flags=before['greg'][17],refault_attempted=0,refaulted=0)
        need(self.i(tr,t,'serial')>0 and self.i(tr,t,'event')>self.i(slot,'li2_tf_chain_slot','event_id')and seq>oldseq,'actual same-event completed old borrow before newer source borrow')
        pc=self.i(self.f(slot,'li2_tf_chain_slot','decoded'),'li2_decoded','pc');self.observation(self.f(tr,t,'released'),pc,False,oldref)
        if consumed:self.observation(self.f(tr,t,'fresh'),before['greg'][16],True,ref)
        else:zero(self.f(tr,t,'fresh'),'unconsumed ticket has no fabricated consume observation')

    def epoch(self,b,index,previous=None):
        t='pro_epoch';st='pro_stage';gt='li2_pg_generation';pt='li2_pg_progress';it='pro_epoch_info'
        h=q(self.f(b,t,'h'));need(index==0 and previous is None,'one actual resident cold epoch')
        need(h[:3]==(1,index,self.head)and h[3]>0 and h[4:11]==(1,1,h[3],0,1,1,0)and h[11]==h[3]+1 and h[12:15]==(0,0,1),'actual group entry/exit with zero interior signal')
        need(h[15]in(0,1)and h[16]==self.symbol('selected_session')and h[17]>0 and h[18]<U64 and h[19:]==(h[15],1,0,0,1),'actual selected preclose group predecessor')
        initial=self.f(b,t,'initial_registry');need(initial==self.f(b,t,'terminal_registry'),'whole group registry unchanged during epoch')
        self.ranges,kinds=self.registry_prefix(self.f(self.b,'pro_wire','startup_registry'),initial)
        payload=self.f(b,t,'initial_payload');need(payload==self.f(b,t,'terminal_payload'),'whole literal immutable group primary unchanged')
        for k in('initial_tail','terminal_tail'):zero(self.f(b,t,k),'whole group proof tail zero')
        ph=self.f(payload,'pe_payload','header');self.geometry=self.layout(self.f(ph,'pe_header','layout'),self.h[26]);self.generated=self.geometry[0];self.spill=self.geometry[4];self.proof=self.h[27]
        self.table=self.proof+self.r.types['pe_payload']['fields']['plan']['offset']+self.r.types['li2_pg_compact']['fields']['table']['offset']
        for a,z in((self.h[26],self.h[28]+PAGE),(self.h[29],self.h[30]+PAGE),(self.proof,self.proof+364544)):
            need(self.ranges.count((a,z))==1 and kinds[self.ranges.index((a,z))]==0,'whole group banks and immutable proof protected')
        entered=self.f(b,t,'entered');end=self.f(b,t,'terminal');p=self.f(entered,st,'progress');ep=self.f(end,st,'progress');serial=self.i(p,pt,'serial');gen=self.i(p,pt,'generation')
        prior=self.f(b,t,'prior_counts');pc=self.counts(prior);resident=self.f(b,t,'prior_generation');installed=self.i(resident,gt,'installed')
        need(installed in(0,1)and serial==pc['next_serial']+1 and 0<gen<U64//2,'actual monotonic group serial/member generation')
        need(pc['entries']==pc['completed']and pc['publications']==pc['next_generation']and pc['unexpected']==0,'all preceding resident epochs completed before focal entry')
        if installed:self.prior_completed(self.f(b,t,'prior_permit'),resident,pc)
        else:
            zero(self.f(b,t,'prior_permit'),'no virgin completion permit');zero(resident,'whole virgin generation')
            need(pc['next_generation']==0,'no unseen prior publication')
        inc=dict(next_serial=1,offers=1,entries=1,permit_claims=int(installed))
        inc.update(next_generation=1,publications=1,cold_attempts=1,retirements=int(installed))
        self.delta(prior,self.f(entered,st,'counts'),**inc);self.delta(self.f(entered,st,'counts'),self.f(end,st,'counts'),completed=1)
        self.eq(p,pt,serial=serial,registration_epoch=1,publication=1,generation=gen,phase=9,first_error=0,source_count=2,opened_pages=17,closed_pages=0,anchor_released=0,registration_rechecked=0,completion_permit=0,first_detail=0,generated=self.generated,proof=self.proof,table=self.table,spill=self.spill)
        need(q(self.f(p,pt,'source'))==(self.page,self.page+PAGE)and self.layout(self.f(p,pt,'layout'))==self.geometry,'actual group progress source/layout')
        self.r.change(p,ep,pt,values=dict(phase=13,closed_pages=17,anchor_released=1,registration_rechecked=1,completion_permit=1))
        for s in(entered,end):self.eq(s,st,busy=1,active=1,failing=0,resuming=0,pending=1);need(0<self.i(s,st,'route')<32,'actual generated group route')
        need(self.f(entered,st,'route')==self.f(end,st,'route'),'unchanged active route through group close')
        self.eq(ph,'pe_header',version=1,generation=gen,registry=self.symbol('pe'),generated=self.generated,spill=self.spill,table=self.table,plan_proof=2,none_proof=1,source_validations=1,registered_epoch=1,rseq_address=RSEQ,rseq_length=32,rseq_signature=0x53053053)
        need(q(self.f(ph,'pe_header','member_generation'))==(2*gen,2*gen+1),'two exact generation-bound members');zero(self.f(ph,'pe_header','reserved'),'whole group header reserved')
        binding=self.image['persistent_binding'];need(binding['version']==2 and binding['profile']=='persistent-resident-dispatch-v2','explicit distinct group source binding')
        need(self.f(ph,'pe_header','archive')==bytes.fromhex(binding['archive']['sha256'])and self.f(ph,'pe_header','policy')==bytes.fromhex(binding['policy_sha256']),'whole actual group archive/policy authority')
        key=self.f(payload,'pe_payload','source');self.source_key(key,self.head);expected=self.compact(payload)
        need(self.f(b,t,'initial_code')==self.f(b,t,'terminal_code')==expected['image']+expected['stub_image'],'all17 actual code pages literal and immutable')
        need(self.f(b,t,'initial_slots')==expected['initial_slots']and self.f(b,t,'terminal_slots')==expected['terminal_slots'],'actual LINKED-to-RESET slots with whole unused page zero')
        g=self.f(entered,st,'generation');eg=self.f(end,st,'generation');buildserial=self.i(g,gt,'build_serial')
        self.eq(g,gt,installed=1,complete=1,proof_complete=1,generation=gen,ready_generation=gen,build_serial=buildserial,plan_proofs=2,none_proofs=1,generated=self.generated,proof=self.proof,spill=self.spill,active_refs=1,linked=1,code_copied=69632,code_verified=69632,proof_zeroed=364544,proof_copied=362624,proof_verified=364544)
        need(self.f(g,gt,'layout')==self.f(ph,'pe_header','layout')and self.f(g,gt,'member_generation')==self.f(ph,'pe_header','member_generation')and q(self.f(g,gt,'incoming'))==q(self.f(g,gt,'member_refs'))==(1,1),'actual linked member generations and incoming/active refs')
        need(self.i(ph,'pe_header','serial')==buildserial and buildserial==serial,'actual focal cold publication serial')
        self.query3(self.f(g,gt,'code_writable'),3);self.proof_query(self.f(g,gt,'proof_writable'),self.proof,3);self.query(self.f(g,gt,'spill_query'),self.spill,3);zero(self.f(g,gt,'slot_query'),'unused aggregate slot query remains zero')
        self.permission3(self.f(g,gt,'code_sealed'),1);self.proof_permission(self.f(g,gt,'proof_sealed'),self.proof,1);self.permission3(self.f(g,gt,'open'),5)
        for k in('close','cleanup'):zero(self.f(g,gt,k),'no premature group code close')
        transitions=self.r.items(g,gt,'slots','pg_slot_transition');self.slots_transition(transitions[0],False);self.slots_transition(transitions[1],True);zero(transitions[2],'no premature RESET after entry')
        self.r.change(g,eg,gt,values=dict(active_refs=0,linked=0),observed=('incoming','member_refs','close','slots','cell'))
        zero(self.f(eg,gt,'incoming'),'all incoming refs drained');zero(self.f(eg,gt,'member_refs'),'both member refs drained');self.permission3(self.f(eg,gt,'close'),1)
        ends=self.r.items(eg,gt,'slots','pg_slot_transition');need(ends[:2]==transitions[:2],'initial RESET and LINKED receipts retained');self.slots_transition(ends[2],False)
        cells=self.r.items(g,gt,'cell','pg_dispatch_cell_transition');endcells=self.r.items(eg,gt,'cell','pg_dispatch_cell_transition')
        self.cell(cells[0],gen,serial,0);self.cell(cells[1],gen,serial,0);zero(cells[2],'no premature terminal cell reset')
        need(endcells[:2]==cells[:2],'initial cell reset receipts retained exactly');self.cell(endcells[2],gen,serial,self.generated)
        need(gen==pc['next_generation']+1,'actual new cold generation')
        info=self.f(b,t,'info');self.eq(info,it,selected_bank=0,warm=0,initialized=1,registered=1,code_allocated=2,proof_allocated=1,code_registered=2,proof_registered=1,close_started=1,close_complete=1,prepare_started=1,prepare_complete=1,build_started=1,build_returned=1,redirected=1,exit_seen=1,exit_index=0,recovery_started=1,recovery_complete=1,guest_data_fault=0,cleanup_started=0,cleanup_complete=0,consumed=1,plan_proofs=2,none_proofs=1,code_allocation=self.h[29],proof_allocation=self.proof,build_result=0,recovery_result=0,release_result=0,gpr_written=0x40f,flags_written=0x8d5,ticket=self.symbol('span_transfer'),registry_count=len(self.ranges))
        self.eq(self.f(info,it,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
        need(self.f(info,it,'session')==self.f(self.b,'pro_wire','session')and self.f(info,it,'registry')==self.f(initial,'pro_registry','ranges'),'whole source session/registry proof inputs')
        saved=self.geometry
        for i,bank in enumerate(self.r.items(info,it,'banks','ped_bank')):
            address=self.h[26 if i==0 else 29];self.geometry=self.layout(self.f(bank,'ped_bank','layout'),address)
            self.eq(bank,'ped_bank',generated=address,spill=self.h[28 if i==0 else 30],allocated=1,registered=1);self.query3(self.f(bank,'ped_bank','initial'),3);self.query(self.f(bank,'ped_bank','initial_spill'),self.geometry[4],3);self.query(self.f(bank,'ped_bank','initial_slots'),self.geometry[3],3)
            if not i:self.eq(bank,'ped_bank',virgin=0,prot=1)
            else:need(self.i(bank,'ped_bank','virgin')in(0,1)and self.i(bank,'ped_bank','prot')in(1,3),'actual unused or completed alternative bank')
        self.geometry=saved
        if installed:
            save=self.geometry;self.geometry=self.layout(self.f(resident,gt,'layout'));self.query3(self.f(info,it,'claim_code'),1);self.proof_query(self.f(info,it,'claim_proof'),self.proof,1);self.query(self.f(info,it,'claim_spill'),self.geometry[4],3);self.query(self.f(info,it,'claim_slots'),self.geometry[3],1);self.geometry=save
        else:
            for k in('claim_code','claim_proof','claim_spill','claim_slots'):zero(self.f(info,it,k),'no fabricated virgin claim')
        rows=self.r.items(info,it,'bank_before','li2_private_code_query');prot=self.i(rows[0],'li2_private_code_query','actual_prot');need(prot in(1,3),'cold target is closed or virgin');self.query3(self.f(info,it,'bank_before'),prot)
        self.proof_query(self.f(info,it,'proof_before'),self.proof,1 if pc['next_generation']else 3);self.permission3(self.f(info,it,'reopen_code'),3);self.proof_permission(self.f(info,it,'reopen_proof'),self.proof,3)
        for a,z in zip(self.r.items(g,gt,'code_writable','li2_private_code_query'),self.r.items(info,it,'reopen_code','le_permission'),strict=True):need(a==self.f(z,'le_permission','query'),'whole actual code reopen publication join')
        need(self.f(g,gt,'proof_writable')==self.f(self.f(info,it,'reopen_proof'),'pg_proof_permission','query'),'whole actual proof reopen publication join')
        before=self.frame(self.f(b,t,'before'));ingress=self.normalized(self.f(b,t,'ingress'),before);returned=self.frame(self.f(b,t,'returned'));after=self.frame(self.f(b,t,'after'));flags=before['greg'][17]
        self.eq(info,it,flags=flags);self.trace(ingress,self.head,flags|TF);self.trace(before,self.head,flags);self.same_event(ingress,before,flags)
        want=list(before['greg']);want[16]=self.generated
        need(returned['greg']==tuple(want)and returned['fp']==before['fp']and returned['si']==before['si']and(returned['fs'],returned['gs'])==tuple(self.app['machine'][1:3]),'whole group redirect changes only original RIP')
        uc=bytearray(before['uc']);struct.pack_into('<Q',uc,40+16*8,self.generated);need(returned['uc']==bytes(uc),'whole group return UC except actual redirect')
        self.nx(after,self.page+0xf18)
        need(after['fp']==before['fp']and after['fp_bytes']==before['fp_bytes']and after['mask']==MASK and(after['fs'],after['gs'])==tuple(self.app['machine'][1:3]),'all group FP/AF/mask/TLS preserved')
        projection=self.f(b,t,'predecessor');self.eq(projection,'pro_predecessor',complete=1,unexpected_compared=self.r.types['li2_step_frame']['bytes'],unexpected_nonzero=0)
        slot=self.f(projection,'pro_predecessor','closed')+bytes(self.r.types['li2_step_frame']['bytes']);self.r.walk(slot,'li2_tf_chain_slot')
        prefix=self.f(projection,'pro_predecessor','before_prefix');wanted=bytearray(prefix);sf=self.r.types['li2_tf_chain_slot']['fields'];of=self.r.types['li2_tf_owner']['fields'];tf=self.r.types['li2_step_owner']['fields']
        struct.pack_into('<I',wanted,sf['phase']['offset'],5);at=sf['owner']['offset']+of['step']['offset']
        for k,v in(('phase',5),('trace_seen',1),('revoke_sync_started',1)):struct.pack_into('<I',wanted,at+tf[k]['offset'],v)
        need(bytes(wanted)==slot[:len(prefix)],'whole actual group predecessor prefix close transition')
        need(self.i(slot,'li2_tf_chain_slot','index')==h[15]and self.i(slot,'li2_tf_chain_slot','event_id')<h[17],'actual group predecessor older generation/event')
        predecessor,oldref=self.predecessor(slot,self.page+0xdfe,ingress)
        priorstep=prefix+bytes(self.r.types['li2_tf_chain_slot']['bytes']-len(prefix));self.eq(priorstep,'li2_tf_chain_slot',phase=3);self.eq(self.f(self.f(priorstep,'li2_tf_chain_slot','owner'),'li2_tf_owner','step'),'li2_step_owner',phase=3,trace_seen=0,revoke_sync_started=0)
        ref=self.f(info,it,'ref');seq=self.i(ref,'li2_fetch_ref','sequence');tr=self.f(entered,st,'transfer');self.transfer(tr,slot,ingress,before,ref)
        need(tr==self.f(end,st,'transfer')and self.i(tr,'li2_span_transfer_progress','event')==h[17]and self.i(tr,'li2_span_transfer_progress','serial')==self.i(p,pt,'transfer_serial'),'whole exact consumed group transfer')
        es=self.f(entered,st,'source');zs=self.f(end,st,'source');self.source(es,serial,self.head,key,ref);self.source(zs,serial,self.head,key,ref,terminal=True)
        need(self.f(es,'li2_pg_source_progress','source')==self.f(zs,'li2_pg_source_progress','source'),'whole source anchor retained throughout linked execution')
        er=self.f(entered,st,'rseq');zr=self.f(end,st,'rseq');estate=self.f(entered,st,'state');zstate=self.f(end,st,'state')
        a=self.pin(er,estate,serial,70,0,2);z=self.pin(zr,zstate,serial,70,0,2,terminal=True)
        need(z>a and estate==zstate,'actual zero-word pin closes with full old rseq state unchanged')
        lastpc=self.geometry[2]+6
        self.eq(estate,'li2_rseq_state',last_first=0,last_end=0,last_pc=lastpc,last_code=765,last_policy=1)
        self.eq(self.f(estate,'li2_rseq_state','last_footprint'),'li2_write_footprint',pc=lastpc,next_pc=lastpc+6,first=0,end=0,abi_version=1,policy=1,code=765,length=6)
        self.progress(self.f(entered,st,'fetch'),seq,True);self.progress(self.f(end,st,'fetch'),seq,False);need(self.f(info,it,'final_fetch')==self.f(end,st,'fetch'),'whole actual released group fetch')
        lives=self.r.items(info,it,'live','li2_link_rseq_live')
        for x in lives[:2]:self.live_rseq(x,estate,before)
        self.live_rseq(lives[2],zstate,after)
        self.proof_query(self.f(info,it,'proof_exit'),self.proof,1)
        for k in('code_exit','recovered','recovery_scratch'):zero(self.f(info,it,k),'normal group exit claims no unexpected recovery')
        self.permit(self.f(end,st,'permit'),eg,zs,zr,self.f(end,st,'fetch'));self.eq(self.f(entered,st,'permit'),'ped_permit',valid=0)
        need(self.f(self.f(end,st,'permit'),'ped_permit','generation_source')==key,'actual immutable source in completed group permit')
        bm=self.memory(self.f(b,t,'before_memory'),False);am=self.memory(self.f(b,t,'after_memory'),False)
        need(bm==am==dict(data=self.app['data'],stack=self.app['stack']),'whole loop data/stack remains byte-identical')
        return dict(kind='cold',mode=0,prior_generation_installed=int(installed),dispatch_head=69,dispatch_pc=self.page+0xf18,dispatch_cell_reset=1,terminal_ordinal=h[11],ingress=ingress,before=before,returned=returned,logical=after,after=after,predecessor_before=predecessor,before_memory=bm,after_memory=am,completed=1,closed_pages=17,anchor_released=1,permit=1,guest_data_fault=0,guard_rejected=0,interior_signals=0,payload=payload,permit_raw=self.f(end,st,'permit'),generation_raw=eg,counts_raw=self.f(end,st,'counts'),serial=serial)



    def next_trace(self,b,cold,epoch):
        t='pro_next';slot=self.f(b,t,'closed');st='li2_tf_chain_slot'
        self.eq(b,t,expected_ordinal=cold['terminal_ordinal']+1,raw_ordinal=cold['terminal_ordinal']+1,
                capture_result=0,ingress_complete=1,closed_complete=1,tls_complete=1)
        index=self.i(b,t,'slot_index');event=self.i(b,t,'event_id')
        need(index in(0,1)and self.i(slot,st,'index')==index and event>self.i(slot,st,'event_id')>0,
             'actual next TRACE chain/index/event and closed predecessor')
        self.eq(slot,st,origin=1)
        frame=self.frame(self.f(b,t,'frame'))
        flags=(cold['logical']['greg'][17]&~RF)|TF
        self.trace(frame,self.app['expected_exit_pc'],flags)
        need(frame['greg'][22]==cold['dispatch_pc']and (frame['fs'],frame['gs'])==tuple(self.app['machine'][1:3]),
             'actual next TRACE retains dispatch CR2 and observed post-close TLS')
        before,ref=self.predecessor(slot,cold['dispatch_pc'],frame)
        owner=self.f(slot,st,'owner');step=self.f(owner,'li2_tf_owner','step')
        self.step_frame(self.f(step,'li2_step_owner','before'),cold['logical'])
        need(before['greg']==cold['logical']['greg']and before['fp']==cold['logical']['fp'],
             'ordinary original JMP starts at the actual completed resident NX frame')
        terminal=self.f(epoch,'pro_epoch','terminal');fetch=self.f(terminal,'pro_stage','fetch')
        need(self.i(ref,'li2_fetch_ref','sequence')>self.i(fetch,'li2_fetch_progress','sequence'),
             'ordinary JMP borrows only after actual resident source release')
        cold['next_trace']=frame;cold['next_trace_ordinal']=self.i(b,t,'raw_ordinal')

    def finish(self,status):
        h=self.h;t='pro_wire';r=self.r
        need(type(status)is int and status==0 and self.app['mode']==0,'actual successful loop-only process and mode')
        need(h[:9]==(0x324f525049324c,2,1719936,r.layout['registrations']['pe']['bytes'],362624,364544,69632,968,128),'actual distinct group record version and complete extents')
        need(canonical(self.bias)and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(n)for n in('li2_raw6','li2_gateway_start','li2_gateway_end'))and h[10]<=h[9]<h[11],'actual emitted gateway identity')
        need(h[12]%PAGE==0 and h[13]==524288 and h[14:16]==(1,0)and h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,0),'actual altstack and FD3/profile')
        need(h[20:26]==tuple(self.symbol(n)for n in('pe','pro_wire','pg_source','pg_rseq','selected_chain','span_progress')),'actual protected group addresses')
        need(PAGE<=h[26]<1<<31 and all(x%PAGE==0 for x in h[26:31])and h[28]==h[26]+73728 and h[30]==h[29]+73728 and all(canonical(a,n)for a,n in((h[26],77824),(h[27],364544),(h[29],77824))),'actual two distinct complete group banks/proof')
        ranges=[(h[26],h[28]+PAGE),(h[27],h[27]+364544),(h[29],h[30]+PAGE)]
        need(all(z<=b or e<=a for i,(a,z)in enumerate(ranges)for b,e in ranges[i+1:]),'separate whole group code/slots/spill/proof allocations')
        need(self.head==self.page+0xe00 and self.page+8192<1<<31 and h[31:34]==(self.head,self.page+0xf18,self.app['expected_exit_pc'])and h[34:39]==(0,1,0,0,0)and not any(h[39:47])and h[47:53]==(1,0,0,0,h[16],0)and not any(h[53:]),'exact one resident epoch and retained successful prefix')
        raw=q(self.f(self.b,t,'raw_ingress'));need(sum(raw[1:])==raw[0]>0,'whole actual signal population')
        for k in('sink_initial','sink_terminal'):
            st=self.f(self.b,t,k);d=self.stat(st);need(d['mode']&0xffff==0x8180 and d['size']==0,'actual empty regular0600 sink');self.eq(st,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(self.f(self.b,t,'sink_initial'),self.f(self.b,t,'sink_terminal'),'stat',observed=('st_atim','st_mtim','st_ctim'))
        footer=q(r.data[-64:]);need(footer[:4]==(0x3246525049324c,2,len(self.b),len(self.b))and 1<=footer[4]<=64 and 0<footer[5]<=len(self.b)and footer[6:]==(0,0),'complete actual group output footer')
        if footer[4]==1:need(footer[5]==len(self.b),'single actual complete group write')
        hardware=self.f(self.b,t,'hardware');self.eq(hardware,'li2_selected_hardware',abi_version=1,reserved=0)
        for i,k in enumerate(('leaf0','leaf1','leaf7')):need(struct.unpack('<4I',self.f(hardware,'li2_selected_hardware',k))==tuple(self.app['hardware'][i][2:]),'actual bridge/app CPUID hardware equality')
        for key,objid in(('main',self.image['main_object']),('interpreter',self.image['interpreter_object'])):self.image_header(self.f(self.b,t,key),objid)
        self.eq(self.f(self.b,t,'session'),'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        need(self.i(self.f(self.b,t,'session'),'li2_step_session','sync_query')&96==96,'actual registered membarrier support')
        obj,_,loads=self.objects[self.image['main_object']];bias=self.bases[self.image['main_object']]
        owners=[p for p in loads if p[1]==5 and bias+p[3]<=self.page and self.page+8192<=bias+p[3]+p[5]]
        need(len(owners)==1 and self.source_offset==owners[0][2]+self.page-bias-owners[0][3]and obj['data'][self.source_offset:self.source_offset+8192]==self.app['source'],'whole source two-page original ELF bytes')
        epochs=r.items(self.b,t,'epochs','pro_epoch');need(len(epochs)==1,'one literal resident epoch')
        cold=self.epoch(epochs[0],0);self.next_trace(self.f(self.b,t,'next'),cold,epochs[0])
        need(raw[0]>=cold['next_trace_ordinal'],'whole chronological resident ingress ordinals')
        final=self.counts(self.f(self.b,t,'final_counts'));last=self.counts(cold['counts_raw'])
        need(all(final[k]>=last[k]for k in final if k!='misses')and all(a>=b for a,b in zip(final['misses'],last['misses'],strict=True)),'final counters retain every focal event without attributing later work')
        names='version status failure_code detail_abs detail_negative phase serial generation build_serial offers cold_attempts publications hits cancelled retirements permit_claims entries completed unexpected permit opened_pages closed_pages anchor_released registration_rechecked guest_data_fault recovery_complete first_error active busy'.split()
        values=q(self.f(self.b,t,'final_row'));need(len(values)==len(names),'whole exact group terminal schema');row=dict(zip(names,values,strict=True));row['misses']=list(final['misses'])
        need((row['version'],row['status'],row['failure_code'],row['detail_abs'],row['detail_negative'])==(2,0,0,0,0),'actual protected resident terminal outcome')
        for k in('offers','cold_attempts','publications','hits','cancelled','retirements','permit_claims','entries','completed','unexpected'):need(row[k]==final[k],'whole final counter-to-report join '+k)
        p=self.f(self.b,t,'final_progress');pt='li2_pg_progress'
        for k in('phase','serial','opened_pages','closed_pages','anchor_released','registration_rechecked','first_error'):need(row[k]==self.i(p,pt,k),'actual group progress-to-report join '+k)
        # The report uses resident generation; a later cancelled progress has
        # generation zero and does not erase the retained resident identity.
        need(row['generation']==final['next_generation']and 0<row['build_serial']<=row['serial'],'actual retained resident generation/build serial')
        need(final['offers']==final['entries']+final['cancelled']and final['entries']==final['publications']+final['hits']and final['cold_attempts']==final['publications']+final['cancelled']and sum(final['misses'])==final['cancelled']and final['next_serial']==final['offers']and final['next_generation']==final['publications'],'whole completed/cancelled group partition')
        need(final['entries']==final['completed']and final['unexpected']==0 and final['retirements']==final['publications']-1 and final['permit_claims']==final['retirements']+final['hits'],'whole one-resident group permit/publication accounting')
        need(row['phase']in(13,14)and row['active']==row['busy']==row['first_error']==row['guest_data_fault']==0 and row['permit']==1 and row['anchor_released']==row['registration_rechecked']==1,'actual final closed group or completed cancellation')
        need((row['opened_pages'],row['closed_pages'],row['recovery_complete'])==((17,17,1)if row['phase']==13 else(0,0,0)),'exact final group extent and recovery for its terminal phase')
        prior=cold['prior_generation_installed']
        return dict(terminal=row,mode=0,attempts=[cold],cold_publications=1,warm_entries=0,replacements=prior,permit_claims=prior,interior_signals=0,source=self.app['source'],word=0,status=0,code=0,detail=0,qualification_credit=False)


def read(data,layout,image,app,pid,cpu,exit_status):
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    return Check(wire.Reader(data,layout),image,app,pid,cpu).finish(exit_status)


def terminal(parsed,owner):
    expected=owner['terminal'];need(type(parsed)is dict and set(parsed)==set(expected)and all(type(v)is int for k,v in parsed.items()if k!='misses')and type(parsed['misses'])is list and all(type(v)is int for v in parsed['misses'])and parsed==expected,'whole actual protected resident terminal row')
    return dict(fields=len(expected),protected_resident_row=1,inherited_row_protection=0)


CONTROL_COUNTS={0:81}

def controls(data,layout,image,app,pid,cpu,exit_status):
    """Actual supplied resident record mutations; old group79 remains separate."""
    read(data,layout,image,app,pid,cpu,exit_status);types=layout['types']
    def at(t,k,base=0,index=0,child=None):return base+types[t]['fields'][k]['offset']+(index*types[child]['bytes']if child else index)
    w='pro_wire';et='pro_epoch';st='pro_stage';it='pro_epoch_info';gt='li2_pg_generation';pt='li2_pg_progress';ct='li2_pg_compact'
    e=at(w,'epochs');ent=at(et,'entered',e);end=at(et,'terminal',e);info=at(et,'info',e)
    p=at(st,'progress',end);g=at(st,'generation',end);eg=at(st,'generation',ent)
    payload=at(et,'initial_payload',e);cp=at('pe_payload','plan',payload)
    pred=at(et,'predecessor',e);closed=at('pro_predecessor','closed',pred);owner=at('li2_tf_chain_slot','owner',closed);step=at('li2_tf_owner','step',owner)
    n=at(w,'next');ns=at('pro_next','closed',n);no=at('li2_tf_chain_slot','owner',ns);nt=at('li2_tf_owner','step',no)
    nf=at('pro_next','frame',n);cell=at(gt,'cell',g,2,'pg_dispatch_cell_transition')
    tests=[
      ('wire_version',8),('footer_version',len(data)-56),('actual_hardware',at('li2_selected_hardware','leaf0',at(w,'hardware'))),
      ('interior_signal',at(et,'h',e)+11*8),('full_terminal_FP',at('li2_step_frame','fp',at('le_frame','frame',at(et,'after',e)))),
      ('full_data',at('li2_pro_memory','data',at(et,'after_memory',e))),('full_stack',at('li2_pro_memory','stack',at(et,'after_memory',e))),
      ('source_second_page',at(ct,'source',cp)+4096),('proof_padding',at(et,'terminal_tail',e)),('literal_second_image',at(et,'terminal_code',e)+32768),
      ('literal_stub_code',at(et,'terminal_code',e)+65536),('initial_link_slot',at(et,'initial_slots',e)),('terminal_reset_slot',at(et,'terminal_slots',e)),
      ('member_generation',at('pe_header','member_generation',at('pe_payload','header',payload))+8),('global_head_population',at(ct,'heads',cp)),
      ('member_partition',at(ct,'member_heads',cp)+4),('typed_link_target',at('li2_pg_edge','target_head',at(ct,'edge',cp))),
      ('entry_word',at('li2_pg_rseq_progress','word_entry',at(st,'rseq',ent))),('closing_word',at('li2_pg_rseq_progress','word_after',at(st,'rseq',end))),
      ('cold_stub_proof',at('li2_pg_rseq_progress','cold_stubs',at(st,'rseq',ent))),('cold_head_proof',at('li2_pg_rseq_progress','cold_heads',at(st,'rseq',ent))),
      ('live_GPR',at('li2_write_registers','gpr',at('li2_link_rseq_live','registers',at(it,'live',info)))),
      ('active_member_reference',at(gt,'member_refs',eg)+8),('closed_incoming_reference',at(gt,'incoming',g)),
      ('first_image_revoke',at('le_permission','complete',at(gt,'close',g))),('second_image_revoke',at('le_permission','complete',at(gt,'close',g,1,'le_permission'))),
      ('stub_page_revoke',at('le_permission','complete',at(gt,'close',g,2,'le_permission'))),
      ('source_anchor_release',at('li2_pg_source_progress','release_complete',at(st,'source',end))),('source_closed_pages',at('li2_pg_source_progress','closed_pages',at(st,'source',end))),
      ('completion_permit',at(pt,'completion_permit',p)),('reset_seal',at('le_permission','complete',at('pg_slot_transition','seal',at(gt,'slots',g,2,'pg_slot_transition')))),
      ('predecessor_before_FP',at('li2_step_frame','fp',at('li2_step_owner','before',step))),('predecessor_after_FP',at('li2_step_frame','fp',at('li2_step_owner','after',step))),
      ('predecessor_actual_revoke',at('li2_step_owner','revoked',step)),('predecessor_unexpected_scan',at('pro_predecessor','unexpected_compared',pred)),
      ('cell_generation',at('pg_dispatch_cell_transition','generation',cell)),('cell_serial',at('pg_dispatch_cell_transition','serial',cell)),
      ('cell_last_hit_target',at('pg_dispatch_cell_transition','before',cell)),('cell_zero_after_reset',at('pg_dispatch_cell_transition','after',cell)),
      ('cell_mapping',at('li2_private_code_query','complete',at('pg_dispatch_cell_transition','mapping',cell))),
      ('next_actual_ordinal',at('pro_next','raw_ordinal',n)),('next_raw_capture',at('pro_next','ingress_complete',n)),
      ('next_full_slot_close',at('pro_next','closed_complete',n)),('next_observed_TLS',at('pro_next','tls_complete',n)),
      ('next_full_FP',at('li2_step_frame','fp',at('le_frame','frame',nf))),('next_actual_FS',at('le_frame','fs',nf)),
      ('next_original_JMP_before_FP',at('li2_step_frame','fp',at('li2_step_owner','before',nt))),
      ('next_original_JMP_revoke',at('li2_step_owner','revoked',nt)),('next_original_JMP_release',at('li2_chain_release','complete',at('li2_tf_chain_slot','release',ns))),
      ('final_publication_partition',at('pro_counts','publications',at(w,'final_counts'))),('whole_terminal_row',at(w,'final_row')+17*8)]
    startup=at(w,'startup_registry');reg=at(et,'terminal_registry',e);rt='pro_registry'
    registry=[('startup_population',at(rt,'count',startup),'startup registry population is an exact predecessor',True),
      ('startup_table_headers',at(rt,'ph',startup),'startup registry keeps exact table, bridge and program headers',False),
      ('startup_range_prefix',at(rt,'ranges',startup),'startup registry retains every original range and classification',False),
      ('startup_classification_prefix',at(rt,'initial_code',startup),'startup registry retains every original range and classification',False),
      ('epoch_terminal_population',at(rt,'count',reg),'whole group registry unchanged during epoch',False),
      ('epoch_owner_population',at(it,'registry_count',info),'exact pro_epoch_info.registry_count',False)]
    refused=[]
    def reject(name,mutant,expected=None):
        try:read(bytes(mutant),layout,image,app,pid,cpu,exit_status)
        except ValueError as error:
            if expected is not None:need(str(error)==expected,'exact source-causal resident refusal '+name)
            refused.append(name)
        else:raise ValueError('supplied resident corruption accepted '+name)
    for name,offset in tests:
        mutant=bytearray(data);mutant[offset]^=1;reject(name,mutant)
    for name,offset,message,clear in registry:
        mutant=bytearray(data)
        if clear:mutant[offset:offset+4]=bytes(4)
        else:mutant[offset]^=1
        reject(name,mutant,message)
    # Coherent two-copy corruptions must reach the independent static model.
    coherent=(('head_descriptor','original','li2_span_decoded',0,'gpr_write'),
      ('memberB_descriptor','original','li2_span_decoded',64,'flags_read'),
      ('dispatch_original','original','li2_span_decoded',69,'refusal'),
      ('dispatch_head_kind','head','li2_pe_head',69,'kind'))
    for name,array,child,index,field in coherent:
        mutant=bytearray(data)
        for k in('initial_payload','terminal_payload'):
            base=at('pe_payload','plan',at(et,k,e));d=at(ct,array,base,index,child);mutant[at(child,field,d)]^=1
        reject('coherent_'+name,mutant,'whole independent resident '+array)
    for name,union,array,child,field in(
      ('dispatch_target_register','li2_pg_instruction','instruction','li2_jd_descriptor','target'),
      ('dispatch_hit_boundary','li2_pg_guard_record','guard','li2_jd_record','hit_offset'),
      ('dispatch_miss_boundary','li2_pg_guard_record','guard','li2_jd_record','miss_offset')):
        mutant=bytearray(data)
        for k in('initial_payload','terminal_payload'):
            base=at('pe_payload','plan',at(et,k,e));d=at(ct,array,base,69,union);typed=at(union,'dispatch',d);mutant[at(child,field,typed)]^=1
        reject('coherent_'+name,mutant,'whole independent resident '+array)
    mutant=bytearray(data);fp=at(w,'final_progress');fr=at(w,'final_row');closed_pages=struct.unpack_from('<I',data,at(pt,'closed_pages',fp))[0]
    struct.pack_into('<I',mutant,at(pt,'closed_pages',fp),closed_pages^1);struct.pack_into('<Q',mutant,fr+21*8,closed_pages^1)
    reject('coherent_final_extent',mutant,'exact final group extent and recovery for its terminal phase')
    # Correctly shaped full next record still must be this exact raw event,
    # original pre-effect JMP, and genuine ordinary source release.
    mutant=bytearray(data);event=struct.unpack_from('<Q',data,at('li2_tf_chain_slot','event_id',ns))[0]
    struct.pack_into('<Q',mutant,at('pro_next','event_id',n),event)
    reject('next_event_not_newer',mutant,'actual next TRACE chain/index/event and closed predecessor')
    mutant=bytearray(data);struct.pack_into('<I',mutant,at('li2_tf_classification','family',at('li2_tf_owner','classification',no)),4)
    reject('next_JMP_not_CALL',mutant,'exact li2_tf_classification.family')
    mutant=bytearray(data);struct.pack_into('<I',mutant,at('li2_tf_chain_slot','origin',ns),2)
    reject('next_requires_original_NX',mutant,'exact li2_tf_chain_slot.origin')
    # The prior resident may be absent. This mutation always uses a real
    # valid completed permit; it never invents a prior generation.
    prior=at(et,'prior_generation',e)
    valid_prior=struct.unpack_from('<I',data,at(gt,'installed',prior))[0]
    permit=at(et,'prior_permit',e)if valid_prior else at(st,'permit',end)
    mutant=bytearray(data);mutant[at('li2_pg_source_progress','layout',at('ped_permit','source',permit))]^=1
    reject('completed_permit_source_layout',mutant,'permit source binds the actual complete generation layout')
    # Same12 actual proof-query controls as the separate original group.
    proof=at(gt,'proof_writable',eg)
    for index in(0,1):
        row=at('pg_proof_query','part',proof,index,'li2_private_code_query');maps=at('li2_private_code_query','maps',row)
        observation=at('li2_fetch_map_progress','observation',maps);coverage='end'if index==0 else'first'
        for name,offset,width,value,message in(
          ('coverage',at('li2_private_code_query',coverage,row),8,struct.unpack_from('<Q',data,at('li2_private_code_query',coverage,row))[0]-PAGE,'exact li2_private_code_query.'+coverage),
          ('page_count',at('li2_private_code_query','pages_checked',row),8,(64 if index==0 else 25)-1,'exact li2_private_code_query.pages_checked'),
          ('completion',at('li2_private_code_query','complete',row),4,0,'exact li2_private_code_query.complete'),
          ('protection',at('li2_private_code_query','actual_prot',row),4,7,'exact li2_private_code_query.actual_prot'),
          ('maps_close',at('li2_fetch_map_progress','closed',maps),4,0,'exact li2_fetch_map_progress.closed'),
          ('maps_receipt',at('li2_maps_observation','io_performed',observation),4,struct.unpack_from('<I',data,at('li2_maps_observation','io_performed',observation))[0]^1,'exact maintained acquisition class and physical I/O')):
            mutant=bytearray(data);struct.pack_into('<Q'if width==8 else'<I',mutant,offset,value);reject('proof_part'+str(index)+'_'+name,mutant,message)
    need(len(refused)==CONTROL_COUNTS[0],'all exact separately counted resident owner controls')
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0,mode=0)
