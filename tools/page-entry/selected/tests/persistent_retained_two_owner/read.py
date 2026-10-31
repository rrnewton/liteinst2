"""Distinct retained-two owner: A cold, B cold, two real cancellations, A warm.
Old fixed/dynamic/group267 profiles remain separate mandatory prerequisites."""
import hashlib,struct,importlib.util
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
HERE=Path(__file__).resolve().parent
wire=load('persistent_retained_two_wire',HERE/'wire.py');plan=load('persistent_retained_two_plan',HERE/'plan.py')
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
            t='ptr2o_registry';self.eq(b,t,complete=1,table=self.symbol('protected'));count=self.i(b,t,'count');need(0<count<=128,'bounded actual registration table')
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
        t='li2_ptr2o_memory';self.eq(b,t,attempted=1,complete=1,after_abort=int(failed),rows_checked=6,data_copied=8192,stack_copied=224,result=0,detail=0,rsp=RSP,data_first=DATA,stack_first=RSP-128)
        m=self.maps(self.f(b,t,'maps'),0)
        before,after=(self.f(b,t,k)for k in('before','after'));mt='li2_maps_stats'
        self.eq(before,mt,active=0,poisoned=0,reserved=0);self.eq(after,mt,active=0,poisoned=0,reserved=0,valid=1)
        self.r.change(before,after,mt,values=dict(fresh_calls=self.i(before,mt,'fresh_calls')+1,acquisitions=self.i(before,mt,'acquisitions')+1),observed=('valid','invalidations','mutation_epoch'))
        invalidations=self.i(after,mt,'invalidations')-self.i(before,mt,'invalidations')
        need(invalidations>=1 and self.i(after,mt,'mutation_epoch')-self.i(before,mt,'mutation_epoch')==invalidations,'actual explicit fresh invalidation and every gateway invalidation')
        need(m[:3]==(self.i(after,mt,'acquisitions'),0,self.i(after,mt,'mutation_epoch')),'memory acquisition actual stats join')
        rows=self.r.items(b,t,'rows','li2_ptr2o_map_row')
        for i,row in enumerate(rows):
            self.eq(row,'li2_ptr2o_map_row',offset=0,major=0,minor=0,inode=0,private=1)
            a,z,prot=self.v(row,'li2_ptr2o_map_row','first end prot');need(a%PAGE==z%PAGE==0 and a<z,'actual page-aligned memory extent')
            if i<2:need((a,z,prot)==(DATA,DATA+8192,3),'actual two-page writable data')
            elif i==4:need((a,z,prot)==(STACK+4096,STACK+4096+131072,3),'actual fixed writable guest stack')
            else:
                point=(DATA+8192,STACK,STACK+4096+131072)[(2,3,5).index(i)]
                need(a<=point and point+PAGE<=z and prot==0,'actual inaccessible data/stack guard')
        return dict(data=self.f(b,t,'data'),stack=self.f(b,t,'stack'))

    def registry_prefix(self,a,b):
        t='ptr2o_registry';n,m=self.i(a,t,'count'),self.i(b,t,'count');need(0<n<=m<=128,'startup registry population is an exact predecessor')
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
        t='ptr2o_counts';names='next_serial next_generation offers publications hits cold_attempts cancelled retirements permit_claims entries completed unexpected'.split()
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
        kind='nop'if pc==self.page+0x1fe else'xchg'if pc==self.page+0x600 else'jmp';code,length=self.decoded(self.f(slot,t,'decoded'),pc,kind)
        ref=self.chain_fetch(self.f(slot,t,'fetch'),pc,not closed);o=self.f(slot,t,'owner');st=self.f(o,'li2_tf_owner','step');qt='li2_step_owner'
        flags=ingress['greg'][17]&~TF
        self.eq(st,qt,phase=5 if closed else 3,first_error=0,in_handler=0,self_test=0,trace_seen=int(closed),revoke_sync_started=int(closed),first_detail=0,session=self.symbol('selected_session'),open_sync=0,revoke_sync=0,destination=0,width=0,immediate=0,effect=0,source=0)
        request=self.f(st,qt,'request');self.eq(request,'li2_step_request',page_count=1,original_flags=flags);self.decoded(self.f(request,'li2_step_request','decoded'),pc,kind)
        cl=self.f(o,'li2_tf_owner','classification');self.eq(cl,'li2_tf_classification',pc=pc,next_pc=pc+length,abi_version=1,policy=1,code=code,length=length,flow=2 if kind=='jmp'else 1,family=3 if kind=='jmp'else 1)
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

    def slot_metadata(self,slot,pc,frame,closed=True):
        t='li2_tf_chain_slot';index=self.i(slot,t,'index');need(index in(0,1),'actual predecessor slot index')
        self.eq(slot,t,chain=self.symbol('selected_chain'),phase=5 if closed else 3,fallback=0,prepare_complete=1,decode_attempted=1,decode_complete=1,retry=0,unexpected_frame_observed=0,unexpected_signal=0,unexpected_code=0,unexpected_errno=0,unexpected_address=0,prepare_result=0,decode_result=0,classify_result=0)
        need(self.i(slot,t,'generation')>0 and self.i(slot,t,'event_id')>0,'actual predecessor generation/event')
        origin=self.i(slot,t,'origin');need(origin in(1,2)and self.i(slot,t,'prepare_attempted')==int(origin==2),'actual predecessor NX/TRACE preparation')
        for k in('first_decoded','first_fetch','first_release'):zero(self.f(slot,t,k),'no unused predecessor '+k)
        kind='nop'if pc==self.page+0x1fe else'xchg'if pc==self.page+0x600 else'jmp';code,length=self.decoded(self.f(slot,t,'decoded'),pc,kind)
        ref=self.chain_fetch(self.f(slot,t,'fetch'),pc,not closed);o=self.f(slot,t,'owner');st=self.f(o,'li2_tf_owner','step');qt='li2_step_owner'
        flags=frame['greg'][17]&~TF
        self.eq(st,qt,phase=5 if closed else 3,first_error=0,in_handler=0,self_test=0,trace_seen=int(closed),revoke_sync_started=int(closed),first_detail=0,session=self.symbol('selected_session'),open_sync=0,revoke_sync=0,destination=0,width=0,immediate=0,effect=0,source=0)
        request=self.f(st,qt,'request');self.eq(request,'li2_step_request',page_count=1,original_flags=flags);self.decoded(self.f(request,'li2_step_request','decoded'),pc,kind)
        cl=self.f(o,'li2_tf_owner','classification');self.eq(cl,'li2_tf_classification',pc=pc,next_pc=pc+length,abi_version=1,policy=1,code=code,length=length,flow=2 if kind=='jmp'else 1,family=3 if kind=='jmp'else 1)
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
        if closed:
            self.eq(st,qt,signal_number=5,signal_code=2,signal_errno=0,signal_address=frame['greg'][16])
            self.eq(o,'li2_tf_owner',actual_post_pc=frame['greg'][16],actual_post_flags=frame['greg'][17])
            query=self.f(slot,t,'query');self.eq(query,'li2_tf_continuation',pc=frame['greg'][16],attempted=1,page_observed=1,complete=1,result=0);self.maps(self.f(query,'li2_tf_continuation','maps'));self.continuation_page(self.f(query,'li2_tf_continuation','page'),frame['greg'][16]);self.backing(self.f(query,'li2_tf_continuation','backing'))
            self.eq(self.f(slot,t,'release'),'li2_chain_release',started=1,complete=1,result=0)
        else:
            for k in('query','release'):zero(self.f(slot,t,k),'no premature predecessor '+k)
            self.eq(o,'li2_tf_owner',actual_post_pc=0,actual_post_flags=0)
            self.eq(st,qt,signal_number=11 if origin==1 else 5,signal_code=2,signal_errno=0,signal_address=pc)
        return ref

    def projected_slot(self,b):
        t='ptr2o_slot_progress';self.eq(b,t,complete=1);index=self.i(b,t,'index');need(index in(0,1),'actual projected ordinary slot index')
        # Offset adapter only: no claim or comparison of the omitted step frames.
        slot=bytearray(self.r.types['li2_tf_chain_slot']['bytes']);prefix=self.f(b,t,'prefix');suffix=self.f(b,t,'suffix')
        sf=self.r.types['li2_tf_chain_slot']['fields'];of=self.r.types['li2_tf_owner']['fields'];st=self.r.types['li2_step_owner']['fields']
        after=sf['owner']['offset']+of['step']['offset']+st['after']['offset']+self.r.types['li2_step_frame']['bytes']
        need(len(prefix)==384 and len(suffix)==sf['unexpected']['offset']-after,'actual projected prefix/suffix extents')
        slot[:len(prefix)]=prefix;slot[after:after+len(suffix)]=suffix
        need(self.i(slot,'li2_tf_chain_slot','index')==index,'projected actual selected index')
        chain=bytearray(self.r.types['li2_tf_chain']['bytes']);cp=self.f(b,t,'chain');need(len(cp)==self.r.types['li2_tf_chain']['fields']['slots']['offset'],'complete ordinary chain scalar prefix');chain[:len(cp)]=cp
        return bytes(slot),bytes(chain),index

    def __init__(self,r,image,app,pid,cpu):
        self.r,self.image,self.app,self.pid,self.cpu=r,image,app,pid,cpu
        self.b=r.data[:-64];self.h=q(self.f(self.b,'ptr2o_wire','h'));self.bias=self.h[9]-r.layout['symbols']['li2_raw6']
        self.page=app['head']&-PAGE;self.head=app['head'];self.objects={};self.bases={};self.backings={};self.maps_seen={};self.source_ids={}
        for key,obj in image['objects'].items():
            need(type(key)is int and type(obj)is dict,'actual complete object inventory');h,loads=old.elf(obj['data']);self.objects[key]=(obj,h,loads)
        need(image['main_object']in self.objects and image['interpreter_object']in self.objects,'actual source object identities')
        self.eh,self.ph,self.symbols=elf_symbols(image['bridge'])
        need(set(r.layout['symbols'])==set(self.symbols)|{'span_progress'}and all(r.layout['symbols'][k]==v[0]for k,v in self.symbols.items()),'same actual bridge/DWARF symbols')
        self.certificates=r.items(self.b,'ptr2o_wire','certificates','ptr2o_certificate')
        payload=self.f(self.certificates[0],'ptr2o_certificate','payload');key=self.f(payload,'pe_payload','source')
        row=r.items(key,'li2_pg_source_key','page','li2_pg_source_page')[0]
        self.main_backing=self.f(row,'li2_pg_source_page','backing');self.source_offset=self.i(self.f(row,'li2_pg_source_page','identity'),'li2_fetch_page','offset')
        self.main_vma_identity=self.v(self.f(row,'li2_pg_source_page','identity'),'li2_fetch_page','vma_major vma_minor vma_inode')

    def decoded(self,b,pc,kind=None):
        off=pc-self.page;forms={0x1fe:(299,2,1),0x208:(765,2,0),0x408:(765,2,0),0x600:(278,3,0),0x603:(765,6,0)}
        need(off in forms,'one actual retained-two ordinary boundary');code,length,step=forms[off]
        self.eq(b,'li2_decoded',pc=pc,next_pc=pc+length,abi_version=1,decode_status=0,code=code,kind=0,destination=16,width_bits=0,step_disposition=step,available=15,length=length,reserved=0)
        need(self.f(b,'li2_decoded','bytes')==self.app['source'][off:off+15]+b'\0','whole actual ordinary retained-two decoder window')
        return code,length

    def setup(self,slot):
        self.proof=self.i(slot,'ptr2o_slot','proof');g=self.f(slot,'ptr2o_slot','generation')
        self.geometry=self.layout(self.f(g,'li2_pg_generation','layout'));self.generated=self.geometry[0];self.spill=self.geometry[4]
        self.table=self.proof+self.r.types['pe_payload']['fields']['plan']['offset']+self.r.types['li2_pg_compact']['fields']['table']['offset']

    def compact(self,payload,entry):
        c=self.f(payload,'pe_payload','plan');t='li2_pg_compact'
        self.eq(c,t,version=2,bytes=353600,ready=1,result=0,heads=2,exits=1,stores=0,source_bytes=8,source_mask=1,decoder_result=0,guard_result=0,reserved=0,links=0,reserved2=0,entry=entry)
        need(struct.unpack('<2I',self.f(c,t,'member_heads'))==(2,0)and q(self.f(c,t,'page'))==(self.page,self.page+PAGE)and self.layout(self.f(c,t,'layout'))==self.geometry and self.f(c,t,'source')==self.app['source'],'whole independent retained-two source and2/0 partition')
        expected=plan.graph(self.app['source'],self.page,entry,self.geometry)
        for k in('image','stub_image','head','original','frontier','edge','instruction','guard'):
            need(self.f(c,t,k)==expected[k],'whole independent retained-two '+k)
        need(q(self.f(c,t,'exit_pc'))==(entry+8,0,0,0,0,0,0,0),'one actual ordinary memory-JMP frontier')
        table=plan.table(self.ranges+[(self.page,self.page+PAGE),(self.page+PAGE,self.page+2*PAGE),(RSEQ+8,RSEQ+16)],self.table)
        need(self.f(c,t,'table')==table,'whole independent exclusion table including both source pages and registered word')
        need(self.table-64576==self.proof+self.r.types['pe_payload']['fields']['plan']['offset']+self.r.types[t]['fields']['original']['offset'],'actual immutable row address and common full/compact table relation')
        return expected

    def scan(self,b,n):
        self.eq(b,'ptr2o_scan',started=1,complete=1,expected=n,compared=n,differences=0,first_offset=0,expected_value=0,actual_value=0)

    def checkpoint(self,slot,index,known):
        t='ptr2o_slot';g=self.f(slot,t,'generation');ref=self.f(slot,t,'identity');gen=self.i(ref,'li2_ptr_slot_ref','generation')
        self.eq(ref,'li2_ptr_slot_ref',owner=self.symbol('pe'),index=index,reserved=0)
        self.eq(g,'li2_pg_generation',generation=gen,proof=self.i(slot,t,'proof'))
        check=self.f(slot,t,'check');self.eq(check,'ptr2o_check',slot=index,generation=gen)
        matches=[i for i,c in enumerate(self.certificates)if self.i(c,'ptr2o_certificate','slot')==index and self.i(c,'ptr2o_certificate','generation')==gen]
        expected=next((i for i in matches if i in known),None)
        if expected is None:
            self.eq(check,'ptr2o_check',certificate=0)
            for k in('proof','code','publication'):zero(self.f(check,'ptr2o_check',k),'explicit unavailable unrelated-startup immutable comparison')
            need(not matches,'known focal generation cannot claim unavailable certificate')
            if self.i(g,'li2_pg_generation','installed'):
                key=self.f(self.f(slot,t,'permit'),'ped_permit','generation_source')
                need(self.i(key,'li2_pg_source_key','entry')not in(self.page+0x200,self.page+0x400),'unrelated startup identity is not an unobserved focal root')
        else:
            c=self.certificates[expected];self.eq(check,'ptr2o_check',certificate=expected+1)
            self.eq(g,'li2_pg_generation',installed=1,complete=1,proof_complete=1,ready_generation=gen)
            payload=self.f(c,'ptr2o_certificate','payload');header=self.f(payload,'pe_payload','header')
            need(self.f(g,'li2_pg_generation','layout')==self.f(header,'pe_header','layout')and self.i(g,'li2_pg_generation','build_serial')==self.i(header,'pe_header','serial'),'certificate binds actual immutable generation layout/build')
            for k,n in(('proof',364544),('code',69632),('publication',362624)):self.scan(self.f(check,'ptr2o_check',k),n)
        return gen

    def prior_completed(self,slot,counts):
        t='ptr2o_slot';g=self.f(slot,t,'generation');b=self.f(slot,t,'permit');gt='li2_pg_generation'
        generation=self.i(g,gt,'generation');serial=self.i(b,'ped_permit','serial');self.setup(slot)
        self.eq(g,gt,installed=1,complete=1,proof_complete=1,ready_generation=generation,plan_proofs=2,none_proofs=1,active_refs=0,linked=0,proof=self.proof,code_copied=69632,code_verified=69632,proof_zeroed=364544,proof_copied=362624,proof_verified=364544)
        need(0<generation<=counts['next_generation']and generation<U64//2 and 0<self.i(g,gt,'build_serial')<=serial<=counts['next_serial'],'actual completed retained publication serial/generation')
        self.eq(slot,t,last_completed=serial)
        need(q(self.f(g,gt,'member_generation'))==(2*generation,2*generation+1),'prior exact member generations')
        for k in('incoming','member_refs','cleanup'):zero(self.f(g,gt,k),'prior completed group has no active refs or failure cleanup')
        banks=self.r.items(slot,t,'banks','ped_bank')
        need(sum(self.f(x,'ped_bank','layout')==self.f(g,gt,'layout')for x in banks)==1 and self.i(g,gt,'generated')==self.geometry[0]and self.i(g,gt,'spill')==self.geometry[4],'prior actual registered bank identity')
        self.query3(self.f(g,gt,'code_writable'),3);self.proof_query(self.f(g,gt,'proof_writable'),self.proof,3);self.query(self.f(g,gt,'spill_query'),self.spill,3);zero(self.f(g,gt,'slot_query'),'prior unused aggregate slots query')
        self.permission3(self.f(g,gt,'code_sealed'),1);self.proof_permission(self.f(g,gt,'proof_sealed'),self.proof,1);self.permission3(self.f(g,gt,'open'),5);self.permission3(self.f(g,gt,'close'),1)
        for row,linked in zip(self.r.items(g,gt,'slots','pg_slot_transition'),(False,True,False),strict=True):self.slots_transition(row,linked)
        for i,row in enumerate(self.r.items(g,gt,'cell','pg_dispatch_cell_transition')):
            actual_serial=self.i(g,gt,'build_serial')if i==0 else serial
            self.cell(row,generation,actual_serial,0 if i<2 else self.i(row,'pg_dispatch_cell_transition','before'))
        self.permit(b,g)
        source=self.f(b,'ped_permit','source');self.query3(self.f(source,'li2_pg_source_progress','opened'),5);self.query3(self.f(source,'li2_pg_source_progress','closed'),1)
        self.maps(self.f(source,'li2_pg_source_progress','preparation'));self.maps(self.f(source,'li2_pg_source_progress','validation'))

    def storage(self,b,counts,known,active=None):
        t='ptr2o_slots';selected=self.i(b,t,'selected_slot');need(selected in(0,1),'actual retained selected slot')
        self.eq(b,t,reserved=0);slots=self.r.items(b,t,'slots','ptr2o_slot');ranges=[];generations=[]
        need(self.f(b,t,'selection')==self.f(slots[selected],'ptr2o_slot','identity'),'selection is exact actual retained identity')
        previous=self.f(b,t,'previous_selection');self.eq(previous,'li2_ptr_slot_ref',reserved=0)
        need((not any(previous))or(self.i(previous,'li2_ptr_slot_ref','owner')==self.symbol('pe')and self.i(previous,'li2_ptr_slot_ref','index')in(0,1)and self.i(previous,'li2_ptr_slot_ref','generation')<=counts['next_generation']),'typed previous selection is observation only')
        for index,s in enumerate(slots):
            st='ptr2o_slot';self.eq(s,st,code_allocated=2,code_registered=2,proof_allocated=1,proof_registered=1)
            proof=self.i(s,st,'proof');need(proof%PAGE==0 and canonical(proof,364544),'whole actual retained proof allocation');ranges.append((proof,proof+364544))
            gen=self.checkpoint(s,index,known);generations.append(gen);g=self.f(s,st,'generation')
            for j,bank in enumerate(self.r.items(s,st,'banks','ped_bank')):
                saved=getattr(self,'geometry',None);geometry=self.layout(self.f(bank,'ped_bank','layout'));self.geometry=geometry
                self.eq(bank,'ped_bank',generated=geometry[0],spill=geometry[4],allocated=1,registered=1)
                need((j or geometry[0]+77824<1<<31)and self.i(bank,'ped_bank','virgin')in(0,1),'actual low and ordinary bank geometry')
                prot=self.i(bank,'ped_bank','prot');need(prot in(1,3,5),'actual bank permission state')
                self.query3(self.f(bank,'ped_bank','initial'),3);self.query(self.f(bank,'ped_bank','initial_spill'),geometry[4],3);self.query(self.f(bank,'ped_bank','initial_slots'),geometry[3],3)
                ranges.append((geometry[0],geometry[0]+77824));self.geometry=saved
            installed=self.i(g,'li2_pg_generation','installed');need(installed in(0,1),'literal installed retained state')
            if installed:
                if active!=index:self.prior_completed(s,counts)
                n=self.i(s,st,'registry_count');need(0<n<=len(self.ranges),'actual retained registry population')
                rows=self.f(s,st,'registry');need(rows[:n*16]==b''.join(struct.pack('<QQ',*x)for x in self.ranges[:n])and not any(rows[n*16:]),'retained complete registry prefix and zero tail')
            else:
                need(active!=index,'active slot cannot be empty');self.eq(s,st,last_completed=0,registry_count=0);zero(self.f(s,st,'registry'),'empty slot has no publication registry');zero(self.f(s,st,'permit'),'empty slot has no completion permit')
                self.setup(s);self.eq(g,'li2_pg_generation',generation=0,ready_generation=0,complete=0,proof_complete=0,build_serial=0,generated=self.geometry[0],spill=self.geometry[4])
                self.proof_query(self.f(g,'li2_pg_generation','proof_writable'),proof,3)
                expect=bytearray(len(g))
                for k in('generated','proof','spill','layout','proof_writable'):
                    f=self.r.types['li2_pg_generation']['fields'][k];expect[f['offset']:f['offset']+f['bytes']]=self.f(g,'li2_pg_generation',k)
                need(g==bytes(expect),'whole actual initialized virgin retained generation')
        need(not generations[0]or not generations[1]or generations[0]!=generations[1],'distinct actual retained generations')
        owner=(self.symbol('pe'),self.symbol('pe')+self.h[3])
        need(all(z<=c or d<=a for i,(a,z)in enumerate(ranges)for c,d in ranges[i+1:]+[owner]),'all six retained allocations and protected owner disjoint')
        for interval in ranges:need(self.ranges.count(interval)==1,'whole actual retained allocation protected')
        return slots,selected

    def choose(self,slots,entry):
        matches=[];empty=[]
        for i,s in enumerate(slots):
            g=self.f(s,'ptr2o_slot','generation')
            if not self.i(g,'li2_pg_generation','installed'):empty.append(i)
            elif self.i(self.f(self.f(s,'ptr2o_slot','permit'),'ped_permit','generation_source'),'li2_pg_source_key','entry')==entry:matches.append(i)
        need(len(matches)<=1,'unique exact-root retained candidate')
        return matches[0]if matches else empty[0]if empty else min(range(2),key=lambda i:(self.i(slots[i],'ptr2o_slot','last_completed'),i))

    def same_slots(self,a,b):
        for x,y in zip(self.r.items(a,'ptr2o_slots','slots','ptr2o_slot'),self.r.items(b,'ptr2o_slots','slots','ptr2o_slot'),strict=True):
            need(x==y,'both actual retained slots preserved byte-for-byte')

    def certificate(self,index,slot,entry,serial,gen):
        c=self.certificates[index];t='ptr2o_certificate';self.setup(slot)
        self.eq(c,t,complete=1,index=index,slot=self.i(self.f(slot,'ptr2o_slot','identity'),'li2_ptr_slot_ref','index'),generation=gen,entry=entry,proof_bytes=364544,code_bytes=69632,publication_bytes=362624)
        zero(self.f(c,t,'tail'),'whole literal immutable proof tail zero')
        payload=self.f(c,t,'payload');ph=self.f(payload,'pe_payload','header')
        self.eq(ph,'pe_header',version=1,serial=serial,generation=gen,registry=self.symbol('pe'),generated=self.generated,spill=self.spill,table=self.table,plan_proof=2,none_proof=1,source_validations=1,registered_epoch=1,rseq_address=RSEQ,rseq_length=32,rseq_signature=0x53053053)
        need(self.layout(self.f(ph,'pe_header','layout'))==self.geometry and q(self.f(ph,'pe_header','member_generation'))==(2*gen,2*gen+1),'immutable actual retained member identities/layout');zero(self.f(ph,'pe_header','reserved'),'whole header reserved')
        binding=self.image['persistent_binding'];need(binding['version']==3 and binding['profile']=='persistent-retained-two-v3','explicit retained-two source binding')
        need(self.f(ph,'pe_header','archive')==bytes.fromhex(binding['archive']['sha256'])and self.f(ph,'pe_header','policy')==bytes.fromhex(binding['policy_sha256']),'whole actual retained archive/policy authority')
        key=self.f(payload,'pe_payload','source');self.source_key(key,entry);expected=self.compact(payload,entry)
        need(self.f(c,t,'code')==expected['image']+expected['stub_image'],'all17 actual code pages in shared literal certificate')
        return payload
    def epoch(self,b,index,previous=None):
        t='ptr2o_epoch';st='ptr2o_stage';gt='li2_pg_generation';pt='li2_pg_progress';it='ptr2o_epoch_info'
        entry=self.page+(0x400 if index==1 else 0x200);warm=index==2;ci=1 if index==1 else 0
        h=q(self.f(b,t,'h'));need(h[:3]==(1,index,entry)and h[3]>0 and h[4:11]==(1,1,h[3],0,1,1,0)and h[11]==h[3]+1 and h[12:15]==(0,0,1)and h[24]in(0,1)and not any(h[25:]),'actual accepted retained entry/exit with zero interior signal')
        need(h[15]in(0,1)and h[16]==self.symbol('selected_session')and h[17]>0 and h[18]<U64 and h[19:24]==(h[15],1,0,0,1),'actual selected preclose retained predecessor')
        initial=self.f(b,t,'initial_registry');need(initial==self.f(b,t,'terminal_registry'),'whole retained registry unchanged during epoch')
        self.ranges,kinds=self.registry_prefix(self.f(self.b,'ptr2o_wire','startup_registry'),initial)
        prior=self.f(b,t,'prior_counts');pc=self.counts(prior);prior_slots=self.f(b,t,'prior')
        need(pc['entries']==pc['completed']and pc['publications']==pc['next_generation']and pc['unexpected']==0,'all preceding retained epochs completed before focal entry')
        prior_rows,_=self.storage(prior_slots,pc,set(range(min(index,2))))
        chosen=self.choose(prior_rows,entry);need(chosen==h[24],'actual root/empty/oldest-completed selection')
        resident=prior_rows[chosen];rg=self.f(resident,'ptr2o_slot','generation');installed=self.i(rg,gt,'installed')
        entered=self.f(b,t,'entered');end=self.f(b,t,'terminal');p=self.f(entered,st,'progress');ep=self.f(end,st,'progress');serial=self.i(p,pt,'serial');gen=self.i(p,pt,'generation')
        need(serial==pc['next_serial']+1 and 0<gen<U64//2,'actual monotonic retained attempt/member generation')
        inc=dict(next_serial=1,offers=1,entries=1,permit_claims=1 if warm else installed)
        if warm:inc.update(hits=1)
        else:inc.update(next_generation=1,publications=1,cold_attempts=1,retirements=installed)
        self.delta(prior,self.f(entered,st,'counts'),**inc);self.delta(self.f(entered,st,'counts'),self.f(end,st,'counts'),completed=1)
        eslots=self.f(entered,st,'slots');zslots=self.f(end,st,'slots')
        erows,selected=self.storage(eslots,self.counts(self.f(entered,st,'counts')),set(range(2 if index else 1)),active=chosen)
        zrows,zselected=self.storage(zslots,self.counts(self.f(end,st,'counts')),set(range(2 if index else 1)))
        need(selected==zselected==chosen and self.f(eslots,'ptr2o_slots','previous_selection')==self.f(prior_slots,'ptr2o_slots','selection')and self.f(zslots,'ptr2o_slots','previous_selection')==self.f(eslots,'ptr2o_slots','previous_selection'),'actual previous and selected typed slot identities')
        need(prior_rows[1-chosen]==erows[1-chosen]==zrows[1-chosen],'other actual retained slot and immutable certificate scans remain unchanged')
        actual=erows[chosen];terminal=zrows[chosen];self.setup(actual);g=self.f(actual,'ptr2o_slot','generation');eg=self.f(terminal,'ptr2o_slot','generation');buildserial=self.i(g,gt,'build_serial')
        payload=self.certificate(ci,actual,entry,buildserial,gen);key=self.f(payload,'pe_payload','source');ph=self.f(payload,'pe_payload','header')
        need(gen==(self.i(rg,gt,'generation')if warm else pc['next_generation']+1)and buildserial==(self.i(rg,gt,'build_serial')if warm else serial),'exact fresh publication or same-generation warm identity')
        need(not warm or installed==1,'warm requires actual prior completed generation')
        self.eq(p,pt,serial=serial,registration_epoch=1,publication=1,generation=gen,phase=9,first_error=0,source_count=2,opened_pages=17,closed_pages=0,anchor_released=0,registration_rechecked=0,completion_permit=0,first_detail=0,generated=self.generated,proof=self.proof,table=self.table,spill=self.spill)
        need(q(self.f(p,pt,'source'))==(self.page,self.page+PAGE)and self.layout(self.f(p,pt,'layout'))==self.geometry,'actual retained progress source/layout')
        self.r.change(p,ep,pt,values=dict(phase=13,closed_pages=17,anchor_released=1,registration_rechecked=1,completion_permit=1))
        for s in(entered,end):self.eq(s,st,busy=1,active=1,failing=0,resuming=0,pending=1);need(0<self.i(s,st,'route')<32,'actual generated retained route')
        need(self.f(entered,st,'route')==self.f(end,st,'route'),'unchanged active route through retained close')
        self.eq(g,gt,installed=1,complete=1,proof_complete=1,generation=gen,ready_generation=gen,build_serial=buildserial,plan_proofs=2,none_proofs=1,generated=self.generated,proof=self.proof,spill=self.spill,active_refs=1,linked=1,code_copied=69632,code_verified=69632,proof_zeroed=364544,proof_copied=362624,proof_verified=364544)
        need(self.f(g,gt,'layout')==self.f(ph,'pe_header','layout')and self.f(g,gt,'member_generation')==self.f(ph,'pe_header','member_generation')and q(self.f(g,gt,'member_refs'))==(1,1),'actual typed member generations and active refs')
        zero(self.f(g,gt,'incoming'),'zero links have no incoming refs')
        self.query3(self.f(g,gt,'code_writable'),3);self.proof_query(self.f(g,gt,'proof_writable'),self.proof,3);self.query(self.f(g,gt,'spill_query'),self.spill,3);zero(self.f(g,gt,'slot_query'),'unused aggregate slot query remains zero')
        self.permission3(self.f(g,gt,'code_sealed'),1);self.proof_permission(self.f(g,gt,'proof_sealed'),self.proof,1);self.permission3(self.f(g,gt,'open'),5)
        for k in('close','cleanup'):zero(self.f(g,gt,k),'no premature retained code close')
        transitions=self.r.items(g,gt,'slots','pg_slot_transition');self.slots_transition(transitions[0],False);self.slots_transition(transitions[1],True);zero(transitions[2],'no premature RESET after entry')
        self.r.change(g,eg,gt,values=dict(active_refs=0,linked=0),observed=('incoming','member_refs','close','slots','cell'))
        zero(self.f(eg,gt,'incoming'),'all incoming refs drained');zero(self.f(eg,gt,'member_refs'),'both member refs drained');self.permission3(self.f(eg,gt,'close'),1)
        ends=self.r.items(eg,gt,'slots','pg_slot_transition');need(ends[:2]==transitions[:2],'initial RESET and LINKED receipts retained');self.slots_transition(ends[2],False)
        cells=self.r.items(g,gt,'cell','pg_dispatch_cell_transition');endcells=self.r.items(eg,gt,'cell','pg_dispatch_cell_transition')
        self.cell(cells[0],gen,buildserial,0);self.cell(cells[1],gen,serial,0);zero(cells[2],'no premature terminal cell reset')
        need(endcells[:2]==cells[:2],'initial cell reset receipts retained exactly');self.cell(endcells[2],gen,serial,0)
        for k in('initial_slots','terminal_slots'):zero(self.f(b,t,k),'whole zero-link slot page')
        self.r.change(actual,terminal,'ptr2o_slot',values=dict(last_completed=serial),observed=('generation','permit','banks'))
        banks=self.r.items(actual,'ptr2o_slot','banks','ped_bank');zbanks=self.r.items(terminal,'ptr2o_slot','banks','ped_bank');bank_index=[i for i,x in enumerate(banks)if self.f(x,'ped_bank','layout')==self.f(g,gt,'layout')]
        need(len(bank_index)==1,'exact selected source bank');bank_index=bank_index[0]
        self.eq(banks[bank_index],'ped_bank',virgin=0,prot=5);self.r.change(banks[bank_index],zbanks[bank_index],'ped_bank',values=dict(prot=1));need(banks[1-bank_index]==zbanks[1-bank_index],'other selected-slot bank unchanged')
        prior_permit=self.f(resident,'ptr2o_slot','permit');permit=self.f(actual,'ptr2o_slot','permit')
        self.r.change(prior_permit,permit,'ped_permit',values=dict(valid=0))
        need(self.i(actual,'ptr2o_slot','last_completed')==self.i(resident,'ptr2o_slot','last_completed'),'claim preserves actual prior completion serial until drain')
        if warm:
            self.r.change(rg,g,gt,values=dict(active_refs=1,linked=1),observed=('member_refs','open','close','slots','cell'))
            need(self.f(resident,'ptr2o_slot','check')==self.f(actual,'ptr2o_slot','check'),'warm unchanged immutable certificate and scans')
        info=self.f(b,t,'info');self.eq(info,it,selected_bank=bank_index,warm=int(warm),initialized=1,registered=1,code_allocated=2,proof_allocated=1,code_registered=2,proof_registered=1,close_started=1,close_complete=1,prepare_started=1,prepare_complete=1,build_started=int(not warm),build_returned=int(not warm),redirected=1,exit_seen=1,exit_index=0,recovery_started=1,recovery_complete=1,guest_data_fault=0,cleanup_started=0,cleanup_complete=0,consumed=1,plan_proofs=0 if warm else 2,none_proofs=0 if warm else 1,code_allocation=self.h_alloc,proof_allocation=self.h_proof_alloc,build_result=0,recovery_result=0,release_result=0,gpr_written=5,flags_written=0x8d5,ticket=self.symbol('span_transfer'),registry_count=len(self.ranges))
        self.eq(self.f(info,it,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
        need(self.f(info,it,'session')==self.f(self.b,'ptr2o_wire','session')and self.f(info,it,'registry')==self.f(initial,'ptr2o_registry','ranges')and self.f(info,it,'banks')==self.f(terminal,'ptr2o_slot','banks'),'whole actual retained session/registry/bank inputs')
        if installed:
            save=self.geometry;self.geometry=self.layout(self.f(rg,gt,'layout'));self.query3(self.f(info,it,'claim_code'),1);self.proof_query(self.f(info,it,'claim_proof'),self.proof,1);self.query(self.f(info,it,'claim_spill'),self.geometry[4],3);self.query(self.f(info,it,'claim_slots'),self.geometry[3],1);self.geometry=save
        else:
            for k in('claim_code','claim_proof','claim_spill','claim_slots'):zero(self.f(info,it,k),'no fabricated virgin claim')
        if warm:
            for k in('bank_before','proof_before','reopen_code','reopen_proof'):zero(self.f(info,it,k),'warm never reopens or rebuilds immutable proof/code')
        else:
            rows=self.r.items(info,it,'bank_before','li2_private_code_query');prot=self.i(rows[0],'li2_private_code_query','actual_prot');need(prot in(1,3),'cold target is closed or virgin');self.query3(self.f(info,it,'bank_before'),prot)
            self.proof_query(self.f(info,it,'proof_before'),self.proof,1 if installed else 3);self.permission3(self.f(info,it,'reopen_code'),3);self.proof_permission(self.f(info,it,'reopen_proof'),self.proof,3)
            for a,z in zip(self.r.items(g,gt,'code_writable','li2_private_code_query'),self.r.items(info,it,'reopen_code','le_permission'),strict=True):need(a==self.f(z,'le_permission','query'),'whole actual code reopen publication join')
            need(self.f(g,gt,'proof_writable')==self.f(self.f(info,it,'reopen_proof'),'pg_proof_permission','query'),'whole actual proof reopen publication join')
        before=self.frame(self.f(b,t,'before'));ingress=self.normalized(self.f(b,t,'ingress'),before);returned=self.frame(self.f(b,t,'returned'));after=self.frame(self.f(b,t,'after'));flags=before['greg'][17]
        self.eq(info,it,flags=flags);self.trace(ingress,entry,flags|TF);self.trace(before,entry,flags);self.same_event(ingress,before,flags)
        want=list(before['greg']);want[16]=self.generated
        need(returned['greg']==tuple(want)and returned['fp']==before['fp']and returned['si']==before['si']and(returned['fs'],returned['gs'])==tuple(self.app['machine'][1:3]),'whole retained redirect changes only original RIP')
        uc=bytearray(before['uc']);struct.pack_into('<Q',uc,40+16*8,self.generated);need(returned['uc']==bytes(uc),'whole retained return UC except actual redirect')
        self.nx(after,entry+8);need(after['fp']==before['fp']and after['fp_bytes']==before['fp_bytes']and after['mask']==MASK and(after['fs'],after['gs'])==tuple(self.app['machine'][1:3]),'all retained FP/AF/mask/TLS preserved')
        projection=self.f(b,t,'predecessor');self.eq(projection,'ptr2o_predecessor',complete=1,unexpected_compared=self.r.types['li2_step_frame']['bytes'],unexpected_nonzero=0)
        slot=self.f(projection,'ptr2o_predecessor','closed')+bytes(self.r.types['li2_step_frame']['bytes']);self.r.walk(slot,'li2_tf_chain_slot')
        prefix=self.f(projection,'ptr2o_predecessor','before_prefix');wanted=bytearray(prefix);sf=self.r.types['li2_tf_chain_slot']['fields'];of=self.r.types['li2_tf_owner']['fields'];tf=self.r.types['li2_step_owner']['fields']
        struct.pack_into('<I',wanted,sf['phase']['offset'],5);at=sf['owner']['offset']+of['step']['offset']
        for k,v in(('phase',5),('trace_seen',1),('revoke_sync_started',1)):struct.pack_into('<I',wanted,at+tf[k]['offset'],v)
        need(bytes(wanted)==slot[:len(prefix)],'whole actual retained predecessor prefix close transition')
        need(self.i(slot,'li2_tf_chain_slot','index')==h[15]and self.i(slot,'li2_tf_chain_slot','event_id')<h[17],'actual retained predecessor older generation/event')
        predecessor_pc=self.page+(0x1fe if index==0 else 0x208 if index==1 else 0x603)
        predecessor,oldref=self.predecessor(slot,predecessor_pc,ingress)
        self.eq(slot,'li2_tf_chain_slot',origin=2 if warm else 1)
        ref=self.f(info,it,'ref');seq=self.i(ref,'li2_fetch_ref','sequence');tr=self.f(entered,st,'transfer');self.transfer(tr,slot,ingress,before,ref)
        need(tr==self.f(end,st,'transfer')and self.i(tr,'li2_span_transfer_progress','event')==h[17]and self.i(tr,'li2_span_transfer_progress','serial')==self.i(p,pt,'transfer_serial'),'whole exact consumed retained transfer')
        es=self.f(entered,st,'source');zs=self.f(end,st,'source');self.source(es,serial,entry,key,ref);self.source(zs,serial,entry,key,ref,terminal=True)
        need(self.f(es,'li2_pg_source_progress','source')==self.f(zs,'li2_pg_source_progress','source'),'whole source anchor retained throughout execution')
        er=self.f(entered,st,'rseq');zr=self.f(end,st,'rseq');estate=self.f(entered,st,'state');zstate=self.f(end,st,'state')
        a=self.pin(er,estate,serial,0 if warm else 2,0);z=self.pin(zr,zstate,serial,0 if warm else 2,0,terminal=True)
        need(z>a and estate==zstate,'actual zero-word pin closes with full old rseq state unchanged')
        lastpc=self.page+0x603 if warm else entry+4;code,length=(765,6)if warm else(249,4)
        self.eq(estate,'li2_rseq_state',last_first=0,last_end=0,last_pc=lastpc,last_code=code,last_policy=1)
        self.eq(self.f(estate,'li2_rseq_state','last_footprint'),'li2_write_footprint',pc=lastpc,next_pc=lastpc+length,first=0,end=0,abi_version=1,policy=1,code=code,length=length)
        self.progress(self.f(entered,st,'fetch'),seq,True);self.progress(self.f(end,st,'fetch'),seq,False);need(self.f(info,it,'final_fetch')==self.f(end,st,'fetch'),'whole actual released retained fetch')
        lives=self.r.items(info,it,'live','li2_link_rseq_live')
        for x in lives[:2]:self.live_rseq(x,estate,before)
        self.live_rseq(lives[2],zstate,after);self.proof_query(self.f(info,it,'proof_exit'),self.proof,1)
        for k in('code_exit','recovered','recovery_scratch'):zero(self.f(info,it,k),'normal retained exit claims no unexpected recovery')
        self.permit(self.f(terminal,'ptr2o_slot','permit'),eg,zs,zr,self.f(end,st,'fetch'))
        need(self.f(self.f(terminal,'ptr2o_slot','permit'),'ped_permit','generation_source')==key,'actual immutable source in completed retained permit')
        bm=self.memory(self.f(b,t,'before_memory'),False);am=self.memory(self.f(b,t,'after_memory'),False);need(bm==am==dict(data=self.app['data'],stack=self.app['stack']),'whole retained data/stack remains byte-identical')
        return dict(kind='warm'if warm else'cold',mode=0,slot=chosen,generation=gen,build_serial=buildserial,prior_generation_installed=installed,begin=h[3],event=h[17],terminal_ordinal=h[11],ingress=ingress,before=before,returned=returned,logical=after,after=after,predecessor_before=predecessor,before_memory=bm,after_memory=am,completed=1,closed_pages=17,anchor_released=1,permit=1,interior_signals=0,slots_raw=zslots,counts_raw=self.f(end,st,'counts'),serial=serial,closed_slot=slot)
    def miss(self,b,index,previous):
        t='ptr2o_miss';st='ptr2o_stage';pt='li2_pg_progress';h=q(self.f(b,t,'h'));entry=self.page+(0x600 if index==0 else 0x603)
        need(h[:3]==(1,index,entry)and h[3]>0 and h[4:10]==(1,1,1,h[3],1,1)and h[10]==h[3]+1 and h[11:13]==(0,1)and h[13]in(0,1)and h[14]==1 and h[24]in(0,1)and h[25]>h[17]and h[26]==1 and not any(h[27:]),'actual classified miss and safe immediate next TRACE close')
        need(h[15]in(0,1)and h[16]==self.symbol('selected_session')and h[17]>0 and h[18]<U64 and h[19:24]==(h[15],1,0,0,1),'actual preclose miss selector')
        initial=self.f(b,t,'initial_registry');need(initial==self.f(b,t,'terminal_registry'),'cancel retains complete actual registry');self.ranges,_=self.registry_prefix(self.f(self.b,'ptr2o_wire','startup_registry'),initial)
        prior=self.f(b,t,'prior');need(prior==previous['slots_raw'],'actual miss begins with both completed predecessor slots')
        counts=self.counts(previous['counts_raw']);prior_rows,_=self.storage(prior,counts,{0,1});chosen=self.choose(prior_rows,entry);need(chosen==h[24],'actual miss chooses completed least-recent slot without claiming it')
        before=self.frame(self.f(b,t,'before'));returned=self.frame(self.f(b,t,'returned'));nextframe=self.frame(self.f(b,t,'next_trace'));flags=before['greg'][17]
        self.trace(before,entry,flags);self.trace(returned,entry,flags|TF);self.same_event(before,returned,flags|TF)
        want=list(returned['greg'])
        if index==0:want[3],want[4]=want[4],want[3];want[16]=entry+3
        else:want[16]=self.head
        self.trace(nextframe,want[16],flags|TF)
        need(nextframe['greg']==tuple(want)and nextframe['fp']==returned['fp']and nextframe['fp_bytes']==returned['fp_bytes']and(nextframe['fs'],nextframe['gs'])==(returned['fs'],returned['gs']),'whole actual resumed original instruction state and observed TLS')
        held=self.f(b,t,'held');end=self.f(b,t,'resumed');p=self.f(held,st,'progress');ep=self.f(end,st,'progress');serial=self.i(p,pt,'serial')
        self.delta(previous['counts_raw'],self.f(held,st,'counts'),next_serial=1,offers=1,cold_attempts=1,miss_reason=1);self.delta(self.f(held,st,'counts'),self.f(end,st,'counts'),cancelled=1)
        hs=self.f(held,st,'slots');zs=self.f(end,st,'slots');self.same_slots(prior,hs);need(hs==zs,'entire selected-slot state unchanged through cancelled attempt')
        rows,selected=self.storage(hs,self.counts(self.f(held,st,'counts')),{0,1});need(selected==chosen and self.f(hs,'ptr2o_slots','previous_selection')==self.f(prior,'ptr2o_slots','selection'),'miss switches only actual typed selection')
        self.proof=self.i(rows[selected],'ptr2o_slot','proof');self.geometry=self.layout(self.f(p,pt,'layout'));self.generated=self.geometry[0];self.spill=self.geometry[4]
        self.table=self.proof+self.r.types['pe_payload']['fields']['plan']['offset']+self.r.types['li2_pg_compact']['fields']['table']['offset']
        need(sum(self.f(x,'ped_bank','layout')==self.f(p,pt,'layout')for x in self.r.items(rows[selected],'ptr2o_slot','banks','ped_bank'))==1,'miss uses an actual selected-slot bank')
        self.eq(p,pt,serial=serial,registration_epoch=1,phase=4,first_error=0,source_count=2,opened_pages=0,closed_pages=0,anchor_released=0,registration_rechecked=0,completion_permit=0,first_detail=0,generated=self.generated,proof=self.proof,table=self.table,spill=self.spill,generation=0,publication=0)
        need(q(self.f(p,pt,'source'))==(self.page,self.page+PAGE),'actual cancelled source pair');self.r.change(p,ep,pt,values=dict(phase=14,anchor_released=1,registration_rechecked=1))
        self.eq(held,st,busy=1,active=0,failing=0,resuming=0,route=0,pending=0);self.eq(end,st,busy=1,active=0,failing=0,resuming=1,pending=1);need(0<self.i(end,st,'route')<32,'actual ordinary resumed route')
        encoded=self.f(b,t,'plan');mt='ptr2o_miss_plan';ft='li2_pg_plan';full=bytearray(self.r.types[ft]['bytes'])
        for k in('version','bytes','ready','result','heads','exits','stores','source_bytes','source_mask','decoder_result','guard_result','reserved','member_heads','links','reserved2','page','entry','layout','source','table'):
            f=self.r.types[ft]['fields'][k];v=self.f(encoded,mt,k);need(len(v)==f['bytes'],'exact unready plan projection extent');full[f['offset']:f['offset']+f['bytes']]=v
        fields=self.r.types[ft]['fields'];omitted=len(full)-fields['image']['offset']-fields['table']['bytes'];self.eq(encoded,mt,scan_started=1,scan_complete=1,scanned=omitted,nonzero=0,first_nonzero=0,first_value=0)
        full=bytes(full);self.r.walk(full,ft);self.eq(full,ft,version=2,bytes=981312,ready=0,result=1,heads=0,exits=0,stores=0,source_bytes=0,source_mask=1,decoder_result=0,guard_result=0,reserved=0,links=0,reserved2=0,entry=entry)
        need(q(self.f(full,ft,'page'))==(self.page,self.page+PAGE)and self.f(full,ft,'source')==self.app['source']and self.layout(self.f(full,ft,'layout'))==self.geometry,'whole actual unready source input')
        expected=plan.table(self.ranges+[(self.page,self.page+PAGE),(self.page+PAGE,self.page+2*PAGE),(RSEQ+8,RSEQ+16)],self.table);need(self.f(full,ft,'table')==expected,'cancelled exact exclusion table')
        for k in('member_heads','image','stub_image','head','original','frontier','instruction','exit_pc','edge','guard'):zero(self.f(full,ft,k),'unready miss has no invented authority')
        self.eq(self.f(b,t,'miss'),'li2_pg_miss',version=2,status=1,reason=1,site=1,pc=entry,detail=1)
        source=self.f(held,st,'source');src=self.f(source,'li2_pg_source_progress','source');key=self.f(src,'li2_pg_sources','key');ref=self.f(src,'li2_pg_sources','anchor')
        self.source(source,serial,entry,key,ref,cancel=True);self.source(self.f(end,st,'source'),serial,entry,key,ref,terminal=True,cancel=True)
        es=self.f(held,st,'state');zstate=self.f(end,st,'state');a=self.pin(self.f(held,st,'rseq'),es,serial,0,0,cancel=True);z=self.pin(self.f(end,st,'rseq'),zstate,serial,0,0,terminal=True,cancel=True);need(z>a,'actual zero-word cancellation checks')
        checks=self.i(es,'li2_rseq_state','instruction_checks');need(checks<U64,'ordinary resume count cannot wrap');self.r.change(es,zstate,'li2_rseq_state',values={'instruction_checks':checks+1},observed=('last_first','last_end','last_pc','last_code','last_policy','last_footprint'))
        code,length=(278,3)if index==0 else(765,6);self.eq(zstate,'li2_rseq_state',last_first=0,last_end=0,last_pc=entry,last_code=code,last_policy=1);self.eq(self.f(zstate,'li2_rseq_state','last_footprint'),'li2_write_footprint',pc=entry,next_pc=entry+length,first=0,end=0,abi_version=1,policy=1,code=code,length=length)
        closed,cchain,ci=self.projected_slot(self.f(b,t,'closed_slot'));successor,chain,ni=self.projected_slot(self.f(b,t,'resumed_slot'));nextslot,nextchain,nn=self.projected_slot(self.f(b,t,'next_slot'))
        need(ci==h[15]and ni==1-ci and nn==ni==h[13],'actual alternating ordinary chain slots')
        origin=dict(before,greg=tuple(list(before['greg'][:17])+[flags|TF]+list(before['greg'][18:])))
        oldpc=self.page+(0x408 if index==0 else 0x600)
        oldref=self.slot_metadata(closed,oldpc,origin,True);newref=self.slot_metadata(successor,entry,returned,False);nextref=self.slot_metadata(nextslot,entry,nextframe,True)
        need(newref==nextref,'next actual closed slot owns exact resumed ordinary borrow')
        self.eq(successor,'li2_tf_chain_slot',origin=2,event_id=h[17]);self.eq(nextslot,'li2_tf_chain_slot',origin=2,event_id=h[17])
        need(self.i(newref,'li2_fetch_ref','sequence')>self.i(ref,'li2_fetch_ref','sequence'),'ordinary source borrow follows completed cancellation release')
        tr=self.f(held,st,'transfer');self.transfer(tr,closed,origin,before,ref,False);need(self.i(tr,'li2_span_transfer_progress','event')==h[17],'actual cancelled transfer event')
        need(self.i(p,pt,'transfer_serial')==self.i(tr,'li2_span_transfer_progress','serial'),'actual cancelled progress binds CLOSED transfer serial')
        resumed=self.f(end,st,'transfer');tt='li2_span_transfer_progress';self.r.change(tr,resumed,tt,observed=('phase','resume_attempted','resumed','next','successor_installed','fresh_borrow','fresh'))
        self.eq(resumed,tt,phase=5,resume_attempted=1,resumed=1,next=ni,successor_installed=1,fresh_borrow=self.i(ref,'li2_fetch_ref','sequence'));self.observation(self.f(resumed,tt,'fresh'),entry,False,ref)
        for x in(cchain,chain):self.eq(x,'li2_tf_chain',session=self.symbol('selected_session'),initialized=1,first_error=0,first_detail=0,in_handler=0,event_id=h[17],unexpected_events=0);need(canonical(self.i(x,'li2_tf_chain','failure')),'actual projected failure callback')
        self.eq(cchain,'li2_tf_chain',active=ci,pending=0,sequence=h[18]);self.eq(chain,'li2_tf_chain',active=ni,pending=1,sequence=h[18]+1)
        en=self.f(chain,'li2_tf_chain','entry');self.eq(en,'li2_tf_trace_entry',valid=0,previous=ci,next=ni,event_id=h[17],sequence=h[18]+1,previous_generation=self.i(closed,'li2_tf_chain_slot','generation'),next_generation=self.i(successor,'li2_tf_chain_slot','generation'),pc=entry,flags=flags,previous_borrow_sequence=self.i(oldref,'li2_fetch_ref','sequence'))
        self.eq(nextchain,'li2_tf_chain',session=self.symbol('selected_session'),initialized=1,first_error=0,first_detail=0,in_handler=1,event_id=h[25],unexpected_events=0,active=ni,pending=1,sequence=h[18]+1)
        for k in('generation','event_id','chain','index','origin','decoded','descriptive_classification'):need(self.f(successor,'li2_tf_chain_slot',k)==self.f(nextslot,'li2_tf_chain_slot',k),'same actual resumed/closed ordinary identity '+k)
        self.progress(self.f(held,st,'fetch'),self.i(ref,'li2_fetch_ref','sequence'),True);self.progress(self.f(end,st,'fetch'),self.i(newref,'li2_fetch_ref','sequence'),True)
        need(serial==counts['next_serial']+1,'actual fresh cancelled attempt serial')
        return dict(counts_raw=self.f(end,st,'counts'),slots_raw=zs,next_frame=self.f(b,t,'next_trace'),before=before,returned=returned,next=nextframe,begin=h[3],next_ordinal=h[10],closed_slot=closed,next_slot=nextslot,serial=serial,slot=chosen,event=h[17],next_event=h[25])

    def next_trace(self,b,last,epoch):
        t='ptr2o_next';slot=self.f(b,t,'closed');st='li2_tf_chain_slot'
        self.eq(b,t,expected_ordinal=last['terminal_ordinal']+1,raw_ordinal=last['terminal_ordinal']+1,capture_result=0,ingress_complete=1,closed_complete=1,tls_complete=1)
        index=self.i(b,t,'slot_index');event=self.i(b,t,'event_id');need(index in(0,1)and self.i(slot,st,'index')==index and event>self.i(slot,st,'event_id')>0,'actual next TRACE chain/index/event and closed predecessor')
        self.eq(slot,st,origin=1);frame=self.frame(self.f(b,t,'frame'));flags=(last['logical']['greg'][17]&~RF)|TF;self.trace(frame,self.app['expected_exit_pc'],flags)
        need(frame['greg'][22]==self.head+8 and(frame['fs'],frame['gs'])==tuple(self.app['machine'][1:3]),'actual next TRACE retains ordinary JMP CR2 and post-close TLS')
        before,ref=self.predecessor(slot,self.head+8,frame);owner=self.f(slot,st,'owner');step=self.f(owner,'li2_tf_owner','step');self.step_frame(self.f(step,'li2_step_owner','before'),last['logical'])
        need(before['greg']==last['logical']['greg']and before['fp']==last['logical']['fp'],'ordinary original JMP begins at actual retained exit NX frame')
        fetch=self.f(self.f(epoch,'ptr2o_epoch','terminal'),'ptr2o_stage','fetch');need(self.i(ref,'li2_fetch_ref','sequence')>self.i(fetch,'li2_fetch_progress','sequence'),'ordinary JMP borrows after actual retained source release')
        last['next_trace']=frame;last['next_trace_ordinal']=self.i(b,t,'raw_ordinal')

    def finish(self,status):
        h=self.h;t='ptr2o_wire';r=self.r
        need(type(status)is int and status==0 and self.app['mode']==0,'actual successful loop-only process and mode')
        need(h[:9]==(0x334f32525449324c,3,4169600,r.layout['registrations']['pe']['bytes'],362624,364544,69632,968,128),'actual distinct group record version and complete extents')
        need(canonical(self.bias)and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(n)for n in('li2_raw6','li2_gateway_start','li2_gateway_end'))and h[10]<=h[9]<h[11],'actual emitted gateway identity')
        need(h[12]%PAGE==0 and h[13]==524288 and h[14:16]==(1,0)and h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,0),'actual altstack and FD3/profile')
        need(h[20:26]==tuple(self.symbol(n)for n in('pe','ptr2o_wire','pg_source','pg_rseq','selected_chain','span_progress')),'actual protected group addresses')
        storage=r.layout['retained_storage'];size=r.types['li2_ptr_slot']['bytes'];prefix=(2*r.types['li2_pg_progress']['bytes']+9*8+18*8+3*4+7)&-8
        selected=prefix+2*size;selection=(selected+4+7)&-8
        need(storage==dict(retained=dict(offset=prefix,bytes=2*size),selected_slot=dict(offset=selected,bytes=4),selection=dict(offset=selection,bytes=24),previous_selection=dict(offset=selection+24,bytes=24)),'actual owner retained-array fields match independent source prefix')
        need(h[26:31]==(self.symbol('pe')+prefix,self.symbol('pe')+prefix+size,2,size,24)and prefix+2*size<=h[3],'actual fixed retained-slot addresses/extent')
        need(self.head==self.page+0x200 and self.page+8192<1<<31 and h[31:41]==(self.head,self.page+0x400,self.page+0x600,self.page+0x603,3,2,0,0,self.app['expected_exit_pc'],0)and not any(h[41:47])and h[47:53]==(1,0,0,0,h[16],0)and not any(h[53:]),'exact three epochs/two misses and successful retained prefix')
        raw=q(self.f(self.b,t,'raw_ingress'));need(sum(raw[1:])==raw[0]>0,'whole actual signal population')
        for k in('sink_initial','sink_terminal'):
            st=self.f(self.b,t,k);d=self.stat(st);need(d['mode']&0xffff==0x8180 and d['size']==0,'actual empty regular0600 sink');self.eq(st,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(self.f(self.b,t,'sink_initial'),self.f(self.b,t,'sink_terminal'),'stat',observed=('st_atim','st_mtim','st_ctim'))
        footer=q(r.data[-64:]);need(footer[:4]==(0x334632525449324c,3,len(self.b),len(self.b))and 1<=footer[4]<=64 and 0<footer[5]<=len(self.b)and footer[6:]==(0,0),'complete actual group output footer')
        if footer[4]==1:need(footer[5]==len(self.b),'single actual complete group write')
        hardware=self.f(self.b,t,'hardware');self.eq(hardware,'li2_selected_hardware',abi_version=1,reserved=0)
        for i,k in enumerate(('leaf0','leaf1','leaf7')):need(struct.unpack('<4I',self.f(hardware,'li2_selected_hardware',k))==tuple(self.app['hardware'][i][2:]),'actual bridge/app CPUID hardware equality')
        for key,objid in(('main',self.image['main_object']),('interpreter',self.image['interpreter_object'])):self.image_header(self.f(self.b,t,key),objid)
        self.eq(self.f(self.b,t,'session'),'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        need(self.i(self.f(self.b,t,'session'),'li2_step_session','sync_query')&96==96,'actual registered membarrier support')
        obj,_,loads=self.objects[self.image['main_object']];bias=self.bases[self.image['main_object']]
        owners=[p for p in loads if p[1]==5 and bias+p[3]<=self.page and self.page+8192<=bias+p[3]+p[5]]
        need(len(owners)==1 and self.source_offset==owners[0][2]+self.page-bias-owners[0][3]and obj['data'][self.source_offset:self.source_offset+8192]==self.app['source'],'whole source two-page original ELF bytes')

        epochs=r.items(self.b,t,'epochs','ptr2o_epoch');misses=r.items(self.b,t,'misses','ptr2o_miss')
        initial_slots=r.items(self.f(epochs[0],'ptr2o_epoch','prior'),'ptr2o_slots','slots','ptr2o_slot')
        self.h_alloc=self.i(r.items(initial_slots[1],'ptr2o_slot','banks','ped_bank')[1],'ped_bank','generated');self.h_proof_alloc=self.i(initial_slots[1],'ptr2o_slot','proof')
        a=self.epoch(epochs[0],0);b=self.epoch(epochs[1],1)
        need(self.f(epochs[1],'ptr2o_epoch','prior_counts')==a['counts_raw']and self.f(epochs[1],'ptr2o_epoch','prior')==a['slots_raw'],'B follows actual A completion without hidden offer')
        need(a['slot']!=b['slot']and a['generation']!=b['generation']and b['generation']==a['generation']+1,'two distinct actual retained identities')
        m0=self.miss(misses[0],0,b);m1=self.miss(misses[1],1,m0);warm=self.epoch(epochs[2],2)
        need(self.f(epochs[2],'ptr2o_epoch','prior_counts')==m1['counts_raw']and self.f(epochs[2],'ptr2o_epoch','prior')==m1['slots_raw'],'warm A follows two genuine cancellations with both slots intact')
        need((warm['slot'],warm['generation'],warm['build_serial'])==(a['slot'],a['generation'],a['build_serial']),'warm A reuses exact original retained generation')
        need(b['begin']==a['terminal_ordinal']+1 and m0['begin']==b['terminal_ordinal']+1 and m1['begin']==m0['next_ordinal']and warm['begin']==m1['next_ordinal'],'complete focal raw-event chronology')
        need(m0['next_event']==m1['event']and m1['next_event']==warm['event'],'actual same-handler next close and following offer event identity')
        self.same_event(m0['next'],m1['before'],m1['before']['greg'][17]);self.same_event(m1['next'],warm['before'],warm['before']['greg'][17])
        for projection,actual in((m0['next_slot'],m1['closed_slot']),(m1['next_slot'],warm['closed_slot'])):
            sf=r.types['li2_tf_chain_slot']['fields'];of=r.types['li2_tf_owner']['fields'];tf=r.types['li2_step_owner']['fields'];start=sf['owner']['offset']+of['step']['offset']+tf['after']['offset']+r.types['li2_step_frame']['bytes']
            need(projection[:384]==actual[:384]and projection[start:sf['unexpected']['offset']]==actual[start:sf['unexpected']['offset']],'same actual closed ordinary predecessor at both capture hooks')
        self.next_trace(self.f(self.b,t,'next'),warm,epochs[2]);need(raw[0]>=warm['next_trace_ordinal'],'whole chronological retained ingress ordinals')
        final=self.counts(self.f(self.b,t,'final_counts'));last=self.counts(warm['counts_raw'])
        need(all(final[k]>=last[k]for k in final if k!='misses')and all(a>=b for a,b in zip(final['misses'],last['misses'],strict=True)),'final counters retain every focal event without attributing later work')
        names='version status failure_code detail_abs detail_negative phase serial generation build_serial offers cold_attempts publications hits cancelled retirements permit_claims entries completed unexpected permit opened_pages closed_pages anchor_released registration_rechecked guest_data_fault recovery_complete first_error active busy selected_slot slot0_generation slot1_generation slot0_permit slot1_permit slot0_completed_serial slot1_completed_serial'.split()
        values=q(self.f(self.b,t,'final_row'));need(len(values)==len(names),'whole exact retained terminal schema');row=dict(zip(names,values,strict=True));row['misses']=list(final['misses'])
        need((row['version'],row['status'],row['failure_code'],row['detail_abs'],row['detail_negative'])==(3,0,0,0,0),'actual protected retained terminal outcome')
        for k in('offers','cold_attempts','publications','hits','cancelled','retirements','permit_claims','entries','completed','unexpected'):need(row[k]==final[k],'whole final counter-to-report join '+k)
        p=self.f(self.b,t,'final_progress');pt='li2_pg_progress'
        for k in('phase','serial','opened_pages','closed_pages','anchor_released','registration_rechecked','first_error'):need(row[k]==self.i(p,pt,k),'actual retained progress-to-report join '+k)
        need(row['selected_slot']in(0,1)and 0<row['build_serial']<=row['serial'],'actual final selected slot/build serial')
        gs=(row['slot0_generation'],row['slot1_generation']);ps=(row['slot0_permit'],row['slot1_permit']);cs=(row['slot0_completed_serial'],row['slot1_completed_serial'])
        need(all(0<g<=final['next_generation']for g in gs)and gs[0]!=gs[1]and ps==(1,1)and all(0<c<=final['next_serial']for c in cs)and row['generation']==gs[row['selected_slot']]and row['permit']==ps[row['selected_slot']],'actual final two retained identities and completed permits')
        need(final['offers']==final['entries']+final['cancelled']and final['entries']==final['publications']+final['hits']and final['cold_attempts']==final['publications']+final['cancelled']and sum(final['misses'])==final['cancelled']and final['next_serial']==final['offers']and final['next_generation']==final['publications'],'whole completed/cancelled retained partition')
        need(final['entries']==final['completed']and final['unexpected']==0 and final['retirements']==final['publications']-2 and final['permit_claims']==final['retirements']+final['hits'],'whole two-resident permit/publication accounting')
        need(row['phase']in(13,14)and row['active']==row['busy']==row['first_error']==row['guest_data_fault']==0 and row['anchor_released']==row['registration_rechecked']==1,'actual final closed retained epoch or completed cancellation')
        need((row['opened_pages'],row['closed_pages'],row['recovery_complete'])==((17,17,1)if row['phase']==13 else(0,0,0)),'exact final retained extent and recovery for its terminal phase')
        replacements=a['prior_generation_installed']+b['prior_generation_installed']
        return dict(terminal=row,mode=0,attempts=[a,b,warm],misses=[m0,m1],cold_publications=2,warm_entries=1,replacements=replacements,permit_claims=replacements+1,interior_signals=0,source=self.app['source'],word=0,status=0,code=0,detail=0,qualification_credit=False)


def read(data,layout,image,app,pid,cpu,exit_status):
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    return Check(wire.Reader(data,layout),image,app,pid,cpu).finish(exit_status)


def terminal(parsed,owner):
    expected=owner['terminal'];need(type(parsed)is dict and set(parsed)==set(expected)and all(type(v)is int for k,v in parsed.items()if k!='misses')and type(parsed['misses'])is list and all(type(v)is int for v in parsed['misses'])and parsed==expected,'whole actual protected retained-two terminal row')
    return dict(fields=len(expected),protected_retained_two_row=1,inherited_row_protection=0)

CONTROL_COUNTS={0:109}

def controls(data,layout,image,app,pid,cpu,exit_status):
    """Actual retained input mutations; old resident/group controls stay separate."""
    read(data,layout,image,app,pid,cpu,exit_status);types=layout['types']
    def at(t,k,base=0,index=0,child=None):return base+types[t]['fields'][k]['offset']+(index*types[child]['bytes']if child else index)
    w='ptr2o_wire';et='ptr2o_epoch';st='ptr2o_stage';it='ptr2o_epoch_info';gt='li2_pg_generation';pt='li2_pg_progress';ct='li2_pg_compact';ss='ptr2o_slots';sl='ptr2o_slot'
    e=at(w,'epochs');b=at(w,'epochs',index=1,child=et);warm=at(w,'epochs',index=2,child=et)
    ent=at(et,'entered',e);end=at(et,'terminal',e);info=at(et,'info',e);p=at(st,'progress',end)
    def selected(stage):
        slots=at(st,'slots',stage);index=struct.unpack_from('<I',data,at(ss,'selected_slot',slots))[0];need(index in(0,1),'control actual selected slot');return at(ss,'slots',slots,index,sl)
    es=selected(ent);zs=selected(end);g=at(sl,'generation',zs);eg=at(sl,'generation',es)
    cert=at(w,'certificates');payload=at('ptr2o_certificate','payload',cert);cp=at('pe_payload','plan',payload)
    pred=at(et,'predecessor',e);closed=at('ptr2o_predecessor','closed',pred);owner=at('li2_tf_chain_slot','owner',closed);step=at('li2_tf_owner','step',owner)
    m=at(w,'misses');mh=at('ptr2o_miss','held',m);mr=at('ptr2o_miss','resumed',m);mp=at('ptr2o_miss','plan',m)
    wi=at(et,'info',warm);we=at(et,'entered',warm);ws=selected(we);wg=at(sl,'generation',ws)
    n=at(w,'next');ns=at('ptr2o_next','closed',n);no=at('li2_tf_chain_slot','owner',ns);nt=at('li2_tf_owner','step',no);nf=at('ptr2o_next','frame',n)
    tests=[
      ('wire_version',8),('footer_version',len(data)-56),('actual_hardware',at('li2_selected_hardware','leaf0',at(w,'hardware'))),
      ('interior_signal',at(et,'h',e)+11*8),('full_terminal_FP',at('li2_step_frame','fp',at('le_frame','frame',at(et,'after',e)))),
      ('full_data',at('li2_ptr2o_memory','data',at(et,'after_memory',e))),('full_stack',at('li2_ptr2o_memory','stack',at(et,'after_memory',e))),
      ('source_second_page',at(ct,'source',cp)+4096),('proof_padding',at('ptr2o_certificate','tail',cert)),('literal_second_image',at('ptr2o_certificate','code',cert)+32768),('literal_stub',at('ptr2o_certificate','code',cert)+65536),
      ('initial_slot_zero',at(et,'initial_slots',e)),('terminal_slot_zero',at(et,'terminal_slots',e)),('member_generation',at('pe_header','member_generation',at('pe_payload','header',payload))+8),
      ('global_head_population',at(ct,'heads',cp)),('member_partition',at(ct,'member_heads',cp)+4),('typed_edge_unused',at('li2_pg_edge','target_head',at(ct,'edge',cp))),
      ('entry_word',at('li2_pg_rseq_progress','word_entry',at(st,'rseq',ent))),('closing_word',at('li2_pg_rseq_progress','word_after',at(st,'rseq',end))),
      ('cold_head_proof',at('li2_pg_rseq_progress','cold_heads',at(st,'rseq',ent))),('no_invented_stub_proof',at('li2_pg_rseq_progress','cold_stubs',at(st,'rseq',ent))),
      ('live_GPR',at('li2_write_registers','gpr',at('li2_link_rseq_live','registers',at(it,'live',info)))),
      ('active_member_reference',at(gt,'member_refs',eg)+8),('closed_incoming_reference',at(gt,'incoming',g)),
      ('first_image_revoke',at('le_permission','complete',at(gt,'close',g))),('second_image_revoke',at('le_permission','complete',at(gt,'close',g,1,'le_permission'))),('stub_revoke',at('le_permission','complete',at(gt,'close',g,2,'le_permission'))),
      ('source_anchor_release',at('li2_pg_source_progress','release_complete',at(st,'source',end))),('source_closed_pages',at('li2_pg_source_progress','closed_pages',at(st,'source',end))),
      ('completion_permit',at(pt,'completion_permit',p)),('reset_seal',at('le_permission','complete',at('pg_slot_transition','seal',at(gt,'slots',g,2,'pg_slot_transition')))),
      ('predecessor_before_FP',at('li2_step_frame','fp',at('li2_step_owner','before',step))),('predecessor_after_FP',at('li2_step_frame','fp',at('li2_step_owner','after',step))),('predecessor_actual_revoke',at('li2_step_owner','revoked',step)),('predecessor_zero_scan',at('ptr2o_predecessor','unexpected_compared',pred)),
      ('slot_owner',at('li2_ptr_slot_ref','owner',at(sl,'identity',es))),('slot_index',at('li2_ptr_slot_ref','index',at(sl,'identity',es))),('slot_generation',at('li2_ptr_slot_ref','generation',at(sl,'identity',es))),
      ('selected_slot',at(ss,'selected_slot',at(st,'slots',ent))),('actual_victim',at(et,'h',e)+24*8),('actual_B_certificate_slot',at('ptr2o_certificate','slot',at(w,'certificates',index=1,child='ptr2o_certificate'))),
      ('known_certificate_required',at('ptr2o_check','certificate',at(sl,'check',es))),('certificate_generation',at('ptr2o_certificate','generation',cert)),('certificate_literal_extent',at('ptr2o_certificate','proof_bytes',cert)),
      ('miss_zero_scan_complete',at('ptr2o_miss_plan','scan_complete',mp)),('miss_zero_scan_length',at('ptr2o_miss_plan','scanned',mp)),('miss_omitted_nonzero',at('ptr2o_miss_plan','nonzero',mp)),('miss_reason',at('li2_pg_miss','reason',at('ptr2o_miss','miss',m))),('miss_source_bytes',at('ptr2o_miss_plan','source',mp)),
      ('cancel_all17_pages',at('li2_pg_source_progress','cancel_pages',at(st,'source',mr))),('cancel_rseq_completion',at('li2_pg_rseq_progress','cancel_complete',at(st,'rseq',mr))),
      ('miss_next_full_FP',at('li2_step_frame','fp',at('le_frame','frame',at('ptr2o_miss','next_trace',m)))),('miss_next_event',at('ptr2o_miss','h',m)+10*8),('miss_next_TLS',at('le_frame','fs',at('ptr2o_miss','next_trace',m))),('miss_close_observed',at('ptr2o_miss','h',m)+26*8),
      ('miss_next_release',at('ptr2o_slot_progress','complete',at('ptr2o_miss','next_slot',m))),('warm_build_serial',at(gt,'build_serial',wg)),('warm_no_reopen',at('le_permission','started',at(it,'reopen_code',wi))),('warm_no_static_reproof',at(it,'none_proofs',wi)),('warm_claim',at('li2_private_code_query','complete',at(it,'claim_slots',wi))),
      ('cell_generation',at('pg_dispatch_cell_transition','generation',at(gt,'cell',g,2,'pg_dispatch_cell_transition'))),('cell_zero',at('pg_dispatch_cell_transition','after',at(gt,'cell',g,2,'pg_dispatch_cell_transition'))),
      ('next_ordinal',at('ptr2o_next','raw_ordinal',n)),('next_close',at('ptr2o_next','closed_complete',n)),('next_TLS',at('ptr2o_next','tls_complete',n)),('next_FP',at('li2_step_frame','fp',at('le_frame','frame',nf))),('next_original_before_FP',at('li2_step_frame','fp',at('li2_step_owner','before',nt))),('next_original_revoke',at('li2_step_owner','revoked',nt)),
      ('final_partition',at('ptr2o_counts','publications',at(w,'final_counts'))),('final_slot_permit',at(w,'final_row')+32*8),('whole_terminal_row',at(w,'final_row')+17*8)]
    refused=[]
    def reject(name,mutant,expected=None):
        try:read(bytes(mutant),layout,image,app,pid,cpu,exit_status)
        except ValueError as error:
            if expected is not None:need(str(error)==expected,'exact source-causal retained-two refusal '+name)
            refused.append(name)
        else:raise ValueError('supplied retained-two corruption accepted '+name)
    for name,offset in tests:
        mutant=bytearray(data);mutant[offset]^=1;reject(name,mutant)
    startup=at(w,'startup_registry');reg=at(et,'terminal_registry',e);rt='ptr2o_registry'
    registry=[('startup_population',at(rt,'count',startup),'startup registry population is an exact predecessor',True),
      ('startup_table_headers',at(rt,'ph',startup),'startup registry keeps exact table, bridge and program headers',False),
      ('startup_range_prefix',at(rt,'ranges',startup),'startup registry retains every original range and classification',False),
      ('startup_classification_prefix',at(rt,'initial_code',startup),'startup registry retains every original range and classification',False),
      ('epoch_terminal_population',at(rt,'count',reg),'whole retained registry unchanged during epoch',False),
      ('epoch_owner_population',at(it,'registry_count',info),'exact ptr2o_epoch_info.registry_count',False)]
    for name,offset,message,clear in registry:
        mutant=bytearray(data)
        if clear:mutant[offset:offset+4]=bytes(4)
        else:mutant[offset]^=1
        reject(name,mutant,message)
    # A digest is never accepted in place of each complete immutable byte scan.
    for field,nbytes in(('proof',364544),('code',69632),('publication',362624)):
        base=at('ptr2o_check',field,at(sl,'check',es))
        for name,k,value in(('completion','complete',0),('coverage','compared',nbytes-1),('actual_difference','differences',1)):
            mutant=bytearray(data);struct.pack_into('<Q',mutant,at('ptr2o_scan',k,base),value);reject(field+'_'+name,mutant,'exact ptr2o_scan.'+k)
    # The shared literal still needs the independent full descriptor model.
    for name,array,child,index,field in(('descriptor','original','li2_span_decoded',0,'gpr_write'),('second_descriptor','original','li2_span_decoded',1,'flags_read'),('frontier','frontier','li2_span_decoded',0,'refusal'),('head_kind','head','li2_pe_head',0,'kind')):
        mutant=bytearray(data);mutant[at(child,field,at(ct,array,cp,index,child))]^=1;reject('independent_'+name,mutant,'whole independent retained-two '+array)
    hs=at(st,'state',mh);rs=at(st,'state',mr);checks=struct.unpack_from('<Q',data,at('li2_rseq_state','instruction_checks',hs))[0]
    for name,field,value in(('ordinary_check_omitted','instruction_checks',checks),('ordinary_check_doubled','instruction_checks',(checks+2)&U64),('ordinary_unrelated_counter','range_checks',(struct.unpack_from('<Q',data,at('li2_rseq_state','range_checks',rs))[0]+1)&U64)):
        mutant=bytearray(data);struct.pack_into('<Q',mutant,at('li2_rseq_state',field,rs),value);reject(name,mutant,'complete exact transition li2_rseq_state')
    mutant=bytearray(data)
    for stage in(mh,mr):mutant[at(pt,'transfer_serial',at(st,'progress',stage))]^=1
    reject('coherent_cancel_transfer_serial',mutant,'actual cancelled progress binds CLOSED transfer serial')
    permit=at(sl,'permit',zs);mutant=bytearray(data);mutant[at('li2_pg_source_progress','layout',at('ped_permit','source',permit))]^=1
    reject('completed_permit_source_layout',mutant,'permit source binds the actual complete generation layout')
    # Preserve both slot copies across held/resumed; prior checkpoint must reject.
    mutant=bytearray(data)
    for stage in(mh,mr):
        slots=at(st,'slots',stage);slot=at(ss,'slots',slots,0,sl);mutant[at(sl,'last_completed',slot)]^=1
    reject('coherent_miss_slot_mutation',mutant,'both actual retained slots preserved byte-for-byte')
    mutant=bytearray(data);fp=at(w,'final_progress');fr=at(w,'final_row');closed_pages=struct.unpack_from('<I',data,at(pt,'closed_pages',fp))[0]
    struct.pack_into('<I',mutant,at(pt,'closed_pages',fp),closed_pages^1);struct.pack_into('<Q',mutant,fr+21*8,closed_pages^1)
    reject('coherent_final_extent',mutant,'exact final retained extent and recovery for its terminal phase')
    proof=at(gt,'proof_writable',eg)
    for index in(0,1):
        row=at('pg_proof_query','part',proof,index,'li2_private_code_query');maps=at('li2_private_code_query','maps',row);observation=at('li2_fetch_map_progress','observation',maps);coverage='end'if index==0 else'first'
        for name,offset,width,value,message in(
          ('coverage',at('li2_private_code_query',coverage,row),8,struct.unpack_from('<Q',data,at('li2_private_code_query',coverage,row))[0]-PAGE,'exact li2_private_code_query.'+coverage),
          ('page_count',at('li2_private_code_query','pages_checked',row),8,(64 if index==0 else 25)-1,'exact li2_private_code_query.pages_checked'),
          ('completion',at('li2_private_code_query','complete',row),4,0,'exact li2_private_code_query.complete'),
          ('protection',at('li2_private_code_query','actual_prot',row),4,7,'exact li2_private_code_query.actual_prot'),
          ('maps_close',at('li2_fetch_map_progress','closed',maps),4,0,'exact li2_fetch_map_progress.closed'),
          ('maps_receipt',at('li2_maps_observation','io_performed',observation),4,struct.unpack_from('<I',data,at('li2_maps_observation','io_performed',observation))[0]^1,'exact maintained acquisition class and physical I/O')):
            mutant=bytearray(data);struct.pack_into('<Q'if width==8 else'<I',mutant,offset,value);reject('proof_part'+str(index)+'_'+name,mutant,message)
    need(len(refused)==CONTROL_COUNTS[0],'all exact separately counted retained-two owner controls')
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0,mode=0)
