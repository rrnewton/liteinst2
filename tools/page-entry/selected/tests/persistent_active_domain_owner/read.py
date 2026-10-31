"""Distinct shared active domain with maintained mapping receipts.
Old fixed/dynamic/group267 profiles remain separate mandatory prerequisites."""
import hashlib,struct,importlib.util
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
HERE=Path(__file__).resolve().parent
wire=load('persistent_active_domain_wire',HERE/'wire.py');plan=load('persistent_active_domain_plan',HERE/'plan.py')
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
            if name in registered or name in ('li2_raw6','li2_gateway_start','li2_gateway_end','span_transfer','selected_chain','protected','maps_current','rows'):
                need(name not in symbols,'unique actual bridge symbol');symbols[name]=(address,size)
    need(set(symbols)==set(registered)|{'li2_raw6','li2_gateway_start','li2_gateway_end','span_transfer','selected_chain','protected','maps_current','rows'},'whole required compiled object inventory')
    ph=[struct.unpack_from('<IIQQQQQQ',data,h[5]+56*i)for i in range(h[10])]
    return h,ph,symbols

class Check(old.Check):
    def layout(self,b,base=None):
        values=q(b)
        need(len(values)==6,'whole distinct active-domain layout')
        a,c,stubs,slots,spill,directory=values
        need(PAGE<=a<1<<47 and a%PAGE==0 and values[:5]==(a,a+32768,a+65536,a+69632,a+73728)and canonical(a,77824),'exact contiguous two-image stub/slots/spill bank')
        need(directory==self.h[40]and directory%PAGE==0 and canonical(directory,12288)and(directory+12288<=a or a+77824<=directory),'actual shared directory disjoint from each complete bank')
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
            self.eq(b,t,validations=4 if terminal else 3);self.maps(self.f(b,t,'validation'));self.query3(self.f(b,t,'opened'),5)
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
            t='pdao_registry';self.eq(b,t,complete=1,table=self.symbol('protected'));count=self.i(b,t,'count');need(0<count<=128,'bounded actual registration table')
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
        t='li2_pdao_memory';self.eq(b,t,attempted=1,complete=1,after_abort=int(failed),rows_checked=6,data_copied=8192,stack_copied=224,result=0,detail=0,rsp=RSP,data_first=DATA,stack_first=RSP-128)
        m=self.maps(self.f(b,t,'maps'),0)
        before,after=(self.f(b,t,k)for k in('before','after'));mt='li2_maps_stats'
        self.eq(before,mt,active=0,poisoned=0,reserved=0);self.eq(after,mt,active=0,poisoned=0,reserved=0,valid=1)
        self.r.change(before,after,mt,values=dict(fresh_calls=self.i(before,mt,'fresh_calls')+1,acquisitions=self.i(before,mt,'acquisitions')+1),observed=('valid','invalidations','mutation_epoch'))
        invalidations=self.i(after,mt,'invalidations')-self.i(before,mt,'invalidations')
        need(invalidations>=1 and self.i(after,mt,'mutation_epoch')-self.i(before,mt,'mutation_epoch')==invalidations,'actual explicit fresh invalidation and every gateway invalidation')
        need(m[:3]==(self.i(after,mt,'acquisitions'),0,self.i(after,mt,'mutation_epoch')),'memory acquisition actual stats join')
        rows=self.r.items(b,t,'rows','li2_pdao_map_row')
        for i,row in enumerate(rows):
            self.eq(row,'li2_pdao_map_row',offset=0,major=0,minor=0,inode=0,private=1)
            a,z,prot=self.v(row,'li2_pdao_map_row','first end prot');need(a%PAGE==z%PAGE==0 and a<z,'actual page-aligned memory extent')
            if i<2:need((a,z,prot)==(DATA,DATA+8192,3),'actual two-page writable data')
            elif i==4:need((a,z,prot)==(STACK+4096,STACK+4096+131072,3),'actual fixed writable guest stack')
            else:
                point=(DATA+8192,STACK,STACK+4096+131072)[(2,3,5).index(i)]
                need(a<=point and point+PAGE<=z and prot==0,'actual inaccessible data/stack guard')
        return dict(data=self.f(b,t,'data'),stack=self.f(b,t,'stack'))

    def registry_prefix(self,a,b):
        t='pdao_registry';n,m=self.i(a,t,'count'),self.i(b,t,'count');need(0<n<=m<=128,'startup registry population is an exact predecessor')
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
        t='pdao_counts';names='next_serial next_generation offers publications hits cold_attempts cancelled retirements permit_claims entries completed unexpected'.split()
        d={k:self.i(b,t,k)for k in names};d['misses']=q(self.f(b,t,'misses'));need(len(d['misses'])==18 and d['misses'][0]==0,'exact eighteen descriptive reason buckets')
        need(all(0<=x<U64 for x in d.values()if type(x)is int)and all(0<=x<U64 for x in d['misses']),'bounded exact dynamic counters')
        return d

    def delta(self,a,b,**increments):
        x,y=self.counts(a),self.counts(b)
        for k in x:
            if k=='misses':need(y[k]==tuple(v+(1 if i==increments.get('miss_reason',-1)else 0)for i,v in enumerate(x[k])),'exact classified miss bucket delta')
            else:need(y[k]==x[k]+increments.get(k,0),'exact focal dynamic counter delta '+k)

    def predecessor(self,slot,pc,ingress,closed=True):
        t='li2_tf_chain_slot';index=self.i(slot,t,'index');need(index in(0,1),'actual predecessor slot index')
        self.eq(slot,t,chain=self.symbol('selected_chain'),phase=5 if closed else 3,fallback=0,prepare_complete=1,decode_attempted=1,decode_complete=1,retry=0,unexpected_frame_observed=0,unexpected_signal=0,unexpected_code=0,unexpected_errno=0,unexpected_address=0,prepare_result=0,decode_result=0,classify_result=0)
        need(self.i(slot,t,'generation')>0 and self.i(slot,t,'event_id')>0,'actual predecessor generation/event')
        origin=self.i(slot,t,'origin');need(origin in(1,2)and self.i(slot,t,'prepare_attempted')==int(origin==2),'actual predecessor NX/TRACE preparation')
        for k in('first_decoded','first_fetch','first_release','unexpected'):zero(self.f(slot,t,k),'no unused predecessor '+k)
        kind='nop'if pc==self.page+0x1fe else'jmp';code,length=self.decoded(self.f(slot,t,'decoded'),pc,kind)
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

    def __init__(self,r,image,app,pid,cpu):
        self.r,self.image,self.app,self.pid,self.cpu=r,image,app,pid,cpu
        self.b=r.data[:-64];self.h=q(self.f(self.b,'pdao_wire','h'));self.bias=self.h[9]-r.layout['symbols']['li2_raw6']
        self.page=app['head']&-PAGE;self.head=app['head'];self.objects={};self.bases={};self.backings={};self.maps_seen={};self.source_ids={}
        for key,obj in image['objects'].items():
            need(type(key)is int and type(obj)is dict,'actual complete object inventory');h,loads=old.elf(obj['data']);self.objects[key]=(obj,h,loads)
        need(image['main_object']in self.objects and image['interpreter_object']in self.objects,'actual source object identities')
        self.eh,self.ph,self.symbols=elf_symbols(image['bridge'])
        need(set(r.layout['symbols'])==set(self.symbols)|{'span_progress','pg_domain_source'}and all(r.layout['symbols'][k]==v[0]for k,v in self.symbols.items()),'same actual bridge/DWARF symbols')
        initial_epoch=r.items(self.b,'pdao_wire','epochs','pdao_epoch')[0]
        initial_slots=r.items(self.f(initial_epoch,'pdao_epoch','prior'),'pdao_slots','slots','pdao_slot')
        self.bank_layouts=[[self.f(bank,'ped_bank','layout')for bank in r.items(slot,'pdao_slot','banks','ped_bank')]for slot in initial_slots]
        self.certificates=r.items(self.b,'pdao_wire','certificates','pdao_certificate')
        payload=self.f(self.certificates[0],'pdao_certificate','payload');key=self.f(payload,'pe_payload','source')
        row=r.items(key,'li2_pg_source_key','page','li2_pg_source_page')[0]
        self.main_backing=self.f(row,'li2_pg_source_page','backing');self.source_offset=self.i(self.f(row,'li2_pg_source_page','identity'),'li2_fetch_page','offset')
        self.main_vma_identity=self.v(self.f(row,'li2_pg_source_page','identity'),'li2_fetch_page','vma_major vma_minor vma_inode')
        binding=image['persistent_binding'];need(binding['version']==4 and binding['mode']in('capture','differential')and binding['profile']=='persistent-active-domain-'+binding['mode']+'-v4','actual distinct active-domain build mode')
        self.differential=binding['mode']=='differential';self.geometry=self.layout(self.f(self.f(payload,'pe_payload','header'),'pe_header','layout'))

    def decoded(self,b,pc,kind=None):
        off=pc-self.page;forms={0x1fe:(299,2,1),0x204:(765,2,0),0x40d:(765,2,0)}
        need(off in forms,'one actual retained-two ordinary boundary');code,length,step=forms[off]
        self.eq(b,'li2_decoded',pc=pc,next_pc=pc+length,abi_version=1,decode_status=0,code=code,kind=0,destination=16,width_bits=0,step_disposition=step,available=15,length=length,reserved=0)
        need(self.f(b,'li2_decoded','bytes')==self.app['source'][off:off+15]+b'\0','whole actual ordinary retained-two decoder window')
        return code,length

    def setup(self,slot):
        self.proof=self.i(slot,'pdao_slot','proof');g=self.f(slot,'pdao_slot','generation')
        self.geometry=self.layout(self.f(g,'li2_pg_generation','layout'));self.generated=self.geometry[0];self.spill=self.geometry[4]
        self.table=self.proof+self.r.types['pe_payload']['fields']['plan']['offset']+self.r.types['li2_pg_compact']['fields']['table']['offset']

    def compact(self,payload,entry):
        c=self.f(payload,'pe_payload','plan');t='li2_pg_compact'
        heads=2 if entry==self.page+0x200 else 5
        self.eq(c,t,version=3,bytes=353608,ready=1,result=0,heads=heads,exits=1,stores=0,source_bytes=6 if heads==2 else 15,source_mask=1,decoder_result=0,guard_result=0,reserved=0,links=0,reserved2=0,entry=entry)
        need(struct.unpack('<2I',self.f(c,t,'member_heads'))==(heads,0)and q(self.f(c,t,'page'))==(self.page,self.page+PAGE)and self.layout(self.f(c,t,'layout'))==self.geometry and self.f(c,t,'source')==self.app['source'],'whole independent retained-two source and2/0 partition')
        expected=plan.graph(self.app['source'],self.page,entry,self.geometry)
        for k in('image','stub_image','head','original','frontier','edge','instruction','guard'):
            need(self.f(c,t,k)==expected[k],'whole independent retained-two '+k)
        need(q(self.f(c,t,'exit_pc'))==(entry+(4 if heads==2 else 13),0,0,0,0,0,0,0),'one actual ordinary memory-JMP frontier')
        table=plan.table(self.ranges+[(self.page,self.page+PAGE),(self.page+PAGE,self.page+2*PAGE),(RSEQ+8,RSEQ+16)],self.table)
        need(self.f(c,t,'table')==table,'whole independent exclusion table including both source pages and registered word')
        need(self.table-64576==self.proof+self.r.types['pe_payload']['fields']['plan']['offset']+self.r.types[t]['fields']['original']['offset'],'actual immutable row address and common full/compact table relation')
        return expected

    def scan(self,b,n):
        self.eq(b,'pdao_scan',started=1,complete=1,expected=n,compared=n,differences=0,first_offset=0,expected_value=0,actual_value=0)

    def checkpoint(self,slot,index,known):
        t='pdao_slot';g=self.f(slot,t,'generation');ref=self.f(slot,t,'identity');gen=self.i(ref,'li2_ptr_slot_ref','generation')
        self.eq(ref,'li2_ptr_slot_ref',owner=self.symbol('pe'),index=index,reserved=0)
        self.eq(g,'li2_pg_generation',generation=gen,proof=self.i(slot,t,'proof'))
        check=self.f(slot,t,'check');self.eq(check,'pdao_check',slot=index,generation=gen)
        matches=[i for i,c in enumerate(self.certificates)if self.i(c,'pdao_certificate','slot')==index and self.i(c,'pdao_certificate','generation')==gen]
        expected=next((i for i in matches if i in known),None)
        if expected is None:
            self.eq(check,'pdao_check',certificate=0)
            for k in('proof','code','publication'):zero(self.f(check,'pdao_check',k),'explicit unavailable unrelated-startup immutable comparison')
            need(not matches,'known focal generation cannot claim unavailable certificate')
            if self.i(g,'li2_pg_generation','installed'):
                _,member,_,_=self.claim(slot,self.current_domain);key=self.f(member,'pda_member_completion','source')
                need(self.i(key,'li2_pg_source_key','entry')not in(self.page+0x200,self.page+0x400),'unrelated startup identity is not an unobserved focal root')
        else:
            c=self.certificates[expected];self.eq(check,'pdao_check',certificate=expected+1)
            self.eq(g,'li2_pg_generation',installed=1,complete=1,proof_complete=1,ready_generation=gen)
            payload=self.f(c,'pdao_certificate','payload');header=self.f(payload,'pe_payload','header')
            need(self.f(g,'li2_pg_generation','layout')==self.f(header,'pe_header','layout')and self.i(g,'li2_pg_generation','build_serial')==self.i(header,'pe_header','serial'),'certificate binds actual immutable generation layout/build')
            for k,n in(('proof',364544),('code',69632),('publication',362640)):self.scan(self.f(check,'pdao_check',k),n)
        return gen

    def same_slots(self,a,b):
        for x,y in zip(self.r.items(a,'pdao_slots','slots','pdao_slot'),self.r.items(b,'pdao_slots','slots','pdao_slot'),strict=True):
            need(x==y,'both actual retained slots preserved byte-for-byte')

    def certificate(self,index,slot,entry,serial,gen):
        c=self.certificates[index];t='pdao_certificate';self.setup(slot)
        self.eq(c,t,complete=1,index=index,slot=self.i(self.f(slot,'pdao_slot','identity'),'li2_ptr_slot_ref','index'),generation=gen,entry=entry,proof_bytes=364544,code_bytes=69632,publication_bytes=362640)
        zero(self.f(c,t,'tail'),'whole literal immutable proof tail zero')
        payload=self.f(c,t,'payload');ph=self.f(payload,'pe_payload','header')
        self.eq(ph,'pe_header',version=1,serial=serial,generation=gen,registry=self.symbol('pe'),generated=self.generated,spill=self.spill,table=self.table,plan_proof=2,none_proof=1,source_validations=1,registered_epoch=1,rseq_address=RSEQ,rseq_length=32,rseq_signature=0x53053053)
        need(self.layout(self.f(ph,'pe_header','layout'))==self.geometry and q(self.f(ph,'pe_header','member_generation'))==(2*gen,2*gen+1),'immutable actual retained member identities/layout');zero(self.f(ph,'pe_header','reserved'),'whole header reserved')
        binding=self.image['persistent_binding'];need(binding['version']==4 and binding['profile']=='persistent-active-domain-'+binding['mode']+'-v4','explicit retained-two source binding')
        need(self.f(ph,'pe_header','archive')==bytes.fromhex(binding['archive']['sha256'])and self.f(ph,'pe_header','policy')==bytes.fromhex(binding['policy_sha256']),'whole actual retained archive/policy authority')
        key=self.f(payload,'pe_payload','source');self.source_key(key,entry);expected=self.compact(payload,entry)
        need(self.f(c,t,'code')==expected['image']+expected['stub_image'],'all17 actual code pages in shared literal certificate')
        return payload

    def maps(self,b,kind=None):
        t='li2_fetch_map_progress';self.eq(b,t,last_read=0,close_result=0,opened=1,close_started=1,closed=1)
        fd,n,rows=self.v(b,t,'fd bytes rows');need(fd<1<<31 and 0<n<=256<<10 and 0<rows<=2048,'complete real maps read bounds')
        o=self.f(b,t,'observation');a,h,e,k,io=self.v(o,'li2_maps_observation','acquisition_id handler_id mutation_epoch kind io_performed')
        allowed=(0,1,3)if self.differential else(0,1,4)
        need(a>0 and e>0 and k in allowed and io==int(k!=4)and(h==0 if k==0 else h>0),'exact selected maintained/differential acquisition class')
        if kind is not None:need(k==kind,'exact maps call-site kind')
        identity=self.v(b,t,'fd last_read close_result bytes opened close_started closed')
        if a in self.maps_seen:need(self.maps_seen[a]==identity,'same retained physical acquisition bytes/descriptor')
        else:self.maps_seen[a]=identity
        if(a,e)in self.maps_seen:need(self.maps_seen[a,e]==rows,'same exact canonical view within its mutation epoch')
        else:self.maps_seen[a,e]=rows
        return a,h,e,k

    def current_data(self,b,data):
        t='li2_rseq_current_data';self.eq(b,t,version=1,attempted=1,complete=1,result=0,detail=0,phase_started=1,phase_ended=1)
        need(self.f(b,t,'data')==data,'whole actual mapping data from typed current observation')
        kind=self.i(b,t,'kind');v=self.f(b,t,'view');vt='li2_maps_current_view'
        if kind==1:
            self.eq(b,t,release_attempted=1,release_complete=1,acquire_result=0,release_result=0,fallback_started=0,fallback_complete=0)
            self.eq(v,vt,version=1,complete=1,result=0,detail=0,table=self.symbol('rows'))
            serial=self.i(v,vt,'serial');need(serial>0 and self.i(v,vt,'query_serial')>0,'actual consumed current ticket serial')
            self.eq(self.f(b,t,'ticket'),'li2_maps_current_ref',owner=self.symbol('maps_current'),serial=serial)
            first,end=self.v(v,vt,'stack_first stack_end');need(first>=PAGE and first%PAGE==end%PAGE==0 and first<end<1<<47,'actual guarded current stack interval')
            physical=self.f(v,vt,'physical');query=self.f(v,vt,'query');a,_,pe,pk=self.maps(physical);qa,qh,qe,qk=self.maps(query)
            need(pk in(0,1)and qh>0 and qk in((1,3)if self.differential else(1,4))and a==qa and pe<=qe,'truthful physical origin and separately observed current query')
            need(query==self.f(data,'li2_rseq_data','maps')and self.i(v,vt,'rows')==self.i(query,'li2_fetch_map_progress','rows'),'actual current mapping query belongs to data observation')
        else:
            need(kind==2,'only explicit unavailable current-view fallback')
            self.eq(b,t,release_attempted=0,release_complete=0,acquire_result=1,release_result=0,fallback_started=1,fallback_complete=1)
            zero(self.f(b,t,'ticket'),'unavailable view creates no ticket')
            if any(v):
                self.eq(v,vt,version=1,complete=0,result=1,detail=0,serial=0,query_serial=0,table=0,stack_first=0,stack_end=0,rows=0)
                self.maps(self.f(v,vt,'query'));self.maps(self.f(v,vt,'physical'))
            self.maps(self.f(data,'li2_rseq_data','maps'),0)

        o=self.f(data,'li2_rseq_data','maps');acquisition,handler,epoch,query_kind=self.maps(o)
        return dict(kind=kind,acquisition=acquisition,handler=handler,mutation_epoch=epoch,query_kind=query_kind,physical_kind=(self.i(self.f(self.f(v,vt,'physical'),'li2_fetch_map_progress','observation'),'li2_maps_observation','kind')if kind==1 else 0),ticket_serial=self.i(v,vt,'serial')if kind==1 else 0)

    def rseq_data(self,b):
        t='li2_rseq_data';self.eq(b,t,address=RSEQ,page=RSEQ,pid=self.pid,tid=self.pid,attempted=1,complete=1,error=0,detail=0,offset=0)
        need(self.i(b,t,'allocation')>0 and self.i(b,t,'generation')>0,'actual registered page allocation and generation')
        self.maps(self.f(b,t,'maps'));return self.v(b,t,'address page allocation generation offset pid tid')

    def pin(self,b,state,serial,heads,refs,terminal=False):
        t='li2_pg_rseq_progress';self.eq(b,t,active=int(not terminal),checking=0,first_error=0,unsafe_terminal=0,seed_complete=1,entry_complete=1,close_complete=int(terminal),first_detail=0,pid=self.pid,tid=self.pid,fs_result=0,gs_result=0,registration_epoch=1,address=RSEQ,page=RSEQ,length=32,signature=0x53053053,fs=self.app['machine'][1],gs=self.app['machine'][2],word_before=0,word_entry=0,word_after=0,cold_heads=heads,cold_stores=0,cold_stubs=0,fs_selector=0,gs_selector=0,session=self.symbol('selected_session'),cancel_started=0,cancel_complete=0,domain_bound=1,domain_count=len(refs))
        self.eq(self.f(b,t,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial);need(self.i(b,t,'raw_checks')>0,'actual positive independent zero-word RAW checks')
        need(self.f(b,t,'domain_ref')==b''.join(refs)+bytes((2-len(refs))*80),'whole actual shared rseq member references')
        rt='li2_rseq_state';self.eq(state,rt,initialized=1,registered=1,held=1,first_error=0,phase=3,first_detail=0,pid=self.pid,tid=self.pid,address=RSEQ,page=RSEQ,length=32,signature=0x53053053,epoch=1,fs_base=self.app['machine'][1],gs_base=self.app['machine'][2],fs_result=0,gs_result=0,tls_complete=1,registrations=1,unregistrations=0,kernel_errors=0,calls=1)
        need(self.f(state,rt,'data')==self.f(b,t,'before'),'whole original registered mapping receipt')
        identity=self.rseq_data(self.f(b,t,'before'));self.maps(self.f(self.f(b,t,'before'),'li2_rseq_data','maps'),0)
        for k,receipt in(('observed','current_observed'),('after','current_after')):
            d=self.f(b,t,k);c=self.f(b,t,receipt)
            if k=='after'and not terminal:zero(d,'no premature closing data');zero(c,'no premature closing current receipt');continue
            need(self.rseq_data(d)==identity,'exact unchanged registered page identity');self.current_data(c,d)
        return self.i(b,t,'raw_checks')

    def state_cells(self,state):return self.r.items(state,'pda_state','completion','pda_completion')

    def domain_checkpoint(self,b,baseline):
        t='pdao_domain_checkpoint';z=bytearray(baseline);fields=self.r.types['pda_state']['fields']
        for k in('directory','allocated','registered','next_id','dual_entries','dual_completed','initial_seal','initial','work','claimed'):
            f=fields[k];value=self.f(b,t,k);need(len(value)==f['bytes'],'whole domain checkpoint field');z[f['offset']:f['offset']+f['bytes']]=value
        self.scan(self.f(b,t,'cells'),3*self.r.types['pda_completion']['bytes'])
        out=bytes(z);self.r.walk(out,'pda_state');return out

    def ref(self,b,g,slot,index):
        t='li2_pgd_ref';self.eq(b,t,slot=slot,bank=index,generation=self.i(g,'li2_pg_generation','generation'),proof=self.i(g,'li2_pg_generation','proof'))
        need(slot in(0,1)and index in(0,1)and self.f(b,t,'layout')==self.bank_layouts[slot][index],'actual domain reference bank matches its fixed slot layout')
        need(self.f(b,t,'layout')==self.f(g,'li2_pg_generation','layout'),'whole actual domain reference layout')
        return self.i(b,t,'root')

    def domain_source(self,b,refs,serial,terminal,source):
        t='li2_pgd_source_progress';self.eq(b,t,count=len(refs),bound=1,opened=1,closed=int(terminal),released=int(terminal),first_error=0,first_detail=0)
        self.eq(self.f(b,t,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
        need(self.f(b,t,'ref')==b''.join(refs)+bytes((2-len(refs))*80),'whole source authority member set')
        for field,prot in(('open',5),('close',1)):
            rows=self.f(b,t,field);n=3*self.r.types['li2_private_code_query']['bytes']
            for i,ref in enumerate(refs):
                saved=self.geometry;self.geometry=self.layout(self.f(ref,'li2_pgd_ref','layout'))
                if field=='close'and not terminal:zero(rows[i*n:(i+1)*n],'no premature shared source revoke')
                else:self.query3(rows[i*n:(i+1)*n],prot)
                self.geometry=saved
            zero(rows[len(refs)*n:],'unused source member rows remain literal zero')
        need(self.f(b,t,'open')[:480]==self.f(source,'li2_pg_source_progress','opened')and self.f(b,t,'close')[:480]==self.f(source,'li2_pg_source_progress','closed'),'primary source and domain share the same actual query receipts')

    def completion(self,c,next_id,next_serial):
        t='pda_completion';cid,serial=self.v(c,t,'id serial');count=self.i(c,t,'count')
        need(0<cid<=next_id and 0<serial<=next_serial and count in(1,2),'bounded actual immutable completion identity')
        self.eq(c,t,complete=1);members=self.r.items(c,t,'member','pda_member_completion');refs=[];seen=[]
        pin=self.f(c,t,'rseq');self.eq(pin,'li2_pg_rseq_progress',active=0,checking=0,first_error=0,unsafe_terminal=0,seed_complete=1,entry_complete=1,close_complete=1,first_detail=0,cancel_started=0,cancel_complete=0,word_before=0,word_entry=0,word_after=0,domain_bound=1,domain_count=count)
        self.eq(self.f(pin,'li2_pg_rseq_progress','token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
        ids=[self.rseq_data(self.f(pin,'li2_pg_rseq_progress',k))for k in('before','observed','after')];need(ids[0]==ids[1]==ids[2],'completed shared registration mapping identity')
        for k,r in(('observed','current_observed'),('after','current_after')):self.current_data(self.f(pin,'li2_pg_rseq_progress',r),self.f(pin,'li2_pg_rseq_progress',k))
        source=self.f(c,t,'source');self.eq(source,'li2_pg_source_progress',phase=6,serial=serial,first_error=0,first_detail=0,aborted=0,release_started=1,release_complete=1,opened_extents=3,opened_pages=17,closed_extents=3,closed_pages=17,cancel_started=0,cancel_complete=0)
        saved_source=self.f(source,'li2_pg_source_progress','source');self.eq(saved_source,'li2_pg_sources',complete=1,reserved=0,serial=serial)
        self.maps(self.f(source,'li2_pg_source_progress','preparation'));self.maps(self.f(source,'li2_pg_source_progress','validation'))
        anchor=self.f(saved_source,'li2_pg_sources','anchor');self.progress(self.f(c,t,'fetch'),self.i(anchor,'li2_fetch_ref','sequence'),False)
        source_key=self.f(self.f(source,'li2_pg_source_progress','source'),'li2_pg_sources','key')
        for i,m in enumerate(members):
            if i>=count:zero(m,'whole unused completion member');continue
            mt='pda_member_completion';g=self.f(m,mt,'generation');v=self.f(m,mt,'identity');h=self.f(m,mt,'header');key=self.f(m,mt,'source');saved=self.geometry;self.geometry=self.layout(self.f(g,'li2_pg_generation','layout'))
            slot,bank=self.v(v,'li2_pgd_ref','slot bank');need(slot in(0,1)and bank in(0,1)and slot not in seen,'distinct actual joint completion member');seen.append(slot)
            root=self.ref(v,g,slot,bank);need(root==self.i(key,'li2_pg_source_key','entry'),'completion retains original member root');refs.append(v)
            if i==0:self.key_identity(source_key,key)
            # Pair identity excludes only separately authenticated root, never source bytes or stable backing identity.
            self.pair_key(source_key,key)
            gen=self.i(g,'li2_pg_generation','generation');self.eq(g,'li2_pg_generation',installed=1,complete=1,proof_complete=1,ready_generation=gen,linked=0,active_refs=0,domain_refs=0)
            for k in('member_refs','incoming','cleanup'):zero(self.f(g,'li2_pg_generation',k),'completed member has no live reference or failed cleanup')
            self.permission3(self.f(g,'li2_pg_generation','open'),5);self.permission3(self.f(g,'li2_pg_generation','close'),1)
            self.proof_query(self.f(m,mt,'proof'),self.i(g,'li2_pg_generation','proof'),1)
            self.eq(h,'pe_header',version=1,serial=self.i(g,'li2_pg_generation','build_serial'),generation=gen,registry=self.symbol('pe'),generated=self.geometry[0],spill=self.geometry[4],registered_epoch=self.i(pin,'li2_pg_rseq_progress','registration_epoch'),rseq_address=self.i(pin,'li2_pg_rseq_progress','address'),rseq_length=self.i(pin,'li2_pg_rseq_progress','length'),rseq_signature=self.i(pin,'li2_pg_rseq_progress','signature'))
            need(self.f(h,'pe_header','layout')==self.f(v,'li2_pgd_ref','layout'),'immutable header and completion layout')
            binding=self.image['persistent_binding'];need(self.f(h,'pe_header','archive')==bytes.fromhex(binding['archive']['sha256'])and self.f(h,'pe_header','policy')==bytes.fromhex(binding['policy_sha256']),'completed member actual archive/policy')
            transitions=self.r.items(g,'li2_pg_generation','slots','pg_slot_transition');self.slots_transition(transitions[2],False)
            cell=self.r.items(g,'li2_pg_generation','cell','pg_dispatch_cell_transition')[2];self.cell(cell,gen,serial,self.i(cell,'pg_dispatch_cell_transition','before'))
            self.geometry=saved
        self.domain_source(self.f(c,t,'domain_source'),refs,serial,True,source)
        need(self.f(pin,'li2_pg_rseq_progress','domain_ref')==b''.join(refs)+bytes((2-count)*80),'completion rseq retains exact shared member set')
        need(self.f(source,'li2_pg_source_progress','layout')==self.f(refs[0],'li2_pgd_ref','layout'),'completion primary source layout')
        self.query(self.f(c,t,'directory_closed'),self.h[40],1,pages=3)
        return count,serial

    def pair_key(self,a,b):
        at='li2_pg_source_key';aa=bytearray(a);field=self.r.types[at]['fields']['entry'];aa[field['offset']:field['offset']+8]=self.f(b,at,'entry');self.key_identity(bytes(aa),b)

    def domain_state(self,b,next_serial):
        t='pda_state';self.eq(b,t,directory=self.h[40],allocated=1,registered=1)
        self.query(self.f(b,t,'initial'),self.h[40],3,pages=3);self.permission(self.f(b,t,'initial_seal'),self.h[40],1,3)
        next_id=self.i(b,t,'next_id');masks=struct.unpack('<3I',self.f(b,t,'claimed'));seen=[]
        for i,c in enumerate(self.state_cells(b)):
            if not any(c):need(masks[i]==0,'unused completion cell has no claim mask');continue
            count,serial=self.completion(c,next_id,next_serial);cid=self.i(c,'pda_completion','id');need(cid not in seen and masks[i]<(1<<count),'unique immutable completion cell and bounded member claim bits');seen.append(cid)
        return masks

    def claim(self,slot,domain):
        t='pdao_slot';qv=self.f(slot,t,'claim');qt='li2_pgd_claim';self.eq(qv,qt,valid=1,reserved=0)
        cid,cell,member=self.v(qv,qt,'id cell member');need(0<cid<=self.i(domain,'pda_state','next_id')and cell<3 and member<2,'bounded actual member completion claim')
        c=self.state_cells(domain)[cell];count=self.i(c,'pda_completion','count');masks=struct.unpack('<3I',self.f(domain,'pda_state','claimed'))
        need(self.i(c,'pda_completion','id')==cid and member<count and not(masks[cell]&(1<<member)),'claim names a live unconsumed immutable completion member')
        m=self.r.items(c,'pda_completion','member','pda_member_completion')[member];ref=self.f(m,'pda_member_completion','identity');identity=self.f(slot,t,'identity');g=self.f(slot,t,'generation')
        need(self.i(ref,'li2_pgd_ref','slot')==self.i(identity,'li2_ptr_slot_ref','index')and self.i(ref,'li2_pgd_ref','generation')==self.i(identity,'li2_ptr_slot_ref','generation')and self.i(ref,'li2_pgd_ref','proof')==self.i(slot,t,'proof')and self.f(m,'pda_member_completion','generation')==g,'exact claimed retained generation and complete saved closure')
        self.eq(slot,t,last_completed=self.i(c,'pda_completion','serial'));zero(self.f(slot,t,'permit'),'old singleton permit is not joint authority')
        return c,m,cell,member
    def prior_completed(self,slot,counts):
        t='pdao_slot';g=self.f(slot,t,'generation');c,m,_,_=self.claim(slot,self.current_domain);gt='li2_pg_generation'
        generation=self.i(g,gt,'generation');serial=self.i(c,'pda_completion','serial');self.setup(slot)
        self.eq(g,gt,installed=1,complete=1,proof_complete=1,ready_generation=generation,plan_proofs=2,none_proofs=1,active_refs=0,linked=0,domain_refs=0,proof=self.proof,code_copied=69632,code_verified=69632,proof_zeroed=364544,proof_copied=362640,proof_verified=364544)
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
        h=self.f(m,'pda_member_completion','header');need(self.f(h,'pe_header','layout')==self.f(g,gt,'layout'),'whole saved completed header layout')


    def storage(self,b,counts,known,domain,active=()):
        self.current_domain=domain
        t='pdao_slots';selected=self.i(b,t,'selected_slot');need(selected in(0,1),'actual retained selected slot')
        self.eq(b,t,reserved=0);slots=self.r.items(b,t,'slots','pdao_slot');ranges=[];generations=[]
        need(self.f(b,t,'selection')==self.f(slots[selected],'pdao_slot','identity'),'selection is exact actual retained identity')
        previous=self.f(b,t,'previous_selection');self.eq(previous,'li2_ptr_slot_ref',reserved=0)
        need((not any(previous))or(self.i(previous,'li2_ptr_slot_ref','owner')==self.symbol('pe')and self.i(previous,'li2_ptr_slot_ref','index')in(0,1)and self.i(previous,'li2_ptr_slot_ref','generation')<=counts['next_generation']),'typed previous selection is observation only')
        for index,s in enumerate(slots):
            st='pdao_slot';self.eq(s,st,code_allocated=2,code_registered=2,proof_allocated=1,proof_registered=1)
            proof=self.i(s,st,'proof');need(proof%PAGE==0 and canonical(proof,364544),'whole actual retained proof allocation');ranges.append((proof,proof+364544))
            gen=self.checkpoint(s,index,known);generations.append(gen);g=self.f(s,st,'generation')
            for j,bank in enumerate(self.r.items(s,st,'banks','ped_bank')):
                need(self.f(bank,'ped_bank','layout')==self.bank_layouts[index][j],'fixed retained bank layout unchanged across every checkpoint')
                saved=getattr(self,'geometry',None);geometry=self.layout(self.f(bank,'ped_bank','layout'));self.geometry=geometry
                self.eq(bank,'ped_bank',generated=geometry[0],spill=geometry[4],allocated=1,registered=1)
                need((j or geometry[0]+77824<1<<31)and self.i(bank,'ped_bank','virgin')in(0,1),'actual low and ordinary bank geometry')
                prot=self.i(bank,'ped_bank','prot');need(prot in(1,3,5),'actual bank permission state')
                self.query3(self.f(bank,'ped_bank','initial'),3);self.query(self.f(bank,'ped_bank','initial_spill'),geometry[4],3);self.query(self.f(bank,'ped_bank','initial_slots'),geometry[3],3)
                ranges.append((geometry[0],geometry[0]+77824));self.geometry=saved
            installed=self.i(g,'li2_pg_generation','installed');need(installed in(0,1),'literal installed retained state')
            if installed:
                if index not in active:self.prior_completed(s,counts)
                else:zero(self.f(s,st,'claim'),'active member consumed its completion claim');zero(self.f(s,st,'permit'),'old singleton permit is not active-domain authority')
                n=self.i(s,st,'registry_count');need(0<n<=len(self.ranges),'actual retained registry population')
                rows=self.f(s,st,'registry');need(rows[:n*16]==b''.join(struct.pack('<QQ',*x)for x in self.ranges[:n])and not any(rows[n*16:]),'retained complete registry prefix and zero tail')
            else:
                need(index not in active,'active slot cannot be empty');self.eq(s,st,last_completed=0,registry_count=0);zero(self.f(s,st,'registry'),'empty slot has no publication registry');zero(self.f(s,st,'permit'),'empty slot has no completion permit');zero(self.f(s,st,'claim'),'empty slot has no joint claim')
                self.setup(s);self.eq(g,'li2_pg_generation',generation=0,ready_generation=0,complete=0,proof_complete=0,build_serial=0,generated=self.geometry[0],spill=self.geometry[4])
                self.proof_query(self.f(g,'li2_pg_generation','proof_writable'),proof,3)
                expect=bytearray(len(g))
                for k in('generated','proof','spill','layout','proof_writable'):
                    f=self.r.types['li2_pg_generation']['fields'][k];expect[f['offset']:f['offset']+f['bytes']]=self.f(g,'li2_pg_generation',k)
                need(g==bytes(expect),'whole actual initialized virgin retained generation')
        need(not generations[0]or not generations[1]or generations[0]!=generations[1],'distinct actual retained generations')
        ranges.append((self.h[40],self.h[40]+12288))
        owner=(self.symbol('pe'),self.symbol('pe')+self.h[3])
        need(all(z<=c or d<=a for i,(a,z)in enumerate(ranges)for c,d in ranges[i+1:]+[owner]),'all six retained allocations and protected owner disjoint')
        for interval in ranges:need(self.ranges.count(interval)==1,'whole actual retained allocation protected')
        return slots,selected

    def choose(self,slots,entry,domain):
        matches=[];empty=[]
        for i,s in enumerate(slots):
            g=self.f(s,'pdao_slot','generation')
            if not self.i(g,'li2_pg_generation','installed'):empty.append(i)
            else:
                _,m,_,_=self.claim(s,domain)
                if self.i(self.f(m,'pda_member_completion','identity'),'li2_pgd_ref','root')==entry:matches.append(i)
        need(len(matches)<=1,'unique exact-root retained candidate')
        return matches[0]if matches else empty[0]if empty else min(range(2),key=lambda i:(self.i(slots[i],'pdao_slot','last_completed'),i))

    def work(self,w,rows,count,serial,terminal=False):
        t='pda_work';v=self.f(w,t,'view');vt='li2_pgd_view';self.eq(w,t,bound=1,completion=int(terminal),aborting=0,recovery_member=2)
        self.eq(v,vt,count=count,reserved=0,directory=self.h[40]);self.eq(self.f(v,vt,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
        members=self.r.items(v,vt,'member','li2_pgd_member');refs=[];pairs=[]
        for i,m in enumerate(members):
            if i>=count:zero(m,'whole unused active-domain member');continue
            mt='li2_pgd_member';ref=self.f(m,mt,'identity');slot,bank=self.v(ref,'li2_pgd_ref','slot bank');need(slot in(0,1)and bank in(0,1),'actual member slot/bank')
            s=rows[slot];g=self.f(s,'pdao_slot','generation');root=self.ref(ref,g,slot,bank);refs.append(ref)
            proof=self.i(s,'pdao_slot','proof');self.eq(m,mt,plan=proof+self.r.types['pe_payload']['fields']['plan']['offset'],key=proof+self.r.types['pe_payload']['fields']['source']['offset'])
            ci=next((j for j,c in enumerate(self.certificates)if self.i(c,'pdao_certificate','slot')==slot and self.i(c,'pdao_certificate','generation')==self.i(g,'li2_pg_generation','generation')),None)
            need(ci is not None and root==self.i(self.certificates[ci],'pdao_certificate','entry'),'actual active member joins its complete literal certificate')
            pairs.append((slot,self.i(g,'li2_pg_generation','generation'),self.i(g,'li2_pg_generation','build_serial')))
        need(len({x[0]for x in pairs})==count and len({x[1]for x in pairs})==count,'distinct actual domain generations')
        self.eq(w,t,primary=pairs[0][0],primary_bank=self.i(refs[0],'li2_pgd_ref','bank'),peer=2 if count==1 else pairs[1][0],exit_member=(count-1)if terminal else 2)
        receipt=self.i(w,t,'receipt');need(receipt<3,'bounded selected immutable completion cell')
        self.permission(self.f(w,t,'directory_write'),self.h[40],3,3);self.permission(self.f(w,t,'directory_seal'),self.h[40],1,3)
        if terminal:self.query(self.f(w,t,'directory_closed'),self.h[40],1,pages=3)
        else:zero(self.f(w,t,'directory_closed'),'no premature directory terminal query')
        d=self.f(w,t,'directory');dt='li2_jd_domain_directory';total=sum(2 if self.i(r,'li2_pgd_ref','root')==self.head else 5 for r in refs)
        self.eq(d,dt,version=1,count=total,serial=serial,reserved=0);expected=[]
        for r in refs:
            root=self.i(r,'li2_pgd_ref','root');offsets=(0x200,0x204)if root==self.head else(0x400,0x404,0x408,0x40d,0x40a);base=q(self.f(r,'li2_pgd_ref','layout'))[0]
            for j,off in enumerate(offsets):expected.append(struct.pack('<3Q2I',self.page+off,base+512*j,self.i(r,'li2_pgd_ref','generation'),self.i(r,'li2_pgd_ref','slot'),j))
        need(self.f(d,dt,'row')==b''.join(expected)+bytes((256-total)*32),'whole exact directory rows and unused tail')
        proofrows=self.r.items(w,t,'proof_exit','pg_proof_query')
        for i,p in enumerate(proofrows):
            if i<count and terminal:self.proof_query(p,self.i(refs[i],'li2_pgd_ref','proof'),1)
            else:zero(p,'no unused or premature member proof exit')
        peer=self.f(w,t,'peer_claim');pt='pda_claim_observation'
        if count==1:zero(peer,'cold activation has no peer claim')
        else:
            saved=self.geometry;self.geometry=self.layout(self.f(refs[1],'li2_pgd_ref','layout'));self.query3(self.f(peer,pt,'code'),1);self.query(self.f(peer,pt,'spill'),self.geometry[4],3);self.query(self.f(peer,pt,'slots'),self.geometry[3],1);self.proof_query(self.f(peer,pt,'proof'),self.i(refs[1],'li2_pgd_ref','proof'),1);self.geometry=saved
        return refs,pairs,receipt

    def member_transition(self,entry,end,serial,cold):
        t='pdao_slot';gt='li2_pg_generation';g=self.f(entry,t,'generation');z=self.f(end,t,'generation');self.setup(entry);gen=self.i(g,gt,'generation');build=self.i(g,gt,'build_serial')
        self.eq(g,gt,installed=1,complete=1,proof_complete=1,ready_generation=gen,plan_proofs=2,none_proofs=1,generated=self.generated,proof=self.proof,spill=self.spill,active_refs=1,linked=1,domain_refs=1,code_copied=69632,code_verified=69632,proof_zeroed=364544,proof_copied=362640,proof_verified=364544)
        need(q(self.f(g,gt,'member_generation'))==(2*gen,2*gen+1)and q(self.f(g,gt,'member_refs'))==(1,1),'exact typed internal member refs');zero(self.f(g,gt,'incoming'),'zero graph links have no incoming refs')
        self.query3(self.f(g,gt,'code_writable'),3);self.proof_query(self.f(g,gt,'proof_writable'),self.proof,3);self.query(self.f(g,gt,'spill_query'),self.spill,3);zero(self.f(g,gt,'slot_query'),'unused aggregate slot query')
        self.permission3(self.f(g,gt,'code_sealed'),1);self.proof_permission(self.f(g,gt,'proof_sealed'),self.proof,1);self.permission3(self.f(g,gt,'open'),5)
        zero(self.f(g,gt,'close'),'no premature member close');zero(self.f(g,gt,'cleanup'),'no failed member cleanup')
        ts=self.r.items(g,gt,'slots','pg_slot_transition');zs=self.r.items(z,gt,'slots','pg_slot_transition');self.slots_transition(ts[0],False);self.slots_transition(ts[1],True);zero(ts[2],'no premature member slot reset')
        self.r.change(g,z,gt,values=dict(active_refs=0,linked=0,domain_refs=0),observed=('member_refs','incoming','close','slots','cell'))
        for k in('incoming','member_refs'):zero(self.f(z,gt,k),'all internal generation references drained')
        self.permission3(self.f(z,gt,'close'),1);need(zs[:2]==ts[:2],'whole initial and link receipts retained');self.slots_transition(zs[2],False)
        cs=self.r.items(g,gt,'cell','pg_dispatch_cell_transition');cz=self.r.items(z,gt,'cell','pg_dispatch_cell_transition')
        self.cell(cs[0],gen,build,0);self.cell(cs[1],gen,serial,0);zero(cs[2],'no premature dispatch-cell reset');need(cz[:2]==cs[:2],'whole initial and entry cell resets retained');self.cell(cz[2],gen,serial,self.i(cz[2],'pg_dispatch_cell_transition','before'))
        self.r.change(entry,end,t,values=dict(last_completed=serial),observed=('generation','claim','banks'))
        eb=self.r.items(entry,t,'banks','ped_bank');zb=self.r.items(end,t,'banks','ped_bank');idx=[i for i,x in enumerate(eb)if self.f(x,'ped_bank','layout')==self.f(g,gt,'layout')];need(len(idx)==1,'actual selected member bank');i=idx[0]
        self.eq(eb[i],'ped_bank',virgin=0,prot=5);self.r.change(eb[i],zb[i],'ped_bank',values=dict(prot=1));need(eb[1-i]==zb[1-i],'unused member bank remains byte-exact')
        return i
    def epoch(self,b,index,baseline,previous=None):
        t='pdao_epoch';st='pdao_stage';gt='li2_pg_generation';pt='li2_pg_progress';it='pdao_epoch_info';warm=index==2;count=2 if warm else 1
        entry=self.page+(0x400 if index==1 else 0x200);ci=int(index==1);heads=5 if index==1 else 2;exitpc=self.page+(0x204 if index==0 else 0x40d)
        h=q(self.f(b,t,'h'));need(h[:3]==(1,index,entry)and h[3]>0 and h[4:11]==(1,1,h[3],0,1,1,0)and h[11]==h[3]+1 and h[12:15]==(0,0,1)and h[24]in(0,1)and not any(h[25:]),'actual accepted domain entry/exit with zero interior signal')
        need(h[15]in(0,1)and h[16]==self.symbol('selected_session')and h[17]>0 and h[18]<U64 and h[19:24]==(h[15],1,0,0,1),'actual selected preclose domain predecessor')
        initial=self.f(b,t,'initial_registry');need(initial==self.f(b,t,'terminal_registry'),'whole domain registry unchanged during epoch');self.ranges,_=self.registry_prefix(self.f(self.b,'pdao_wire','startup_registry'),initial)
        prior=self.f(b,t,'prior_counts');pc=self.counts(prior);prior_slots=self.f(b,t,'prior');prior_domain=self.domain_checkpoint(self.f(b,t,'prior_domain'),baseline)
        need(prior_domain==baseline,'complete prior domain unchanged between focal activations');self.domain_state(prior_domain,pc['next_serial'])
        need(pc['entries']==pc['completed']and pc['publications']==pc['next_generation']and pc['unexpected']==0,'all preceding domain epochs completed before focal entry')
        prior_rows,_=self.storage(prior_slots,pc,set(range(min(index,2))),prior_domain);chosen=self.choose(prior_rows,entry,prior_domain);need(chosen==h[24],'actual root/empty/oldest-completed selection')
        resident=prior_rows[chosen];rg=self.f(resident,'pdao_slot','generation');installed=self.i(rg,gt,'installed')
        entered=self.f(b,t,'entered');end=self.f(b,t,'terminal');p=self.f(entered,st,'progress');ep=self.f(end,st,'progress');serial=self.i(p,pt,'serial');gen=self.i(p,pt,'generation')
        need(serial==pc['next_serial']+1 and 0<gen<U64//2,'actual monotonic domain attempt/member generation')
        inc=dict(next_serial=1,offers=1,entries=1,permit_claims=2 if warm else installed)
        if warm:inc.update(hits=1)
        else:inc.update(next_generation=1,publications=1,cold_attempts=1,retirements=installed)
        self.delta(prior,self.f(entered,st,'counts'),**inc);self.delta(self.f(entered,st,'counts'),self.f(end,st,'counts'),completed=1)
        ed=self.domain_checkpoint(self.f(entered,st,'domain'),baseline);zd=self.f(b,t,'terminal_domain');need(self.domain_checkpoint(self.f(end,st,'domain'),zd)==zd,'whole terminal domain checkpoint and literal state equality')
        self.domain_state(ed,serial);self.domain_state(zd,serial)
        self.r.change(prior_domain,ed,'pda_state',values=dict(dual_entries=self.i(prior_domain,'pda_state','dual_entries')+int(warm)),observed=('work','claimed'))
        eslots=self.f(entered,st,'slots');zslots=self.f(end,st,'slots');active=(chosen,1-chosen)if warm else(chosen,)
        erows,selected=self.storage(eslots,self.counts(self.f(entered,st,'counts')),set(range(2 if index else 1)),ed,active)
        zrows,zselected=self.storage(zslots,self.counts(self.f(end,st,'counts')),set(range(2 if index else 1)),zd)
        need(selected==zselected==chosen and self.f(eslots,'pdao_slots','previous_selection')==self.f(prior_slots,'pdao_slots','selection')and self.f(zslots,'pdao_slots','previous_selection')==self.f(eslots,'pdao_slots','previous_selection'),'actual previous and selected typed slot identities')
        if not warm:need(prior_rows[1-chosen]==erows[1-chosen]==zrows[1-chosen],'inactive retained slot unchanged through cold publication')
        actual=erows[chosen];terminal=zrows[chosen];self.setup(actual);g=self.f(actual,'pdao_slot','generation');eg=self.f(terminal,'pdao_slot','generation');buildserial=self.i(g,gt,'build_serial')
        payload=self.certificate(ci,actual,entry,buildserial,gen);key=self.f(payload,'pe_payload','source');ph=self.f(payload,'pe_payload','header')
        need(gen==(self.i(rg,gt,'generation')if warm else pc['next_generation']+1)and buildserial==(self.i(rg,gt,'build_serial')if warm else serial),'exact cold publication or retained primary generation')
        need(not warm or installed==1,'shared entry requires actual prior completed A')
        ew=self.f(ed,'pda_state','work');zw=self.f(zd,'pda_state','work');refs,members,cell=self.work(ew,erows,count,serial);zrefs,zmem,zcell=self.work(zw,zrows,count,serial,True)
        need(refs==zrefs and members==zmem and cell==zcell,'whole stable shared member set through closure')
        self.r.change(ew,zw,'pda_work',values=dict(exit_member=count-1,completion=1),observed=('proof_exit','directory_closed'))
        # Claim consumption precedes choosing the first fully reusable completion cell.
        masks=list(struct.unpack('<3I',self.f(prior_domain,'pda_state','claimed')))
        for slot in active:
            if warm or(slot==chosen and installed):
                _,_,prior_cell,member=self.claim(prior_rows[slot],prior_domain);masks[prior_cell]|=1<<member
        need(struct.unpack('<3I',self.f(ed,'pda_state','claimed'))==tuple(masks),'exact member claim bits consumed before domain entry')
        cells=self.state_cells(ed);available=[i for i,c in enumerate(cells)if not any(c)or masks[i]==(1<<self.i(c,'pda_completion','count'))-1]
        need(available and cell==available[0],'first complete unclaimed cell is the only reused receipt')
        nextid=self.i(prior_domain,'pda_state','next_id');need(nextid<U64,'nonwrapping immutable completion ID');masks[cell]=0
        self.r.change(ed,zd,'pda_state',values=dict(next_id=nextid+1,dual_completed=self.i(ed,'pda_state','dual_completed')+int(warm)),observed=('work','completion','claimed'))
        need(struct.unpack('<3I',self.f(zd,'pda_state','claimed'))==tuple(masks),'one new completion resets only its own claim mask')
        zcells=self.state_cells(zd)
        for i in range(3):
            if i!=cell:need(zcells[i]==cells[i],'every still-live completion cell remains byte-exact')
        c=zcells[cell];self.eq(c,'pda_completion',id=nextid+1,serial=serial,count=count,complete=1)
        self.eq(p,pt,serial=serial,registration_epoch=1,publication=1,generation=gen,phase=9,first_error=0,source_count=2,opened_pages=17*count,closed_pages=0,anchor_released=0,registration_rechecked=0,completion_permit=0,first_detail=0,generated=self.generated,proof=self.proof,table=self.table,spill=self.spill)
        need(q(self.f(p,pt,'source'))==(self.page,self.page+PAGE)and self.layout(self.f(p,pt,'layout'))==self.geometry,'actual shared progress retains primary source/layout')
        self.r.change(p,ep,pt,values=dict(phase=13,closed_pages=17*count,anchor_released=1,registration_rechecked=1,completion_permit=1))
        for stage in(entered,end):self.eq(stage,st,busy=1,active=1,failing=0,resuming=0,pending=1);need(0<self.i(stage,st,'route')<32,'actual generated domain route')
        need(self.f(entered,st,'route')==self.f(end,st,'route'),'unchanged active route through shared close')
        for i,slot in enumerate(active):
            self.member_transition(erows[slot],zrows[slot],serial,not warm)
            claim,cm,claim_cell,claim_member=self.claim(zrows[slot],zd)
            need(claim==c and claim_cell==cell and claim_member==i and self.f(cm,'pda_member_completion','identity')==refs[i],'each member receives its exact joint completion claim')
            if warm:
                before=self.f(prior_rows[slot],'pdao_slot','generation');current=self.f(erows[slot],'pdao_slot','generation')
                self.r.change(before,current,gt,values=dict(active_refs=1,linked=1,domain_refs=1),observed=('member_refs','open','close','slots','cell'))
                self.r.change(prior_rows[slot],erows[slot],'pdao_slot',observed=('generation','claim','banks'))
        self.setup(actual)
        info=self.f(b,t,'info');bank=self.i(refs[0],'li2_pgd_ref','bank');self.eq(info,it,selected_bank=bank,warm=int(warm),initialized=1,registered=1,code_allocated=2,proof_allocated=1,code_registered=2,proof_registered=1,close_started=1,close_complete=1,prepare_started=1,prepare_complete=1,build_started=int(not warm),build_returned=int(not warm),redirected=1,exit_seen=1,exit_index=0,recovery_started=1,recovery_complete=1,guest_data_fault=0,cleanup_started=0,cleanup_complete=0,consumed=1,plan_proofs=0 if warm else 2,none_proofs=0 if warm else 1,code_allocation=self.h_alloc,proof_allocation=self.h_proof_alloc,build_result=0,recovery_result=0,release_result=0,gpr_written=1 if index==0 else 11,flags_written=0x8d5,ticket=self.symbol('span_transfer'),registry_count=len(self.ranges))
        self.eq(self.f(info,it,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
        need(self.f(info,it,'session')==self.f(self.b,'pdao_wire','session')and self.f(info,it,'registry')==self.f(initial,'pdao_registry','ranges')and self.f(info,it,'banks')==self.f(terminal,'pdao_slot','banks'),'whole actual domain session/registry/banks')
        if installed:
            save=self.geometry;self.geometry=self.layout(self.f(rg,gt,'layout'));self.query3(self.f(info,it,'claim_code'),1);self.proof_query(self.f(info,it,'claim_proof'),self.proof,1);self.query(self.f(info,it,'claim_spill'),self.geometry[4],3);self.query(self.f(info,it,'claim_slots'),self.geometry[3],1);self.geometry=save
        else:
            for k in('claim_code','claim_proof','claim_spill','claim_slots'):zero(self.f(info,it,k),'no invented virgin claim')
        if warm:
            for k in('bank_before','proof_before','reopen_code','reopen_proof'):zero(self.f(info,it,k),'warm never rebuilds immutable proof/code')
        else:
            rows=self.r.items(info,it,'bank_before','li2_private_code_query');prot=self.i(rows[0],'li2_private_code_query','actual_prot');need(prot in(1,3),'cold target bank is closed or virgin');self.query3(self.f(info,it,'bank_before'),prot);self.proof_query(self.f(info,it,'proof_before'),self.proof,1 if installed else 3);self.permission3(self.f(info,it,'reopen_code'),3);self.proof_permission(self.f(info,it,'reopen_proof'),self.proof,3)
            for actual_query,permission in zip(self.r.items(g,gt,'code_writable','li2_private_code_query'),self.r.items(info,it,'reopen_code','le_permission'),strict=True):need(actual_query==self.f(permission,'le_permission','query'),'whole code reopen publication join')
            need(self.f(g,gt,'proof_writable')==self.f(self.f(info,it,'reopen_proof'),'pg_proof_permission','query'),'whole proof reopen publication join')
        before=self.frame(self.f(b,t,'before'));ingress=self.normalized(self.f(b,t,'ingress'),before);returned=self.frame(self.f(b,t,'returned'));after=self.frame(self.f(b,t,'after'));flags=before['greg'][17]
        self.eq(info,it,flags=flags);self.trace(ingress,entry,flags|TF);self.trace(before,entry,flags);self.same_event(ingress,before,flags)
        want=list(before['greg']);want[16]=self.generated;need(returned['greg']==tuple(want)and returned['fp']==before['fp']and returned['si']==before['si']and(returned['fs'],returned['gs'])==tuple(self.app['machine'][1:3]),'whole domain redirect changes only original RIP')
        uc=bytearray(before['uc']);struct.pack_into('<Q',uc,40+16*8,self.generated);need(returned['uc']==bytes(uc),'whole returned UC except actual redirect')
        self.nx(after,exitpc);need(after['fp']==before['fp']and after['fp_bytes']==before['fp_bytes']and after['mask']==MASK and(after['fs'],after['gs'])==tuple(self.app['machine'][1:3]),'all domain FP/AF/mask/TLS preserved')
        projection=self.f(b,t,'predecessor');self.eq(projection,'pdao_predecessor',complete=1,unexpected_compared=self.r.types['li2_step_frame']['bytes'],unexpected_nonzero=0)
        slot=self.f(projection,'pdao_predecessor','closed')+bytes(self.r.types['li2_step_frame']['bytes']);self.r.walk(slot,'li2_tf_chain_slot')
        prefix=self.f(projection,'pdao_predecessor','before_prefix');wanted=bytearray(prefix);sf=self.r.types['li2_tf_chain_slot']['fields'];of=self.r.types['li2_tf_owner']['fields'];tf=self.r.types['li2_step_owner']['fields'];struct.pack_into('<I',wanted,sf['phase']['offset'],5);at=sf['owner']['offset']+of['step']['offset']
        for k,v in(('phase',5),('trace_seen',1),('revoke_sync_started',1)):struct.pack_into('<I',wanted,at+tf[k]['offset'],v)
        need(bytes(wanted)==slot[:len(prefix)],'whole actual predecessor prefix close transition')
        need(self.i(slot,'li2_tf_chain_slot','index')==h[15]and self.i(slot,'li2_tf_chain_slot','event_id')<h[17],'actual predecessor older generation/event')
        predecessor_pc=self.page+(0x1fe if index==0 else 0x204 if index==1 else 0x40d);predecessor,_=self.predecessor(slot,predecessor_pc,ingress);self.eq(slot,'li2_tf_chain_slot',origin=1)
        ref=self.f(info,it,'ref');seq=self.i(ref,'li2_fetch_ref','sequence');tr=self.f(entered,st,'transfer');self.transfer(tr,slot,ingress,before,ref)
        need(tr==self.f(end,st,'transfer')and self.i(tr,'li2_span_transfer_progress','event')==h[17]and self.i(tr,'li2_span_transfer_progress','serial')==self.i(p,pt,'transfer_serial'),'whole actual consumed domain transfer')
        es=self.f(entered,st,'source');zs=self.f(end,st,'source');self.source(es,serial,entry,key,ref);self.source(zs,serial,entry,key,ref,terminal=True);need(self.f(es,'li2_pg_source_progress','source')==self.f(zs,'li2_pg_source_progress','source'),'one complete source anchor held through all internal transfers')
        self.domain_source(self.f(entered,st,'domain_source'),refs,serial,False,es);self.domain_source(self.f(end,st,'domain_source'),refs,serial,True,zs)
        er=self.f(entered,st,'rseq');zr=self.f(end,st,'rseq');estate=self.f(entered,st,'state');zstate=self.f(end,st,'state');a=self.pin(er,estate,serial,0 if warm else heads,refs);z=self.pin(zr,zstate,serial,0 if warm else heads,refs,terminal=True);need(z>a and estate==zstate,'actual zero-word pin and full registration state unchanged throughout shared lifetime')
        lastpc=self.page+(0x204 if index==0 else 0x40a if index==1 else 0x40d);code,length=(282,3)if index==1 else(765,2)
        self.eq(estate,'li2_rseq_state',last_first=0,last_end=0,last_pc=lastpc,last_code=code,last_policy=1);self.eq(self.f(estate,'li2_rseq_state','last_footprint'),'li2_write_footprint',pc=lastpc,next_pc=lastpc+length,first=0,end=0,abi_version=1,policy=1,code=code,length=length)
        self.progress(self.f(entered,st,'fetch'),seq,True);self.progress(self.f(end,st,'fetch'),seq,False);need(self.f(info,it,'final_fetch')==self.f(end,st,'fetch'),'whole actual released shared fetch')
        for k,actual_value in(('source',zs),('domain_source',self.f(end,st,'domain_source')),('rseq',zr),('fetch',self.f(end,st,'fetch'))):need(self.f(c,'pda_completion',k)==actual_value,'joint completion retains whole actual '+k)
        lives=self.r.items(info,it,'live','li2_link_rseq_live')
        for x in lives[:2]:self.live_rseq(x,estate,before)
        self.live_rseq(lives[2],zstate,after);self.proof_query(self.f(info,it,'proof_exit'),self.proof,1)
        for k in('code_exit','recovered','recovery_scratch'):zero(self.f(info,it,k),'normal domain exit invents no unexpected recovery')
        bm=self.memory(self.f(b,t,'before_memory'),False);am=self.memory(self.f(b,t,'after_memory'),False);need(bm==am==dict(data=self.app['data'],stack=self.app['stack']),'whole actual guest stack/data unchanged')
        # Directory pages are sealed exact bytes at entry and drain, including all padding.
        directory=self.f(ew,'pda_work','directory')+bytes(12288-self.r.types['li2_jd_domain_directory']['bytes']);need(self.f(b,t,'initial_directory')==self.f(b,t,'terminal_directory')==directory,'whole actual immutable directory throughout shared lifetime')
        for k in('initial_slots','terminal_slots'):zero(self.f(b,t,k),'all actual zero-link slot pages')
        initial_spill=self.f(b,t,'initial_spill');terminal_spill=self.f(b,t,'terminal_spill')
        for i,member in enumerate(members):
            init=initial_spill[i*PAGE:(i+1)*PAGE];final=terminal_spill[i*PAGE:(i+1)*PAGE];zero(init[32:],'all initial cells and spill tails zero');zero(final[32:],'all final cells and spill tails zero')
            slotindex=member[0];is_a=self.i(refs[i],'li2_pgd_ref','root')==self.head
            regs=[after['greg'][GREG[j]]for j in range(16)]
            if warm and is_a:regs[0]-=2;regs[1]=1;regs[3]=self.head
            scratch=(0,1,3,5)if is_a else(0,1,2,5);need(final[:32]==struct.pack('<4Q',*(regs[j]for j in scratch)),'whole actual final initialized scratch for its owning certificate')
            gend=self.f(zrows[slotindex],'pdao_slot','generation');lastcell=self.r.items(gend,gt,'cell','pg_dispatch_cell_transition')[2];target=(q(self.f(refs[1-i],'li2_pgd_ref','layout'))[0]if warm else 0)
            need(self.i(lastcell,'pg_dispatch_cell_transition','before')==target,'actual final reset binds its last committed directory hit')
            if warm:
                old_epoch=self.epochs[0 if is_a else 1];need(init==self.f(old_epoch,t,'terminal_spill')[:PAGE],'warm actual spill page equals prior completed owning certificate')
        zero(initial_spill[count*PAGE:],'unused initial spill member');zero(terminal_spill[count*PAGE:],'unused terminal spill member')
        mapping=[dict(epoch=index,point=point,**self.current_data(self.f(pin,'li2_pg_rseq_progress',receipt),self.f(pin,'li2_pg_rseq_progress',field)))for point,pin,receipt,field in(('begin',er,'current_observed','observed'),('close',zr,'current_after','after'))]
        return dict(rseq_mapping=mapping,kind='domain'if warm else'cold',mode=0,slot=chosen,generation=gen,build_serial=buildserial,prior_generation_installed=installed,begin=h[3],event=h[17],terminal_ordinal=h[11],ingress=ingress,before=before,returned=returned,logical=after,after=after,predecessor_before=predecessor,before_memory=bm,after_memory=am,completed=1,closed_pages=17*count,domain_members=count,anchor_released=1,permit=1,interior_signals=0,members=members,shared_lifetime=1,completion_id=nextid+1,claim_members=tuple(range(count)),joint_complete=1,slots_raw=zslots,counts_raw=self.f(end,st,'counts'),serial=serial,closed_slot=slot,dispatch_pc=exitpc,domain_raw=zd)

    def next_trace(self,b,last,epoch):
        t='pdao_next';slot=self.f(b,t,'closed');st='li2_tf_chain_slot'
        self.eq(b,t,expected_ordinal=last['terminal_ordinal']+1,raw_ordinal=last['terminal_ordinal']+1,capture_result=0,ingress_complete=1,closed_complete=1,tls_complete=1)
        index=self.i(b,t,'slot_index');event=self.i(b,t,'event_id');need(index in(0,1)and self.i(slot,st,'index')==index and event>self.i(slot,st,'event_id')>0,'actual next TRACE chain/index/event and closed predecessor')
        self.eq(slot,st,origin=1);frame=self.frame(self.f(b,t,'frame'));flags=(last['logical']['greg'][17]&~RF)|TF;self.trace(frame,self.app['expected_exit_pc'],flags)
        need(frame['greg'][22]==self.page+0x40d and(frame['fs'],frame['gs'])==tuple(self.app['machine'][1:3]),'actual next TRACE retains ordinary JMP CR2 and post-close TLS')
        before,ref=self.predecessor(slot,self.page+0x40d,frame);owner=self.f(slot,st,'owner');step=self.f(owner,'li2_tf_owner','step');self.step_frame(self.f(step,'li2_step_owner','before'),last['logical'])
        need(before['greg']==last['logical']['greg']and before['fp']==last['logical']['fp'],'ordinary original JMP begins at actual retained exit NX frame')
        fetch=self.f(self.f(epoch,'pdao_epoch','terminal'),'pdao_stage','fetch');need(self.i(ref,'li2_fetch_ref','sequence')>self.i(fetch,'li2_fetch_progress','sequence'),'ordinary JMP borrows after actual retained source release')
        last['next_trace']=frame;last['next_trace_ordinal']=self.i(b,t,'raw_ordinal')

    def finish(self,status):
        h=self.h;t='pdao_wire';r=self.r
        need(type(status)is int and status==0 and self.app['mode']==0,'actual successful loop-only process and mode')
        need(h[:9]==(0x344f41445049324c,4,4161664,r.layout['registrations']['pe']['bytes'],362640,364544,69632,968,128),'actual distinct group record version and complete extents')
        need(canonical(self.bias)and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(n)for n in('li2_raw6','li2_gateway_start','li2_gateway_end'))and h[10]<=h[9]<h[11],'actual emitted gateway identity')
        need(h[12]%PAGE==0 and h[13]==524288 and h[14:16]==(1,0)and h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,0),'actual altstack and FD3/profile')
        need(h[20:26]==tuple(self.symbol(n)for n in('pe','pdao_wire','pg_source','pg_rseq','selected_chain','span_progress')),'actual protected group addresses')
        storage=r.layout['retained_storage'];size=r.types['li2_ptr_slot']['bytes'];prefix=(2*r.types['li2_pg_progress']['bytes']+9*8+18*8+3*4+7)&-8
        selected=prefix+2*size;selection=(selected+4+7)&-8
        need({k:v for k,v in storage.items()if k!='domain'}==dict(retained=dict(offset=prefix,bytes=2*size),selected_slot=dict(offset=selected,bytes=4),selection=dict(offset=selection,bytes=24),previous_selection=dict(offset=selection+24,bytes=24)),'actual owner retained-array fields match independent source prefix')
        need(storage['domain']['bytes']==161896 and storage['domain']['offset']+161896<=h[3]and h[33]==self.symbol('pe')+storage['domain']['offset']and h[34]==self.symbol('pg_domain_source'),'actual protected domain field and separate shared source state')
        need(h[26:31]==(self.symbol('pe')+prefix,self.symbol('pe')+prefix+size,2,size,24)and prefix+2*size<=h[3],'actual fixed retained-slot addresses/extent')
        need(self.head==self.page+0x200 and self.page+8192<1<<31 and h[31:33]==(self.head,self.page+0x400)and h[35]==3 and h[36]>=1 and h[37]>=3 and h[38]==0 and h[39]==self.app['expected_exit_pc']and canonical(h[40],12288)and h[40]%PAGE==0 and h[41:47]==(161896,50224,10808,12288,3,0)and h[47:53]==(1,0,0,0,h[16],0)and not any(h[53:]),'exact three shared-domain epochs and successful complete record')
        raw=q(self.f(self.b,t,'raw_ingress'));need(sum(raw[1:])==raw[0]>0,'whole actual signal population')
        for k in('sink_initial','sink_terminal'):
            st=self.f(self.b,t,k);d=self.stat(st);need(d['mode']&0xffff==0x8180 and d['size']==0,'actual empty regular0600 sink');self.eq(st,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(self.f(self.b,t,'sink_initial'),self.f(self.b,t,'sink_terminal'),'stat',observed=('st_atim','st_mtim','st_ctim'))
        footer=q(r.data[-64:]);need(footer[:4]==(0x344641445049324c,4,len(self.b),len(self.b))and 1<=footer[4]<=64 and 0<footer[5]<=len(self.b)and footer[6:]==(0,0),'complete actual group output footer')
        if footer[4]==1:need(footer[5]==len(self.b),'single actual complete group write')
        hardware=self.f(self.b,t,'hardware');self.eq(hardware,'li2_selected_hardware',abi_version=1,reserved=0)
        for i,k in enumerate(('leaf0','leaf1','leaf7')):need(struct.unpack('<4I',self.f(hardware,'li2_selected_hardware',k))==tuple(self.app['hardware'][i][2:]),'actual bridge/app CPUID hardware equality')
        for key,objid in(('main',self.image['main_object']),('interpreter',self.image['interpreter_object'])):self.image_header(self.f(self.b,t,key),objid)
        self.eq(self.f(self.b,t,'session'),'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        need(self.i(self.f(self.b,t,'session'),'li2_step_session','sync_query')&96==96,'actual registered membarrier support')
        obj,_,loads=self.objects[self.image['main_object']];bias=self.bases[self.image['main_object']]
        owners=[p for p in loads if p[1]==5 and bias+p[3]<=self.page and self.page+8192<=bias+p[3]+p[5]]
        need(len(owners)==1 and self.source_offset==owners[0][2]+self.page-bias-owners[0][3]and obj['data'][self.source_offset:self.source_offset+8192]==self.app['source'],'whole source two-page original ELF bytes')

        epochs=r.items(self.b,t,'epochs','pdao_epoch');self.epochs=epochs
        initial_slots=r.items(self.f(epochs[0],'pdao_epoch','prior'),'pdao_slots','slots','pdao_slot')
        self.h_alloc=self.i(r.items(initial_slots[1],'pdao_slot','banks','ped_bank')[1],'ped_bank','generated');self.h_proof_alloc=self.i(initial_slots[1],'pdao_slot','proof')
        initial_domain=self.f(self.b,t,'initial_domain')
        a=self.epoch(epochs[0],0,initial_domain);b=self.epoch(epochs[1],1,a['domain_raw']);warm=self.epoch(epochs[2],2,b['domain_raw'])
        for index,previous in((1,a),(2,b)):
            need(self.f(epochs[index],'pdao_epoch','prior_counts')==previous['counts_raw']and self.f(epochs[index],'pdao_epoch','prior')==previous['slots_raw'],'next focal activation follows complete prior closure without hidden offer')
        need(a['slot']!=b['slot']and b['generation']==a['generation']+1,'two distinct actual retained identities')
        need((warm['slot'],warm['generation'],warm['build_serial'])==(a['slot'],a['generation'],a['build_serial'])and warm['members']==[a['members'][0],b['members'][0]],'joint A entry retains both exact cold generations')
        need(b['begin']==a['terminal_ordinal']+1 and warm['begin']==b['terminal_ordinal']+1,'complete focal raw-event chronology')
        self.next_trace(self.f(self.b,t,'next'),warm,epochs[2]);need(raw[0]>=warm['next_trace_ordinal'],'whole chronological active-domain ingress ordinals')
        final=self.counts(self.f(self.b,t,'final_counts'));last=self.counts(warm['counts_raw'])
        need(all(final[k]>=last[k]for k in final if k!='misses')and all(a>=b for a,b in zip(final['misses'],last['misses'],strict=True)),'final counters retain every focal event without attributing later work')
        names='version status failure_code detail_abs detail_negative phase serial generation build_serial offers cold_attempts publications hits cancelled retirements permit_claims entries completed unexpected permit opened_pages closed_pages anchor_released registration_rechecked guest_data_fault recovery_complete first_error active busy selected_slot slot0_generation slot1_generation slot0_permit slot1_permit slot0_completed_serial slot1_completed_serial domain_members dual_entries dual_completed'.split()
        values=q(self.f(self.b,t,'final_row'));need(len(values)==len(names),'whole exact retained terminal schema');row=dict(zip(names,values,strict=True));row['misses']=list(final['misses'])
        need((row['version'],row['status'],row['failure_code'],row['detail_abs'],row['detail_negative'])==(4,0,0,0,0),'actual protected retained terminal outcome')
        for k in('offers','cold_attempts','publications','hits','cancelled','retirements','permit_claims','entries','completed','unexpected'):need(row[k]==final[k],'whole final counter-to-report join '+k)
        p=self.f(self.b,t,'final_progress');pt='li2_pg_progress'
        for k in('phase','serial','opened_pages','closed_pages','anchor_released','registration_rechecked','first_error'):need(row[k]==self.i(p,pt,k),'actual retained progress-to-report join '+k)
        need(row['selected_slot']in(0,1)and 0<row['build_serial']<=row['serial'],'actual final selected slot/build serial')
        gs=(row['slot0_generation'],row['slot1_generation']);ps=(row['slot0_permit'],row['slot1_permit']);cs=(row['slot0_completed_serial'],row['slot1_completed_serial'])
        need(all(0<g<=final['next_generation']for g in gs)and gs[0]!=gs[1]and ps==(1,1)and all(0<c<=final['next_serial']for c in cs)and row['generation']==gs[row['selected_slot']]and row['permit']==ps[row['selected_slot']],'actual final two retained identities and completed permits')
        need(final['offers']==final['entries']+final['cancelled']and final['entries']==final['publications']+final['hits']and final['cold_attempts']==final['publications']+final['cancelled']and sum(final['misses'])==final['cancelled']and final['next_serial']==final['offers']and final['next_generation']==final['publications'],'whole completed/cancelled retained partition')
        need(final['entries']==final['completed']and final['unexpected']==0 and final['retirements']==final['publications']-2 and final['permit_claims']==final['retirements']+final['hits']+row['dual_entries'],'whole two-resident permit/publication accounting')
        need(row['phase']in(13,14)and row['active']==row['busy']==row['first_error']==row['guest_data_fault']==0 and row['anchor_released']==row['registration_rechecked']==1,'actual final closed retained epoch or completed cancellation')
        need((row['opened_pages'],row['closed_pages'],row['recovery_complete'])==((17*row['domain_members'],17*row['domain_members'],1)if row['phase']==13 else(0,0,0)),'exact final retained extent and recovery for its terminal phase')
        need(row['dual_entries']==row['dual_completed']==h[36]and 1<=row['dual_entries']<=final['hits']and row['domain_members']in((1,2)if row['phase']==13 else(0,))and h[37]==final['completed'],'exact actual joint completion/member accounting')
        replacements=a['prior_generation_installed']+b['prior_generation_installed']
        mapping=a['rseq_mapping']+b['rseq_mapping']+warm['rseq_mapping'];need(len(mapping)==6 and any(x['query_kind']==(3 if self.differential else 4)for x in mapping),'actual projected or differential-verified focal rseq observation')
        return dict(rseq_mapping=mapping,terminal=row,mode=0,attempts=[a,b,warm],cold_publications=2,warm_entries=1,dual_entries=1,replacements=replacements,permit_claims=replacements+2,interior_signals=0,source=self.app['source'],word=0,status=0,code=0,detail=0,qualification_credit=False)


def read(data,layout,image,app,pid,cpu,exit_status):
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    return Check(wire.Reader(data,layout),image,app,pid,cpu).finish(exit_status)


def terminal(parsed,owner):
    expected=owner['terminal'];need(type(parsed)is dict and set(parsed)==set(expected)and all(type(v)is int for k,v in parsed.items()if k!='misses')and type(parsed['misses'])is list and all(type(v)is int for v in parsed['misses'])and parsed==expected,'whole actual protected active-domain terminal row')
    return dict(fields=len(expected),protected_active_domain_row=1,inherited_row_protection=0)

CONTROL_COUNTS={0:121}

def controls(data,layout,image,app,pid,cpu,exit_status):
    """Actual shared-domain input mutations; all five old profiles stay mandatory separately."""
    read(data,layout,image,app,pid,cpu,exit_status);types=layout['types']
    def at(t,k,base=0,index=0,child=None):return base+types[t]['fields'][k]['offset']+(index*types[child]['bytes']if child else index)
    w='pdao_wire';et='pdao_epoch';st='pdao_stage';it='pdao_epoch_info';gt='li2_pg_generation';pt='li2_pg_progress';ct='li2_pg_compact';ss='pdao_slots';sl='pdao_slot'
    e=at(w,'epochs');b=at(w,'epochs',index=1,child=et);warm=at(w,'epochs',index=2,child=et)
    ent=at(et,'entered',e);end=at(et,'terminal',e);info=at(et,'info',e);p=at(st,'progress',end)
    def selected(stage):
        slots=at(st,'slots',stage);index=struct.unpack_from('<I',data,at(ss,'selected_slot',slots))[0];need(index in(0,1),'control actual selected slot');return at(ss,'slots',slots,index,sl)
    es=selected(ent);zs=selected(end);g=at(sl,'generation',zs);eg=at(sl,'generation',es)
    cert=at(w,'certificates');payload=at('pdao_certificate','payload',cert);cp=at('pe_payload','plan',payload)
    pred=at(et,'predecessor',e);closed=at('pdao_predecessor','closed',pred);owner=at('li2_tf_chain_slot','owner',closed);step=at('li2_tf_owner','step',owner)
    wi=at(et,'info',warm);we=at(et,'entered',warm);ws=selected(we);wg=at(sl,'generation',ws)
    n=at(w,'next');ns=at('pdao_next','closed',n);no=at('li2_tf_chain_slot','owner',ns);nt=at('li2_tf_owner','step',no);nf=at('pdao_next','frame',n)
    tests=[
      ('wire_version',8),
      ('footer_version',len(data)-56),
      ('actual_hardware',at('li2_selected_hardware','leaf0',at(w,'hardware'))),
      ('interior_signal',at(et,'h',e)+11*8),
      ('full_terminal_FP',at('li2_step_frame','fp',at('le_frame','frame',at(et,'after',e)))),
      ('full_data',at('li2_pdao_memory','data',at(et,'after_memory',e))),
      ('full_stack',at('li2_pdao_memory','stack',at(et,'after_memory',e))),
      ('source_second_page',at(ct,'source',cp)+4096),
      ('proof_padding',at('pdao_certificate','tail',cert)),
      ('literal_second_image',at('pdao_certificate','code',cert)+32768),
      ('literal_stub',at('pdao_certificate','code',cert)+65536),
      ('initial_slot_zero',at(et,'initial_slots',e)),
      ('terminal_slot_zero',at(et,'terminal_slots',e)),
      ('member_generation',at('pe_header','member_generation',at('pe_payload','header',payload))+8),
      ('global_head_population',at(ct,'heads',cp)),
      ('member_partition',at(ct,'member_heads',cp)+4),
      ('typed_edge_unused',at('li2_pg_edge','target_head',at(ct,'edge',cp))),
      ('entry_word',at('li2_pg_rseq_progress','word_entry',at(st,'rseq',ent))),
      ('closing_word',at('li2_pg_rseq_progress','word_after',at(st,'rseq',end))),
      ('cold_head_proof',at('li2_pg_rseq_progress','cold_heads',at(st,'rseq',ent))),
      ('no_invented_stub_proof',at('li2_pg_rseq_progress','cold_stubs',at(st,'rseq',ent))),
      ('live_GPR',at('li2_write_registers','gpr',at('li2_link_rseq_live','registers',at(it,'live',info)))),
      ('active_member_reference',at(gt,'member_refs',eg)+8),
      ('closed_incoming_reference',at(gt,'incoming',g)),
      ('first_image_revoke',at('le_permission','complete',at(gt,'close',g))),
      ('second_image_revoke',at('le_permission','complete',at(gt,'close',g,1,'le_permission'))),
      ('stub_revoke',at('le_permission','complete',at(gt,'close',g,2,'le_permission'))),
      ('source_anchor_release',at('li2_pg_source_progress','release_complete',at(st,'source',end))),
      ('source_closed_pages',at('li2_pg_source_progress','closed_pages',at(st,'source',end))),
      ('completion_permit',at(pt,'completion_permit',p)),
      ('reset_seal',at('le_permission','complete',at('pg_slot_transition','seal',at(gt,'slots',g,2,'pg_slot_transition')))),
      ('predecessor_before_FP',at('li2_step_frame','fp',at('li2_step_owner','before',step))),
      ('predecessor_after_FP',at('li2_step_frame','fp',at('li2_step_owner','after',step))),
      ('predecessor_actual_revoke',at('li2_step_owner','revoked',step)),
      ('predecessor_zero_scan',at('pdao_predecessor','unexpected_compared',pred)),
      ('slot_owner',at('li2_ptr_slot_ref','owner',at(sl,'identity',es))),
      ('slot_index',at('li2_ptr_slot_ref','index',at(sl,'identity',es))),
      ('slot_generation',at('li2_ptr_slot_ref','generation',at(sl,'identity',es))),
      ('selected_slot',at(ss,'selected_slot',at(st,'slots',ent))),
      ('actual_victim',at(et,'h',e)+24*8),
      ('actual_B_certificate_slot',at('pdao_certificate','slot',at(w,'certificates',index=1,child='pdao_certificate'))),
      ('known_certificate_required',at('pdao_check','certificate',at(sl,'check',es))),
      ('certificate_generation',at('pdao_certificate','generation',cert)),
      ('certificate_literal_extent',at('pdao_certificate','proof_bytes',cert)),
      ('warm_build_serial',at(gt,'build_serial',wg)),
      ('warm_no_reopen',at('le_permission','started',at(it,'reopen_code',wi))),
      ('warm_no_static_reproof',at(it,'none_proofs',wi)),
      ('warm_claim',at('li2_private_code_query','complete',at(it,'claim_slots',wi))),
      ('cell_generation',at('pg_dispatch_cell_transition','generation',at(gt,'cell',g,2,'pg_dispatch_cell_transition'))),
      ('cell_zero',at('pg_dispatch_cell_transition','after',at(gt,'cell',g,2,'pg_dispatch_cell_transition'))),
      ('next_ordinal',at('pdao_next','raw_ordinal',n)),
      ('next_close',at('pdao_next','closed_complete',n)),
      ('next_TLS',at('pdao_next','tls_complete',n)),
      ('next_FP',at('li2_step_frame','fp',at('le_frame','frame',nf))),
      ('next_original_before_FP',at('li2_step_frame','fp',at('li2_step_owner','before',nt))),
      ('next_original_revoke',at('li2_step_owner','revoked',nt)),
      ('final_partition',at('pdao_counts','publications',at(w,'final_counts'))),
      ('final_slot_permit',at(w,'final_row')+32*8),
      ('whole_terminal_row',at(w,'final_row')+17*8)]
    refused=[]
    def reject(name,mutant,expected=None):
        try:read(bytes(mutant),layout,image,app,pid,cpu,exit_status)
        except ValueError as error:
            if expected is not None:need(str(error)==expected,'exact source-causal retained-two refusal '+name)
            refused.append(name)
        else:raise ValueError('supplied retained-two corruption accepted '+name)
    for name,offset in tests:
        mutant=bytearray(data);mutant[offset]^=1;reject(name,mutant)
    startup=at(w,'startup_registry');reg=at(et,'terminal_registry',e);rt='pdao_registry'
    registry=[('startup_population',at(rt,'count',startup),'startup registry population is an exact predecessor',True),
      ('startup_table_headers',at(rt,'ph',startup),'startup registry keeps exact table, bridge and program headers',False),
      ('startup_range_prefix',at(rt,'ranges',startup),'startup registry retains every original range and classification',False),
      ('startup_classification_prefix',at(rt,'initial_code',startup),'startup registry retains every original range and classification',False),
      ('epoch_terminal_population',at(rt,'count',reg),'whole domain registry unchanged during epoch',False),
      ('epoch_owner_population',at(it,'registry_count',info),'exact pdao_epoch_info.registry_count',False)]
    for name,offset,message,clear in registry:
        mutant=bytearray(data)
        if clear:mutant[offset:offset+4]=bytes(4)
        else:mutant[offset]^=1
        reject(name,mutant,message)
    # A digest is never accepted in place of each complete immutable byte scan.
    for field,nbytes in(('proof',364544),('code',69632),('publication',362640)):
        base=at('pdao_check',field,at(sl,'check',es))
        for name,k,value in(('completion','complete',0),('coverage','compared',nbytes-1),('actual_difference','differences',1)):
            mutant=bytearray(data);struct.pack_into('<Q',mutant,at('pdao_scan',k,base),value);reject(field+'_'+name,mutant,'exact pdao_scan.'+k)
    # The shared literal still needs the independent full descriptor model.
    for name,array,child,index,field in(('descriptor','original','li2_span_decoded',0,'gpr_write'),('second_descriptor','original','li2_span_decoded',1,'flags_read'),('frontier','frontier','li2_span_decoded',0,'refusal'),('head_kind','head','li2_pe_head',0,'kind')):
        mutant=bytearray(data);mutant[at(child,field,at(ct,array,cp,index,child))]^=1;reject('independent_'+name,mutant,'whole independent retained-two '+array)
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
          ('maps_receipt',at('li2_maps_observation','io_performed',observation),4,struct.unpack_from('<I',data,at('li2_maps_observation','io_performed',observation))[0]^1,'exact selected maintained/differential acquisition class')):
            mutant=bytearray(data);struct.pack_into('<Q'if width==8 else'<I',mutant,offset,value);reject('proof_part'+str(index)+'_'+name,mutant,message)
    # The new authority has one shared receipt, two independently claimable members,
    # a sealed directory and two distinct scratch owners. No old profile is removed.
    wd=at(et,'terminal_domain',warm);entry_domain=at(st,'domain',we);ework=at('pdao_domain_checkpoint','work',entry_domain)
    twork=at('pda_state','work',wd);cell_index=struct.unpack_from('<I',data,at('pda_work','receipt',twork))[0];need(cell_index<3,'actual control receipt cell')
    receipt=at('pda_state','completion',wd,cell_index,'pda_completion');m0=at('pda_completion','member',receipt,0,'pda_member_completion');m1=at('pda_completion','member',receipt,1,'pda_member_completion')
    candidates=[]
    for epoch in(e,b,warm):
        for stage,field in(('entered','current_observed'),('terminal','current_after')):
            current=at('li2_pg_rseq_progress',field,at(st,'rseq',at(et,stage,epoch)))
            if struct.unpack_from('<I',data,at('li2_rseq_current_data','kind',current))[0]==1:candidates.append(current)
    need(candidates,'control has an actual successful current-view observation');current=candidates[0];cv=at('li2_rseq_current_data','view',current)
    query=at('li2_maps_current_view','query',cv);physical=at('li2_maps_current_view','physical',cv)
    extra=[
      ('joint_count',at('pda_completion','count',receipt)),
      ('joint_member_generation',at('li2_pgd_ref','generation',at('pda_member_completion','identity',m1))),
      ('joint_source_pair',at('li2_pg_source_key','page',at('pda_member_completion','source',m1))),
      ('joint_saved_revoke',at('le_permission','complete',at('li2_pg_generation','close',at('pda_member_completion','generation',m1)))),
      ('joint_source_member',at('li2_pgd_source_progress','count',at('pda_completion','domain_source',receipt))),
      ('joint_rseq_member',at('li2_pg_rseq_progress','domain_count',at('pda_completion','rseq',receipt))),
      ('joint_directory_close',at('li2_private_code_query','complete',at('pda_completion','directory_closed',receipt))),
      ('dual_completion',at('pda_state','dual_completed',wd)),
      ('receipt_claim_bit',at('pda_state','claimed',wd)+cell_index*4),
      ('directory_target',at('li2_jd_domain_row','generated',at('li2_jd_domain_directory','row',at('pda_work','directory',ework)))),
      ('directory_other_generation',at('li2_jd_domain_row','generation',at('li2_jd_domain_directory','row',at('pda_work','directory',ework),2,'li2_jd_domain_row'))),
      ('actual_directory_literal',at(et,'terminal_directory',warm)+32),
      ('directory_seal',at('le_permission','complete',at('pda_work','directory_seal',ework))),
      ('peer_claim_proof',at('li2_private_code_query','complete',at('pg_proof_query','part',at('pda_claim_observation','proof',at('pda_work','peer_claim',ework)),0,'li2_private_code_query'))),
      ('peer_scratch',at(et,'terminal_spill',warm)+4096),
      ('primary_scratch',at(et,'terminal_spill',warm)),
      ('current_release',at('li2_rseq_current_data','release_complete',current)),
      ('current_phase_end',at('li2_rseq_current_data','phase_ended',current)),
      ('current_ticket_owner',at('li2_maps_current_ref','owner',at('li2_rseq_current_data','ticket',current))),
      ('current_query_origin',at('li2_maps_observation','acquisition_id',at('li2_fetch_map_progress','observation',query))),
      ('current_physical_origin',at('li2_maps_observation','acquisition_id',at('li2_fetch_map_progress','observation',physical))),
      ('current_page_generation',at('li2_rseq_data','generation',at('li2_rseq_current_data','data',current))),
      ('current_table',at('li2_maps_current_view','table',cv)),
      ('shared_source_release',at('li2_pgd_source_progress','released',at(st,'domain_source',at(et,'terminal',warm)))),
      ('shared_progress_34',at(pt,'closed_pages',at(st,'progress',at(et,'terminal',warm)))),
      ('final_dual_completed',at(w,'final_row')+38*8),
    ]
    for name,offset in extra:
        mutant=bytearray(data);mutant[offset]^=1;reject(name,mutant)
    # The completion arrays omitted at entry still require every actual byte.
    cellscan=at('pdao_domain_checkpoint','cells',entry_domain)
    for name,field,value in(('shared_cells_incomplete','complete',0),('shared_cells_short','compared',3*types['pda_completion']['bytes']-1),('shared_cells_different','differences',1)):
        mutant=bytearray(data);struct.pack_into('<Q',mutant,at('pdao_scan',field,cellscan),value);reject(name,mutant,'exact pdao_scan.'+field)
    # Coherently rename the warm primary's bank through all active/saved refs,
    # while preserving both real fixed-bank layouts and all generation bytes.
    mutant=bytearray(data)
    ref_offsets=[];work_offsets=[]
    for stage in(we,at(et,'terminal',warm)):
        domain=at(st,'domain',stage);work_offsets.append(at('pdao_domain_checkpoint','work',domain))
        ref_offsets.append(at('li2_pgd_source_progress','ref',at(st,'domain_source',stage)))
        ref_offsets.append(at('li2_pg_rseq_progress','domain_ref',at(st,'rseq',stage)))
    work_offsets.append(twork)
    for work_offset in work_offsets:
        ref_offsets.append(at('li2_pgd_member','identity',at('li2_pgd_view','member',at('pda_work','view',work_offset))))
        mutant[at('pda_work','primary_bank',work_offset)]^=1
    ref_offsets.extend((at('pda_member_completion','identity',m0),
        at('li2_pgd_source_progress','ref',at('pda_completion','domain_source',receipt)),
        at('li2_pg_rseq_progress','domain_ref',at('pda_completion','rseq',receipt))))
    for ref_offset in ref_offsets:mutant[at('li2_pgd_ref','bank',ref_offset)]^=1
    mutant[at(it,'selected_bank',wi)]^=1
    reject('coherent_fixed_bank_identity',mutant,'actual domain reference bank matches its fixed slot layout')
    need(len(refused)==CONTROL_COUNTS[0],'all exact separately counted retained-two owner controls')
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0,mode=0)
