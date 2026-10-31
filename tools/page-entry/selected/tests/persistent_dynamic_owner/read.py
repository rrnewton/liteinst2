"""Exact finite dynamic owner: real cancellation, cold/warm entry and completed replacement.
No old fixed/65 qualification is inferred from this distinct record."""
import hashlib,struct,importlib.util
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
HERE=Path(__file__).resolve().parent
wire=load('persistent_owner_wire',HERE/'wire.py');plan=load('persistent_owner_plan',HERE/'plan.py')
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
            t='pdo_registry';self.eq(b,t,complete=1,table=self.symbol('protected'));count=self.i(b,t,'count');need(0<count<=128,'bounded actual registration table')
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
        t='li2_pdo_memory';self.eq(b,t,attempted=1,complete=1,after_abort=int(failed),rows_checked=6,data_copied=8192,stack_copied=224,result=0,detail=0,rsp=RSP,data_first=DATA,stack_first=RSP-128)
        m=self.maps(self.f(b,t,'maps'),0)
        before,after=(self.f(b,t,k)for k in('before','after'));mt='li2_maps_stats'
        self.eq(before,mt,active=0,poisoned=0,reserved=0);self.eq(after,mt,active=0,poisoned=0,reserved=0,valid=1)
        self.r.change(before,after,mt,values=dict(fresh_calls=self.i(before,mt,'fresh_calls')+1,acquisitions=self.i(before,mt,'acquisitions')+1),observed=('valid','invalidations','mutation_epoch'))
        invalidations=self.i(after,mt,'invalidations')-self.i(before,mt,'invalidations')
        need(invalidations>=1 and self.i(after,mt,'mutation_epoch')-self.i(before,mt,'mutation_epoch')==invalidations,'actual explicit fresh invalidation and every gateway invalidation')
        need(m[:3]==(self.i(after,mt,'acquisitions'),0,self.i(after,mt,'mutation_epoch')),'memory acquisition actual stats join')
        rows=self.r.items(b,t,'rows','li2_pdo_map_row')
        for i,row in enumerate(rows):
            self.eq(row,'li2_pdo_map_row',offset=0,major=0,minor=0,inode=0,private=1)
            a,z,prot=self.v(row,'li2_pdo_map_row','first end prot');need(a%PAGE==z%PAGE==0 and a<z,'actual page-aligned memory extent')
            if i<2:need((a,z,prot)==(DATA,DATA+8192,3),'actual two-page writable data')
            elif i==4:need((a,z,prot)==(STACK+4096,STACK+4096+131072,3),'actual fixed writable guest stack')
            else:
                point=(DATA+8192,STACK,STACK+4096+131072)[(2,3,5).index(i)]
                need(a<=point and point+PAGE<=z and prot==0,'actual inaccessible data/stack guard')
        return dict(data=self.f(b,t,'data'),stack=self.f(b,t,'stack'))

    def __init__(self,r,image,app,pid,cpu):
        self.r,self.image,self.app,self.pid,self.cpu=r,image,app,pid,cpu
        self.b=r.data[:-64];self.h=q(self.f(self.b,'pdo_wire','h'));self.bias=self.h[9]-r.layout['symbols']['li2_raw6']
        self.page=app['head']&-PAGE;self.head=app['head'];self.objects={};self.bases={};self.backings={};self.maps_seen={};self.source_ids={}
        for key,obj in image['objects'].items():
            need(type(key)is int and type(obj)is dict,'actual complete object inventory');h,loads=old.elf(obj['data']);self.objects[key]=(obj,h,loads)
        need(image['main_object']in self.objects and image['interpreter_object']in self.objects,'actual source object identities')
        self.eh,self.ph,self.symbols=elf_symbols(image['bridge'])
        need(set(r.layout['symbols'])==set(self.symbols)|{'span_progress'}and all(r.layout['symbols'][k]==v[0]for k,v in self.symbols.items()),'same actual bridge/DWARF symbols')
        first=r.items(self.b,'pdo_wire','epochs','pdo_epoch')[0];payload=self.f(first,'pdo_epoch','initial_payload')
        key=self.f(payload,'pe_payload','source');row=r.items(key,'li2_pe_source_key','page','li2_pe_source_page')[0]
        self.main_backing=self.f(row,'li2_pe_source_page','backing');self.source_offset=self.i(self.f(row,'li2_pe_source_page','identity'),'li2_fetch_page','offset')

    def registry_prefix(self,a,b):
        t='pdo_registry';n,m=self.i(a,t,'count'),self.i(b,t,'count');need(0<n<=m<=128,'startup registry population is an exact predecessor')
        need(all(self.f(a,t,k)==self.f(b,t,k)for k in('complete','table','bridge','ph')),'startup registry keeps exact table, bridge and program headers')
        need(self.f(a,t,'ranges')[:n*16]==self.f(b,t,'ranges')[:n*16]and self.f(a,t,'initial_code')[:n]==self.f(b,t,'initial_code')[:n],'startup registry retains every original range and classification')
        rows=[self.v(x,'li2_fork_range','first end')for x in self.r.items(b,t,'ranges','li2_fork_range')[:m]];kinds=self.f(b,t,'initial_code')
        for i,(first,end)in enumerate(rows[n:],n):need(first%PAGE==0 and end-first==PAGE and not kinds[i]and all(end<=x or y<=first for x,y in rows[:i]),'startup additions are distinct strict PAGE intervals')
        self.registry(a);return self.registry(b)

    def source_key(self,key,entry):
        self.eq(key,'li2_pe_source_key',entry=entry)
        for i,row in enumerate(self.r.items(key,'li2_pe_source_key','page','li2_pe_source_page')):
            self.page_row(self.f(row,'li2_pe_source_page','identity'),i);self.backing(self.f(row,'li2_pe_source_page','backing'))
            need(self.f(row,'li2_pe_source_page','bytes')==self.app['source'][i*PAGE:(i+1)*PAGE],'whole immutable two-source bytes')

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
        t='li2_pe_source_key';need(self.i(a,t,'entry')==self.i(b,t,'entry'),'current and immutable entry identity')
        for x,y in zip(self.r.items(a,t,'page','li2_pe_source_page'),self.r.items(b,t,'page','li2_pe_source_page'),strict=True):
            for k in('identity','bytes'):need(self.f(x,'li2_pe_source_page',k)==self.f(y,'li2_pe_source_page',k),'actual current/immutable complete source identity '+k)
            need(self.backing_identity(self.f(x,'li2_pe_source_page','backing'))==self.backing_identity(self.f(y,'li2_pe_source_page','backing')),'actual source-owned stable backing identity')

    def counts(self,b):
        t='pdo_counts';names='next_serial next_generation offers publications hits cold_attempts cancelled retirements permit_claims entries completed unexpected'.split()
        d={k:self.i(b,t,k)for k in names};d['misses']=q(self.f(b,t,'misses'));need(len(d['misses'])==16 and d['misses'][0]==0,'exact sixteen descriptive reason buckets')
        need(all(0<=x<U64 for x in d.values()if type(x)is int)and all(0<=x<U64 for x in d['misses']),'bounded exact dynamic counters')
        return d

    def delta(self,a,b,**increments):
        x,y=self.counts(a),self.counts(b)
        for k in x:
            if k=='misses':need(y[k]==tuple(v+(1 if i==increments.get('miss_reason',-1)else 0)for i,v in enumerate(x[k])),'exact classified miss bucket delta')
            else:need(y[k]==x[k]+increments.get(k,0),'exact focal dynamic counter delta '+k)

    def pin(self,b,state,serial,heads,stores,terminal=False,failed=False,cancel=False):
        t='li2_pe_rseq_progress';self.eq(b,t,active=int(not terminal or failed),checking=0,first_error=0,unsafe_terminal=0,seed_complete=1,entry_complete=int(not cancel),close_complete=int(terminal and not failed and not cancel),first_detail=0,pid=self.pid,tid=self.pid,fs_result=0,gs_result=0,registration_epoch=1,address=RSEQ,page=RSEQ,length=32,signature=0x53053053,fs=self.app['machine'][1],gs=self.app['machine'][2],word_before=0,word_entry=0,word_after=0,cold_heads=heads,cold_stores=stores,fs_selector=0,gs_selector=0,session=self.symbol('selected_session'),cancel_started=int(terminal and cancel),cancel_complete=int(terminal and cancel))
        self.eq(self.f(b,t,'token'),'li2_pe_token',owner=self.symbol('pe'),serial=serial);need(self.i(b,t,'raw_checks')>0,'actual positive zero-word raw checks')
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

    def source(self,b,serial,entry,key,ref,terminal=False,failed=False,cancel=False):
        t='li2_pe_source_progress';phase=(8 if cancel else 7 if failed else 6)if terminal else(3 if cancel else 4)
        self.eq(b,t,initialized=1,phase=phase,first_error=0,pages_copied=2,release_started=int(terminal),release_complete=int(terminal),aborted=int(terminal and failed),first_detail=0,serial=serial,generated=self.generated,cancel_started=int(terminal and cancel),cancel_complete=int(terminal and cancel))
        need(struct.unpack('<2I',self.f(b,t,'bytes_copied'))==(4096,4096),'whole two-page copies')
        s=self.f(b,t,'source');self.eq(s,'li2_pe_sources',complete=1,reserved=0,serial=serial)
        for name in('allocation_epoch','generation_epoch','records_epoch'):need(self.i(s,'li2_pe_sources',name)>0,'actual lifecycle generation epochs')
        actual=self.f(s,'li2_pe_sources','key');self.source_key(actual,entry);self.key_identity(actual,key)
        need(self.f(s,'li2_pe_sources','anchor')==ref,'actual held source anchor')
        self.maps(self.f(b,t,'preparation'))
        if cancel:
            self.eq(b,t,validations=int(terminal));
            if terminal:self.maps(self.f(b,t,'validation'))
            else:zero(self.f(b,t,'validation'),'miss has no invented plan validation')
            zero(self.f(b,t,'opened'),'cancel never opens generated RX');zero(self.f(b,t,'closed'),'cancel never fabricates RX close')
            if terminal:
                prot=self.i(b,t,'cancel_expected_prot');need(prot in(1,3),'actual closed or virgin bank protection');self.query(self.f(b,t,'cancel_code'),self.generated,prot,pages=8)
                self.observation(self.f(b,t,'cancelled_fetch'),entry,False,ref)
            else:
                self.eq(b,t,cancel_expected_prot=0);zero(self.f(b,t,'cancel_code'),'no premature cancel query');zero(self.f(b,t,'cancelled_fetch'),'no premature cancel release')
        else:
            self.eq(b,t,cancel_expected_prot=0);zero(self.f(b,t,'cancel_code'),'accepted epoch has no cancel query');zero(self.f(b,t,'cancelled_fetch'),'accepted epoch has no cancelled fetch')
            self.maps(self.f(b,t,'validation'));self.query(self.f(b,t,'opened'),self.generated,5,pages=8)
            if terminal:self.query(self.f(b,t,'closed'),self.generated,1,pages=8)
            else:zero(self.f(b,t,'closed'),'no premature close')
        for bb in self.r.items(b,t,'last_backing','li2_fetch_backing'):
            if cancel and not terminal:zero(bb,'unvalidated miss has no invented last backing')
            else:self.backing(bb)
        return self.i(b,t,'validations')

    def decoded(self,b,pc,kind):
        code,length,step=(299,2,1)if kind=='nop'else(765,3 if pc==self.page+0x100 else 2,0)
        self.eq(b,'li2_decoded',pc=pc,next_pc=pc+length,abi_version=1,decode_status=0,code=code,kind=0,destination=16,width_bits=0,step_disposition=step,available=15,length=length,reserved=0)
        need(self.f(b,'li2_decoded','bytes')==self.app['source'][pc-self.page:pc-self.page+15]+b'\0','whole actual ordinary decoder window')
        return code,length

    def predecessor(self,slot,pc,ingress,closed=True):
        t='li2_tf_chain_slot';index=self.i(slot,t,'index');need(index in(0,1),'actual predecessor slot index')
        self.eq(slot,t,chain=self.symbol('selected_chain'),phase=5 if closed else 3,fallback=0,prepare_complete=1,decode_attempted=1,decode_complete=1,retry=0,unexpected_frame_observed=0,unexpected_signal=0,unexpected_code=0,unexpected_errno=0,unexpected_address=0,prepare_result=0,decode_result=0,classify_result=0)
        need(self.i(slot,t,'generation')>0 and self.i(slot,t,'event_id')>0,'actual predecessor generation/event')
        origin=self.i(slot,t,'origin');need(origin in(1,2)and self.i(slot,t,'prepare_attempted')==int(origin==2),'actual predecessor NX/TRACE preparation')
        for k in('first_decoded','first_fetch','first_release','unexpected'):zero(self.f(slot,t,k),'no unused predecessor '+k)
        kind='nop'if pc in(self.page+0xfe,self.page+0x1fe)else'jmp';code,length=self.decoded(self.f(slot,t,'decoded'),pc,kind)
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
            query=self.f(slot,t,'query');self.eq(query,'li2_tf_continuation',pc=ingress['greg'][16],attempted=1,page_observed=1,complete=1,result=0);self.maps(self.f(query,'li2_tf_continuation','maps'));self.page_row(self.f(query,'li2_tf_continuation','page'));self.backing(self.f(query,'li2_tf_continuation','backing'))
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

    def compact_plan(self,payload,kind):
        c=self.f(payload,'pe_payload','plan');t='li2_pe_compact';heads,n,store,exitpc=(9,34,0,self.page+0x219)if kind=='a'else(3,11,1,self.page+0x40b)
        self.eq(c,t,version=1,bytes=182168,ready=1,result=0,heads=heads,exits=1,stores=1,source_bytes=n,source_mask=3 if kind=='a'else 1,decoder_result=0,guard_result=0,reserved=0,entry=self.page+(0x200 if kind=='a'else 0x400),generated=self.generated,spill=self.spill)
        need(q(self.f(c,t,'page'))==(self.page,self.page+PAGE)and self.f(c,t,'source')==self.app['source'],'whole original two-page immutable image')
        table=plan.table(self.ranges+[(self.page,self.page+PAGE),(self.page+PAGE,self.page+2*PAGE),(RSEQ+8,RSEQ+16)],self.table)
        need(self.f(c,t,'table')==table,'whole independent exclusion table including source pair and registered word')
        expected=plan.image(self.page,self.generated,self.spill,table,kind);original,frontier=plan.descriptors(self.app['source'],self.page,kind)
        need(self.f(c,t,'image')==expected['code']and self.f(c,t,'head')==expected['heads'],'whole independent cyclic image/heads')
        need(self.f(c,t,'original')==original and self.f(c,t,'frontier')==frontier,'whole independent336-byte descriptors: code/operands/flags/GPR/static-NONE and refusals')
        need(q(self.f(c,t,'exit_pc'))==(exitpc,0,0,0,0,0,0,0),'exact original unsupported frontier')
        guards=self.r.items(c,t,'guard','li2_pe_guard_record');g=guards[store];gt='li2_pe_guard_record'
        self.eq(g,gt,version=1,ready=1,result=0,image_bytes=len(expected['guard']),boundaries=37,store_offset=expected['store'],reject_offset=expected['reject'],reserved=0)
        need(struct.unpack('<4I',self.f(g,gt,'scratch_regs'))==(0,1,2,3)and self.f(g,gt,'boundary')==expected['boundaries'],'whole independent guard scratch/recovery metadata')
        for i,x in enumerate(guards):
            if i!=store:zero(x,'unused guard record')
        stores=self.r.items(c,t,'store_original','li2_mg_store');s=stores[store];st='li2_mg_store';pc=self.page+(0x200 if kind=='a'else 0x404)
        self.eq(s,st,version=1,ready=1,refusal=0,available=15,width_bytes=8,source_kind=1,source_reg=0,base=7,index=16,scale=1,rip_relative=0,displacement=0,rip_target=0,immediate=0,displacement_offset=0,displacement_bytes=0,modrm_offset=2,opcode_offset=1,reserved=0)
        self.eq(self.f(s,st,'tf'),'li2_mg_tf',pc=pc,next_pc=pc+3,abi_version=1,policy=1,code=282,length=3,flow=1,family=1)
        need(self.f(s,st,'bytes')==self.app['source'][pc-self.page:pc-self.page+15]+b'\0','whole actual guarded MOV source')
        for i,x in enumerate(stores):
            if i!=store:zero(x,'unused MOV descriptor')
        # Exact materialized donor used only at a real terminal guard boundary.
        donor=bytearray(self.r.types['li2_mg_plan']['bytes']);mt='li2_mg_plan'
        for k in('version','ready','result','image_bytes','boundaries','store_offset','reject_offset','reserved','scratch_regs','boundary'):
            f=self.r.types[mt]['fields'][k];donor[f['offset']:f['offset']+f['bytes']]=self.f(g,gt,k)
        for k,v in dict(generated=self.generated+512*store,spill=self.spill,successor=self.generated+512*(store+1)).items():struct.pack_into('<Q',donor,self.r.types[mt]['fields'][k]['offset'],v)
        for k,v in dict(original=s,table=table,image=expected['guard']+bytes(512-len(expected['guard']))).items():
            f=self.r.types[mt]['fields'][k];donor[f['offset']:f['offset']+f['bytes']]=v
        return expected,bytes(donor),heads,exitpc

    def permit(self,b,g,source=None,pin=None,fetch=None):
        t='ped_permit';self.eq(b,t,valid=1,generation=self.i(g,'li2_pe_generation','generation'),generated=self.i(g,'li2_pe_generation','generated'),proof=self.i(g,'li2_pe_generation','proof'))
        serial=self.i(b,t,'serial');seq=self.i(b,t,'ref_sequence');need(serial>0 and seq>0,'actual completed permit serial/borrow')
        need(self.f(b,t,'close')==self.f(g,'li2_pe_generation','close'),'permit is the actual resident generation close')
        self.permission(self.f(b,t,'close'),self.i(b,t,'generated'),1,8);self.query(self.f(b,t,'proof_query'),self.i(b,t,'proof'),1,pages=47)
        f=self.f(b,t,'fetch');self.progress(f,seq,False)
        s=self.f(b,t,'source');self.eq(s,'li2_pe_source_progress',serial=serial,phase=6,first_error=0,release_started=1,release_complete=1,cancel_started=0,cancel_complete=0,aborted=0)
        src=self.f(s,'li2_pe_source_progress','source');self.eq(src,'li2_pe_sources',complete=1,serial=serial,reserved=0)
        need(self.i(self.f(src,'li2_pe_sources','anchor'),'li2_fetch_ref','sequence')==seq,'permit source belongs to actual released borrow')
        self.key_identity(self.f(src,'li2_pe_sources','key'),self.f(b,t,'generation_source'))
        r=self.f(b,t,'rseq');self.eq(r,'li2_pe_rseq_progress',active=0,checking=0,first_error=0,unsafe_terminal=0,seed_complete=1,entry_complete=1,close_complete=1,cancel_started=0,cancel_complete=0,word_before=0,word_entry=0,word_after=0,registration_epoch=1,address=RSEQ,length=32,signature=0x53053053)
        self.eq(self.f(r,'li2_pe_rseq_progress','token'),'li2_pe_token',owner=self.symbol('pe'),serial=serial)
        for actual,expected,name in((s,source,'source'),(r,pin,'rseq'),(f,fetch,'fetch')):
            if expected is not None:need(actual==expected,'permit whole actual completed '+name+' snapshot')

    def epoch(self,b,index,kind,previous=None):
        t='pdo_epoch';h=q(self.f(b,t,'h'));failed=self.app['mode']!=0;warm=kind=='warm';which='b'if kind=='replacement'else'a'
        entry=self.page+(0x400 if which=='b'else 0x200);code,detail=(3304,11 if self.app['mode']==1 else 4)if failed else(0,0)
        need(h[:3]==(1,index,entry)and h[3]>0 and h[4:11]==(1,1,h[3],0,1,1,int(failed))and h[11]==h[3]+1 and h[12:15]==(0,0,1),'actual entry/terminal raw ordinals with zero interior events')
        need(h[15]in(0,1)and h[16]==self.symbol('selected_session')and h[17]>0 and h[18]<U64 and h[19:]==(h[15],1,0,0,1),'actual selected chain before real close')
        initial=self.f(b,t,'initial_registry');terminal=self.f(b,t,'terminal_registry');need(initial==terminal,'entire protected range registry unchanged during accepted epoch')
        self.ranges,kinds=self.registry_prefix(self.f(self.b,'pdo_wire','startup_registry'),initial)
        payload=self.f(b,t,'initial_payload');need(payload==self.f(b,t,'terminal_payload'),'whole immutable primary remains literal and byte-identical')
        for k in('initial_tail','terminal_tail'):zero(self.f(b,t,k),'entire immutable proof tail zero')
        ph=self.f(payload,'pe_payload','header');self.generated,self.spill=self.v(ph,'pe_header','generated spill');self.proof=self.h[27]
        self.table=self.proof+self.r.types['pe_payload']['fields']['plan']['offset']+self.r.types['li2_pe_compact']['fields']['table']['offset']
        need(self.generated==self.h[26]and self.spill==self.h[28],'actual low bank selected for low source')
        for a,z in((self.h[26],self.h[28]+PAGE),(self.h[29],self.h[30]+PAGE),(self.proof,self.proof+192512)):
            need(self.ranges.count((a,z))==1 and kinds[self.ranges.index((a,z))]==0,'actual two code/spill banks and proof in strict registry')
        stage=self.f(b,t,'entered');end=self.f(b,t,'terminal');p=self.f(stage,'pdo_stage','progress');pt='li2_pe_progress';serial=self.i(p,pt,'serial');generation=self.i(p,pt,'generation')
        prior=self.f(b,t,'prior_counts');pc=self.counts(prior);resident=self.f(b,t,'prior_generation');installed=self.i(resident,'li2_pe_generation','installed')
        need(installed in(0,1)and serial==pc['next_serial']+1,'actual monotonic attempt serial')
        if installed:self.permit(self.f(b,t,'prior_permit'),resident)
        else:zero(self.f(b,t,'prior_permit'),'no permit without resident generation');need(pc['next_generation']==0,'no historical publication without resident generation')
        increments=dict(next_serial=1,offers=1,entries=1,permit_claims=int(installed))
        if warm:increments['hits']=1;need(installed==1,'warm requires actual resident permit')
        else:increments.update(next_generation=1,publications=1,cold_attempts=1,retirements=int(installed))
        self.delta(prior,self.f(stage,'pdo_stage','counts'),**increments)
        self.delta(self.f(stage,'pdo_stage','counts'),self.f(end,'pdo_stage','counts'),completed=int(not failed),unexpected=int(failed))
        self.eq(p,pt,serial=serial,registration_epoch=1,publication=1,generation=generation,phase=9,first_error=0,source_count=2,opened_pages=8,closed_pages=0,anchor_released=0,registration_rechecked=0,completion_permit=0,first_detail=0,generated=self.generated,proof=self.proof,table=self.table,spill=self.spill)
        need(q(self.f(p,pt,'source'))==(self.page,self.page+PAGE),'actual source pair progress')
        ep=self.f(end,'pdo_stage','progress');self.r.change(p,ep,pt,values=dict(phase=15 if failed else 13,first_error=code,first_detail=detail,closed_pages=8,anchor_released=1,registration_rechecked=int(not failed),completion_permit=int(not failed)))
        for s in(stage,end):self.eq(s,'pdo_stage',busy=1,active=1,resuming=0,pending=1,failing=int(failed and s==end));need(0<self.i(s,'pdo_stage','route')<32,'actual generated route')
        need(self.f(stage,'pdo_stage','route')==self.f(end,'pdo_stage','route'),'actual route remains installed throughout terminal capture')
        self.eq(ph,'pe_header',version=2,serial=self.i(ph,'pe_header','serial'),generation=generation,registry=self.symbol('pe'),generated=self.generated,spill=self.spill,table=self.table,plan_proof=2,none_proof=1,source_validations=1,registered_epoch=1,rseq_address=RSEQ,rseq_length=32,rseq_signature=0x53053053)
        zero(self.f(ph,'pe_header','reserved'),'whole immutable header reserved tail')
        binding=self.image['persistent_binding'];need(binding['version']==1 and binding['profile']=='persistent-dynamic-adjacent-two-page-v1','explicit dynamic source/archive binding')
        need(self.f(ph,'pe_header','archive')==bytes.fromhex(binding['archive']['sha256'])and self.f(ph,'pe_header','policy')==bytes.fromhex(binding['policy_sha256']),'whole immutable archive and policy authority')
        key=self.f(payload,'pe_payload','source');self.source_key(key,entry);expected,donor,heads,exitpc=self.compact_plan(payload,which)
        need(self.f(b,t,'initial_code')==self.f(b,t,'terminal_code')==expected['code'],'whole literal code image unchanged through terminal')
        g=self.f(stage,'pdo_stage','generation');eg=self.f(end,'pdo_stage','generation');gt='li2_pe_generation'
        buildserial=self.i(g,gt,'build_serial');self.eq(g,gt,installed=1,complete=1,proof_complete=1,generation=generation,ready_generation=generation,build_serial=buildserial,plan_proofs=2,none_proofs=1,generated=self.generated,proof=self.proof,spill=self.spill,code_copied=32768,code_verified=32768,proof_zeroed=192512,proof_copied=self.r.types['pe_payload']['bytes'],proof_verified=192512)
        need(self.i(ph,'pe_header','serial')==buildserial and (buildserial<serial if warm else buildserial==serial),'cold build serial retained across actual warm entry')
        self.query(self.f(g,gt,'code_writable'),self.generated,3,pages=8);self.query(self.f(g,gt,'proof_writable'),self.proof,3,pages=47);self.query(self.f(g,gt,'spill_query'),self.spill,3)
        for k,address,prot,pages in(('code_sealed',self.generated,1,8),('proof_sealed',self.proof,1,47),('open',self.generated,5,8)):self.permission(self.f(g,gt,k),address,prot,pages)
        for k in('close','cleanup'):zero(self.f(g,gt,k),'no premature generation close')
        self.r.change(g,eg,gt,values={'ready_generation':0}if failed else{},observed=('cleanup',)if failed else('close',))
        self.permission(self.f(eg,gt,'cleanup'if failed else'close'),self.generated,1,8)
        if warm:
            self.r.change(resident,g,gt,observed=('open','close','cleanup'));need(previous is not None and previous['payload']==payload,'warm retains actual preceding immutable primary')
        else:need(generation==pc['next_generation']+1,'cold replacement advances actual generation')
        info=self.f(b,t,'info');it='pdo_epoch_info';self.eq(info,it,selected_bank=0,warm=int(warm),initialized=1,registered=1,code_allocated=2,proof_allocated=1,code_registered=2,proof_registered=1,close_started=1,close_complete=1,prepare_started=1,prepare_complete=1,build_started=int(not warm),build_returned=int(not warm),redirected=1,exit_seen=int(not failed),exit_index=0,recovery_started=1,recovery_complete=1,guest_data_fault=int(self.app['mode']==1),cleanup_started=int(failed),cleanup_complete=int(failed),consumed=1,plan_proofs=0 if warm else 2,none_proofs=0 if warm else 1,code_allocation=self.h[29],proof_allocation=self.proof,build_result=0,recovery_result=0,release_result=0,ticket=self.symbol('span_transfer'),flags_written=0x8d5)
        self.eq(self.f(info,it,'token'),'li2_pe_token',owner=self.symbol('pe'),serial=serial)
        need(self.f(info,it,'session')==self.f(self.b,'pdo_wire','session'),'whole actual unchanged selected session')
        self.eq(info,it,registry_count=len(self.ranges));need(self.f(info,it,'registry')==self.f(initial,'pdo_registry','ranges'),'whole actual registry used by immutable proof')
        banks=self.r.items(info,it,'banks','ped_bank')
        for i,bank in enumerate(banks):
            address=self.h[26 if i==0 else 29];spill=self.h[28 if i==0 else 30]
            self.eq(bank,'ped_bank',generated=address,spill=spill,allocated=1,registered=1)
            self.query(self.f(bank,'ped_bank','initial'),address,3,pages=8);self.query(self.f(bank,'ped_bank','initial_spill'),spill,3)
            if i==0:self.eq(bank,'ped_bank',virgin=0,prot=1 if not failed else 5)
            else:need(self.i(bank,'ped_bank','virgin')in(0,1)and self.i(bank,'ped_bank','prot')in(1,3),'unused or formerly completed high bank actual state')
        if installed:
            for k,address,prot,pages in(('claim_code',self.i(resident,gt,'generated'),1,8),('claim_proof',self.proof,1,47),('claim_spill',self.i(resident,gt,'spill'),3,1)):self.query(self.f(info,it,k),address,prot,pages=pages)
        else:
            for k in('claim_code','claim_proof','claim_spill'):zero(self.f(info,it,k),'no invented resident permit claim')
        if warm:
            for k in('bank_before','proof_before','reopen_code','reopen_proof'):zero(self.f(info,it,k),'warm entry never reopens writable code/proof')
        else:
            self.query(self.f(info,it,'bank_before'),self.generated,self.i(self.f(info,it,'bank_before'),'li2_private_code_query','actual_prot'),pages=8)
            need(self.i(self.f(info,it,'bank_before'),'li2_private_code_query','actual_prot')in(1,3),'actual cold target closed or virgin bank')
            self.query(self.f(info,it,'proof_before'),self.proof,1 if pc['next_generation']else 3,pages=47)
            self.permission(self.f(info,it,'reopen_code'),self.generated,3,8);self.permission(self.f(info,it,'reopen_proof'),self.proof,3,47)
            need(self.f(g,gt,'code_writable')==self.f(self.f(info,it,'reopen_code'),'le_permission','query')and self.f(g,gt,'proof_writable')==self.f(self.f(info,it,'reopen_proof'),'le_permission','query'),'actual reopen before new generation publication')
        before=self.frame(self.f(b,t,'before'));ingress=self.normalized(self.f(b,t,'ingress'),before);returned=self.frame(self.f(b,t,'returned'));after=self.frame(self.f(b,t,'after'))
        flags=before['greg'][17];self.eq(info,it,flags=flags,gpr_written=(1<<0)|(1<<7)|((1<<2)|(1<<3)|(1<<10)if which=='a'else 0))
        self.trace(ingress,entry,flags|TF);self.trace(before,entry,flags);self.same_event(ingress,before,flags)
        want=list(before['greg']);want[16]=self.generated
        need(returned['greg']==tuple(want)and returned['fp']==before['fp']and returned['si']==before['si']and(returned['fs'],returned['gs'])==tuple(self.app['machine'][1:3]),'actual redirect changes only RIP')
        uc=bytearray(before['uc']);struct.pack_into('<Q',uc,40+16*8,self.generated);need(returned['uc']==bytes(uc),'whole return UC except actual RIP redirect')
        need(after['fp']==before['fp']and after['fp_bytes']==before['fp_bytes']and after['mask']==MASK and(after['fs'],after['gs'])==tuple(self.app['machine'][1:3]),'whole FP/AF/mask/TLS through generated epoch')
        projection=self.f(b,t,'predecessor');xt='pdo_predecessor';self.eq(projection,xt,complete=1,unexpected_compared=self.r.types['li2_step_frame']['bytes'],unexpected_nonzero=0)
        slot=self.f(projection,xt,'closed')+bytes(self.r.types['li2_step_frame']['bytes']);self.r.walk(slot,'li2_tf_chain_slot')
        prefix=self.f(projection,xt,'before_prefix');endprefix=slot[:len(prefix)]
        # The literal preclose prefix differs only at the real slot/step close fields.
        wanted=bytearray(prefix);sf=self.r.types['li2_tf_chain_slot']['fields'];of=self.r.types['li2_tf_owner']['fields'];tf=self.r.types['li2_step_owner']['fields']
        struct.pack_into('<I',wanted,sf['phase']['offset'],5)
        base=sf['owner']['offset']+of['step']['offset']
        for name,value in(('phase',5),('trace_seen',1),('revoke_sync_started',1)):struct.pack_into('<I',wanted,base+tf[name]['offset'],value)
        need(bytes(wanted)==endprefix,'whole actual predecessor prefix changes only completed close state')
        need(self.i(slot,'li2_tf_chain_slot','index')==h[15]and self.i(slot,'li2_tf_chain_slot','event_id')<h[17],'actual captured predecessor selection/chronology')
        predpc=self.page+(0x100 if index==0 and not failed else 0x219 if index else 0x1fe)
        pbefore,oldref=self.predecessor(slot,predpc,ingress)
        # Prefix independently records that this was executing before the real close.
        pp=prefix+bytes(self.r.types['li2_tf_chain_slot']['bytes']-len(prefix));self.eq(pp,'li2_tf_chain_slot',phase=3)
        self.eq(self.f(self.f(pp,'li2_tf_chain_slot','owner'),'li2_tf_owner','step'),'li2_step_owner',phase=3,trace_seen=0,revoke_sync_started=0)
        ref=self.f(info,it,'ref');seq=self.i(ref,'li2_fetch_ref','sequence');tr=self.f(stage,'pdo_stage','transfer');self.transfer(tr,slot,ingress,before,ref)
        need(self.f(end,'pdo_stage','transfer')==tr and self.i(tr,'li2_span_transfer_progress','event')==h[17]and self.i(tr,'li2_span_transfer_progress','serial')==self.i(p,pt,'transfer_serial'),'whole actual single-use transfer remains immutable')
        es=self.f(stage,'pdo_stage','source');zs=self.f(end,'pdo_stage','source');a=self.source(es,serial,entry,key,ref);z=self.source(zs,serial,entry,key,ref,True,failed);need((a,z)==(2,3),'exact fresh source validation chronology')
        need(self.f(es,'li2_pe_source_progress','source')==self.f(zs,'li2_pe_source_progress','source'),'whole current attempt source anchor/key retained')
        er=self.f(stage,'pdo_stage','rseq');zr=self.f(end,'pdo_stage','rseq');estate=self.f(stage,'pdo_stage','state');zstate=self.f(end,'pdo_stage','state')
        a=self.pin(er,estate,serial,0 if warm else heads,0 if warm else 1);z=self.pin(zr,zstate,serial,0 if warm else heads,0 if warm else 1,True,failed);need(z>a and estate==zstate,'actual zero-word checks and unchanged old registration/footprint state')
        lastpc,lastcode,lastlen=(self.page+0x219,765,2)if warm else(self.page+0x216,282,3)if which=='a'else(self.page+0x407,249,4)
        self.eq(estate,'li2_rseq_state',last_first=0,last_end=0,last_pc=lastpc,last_code=lastcode,last_policy=1)
        self.eq(self.f(estate,'li2_rseq_state','last_footprint'),'li2_write_footprint',pc=lastpc,next_pc=lastpc+lastlen,first=0,end=0,abi_version=1,policy=1,code=lastcode,length=lastlen)
        self.progress(self.f(stage,'pdo_stage','fetch'),seq,True);self.progress(self.f(end,'pdo_stage','fetch'),seq,False);need(self.f(info,it,'final_fetch')==self.f(end,'pdo_stage','fetch'),'actual terminal released fetch snapshot')
        lives=self.r.items(info,it,'live','li2_link_rseq_live')
        for x in lives[:2]:self.live_rseq(x,estate,before)
        if failed:zero(lives[2],'no fabricated successful exit guard')
        else:self.live_rseq(lives[2],zstate,after)
        if failed:
            zero(self.f(info,it,'proof_exit'),'failed prefix has no normal proof-exit query');zero(self.f(info,it,'code_exit'),'unused code query')
            recovered=self.f(info,it,'recovered');rt='li2_pe_recovered';self.eq(recovered,rt,original_pc=entry,head=0,kind=4,phase=1 if self.app['mode']==1 else 3,complete=1)
            need(self.f(info,it,'recovery_scratch')==donor,'whole actual guard recovery materialization')
            need(after['greg'][16]==self.generated+expected['store'if self.app['mode']==1 else'reject'],'exact actual guard boundary')
            need(q(self.f(recovered,rt,'gpr'))==tuple(after['greg'][i]for i in GREG)and self.i(recovered,rt,'flags')==after['greg'][17],'complete recovered architectural register/flag state')
            logical=list(after['greg']);logical[16]=entry
            if self.app['mode']==1:need(after['sig']==11 and struct.unpack_from('<iii',after['si'])==(11,0,2)and after['greg'][19:21]==(6,14)and after['greg'][22]==DATA+8192 and int.from_bytes(after['si'][16:24],'little')==DATA+8192,'actual late third store fault')
            else:
                need(after['sig']==4 and struct.unpack_from('<iii',after['si'])==(4,0,2)and after['greg'][19:21]==(0,6)and int.from_bytes(after['si'][16:24],'little')==after['greg'][16],'actual protected-word guard UD2')
                need(q(self.f(recovered,rt,'gpr'))==self.app['seed'][0]and self.i(recovered,rt,'flags')==self.app['seed'][1]|RF,'protected publication word rejection has zero store effect')
            logical=dict(after,greg=tuple(logical));need(self.f(end,'pdo_stage','permit')==self.f(stage,'pdo_stage','permit'),'failure cannot issue a completion permit');self.eq(self.f(end,'pdo_stage','permit'),'ped_permit',valid=0)
        else:
            self.nx(after,exitpc);logical=after
            zero(self.f(info,it,'recovered'),'normal exit has no invented recovery');zero(self.f(info,it,'recovery_scratch'),'normal exit no recovery scratch')
            self.query(self.f(info,it,'proof_exit'),self.proof,1,pages=47);zero(self.f(info,it,'code_exit'),'unused code query')
            self.permit(self.f(end,'pdo_stage','permit'),eg,zs,zr,self.f(end,'pdo_stage','fetch'))
            need(self.f(self.f(end,'pdo_stage','permit'),'ped_permit','generation_source')==key,'completion permit retains actual immutable source key')
        self.eq(self.f(stage,'pdo_stage','permit'),'ped_permit',valid=0)
        bm=self.memory(self.f(b,t,'before_memory'),False);am=self.memory(self.f(b,t,'after_memory'),failed)
        need(bm['stack']==am['stack']==self.app['stack'],'whole unchanged actual stack')
        want=bytearray(bm['data']);writes=(range(1,5)if index==0 else(5,)if index==1 else(6,))if not failed else(range(1,3)if self.app['mode']==1 else())
        offset=(0 if index==0 else 24 if index==1 else 32)if not failed else 8176
        for i,v in enumerate(writes):struct.pack_into('<Q',want,offset+8*i,v)
        need(am['data']==bytes(want),'exact actual completed writes with no fault/rejection store')
        if previous is not None:
            need(bm==previous['after_memory'],'whole memory at consecutive generated boundaries')
            need(self.f(b,t,'prior_permit')==previous['permit_raw']and self.f(b,t,'prior_generation')==previous['generation_raw'],'actual prior completed permit and generation retained before next attempt')
            need(self.f(b,t,'prior_counts')==previous['counts_raw'],'no intervening dynamic offer between focal generated entries')
        else:need(bm['data']==self.app['data'],'whole initial application data before first accepted epoch')
        return dict(kind=kind,mode=self.app['mode'],ingress=ingress,before=before,returned=returned,after=after,logical=logical,predecessor_before=pbefore,before_memory=bm,after_memory=am,completed=int(not failed),guest_data_fault=int(self.app['mode']==1),guard_rejected=int(self.app['mode']==2),closed_pages=8,anchor_released=1,permit=int(not failed),interior_signals=0,payload=payload,permit_raw=self.f(end,'pdo_stage','permit'),generation_raw=eg,counts_raw=self.f(end,'pdo_stage','counts'),source_raw=zs,pin_raw=zr)

    def miss(self,b):
        t='pdo_miss';h=q(self.f(b,t,'h'));entry=self.page+0x100
        need(h[0]==1 and h[1]>0 and h[2]==entry and h[3]in(0,1)and h[4:10]==(1,1,1,h[1],1,1)and h[10]==h[1]+1 and h[11:13]==(0,1),'actual classified miss and first real resumed TRACE')
        need(h[13]==self.symbol('selected_session')and h[14]>0 and h[15]<U64 and h[16:21]==(h[3],1,0,0,1)and not any(h[21:]),'actual full preclose M chain selector')
        initial=self.f(b,t,'initial_registry');need(initial==self.f(b,t,'terminal_registry'),'miss cancellation keeps whole registry')
        self.ranges,_=self.registry_prefix(self.f(self.b,'pdo_wire','startup_registry'),initial)
        before=self.frame(self.f(b,t,'before'));ingress=self.normalized(self.f(b,t,'ingress'),before);returned=self.frame(self.f(b,t,'returned'));nexttrace=self.normalized(self.f(b,t,'next_trace'),before)
        flags=self.app['seed'][1];self.trace(ingress,entry,flags|TF);self.trace(before,entry,flags);self.same_event(ingress,before,flags);self.trace(returned,entry,flags|TF);self.same_event(before,returned,flags|TF)
        self.trace(nexttrace,self.page+0x200,flags|TF)
        want=list(returned['greg']);want[16]=self.page+0x200
        need(nexttrace['greg']==tuple(want)and nexttrace['fp']==returned['fp'],'actual JMP resume changes only RIP and retains all flags/FP')
        previous=self.f(b,t,'predecessor');pbefore,oldref=self.predecessor(previous,self.page+0xfe,ingress,False)
        need(self.i(previous,'li2_tf_chain_slot','index')==h[3]and self.i(previous,'li2_tf_chain_slot','event_id')<h[14],'actual M predecessor indexed and older event')
        held=self.f(b,t,'held');end=self.f(b,t,'resumed');p=self.f(held,'pdo_stage','progress');ep=self.f(end,'pdo_stage','progress');pt='li2_pe_progress';serial=self.i(p,pt,'serial')
        self.generated,self.proof,self.spill=self.h[26],self.h[27],self.h[28];self.table=self.proof+self.r.types['pe_payload']['fields']['plan']['offset']+self.r.types['li2_pe_compact']['fields']['table']['offset']
        self.eq(p,pt,serial=serial,registration_epoch=1,phase=4,first_error=0,source_count=2,opened_pages=0,closed_pages=0,anchor_released=0,registration_rechecked=0,completion_permit=0,first_detail=0,generated=self.generated,proof=self.proof,table=self.table,spill=self.spill,generation=0,publication=0)
        need(q(self.f(p,pt,'source'))==(self.page,self.page+PAGE),'M actual source pair')
        self.r.change(p,ep,pt,values=dict(phase=14,anchor_released=1,registration_rechecked=1))
        self.eq(held,'pdo_stage',busy=1,active=0,failing=0,resuming=0,route=0,pending=0)
        self.eq(end,'pdo_stage',busy=1,active=0,failing=0,resuming=1,pending=1);need(0<self.i(end,'pdo_stage','route')<32,'real ordinary successor route after cancel')
        self.delta(self.f(b,t,'prior_counts'),self.f(held,'pdo_stage','counts'),next_serial=1,offers=1,cold_attempts=1,miss_reason=1)
        self.delta(self.f(held,'pdo_stage','counts'),self.f(end,'pdo_stage','counts'),cancelled=1)
        for name,tag in(('prior_generation','generation'),('prior_permit','permit')):
            need(self.f(b,t,name)==self.f(held,'pdo_stage',tag)==self.f(end,'pdo_stage',tag),'miss never claims or alters existing resident '+tag)
        prior=self.f(b,t,'prior_generation')
        if self.i(prior,'li2_pe_generation','installed'):self.permit(self.f(b,t,'prior_permit'),prior)
        else:zero(self.f(b,t,'prior_permit'),'miss has no fabricated virgin permit')
        encoded=self.f(b,t,'plan');mt='pdo_miss_plan';fullt='li2_pe_plan';full=bytearray(self.r.types[fullt]['bytes'])
        for k in('version','bytes','ready','result','heads','exits','stores','source_bytes','source_mask','decoder_result','guard_result','reserved','page','entry','generated','spill','source','table'):
            f=self.r.types[fullt]['fields'][k];value=self.f(encoded,mt,k);need(len(value)==f['bytes'],'exact unready plan projection extent');full[f['offset']:f['offset']+f['bytes']]=value
        fields=self.r.types[fullt]['fields'];omitted=len(full)-fields['image']['offset']-fields['table']['bytes']
        self.eq(encoded,mt,scan_started=1,scan_complete=1,scanned=omitted,nonzero=0,first_nonzero=0,first_value=0)
        full=bytes(full);self.r.walk(full,fullt)
        self.eq(full,fullt,version=1,bytes=496024,ready=0,result=1,heads=0,exits=0,stores=0,source_bytes=0,source_mask=1,decoder_result=0,guard_result=0,reserved=0,entry=entry,generated=self.generated,spill=self.spill)
        need(q(self.f(full,fullt,'page'))==(self.page,self.page+PAGE)and self.f(full,fullt,'source')==self.app['source'],'actual complete unready M source input')
        expected=plan.table(self.ranges+[(self.page,self.page+PAGE),(self.page+PAGE,self.page+2*PAGE),(RSEQ+8,RSEQ+16)],self.table)
        need(self.f(full,fullt,'table')==expected,'unready M still binds complete actual guard exclusions')
        for k in('image','head','original','frontier','store_original','exit_pc','guard'):zero(self.f(full,fullt,k),'unready M has no invented plan authority')
        self.eq(self.f(b,t,'miss'),'li2_pe_dynamic_miss',version=1,status=1,reason=1,site=1,pc=entry,detail=1)
        source=self.f(held,'pdo_stage','source');src=self.f(source,'li2_pe_source_progress','source');key=self.f(src,'li2_pe_sources','key');ref=self.f(src,'li2_pe_sources','anchor')
        self.source(source,serial,entry,key,ref,cancel=True);self.source(self.f(end,'pdo_stage','source'),serial,entry,key,ref,terminal=True,cancel=True)
        es=self.f(held,'pdo_stage','state');zs=self.f(end,'pdo_stage','state');a=self.pin(self.f(held,'pdo_stage','rseq'),es,serial,0,0,cancel=True);z=self.pin(self.f(end,'pdo_stage','rseq'),zs,serial,0,0,True,cancel=True);need(z>a,'actual registered cancel checks before ordinary successor')
        instruction_checks=self.i(es,'li2_rseq_state','instruction_checks')
        need(instruction_checks<U64,'ordinary resumed instruction check increment cannot wrap')
        self.r.change(es,zs,'li2_rseq_state',values={'instruction_checks':instruction_checks+1},observed=('last_first','last_end','last_pc','last_code','last_policy','last_footprint'))
        self.eq(zs,'li2_rseq_state',last_first=0,last_end=0,last_pc=entry,last_code=765,last_policy=1)
        self.eq(self.f(zs,'li2_rseq_state','last_footprint'),'li2_write_footprint',pc=entry,next_pc=entry+3,first=0,end=0,abi_version=1,policy=1,code=765,length=3)
        chain=self.f(b,t,'resumed_chain');ct='li2_tf_chain';self.eq(chain,ct,session=self.symbol('selected_session'),initialized=1,first_error=0,first_detail=0,active=h[3]^1,pending=1,in_handler=0,event_id=h[14],sequence=h[15]+1,unexpected_events=0)
        need(canonical(self.i(chain,ct,'failure')),'actual chain failure callback');slots=self.r.items(chain,ct,'slots','li2_tf_chain_slot');closed=slots[h[3]];successor=slots[h[3]^1]
        self.predecessor(closed,self.page+0xfe,ingress)
        self.r.change(previous,closed,'li2_tf_chain_slot',observed=('phase','owner','fetch','release','query'))
        before_owner=self.f(previous,'li2_tf_chain_slot','owner');after_owner=self.f(closed,'li2_tf_chain_slot','owner')
        self.r.change(before_owner,after_owner,'li2_tf_owner',observed=('step','actual_post_pc','actual_post_flags','continuation_started','continuation_complete'))
        self.r.change(self.f(before_owner,'li2_tf_owner','step'),self.f(after_owner,'li2_tf_owner','step'),'li2_step_owner',observed=('phase','trace_seen','revoke_sync_started','after','revoke_started','revoked','signal_number','signal_code','signal_errno','signal_address'))
        tr=self.f(held,'pdo_stage','transfer');self.transfer(tr,closed,ingress,before,ref,False);need(self.i(tr,'li2_span_transfer_progress','event')==h[14],'real M closed ticket event')
        resumed=self.f(end,'pdo_stage','transfer');tt='li2_span_transfer_progress';self.r.change(tr,resumed,tt,observed=('phase','resume_attempted','resumed','next','successor_installed','fresh_borrow','fresh'))
        self.eq(resumed,tt,phase=5,resume_attempted=1,resumed=1,next=h[3]^1,successor_installed=1,fresh_borrow=self.i(ref,'li2_fetch_ref','sequence'))
        self.observation(self.f(resumed,tt,'fresh'),entry,False,ref)
        _,newref=self.predecessor(successor,entry,nexttrace,False);self.eq(successor,'li2_tf_chain_slot',origin=2,event_id=h[14])
        need(self.i(newref,'li2_fetch_ref','sequence')>self.i(ref,'li2_fetch_ref','sequence'),'actual ordinary successor acquires newer borrow after cancelled release')
        self.progress(self.f(held,'pdo_stage','fetch'),self.i(ref,'li2_fetch_ref','sequence'),True)
        self.progress(self.f(end,'pdo_stage','fetch'),self.i(newref,'li2_fetch_ref','sequence'),True)
        st=self.f(self.f(successor,'li2_tf_chain_slot','owner'),'li2_tf_owner','step');self.step_frame(self.f(st,'li2_step_owner','before'),before)
        en=self.f(chain,ct,'entry');self.eq(en,'li2_tf_trace_entry',valid=0,previous=h[3],next=h[3]^1,event_id=h[14],sequence=h[15]+1,previous_generation=self.i(closed,'li2_tf_chain_slot','generation'),next_generation=self.i(successor,'li2_tf_chain_slot','generation'),pc=entry,flags=flags,previous_borrow_sequence=self.i(oldref,'li2_fetch_ref','sequence'))
        lease=self.f(chain,ct,'lease');self.eq(lease,'li2_tf_same_page',origin_active=0)
        memory=self.memory(self.f(b,t,'before_memory'),False);need(memory==dict(data=self.app['data'],stack=self.app['stack']),'actual miss input data/stack, not a fabricated observation')
        return dict(kind='miss',mode=0,ingress=ingress,before=before,returned=returned,after=nexttrace,logical=nexttrace,predecessor_before=pbefore,before_memory=memory,after_memory=memory,completed=0,permit=0,classified_miss=1,interior_signals=0,counts_raw=self.f(end,'pdo_stage','counts'))

    def finish(self,status):
        h=self.h;t='pdo_wire';r=self.r;mode=self.app['mode'];failed=mode!=0;code,detail=(3304,11 if mode==1 else 4)if failed else(0,0)
        need(type(status)is int and status==(125 if failed else 0),'actual exact expected process exit')
        need(h[:9]==(0x314f445049324c,1,r.types[t]['bytes'],r.layout['registrations']['pe']['bytes'],191136,192512,32768,968,128),'actual distinct dynamic record version and complete extents')
        need(canonical(self.bias)and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(n)for n in('li2_raw6','li2_gateway_start','li2_gateway_end'))and h[10]<=h[9]<h[11],'actual emitted gateway identity')
        need(h[12]%PAGE==0 and h[13]==524288 and h[14:16]==(1,0)and h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,mode),'actual altstack and FD3/profile')
        need(h[20:26]==tuple(self.symbol(n)for n in('pe','pdo_wire','pe_source','pe_rseq','selected_chain','span_progress')),'actual protected singleton addresses')
        need(PAGE<=h[26]<1<<31 and all(x%PAGE==0 for x in h[26:31])and h[28]==h[26]+32768 and h[30]==h[29]+32768 and all(canonical(a,n)for a,n in((h[26],36864),(h[27],192512),(h[29],36864))),'actual two distinct whole anonymous banks/proof')
        ranges=[(h[26],h[28]+PAGE),(h[27],h[27]+192512),(h[29],h[30]+PAGE)];need(all(z<=b or e<=a for i,(a,z)in enumerate(ranges)for b,e in ranges[i+1:]),'separate actual code/spill/proof allocations')
        need(h[31:35]==(self.page+0x100,self.page+0x200,self.page+0x400,1 if failed else 3)and not any(h[35:47])and h[47:53]==(1,status,code,detail,h[16],0)and not any(h[53:]),'exact focal population and retained terminal prefix')
        raw=q(self.f(self.b,t,'raw_ingress'));need(sum(raw[1:])==raw[0]>0,'whole raw signal population')
        for k in('sink_initial','sink_terminal'):
            st=self.f(self.b,t,k);d=self.stat(st);need(d['mode']&0xffff==0x8180 and d['size']==0,'actual empty regular0600 sink');self.eq(st,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(self.f(self.b,t,'sink_initial'),self.f(self.b,t,'sink_terminal'),'stat',observed=('st_atim','st_mtim','st_ctim'))
        footer=q(r.data[-64:]);need(footer[:4]==(0x3146445049324c,1,len(self.b),len(self.b))and 1<=footer[4]<=64 and 0<footer[5]<=len(self.b)and footer[6:]==(status,code),'complete real output footer')
        if footer[4]==1:need(footer[5]==len(self.b),'single actual complete wire write')
        hardware=self.f(self.b,t,'hardware');self.eq(hardware,'li2_selected_hardware',abi_version=1,reserved=0)
        for i,k in enumerate(('leaf0','leaf1','leaf7')):need(struct.unpack('<4I',self.f(hardware,'li2_selected_hardware',k))==tuple(self.app['hardware'][i][2:]),'actual bridge/app CPUID hardware equality')
        for key,objid in(('main',self.image['main_object']),('interpreter',self.image['interpreter_object'])):self.image_header(self.f(self.b,t,key),objid)
        self.eq(self.f(self.b,t,'session'),'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        need(self.i(self.f(self.b,t,'session'),'li2_step_session','sync_query')&96==96,'actual registered membarrier support')
        obj,_,loads=self.objects[self.image['main_object']];bias=self.bases[self.image['main_object']]
        owners=[p for p in loads if p[1]==5 and bias+p[3]<=self.page and self.page+8192<=bias+p[3]+p[5]]
        need(len(owners)==1 and self.source_offset==owners[0][2]+self.page-bias-owners[0][3]and obj['data'][self.source_offset:self.source_offset+8192]==self.app['source'],'whole source two-page original ELF bytes')
        epochs=r.items(self.b,t,'epochs','pdo_epoch');attempts=[]
        if failed:zero(self.f(self.b,t,'miss'),'failure profile has no invented M miss')
        else:attempts.append(self.miss(self.f(self.b,t,'miss')))
        previous=None
        for i in range(1 if failed else 3):
            result=self.epoch(epochs[i],i,('cold','warm','replacement')[i],previous)
            if i==0 and not failed:
                need(result['ingress']['raw']==self.f(self.f(self.b,t,'miss'),'pdo_miss','next_trace'),'first actual resumed TRACE is the A ingress')
                need(self.f(epochs[0],'pdo_epoch','prior_counts')==attempts[0]['counts_raw'],'no intervening dynamic offer between M resume and A')
            attempts.append(result);previous=result
        for b in epochs[1 if failed else 3:]:zero(b,'whole unused epoch capacity')
        if failed:
            unexpected=self.f(self.b,t,'unexpected_frame');self.frame(unexpected,False)
            self.r.change(unexpected,self.f(epochs[0],'pdo_epoch','after'),'le_frame',observed=('fs','gs','fs_result','gs_result','tls_complete'))
        else:zero(self.f(self.b,t,'unexpected_frame'),'no invented unexpected frame')
        final=self.counts(self.f(self.b,t,'final_counts'));last=self.counts(previous['counts_raw'])
        need(all(final[k]>=last[k]for k in final if k!='misses')and all(a>=b for a,b in zip(final['misses'],last['misses'],strict=True)),'final counters retain every focal event without attributing later work')
        names='version status failure_code detail_abs detail_negative phase serial generation build_serial offers cold_attempts publications hits cancelled retirements permit_claims entries completed unexpected permit opened_pages closed_pages anchor_released registration_rechecked guest_data_fault recovery_complete first_error active busy'.split();values=q(self.f(self.b,t,'final_row'));need(len(values)==len(names),'whole exact dynamic terminal scalar schema')
        row=dict(zip(names,values,strict=True));row['misses']=list(final['misses'])
        need(row['version']==1 and(row['status'],row['failure_code'],row['detail_abs'],row['detail_negative'])==(status,code,detail,0),'actual protected dynamic outcome')
        for k in('offers','cold_attempts','publications','hits','cancelled','retirements','permit_claims','entries','completed','unexpected'):need(row[k]==final[k],'whole final counter-to-report join '+k)
        p=self.f(self.b,t,'final_progress');pt='li2_pe_progress'
        for k in('phase','serial','generation','opened_pages','closed_pages','anchor_released','registration_rechecked','first_error'):need(row[k]==self.i(p,pt,k),'actual final progress-to-report join '+k)
        need(final['offers']==final['entries']+final['cancelled']and final['entries']==final['publications']+final['hits']and final['cold_attempts']==final['publications']+final['cancelled']and sum(final['misses'])==final['cancelled']and final['next_serial']==final['offers']and final['next_generation']==final['publications'],'whole completed/cancelled actual partition')
        need(final['entries']==final['completed']+int(failed)and final['unexpected']==int(failed)and final['retirements']==final['publications']-1 and final['permit_claims']==final['retirements']+final['hits'],'whole one-resident permit/publication accounting')
        if failed:need(self.f(self.b,t,'final_counts')==previous['counts_raw']and p==self.f(self.f(epochs[0],'pdo_epoch','terminal'),'pdo_stage','progress')and(row['active'],row['busy'],row['permit'])==(1,1,0),'failure preserves exact actual terminal prefix')
        else:need(row['phase']in(13,14)and row['active']==row['busy']==row['first_error']==0,'actual final quiescent release or cancellation')
        return dict(terminal=row,mode=mode,attempts=attempts,classified_misses=int(not failed),cold_publications=1 if failed else 2,warm_entries=int(not failed),replacements=int(not failed),permit_claims=0 if failed else 2,interior_signals=0,source=self.app['source'],word=0,status=status,code=code,detail=detail,whole_reuse_credit=0)


def read(data,layout,image,app,pid,cpu,exit_status):
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    return Check(wire.Reader(data,layout),image,app,pid,cpu).finish(exit_status)


def terminal(parsed,owner):
    expected=owner['terminal'];need(type(parsed)is dict and set(parsed)==set(expected)and all(type(v)is int for k,v in parsed.items()if k!='misses')and type(parsed['misses'])is list and all(type(v)is int for v in parsed['misses'])and parsed==expected,'whole actual protected dynamic terminal row')
    return dict(fields=len(expected),protected_dynamic_row=1,inherited_row_protection=0)


CONTROL_COUNTS={0:55,1:30,2:30}

def controls(data,layout,image,app,pid,cpu,exit_status):
    """Supplied mutations of actual finite records, never native evidence."""
    read(data,layout,image,app,pid,cpu,exit_status);mode=app['mode'];types=layout['types']
    def at(t,k,base=0,index=0,child=None):return base+types[t]['fields'][k]['offset']+(index*types[child]['bytes']if child else index)
    w='pdo_wire';et='pdo_epoch';st='pdo_stage';it='pdo_epoch_info';e=at(w,'epochs');entered=at(et,'entered',e);terminal=at(et,'terminal',e);info=at(et,'info',e)
    g=at(st,'generation',terminal);p=at(st,'progress',terminal);initial=at(et,'initial_payload',e);cp=at('pe_payload','plan',initial)
    source=at(st,'source',terminal);pin=at(st,'rseq',terminal);mem=at(et,'after_memory',e)
    tests=[('wire_version',8),('footer_version',len(data)-56),('interior_event',at(et,'h',e)+11*8),
      ('actual_hardware',at('li2_selected_hardware','leaf0',at(w,'hardware'))),
      ('entry_publication_word',at('li2_pe_rseq_progress','word_entry',at(st,'rseq',entered))),
      ('terminal_publication_word',at('li2_pe_rseq_progress','word_after',pin)),
      ('second_source_byte',at('li2_pe_compact','source',cp)+4096),('whole_generated_code',at(et,'terminal_code',e)),
      ('proof_padding',at(et,'terminal_tail',e)),
      ('live_guard_GPR',at('li2_write_registers','gpr',at('li2_link_rseq_live','registers',at(it,'live',info)))),
      ('guard_recovery_row',at('li2_mg_boundary','dirty',at('li2_pe_guard_record','boundary',at('li2_pe_compact','guard',cp)))),
      ('immutable_generation',at('pe_header','generation',at('pe_payload','header',initial))),
      ('static_plan_proof',at(it,'plan_proofs',info)),('cold_NONE_proof',at(it,'none_proofs',info)),
      ('actual_code_revoke',at('le_permission','complete',at('li2_pe_generation','cleanup'if mode else'close',g))),
      ('actual_anchor_release',at('li2_pe_source_progress','release_complete',source)),
      ('completion_permit',at('li2_pe_progress','completion_permit',p)),
      ('whole_terminal_FP',at('li2_step_frame','fp',at('le_frame','frame',at(et,'after',e)))),
      ('actual_store_effect',at('li2_pdo_memory','data',mem)+(8176 if mode==1 else 0))]
    need(len(tests)==19,'all original fixed-owner control purposes retained in the distinct schema')
    startup=at(w,'startup_registry');reg=at(et,'terminal_registry',e);rt='pdo_registry'
    tests += [('startup_population',at(rt,'count',startup)),('startup_table_headers',at(rt,'ph',startup)),
      ('startup_range_prefix',at(rt,'ranges',startup)),('startup_classification_prefix',at(rt,'initial_code',startup)),
      ('epoch_terminal_population',at(rt,'count',reg)),('epoch_owner_population',at(it,'registry_count',info))]
    registry_expected={
        'startup_population':('startup registry population is an exact predecessor',True),
        'startup_table_headers':('startup registry keeps exact table, bridge and program headers',False),
        'startup_range_prefix':('startup registry retains every original range and classification',False),
        'startup_classification_prefix':('startup registry retains every original range and classification',False),
        'epoch_terminal_population':('entire protected range registry unchanged during accepted epoch',False),
        'epoch_owner_population':('exact pdo_epoch_info.registry_count',False)}
    pred=at(et,'predecessor',e);closed=at('pdo_predecessor','closed',pred);owner=at('li2_tf_chain_slot','owner',closed);step=at('li2_tf_owner','step',owner)
    tests += [('whole_predecessor_before_FP',at('li2_step_frame','fp',at('li2_step_owner','before',step))),
      ('whole_predecessor_after_FP',at('li2_step_frame','fp',at('li2_step_owner','after',step))),
      ('predecessor_actual_revoke',at('li2_step_owner','revoked',step)),
      ('predecessor_unexpected_scan',at('pdo_predecessor','unexpected_nonzero',pred))]
    if mode==0:
        m=at(w,'miss');mp=at('pdo_miss','plan',m);ms=at('pdo_miss','resumed',m);chain=at('pdo_miss','resumed_chain',m)
        tests += [('miss_scan_complete',at('pdo_miss_plan','scan_complete',mp)),('miss_scan_count',at('pdo_miss_plan','scanned',mp)),
          ('miss_omitted_nonzero',at('pdo_miss_plan','nonzero',mp)),('miss_source_mask',at('pdo_miss_plan','source_mask',mp)),
          ('miss_exact_reason',at('li2_pe_dynamic_miss','reason',at('pdo_miss','miss',m))),
          ('cancel_actual_bank_query',at('li2_private_code_query','complete',at('li2_pe_source_progress','cancel_code',at(st,'source',ms)))),
          ('cancel_rseq_completed',at('li2_pe_rseq_progress','cancel_complete',at(st,'rseq',ms))),
          ('resumed_successor_FP',at('li2_step_frame','fp',at('le_frame','frame',at('pdo_miss','next_trace',m)))),
          ('resumed_chain_generation',at('li2_tf_chain','sequence',chain))]
        a2=at(w,'epochs',index=1,child=et);ai=at(et,'info',a2);ae=at(et,'entered',a2)
        tests += [('warm_build_serial',at('li2_pe_generation','build_serial',at(st,'generation',ae))),
          ('warm_prior_permit',at('ped_permit','valid',at(et,'prior_permit',a2))),
          ('warm_actual_claim',at('li2_private_code_query','complete',at(it,'claim_code',ai))),
          ('warm_no_reopen',at('le_permission','started',at(it,'reopen_code',ai))),
          ('warm_no_static_reproof',at(it,'none_proofs',ai)),
          ('warm_prior_source_identity',at('li2_pe_source_key','entry',at('ped_permit','generation_source',at(et,'prior_permit',a2))))]
        b=at(w,'epochs',index=2,child=et);bi=at(et,'info',b);be=at(et,'entered',b)
        tests += [('replacement_prior_permit',at('ped_permit','valid',at(et,'prior_permit',b))),
          ('replacement_actual_claim',at('li2_private_code_query','complete',at(it,'claim_proof',bi))),
          ('replacement_actual_reopen',at('le_permission','complete',at(it,'reopen_code',bi))),
          ('replacement_generation',at('li2_pe_generation','generation',at(st,'generation',be))),
          ('replacement_retirement',at('pdo_counts','retirements',at(st,'counts',be))),
          ('replacement_B_image',at(et,'terminal_code',b))]
    refused=[]
    for name,offset in tests:
        mutant=bytearray(data);message,clear=registry_expected.get(name,(None,False))
        if clear:mutant[offset:offset+4]=bytes(4)
        else:mutant[offset]^=1
        try:read(bytes(mutant),layout,image,app,pid,cpu,exit_status)
        except ValueError as error:
            if message is not None:need(str(error)==message,'exact registry-boundary control refusal '+name)
            refused.append(name)
        else:raise ValueError('supplied dynamic owner corruption accepted '+name)
    mutant=bytearray(data)
    for k in('initial_payload','terminal_payload'):
        base=at('pe_payload','plan',at(et,k,e));d=at('li2_pe_compact','original',base,1,'li2_span_decoded');mutant[at('li2_span_decoded','gpr_write',d)]^=2
    try:read(bytes(mutant),layout,image,app,pid,cpu,exit_status)
    except ValueError as error:
        need(str(error)=='whole independent336-byte descriptors: code/operands/flags/GPR/static-NONE and refusals','exact coherent static-proof refusal');refused.append('coherent_static_descriptor')
    else:raise ValueError('coherent dynamic descriptor corruption accepted')
    if mode==0:
        # The actual registered ordinary successor checks M exactly once after
        # the held capture. Other old-rseq counters remain byte-identical.
        m=at(w,'miss');held_state=at(st,'state',at('pdo_miss','held',m))
        resumed_state=at(st,'state',at('pdo_miss','resumed',m))
        before_checks=struct.unpack_from('<Q',data,at('li2_rseq_state','instruction_checks',held_state))[0]
        resumed_checks=at('li2_rseq_state','instruction_checks',resumed_state)
        unrelated=at('li2_rseq_state','range_checks',resumed_state)
        range_checks=struct.unpack_from('<Q',data,unrelated)[0]
        for name,offset,value in (
            ('miss_ordinary_check_omitted',resumed_checks,before_checks),
            ('miss_ordinary_check_doubled',resumed_checks,(before_checks+2)&U64),
            ('miss_unrelated_range_check',unrelated,(range_checks+1)&U64)):
            mutant=bytearray(data);struct.pack_into('<Q',mutant,offset,value)
            try:read(bytes(mutant),layout,image,app,pid,cpu,exit_status)
            except ValueError as error:
                need(str(error)=='complete exact transition li2_rseq_state','exact ordinary-resume counter control refusal '+name)
                refused.append(name)
            else:raise ValueError('supplied ordinary-resume counter corruption accepted '+name)
        # Both actual TRACE copies must reject CALL's family even when their
        # whole descriptive/owner classification equality remains satisfied.
        chain=at('pdo_miss','resumed_chain',m)
        active=struct.unpack_from('<I',data,at('li2_tf_chain','active',chain))[0]
        successor=at('li2_tf_chain','slots',chain,active,'li2_tf_chain_slot')
        owner_classification=at('li2_tf_owner','classification',at('li2_tf_chain_slot','owner',successor))
        descriptive=at('li2_tf_chain_slot','descriptive_classification',successor)
        mutant=bytearray(data)
        for base in(owner_classification,descriptive):struct.pack_into('<I',mutant,at('li2_tf_classification','family',base),4)
        try:read(bytes(mutant),layout,image,app,pid,cpu,exit_status)
        except ValueError as error:
            need(str(error)=='exact li2_tf_classification.family','exact coherent JMP/CALL family refusal')
            refused.append('miss_coherent_call_family')
        else:raise ValueError('coherent CALL-family classification accepted for actual JMP')
    need(len(refused)==CONTROL_COUNTS[mode],'all exact separately counted dynamic owner controls')
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0,mode=mode)
