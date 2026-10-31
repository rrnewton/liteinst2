"""Actual single-generation persistent capture reader. Source-only snapshots
never authorize execution; compiled DWARF, source/build and native pairs are
separate mandatory caller joins. No warm/replacement or whole65 credit."""
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
    def __init__(self,r,image,app,pid,cpu):
        self.r,self.image,self.app,self.pid,self.cpu=r,image,app,pid,cpu
        self.b=r.data[:-64];self.h=q(self.f(self.b,'peo_wire','h'))
        self.bias=self.h[9]-r.layout['symbols']['li2_raw6'];self.head=app['head'];self.page=self.head&-PAGE
        self.objects={};self.bases={};self.backings={};self.maps_seen={};self.source_ids={}
        for key,obj in image['objects'].items():
            need(type(key)is int and type(obj)is dict,'actual complete object inventory')
            h,loads=old.elf(obj['data']);self.objects[key]=(obj,h,loads)
        need(image['main_object']in self.objects and image['interpreter_object']in self.objects,'actual source object identities')
        self.eh,self.ph,self.symbols=elf_symbols(image['bridge'])
        need(set(r.layout['symbols'])==set(self.symbols)|{'span_progress'}and all(r.layout['symbols'][k]==v[0]for k,v in self.symbols.items()),'same actual bridge/DWARF symbols')
        self.owner=self.f(self.b,'peo_wire','owner');self.p=self.f(self.owner,'li2_pe_epoch','p')
        self.payload=self.f(self.b,'peo_wire','initial_payload');self.compact=self.f(self.payload,'pe_payload','plan')
        self.source_key=self.f(self.payload,'pe_payload','source')
        first=self.r.items(self.source_key,'li2_pe_source_key','page','li2_pe_source_page')[0]
        self.main_backing=self.f(first,'li2_pe_source_page','backing')
        self.source_offset=self.i(self.f(first,'li2_pe_source_page','identity'),'li2_fetch_page','offset')

    def registry(self,b):
            t='peo_registry';self.eq(b,t,complete=1,table=self.symbol('protected'));count=self.i(b,t,'count');need(0<count<=128,'bounded actual registration table')
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

    def startup_registry(self):
        """Keep loader setup and the full generated-epoch interval distinct."""
        t='peo_registry';w='peo_wire'
        startup=self.f(self.b,w,'startup_registry');initial=self.f(self.b,w,'initial_registry')
        a,n=self.i(startup,t,'count'),self.i(initial,t,'count')
        need(0<a<=n<=128,'startup registry population is an exact predecessor')
        need(all(self.f(startup,t,k)==self.f(initial,t,k)for k in('complete','table','bridge','ph')),
             'startup registry keeps exact table, bridge and program headers')
        before=self.f(startup,t,'ranges');after=self.f(initial,t,'ranges')
        before_kinds=self.f(startup,t,'initial_code');after_kinds=self.f(initial,t,'initial_code')
        need(before[:a*16]==after[:a*16]and before_kinds[:a]==after_kinds[:a],
             'startup registry retains every original range and classification')
        # These are actual strict protected pages, not a claim about which
        # lifecycle owner allocated them. No page is added during the epoch.
        rows=[self.v(row,'li2_fork_range','first end')for row in self.r.items(initial,t,'ranges','li2_fork_range')[:n]]
        for i,(first,end)in enumerate(rows[a:],a):
            need(first%PAGE==0 and end-first==PAGE and after_kinds[i]==0 and
                 all(end<=x or y<=first for x,y in rows[:i]),
                 'startup additions are distinct strict PAGE intervals')
        self.registry(startup)

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

    def nop(self,b,pc):
            self.eq(b,'li2_decoded',pc=pc,next_pc=pc+2,abi_version=1,decode_status=0,code=299,kind=0,destination=16,width_bits=0,step_disposition=1,available=15,length=2,reserved=0)
            need(self.f(b,'li2_decoded','bytes')==self.app['source'][pc-self.page:pc-self.page+15]+b'\0','entire actual predecessor or successor NOP window')

    def chain_slot(self,c,index,pc,closed,after=None):
            ct='li2_tf_chain';self.eq(c,ct,session=self.symbol('selected_session'),initialized=1,first_error=0,first_detail=0,in_handler=0,active=index,pending=int(not closed),unexpected_events=0)
            need(canonical(self.i(c,ct,'failure'))and index in(0,1),'actual chain callback/index')
            s=self.r.items(c,ct,'slots','li2_tf_chain_slot')[index];t='li2_tf_chain_slot'
            address=self.symbol('selected_chain')+self.r.types[ct]['fields']['slots']['offset']+index*self.r.types[t]['bytes']
            self.eq(s,t,chain=self.symbol('selected_chain'),index=index,phase=5 if closed else 3,fallback=0,prepare_complete=1,decode_attempted=1,decode_complete=1,retry=0,unexpected_frame_observed=0,unexpected_signal=0,unexpected_code=0,unexpected_errno=0,unexpected_address=0,prepare_result=0,decode_result=0,classify_result=0)
            need(self.i(s,t,'generation')>0 and self.i(c,ct,'event_id')>=self.i(s,t,'event_id')>0,'actual owner generation and event chronology')
            zero(self.f(s,t,'unexpected'),'no fabricated ordinary unexpected frame');self.nop(self.f(s,t,'decoded'),pc)
            need(self.i(s,t,'origin')in(1,2)and self.i(s,t,'prepare_attempted')==int(self.i(s,t,'origin')==2),'actual NX or TRACE-created owner preparation')
            zero(self.f(s,t,'first_decoded'),'no fabricated boundary retry');zero(self.f(s,t,'first_fetch'),'no fabricated boundary fetch');zero(self.f(s,t,'first_release'),'no fabricated boundary release')
            ref=self.chain_fetch(self.f(s,t,'fetch'),pc,not closed)
            o=self.f(s,t,'owner');ot='li2_tf_owner';st=self.f(o,ot,'step');qtype='li2_step_owner'
            self.eq(st,qtype,phase=5 if closed else 3,first_error=0,in_handler=0,self_test=0,trace_seen=int(closed),revoke_sync_started=int(closed),first_detail=0,session=self.symbol('selected_session'),open_sync=0,revoke_sync=0,destination=0,width=0,immediate=0,effect=0,source=0)
            hooks=self.f(st,qtype,'hooks');self.eq(hooks,'li2_step_hooks',context=address)
            for key in ('authenticate','failure'):need(canonical(self.i(hooks,'li2_step_hooks',key)),'actual nonnull ordinary callback')
            need(self.f(self.f(o,ot,'hooks'),'li2_tf_hooks','step')==hooks and canonical(self.i(self.f(o,ot,'hooks'),'li2_tf_hooks','continue_closed')),'actual matching typed TF hooks')
            request=self.f(st,qtype,'request');self.eq(request,'li2_step_request',page_count=1,original_flags=self.app['seed'][1]);self.nop(self.f(request,'li2_step_request','decoded'),pc)
            pages=self.r.items(request,'li2_step_request','pages','li2_step_page');sourcepage=self.r.items(self.f(s,t,'fetch'),'li2_chain_fetch','pages','li2_fetch_page')[0]
            self.eq(pages[0],'li2_step_page',address=self.page,object=self.i(sourcepage,'li2_fetch_page','allocation'),generation=self.i(sourcepage,'li2_fetch_page','generation'),offset=self.source_offset,closed_prot=1,open_prot=5);zero(pages[1],'whole unused permission page')
            for key in ('open_started','opened'):need(struct.unpack('<2I',self.f(st,qtype,key))==(1,0),'one actual permission open')
            for key in ('revoke_started','revoked'):need(struct.unpack('<2I',self.f(st,qtype,key))==(int(closed),0),'one actual completed or not-yet-started revoke')
            for key in ('open_result','revoke_result'):zero(self.f(st,qtype,key),'all actual permission results')
            for key in ('rdssp_query_attempted','rdssp_query_complete','rdssp_query_result','rdssp_features','bnd_xcr0_attempted','bnd_xcr0_complete','bnd_xcr0'):self.eq(o,ot,**{key:0})
            zero(self.f(o,ot,'rdssp_observation'),'NOP has no shadow-stack observer');self.eq(o,ot,unexpected_frame_observed=0,continuation_started=int(closed),continuation_complete=int(closed),continuation_result=0)
            cl=self.f(o,ot,'classification');self.eq(cl,'li2_tf_classification',pc=pc,next_pc=pc+2,abi_version=1,policy=1,code=299,length=2,flow=1,family=1)
            before=self.f(st,qtype,'before');g=q(self.f(before,'li2_step_frame','greg'));n=self.i(before,'li2_step_frame','fp_bytes')
            need(self.i(before,'li2_step_frame','mask')==MASK and self.i(before,'li2_step_frame','initialized')==n and 580<=n<=FP,'actual complete predecessor original frame')
            result=dict(greg=g,mask=MASK,fp=self.f(before,'li2_step_frame','fp'),fp_bytes=n,fs=self.app['machine'][1],gs=self.app['machine'][2])
            if closed:
                need(after is not None,'actual TRACE witness required for close');self.step_frame(self.f(st,qtype,'after'),after)
                self.eq(st,qtype,signal_number=5,signal_code=2,signal_errno=0,signal_address=pc+2)
                self.eq(o,ot,actual_post_pc=pc+2,actual_post_flags=after['greg'][17])
                query=self.f(s,t,'query');self.eq(query,'li2_tf_continuation',pc=pc+2,attempted=1,page_observed=1,complete=1,result=0);self.maps(self.f(query,'li2_tf_continuation','maps'));self.page_row(self.f(query,'li2_tf_continuation','page'));self.backing(self.f(query,'li2_tf_continuation','backing'))
                self.eq(self.f(s,t,'release'),'li2_chain_release',started=1,complete=1,result=0)
            else:
                for key in ('query','release'):zero(self.f(s,t,key),'ordinary owner not prematurely closed/released')
                self.eq(st,qtype,signal_number=11 if self.i(s,t,'origin')==1 else 5,signal_code=2,signal_errno=0,signal_address=pc)
                zero(self.f(st,qtype,'after'),'ordinary owner has no future TRACE frame');self.eq(o,ot,actual_post_pc=0,actual_post_flags=0)
            return s,ref,result

    def closed_transition(self,previous,closed,pc,ingress,new_event=False):
            ct='li2_tf_chain';index=self.i(previous,ct,'active')
            p,ref,before=self.chain_slot(previous,index,pc,False)
            c,cref,_=self.chain_slot(closed,index,pc,True,ingress);need(ref==cref,'real predecessor borrow unchanged through release')
            self.r.change(previous,closed,ct,observed=('pending','steps','releases','slots','lease','event_id','entry'))
            self.eq(closed,ct,steps=self.i(previous,ct,'steps')+1,releases=self.i(previous,ct,'releases')+1,event_id=self.i(previous,ct,'event_id')+int(new_event))
            a,z=(self.f(x,ct,'entry')for x in(previous,closed))
            if new_event:
                self.r.change(a,z,'li2_tf_trace_entry',observed=('valid',));self.eq(z,'li2_tf_trace_entry',valid=0)
            else:need(a==z,'same-event origin proof unchanged by chosen close')
            for i in (index^1,):need(self.r.items(previous,ct,'slots','li2_tf_chain_slot')[i]==self.r.items(closed,ct,'slots','li2_tf_chain_slot')[i],'other real chain slot untouched by close')
            self.r.change(p,c,'li2_tf_chain_slot',observed=('phase','owner','fetch','release','query'))
            op,oc=(self.f(x,'li2_tf_chain_slot','owner')for x in(p,c))
            self.r.change(op,oc,'li2_tf_owner',observed=('step','actual_post_pc','actual_post_flags','continuation_started','continuation_complete'))
            self.r.change(self.f(op,'li2_tf_owner','step'),self.f(oc,'li2_tf_owner','step'),'li2_step_owner',observed=('phase','trace_seen','revoke_sync_started','after','revoke_started','revoked','signal_number','signal_code','signal_errno','signal_address'))
            lp,lc=(self.f(x,ct,'lease')for x in(previous,closed));lt='li2_tf_same_page'
            if self.i(lp,lt,'origin_active'):
                self.r.change(lp,lc,lt,observed=('phase','origin_active','closed_leases'));self.eq(lc,lt,phase=5,origin_active=0,closed_leases=self.i(lp,lt,'closed_leases')+1,slot=index,owner_generation=self.i(c,'li2_tf_chain_slot','generation'))
            else:need(lp==lc,'inactive lease history unchanged')
            return index,c,ref,before

    def backing(self,b):
        t='li2_fetch_backing';self.eq(b,t,seals_observed=1,stat_observed=1,seals=15,stat_result=0)
        st=self.stat(self.f(b,t,'stat'));actual=self.stat(self.f(self.main_backing,t,'stat'))
        need(200<=self.i(b,t,'retained_fd')<1<<31 and st==actual and st['mode']&0xf000==0x8000 and
             st['size']==self.image['objects'][self.image['main_object']]['carrier_bytes'],'actual sealed main carrier identity')
        need(b==self.main_backing,'whole same retained backing receipt')

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

    def memory(self,b,failed):
        t='li2_peo_memory';self.eq(b,t,attempted=1,complete=1,after_abort=int(failed),rows_checked=6,data_copied=8192,stack_copied=224,result=0,detail=0,rsp=RSP,data_first=DATA,stack_first=RSP-128)
        m=self.maps(self.f(b,t,'maps'),0)
        before,after=(self.f(b,t,k)for k in('before','after'));mt='li2_maps_stats'
        self.eq(before,mt,active=0,poisoned=0,reserved=0);self.eq(after,mt,active=0,poisoned=0,reserved=0,valid=1)
        self.r.change(before,after,mt,values=dict(fresh_calls=self.i(before,mt,'fresh_calls')+1,acquisitions=self.i(before,mt,'acquisitions')+1),observed=('valid','invalidations','mutation_epoch'))
        invalidations=self.i(after,mt,'invalidations')-self.i(before,mt,'invalidations')
        need(invalidations>=1 and self.i(after,mt,'mutation_epoch')-self.i(before,mt,'mutation_epoch')==invalidations,'actual explicit fresh invalidation and every gateway invalidation')
        need(m[:3]==(self.i(after,mt,'acquisitions'),0,self.i(after,mt,'mutation_epoch')),'memory acquisition actual stats join')
        rows=self.r.items(b,t,'rows','li2_peo_map_row')
        for i,row in enumerate(rows):
            self.eq(row,'li2_peo_map_row',offset=0,major=0,minor=0,inode=0,private=1)
            a,z,prot=self.v(row,'li2_peo_map_row','first end prot');need(a%PAGE==z%PAGE==0 and a<z,'actual page-aligned memory extent')
            if i<2:need((a,z,prot)==(DATA,DATA+8192,3),'actual two-page writable data')
            elif i==4:need((a,z,prot)==(STACK+4096,STACK+4096+131072,3),'actual fixed writable guest stack')
            else:
                point=(DATA+8192,STACK,STACK+4096+131072)[(2,3,5).index(i)]
                need(a<=point and point+PAGE<=z and prot==0,'actual inaccessible data/stack guard')
        return dict(data=self.f(b,t,'data'),stack=self.f(b,t,'stack'))

    def source(self,b,terminal,failed):
        t='li2_pe_source_progress';self.eq(b,t,initialized=1,phase=(7 if failed else 6)if terminal else 4,first_error=0,pages_copied=2,release_started=int(terminal),release_complete=int(terminal),aborted=int(terminal and failed),first_detail=0,serial=1,generated=self.generated)
        need(struct.unpack('<2I',self.f(b,t,'bytes_copied'))==(4096,4096),'both full actual source copies')
        s=self.f(b,t,'source');st='li2_pe_sources';self.eq(s,st,complete=1,reserved=0,serial=1)
        for name in('allocation_epoch','generation_epoch','records_epoch'):need(self.i(s,st,name)>0,'actual source lifecycle epoch')
        need(self.f(s,st,'key')==self.source_key,'whole immutable source identity and bytes')
        ref=self.f(s,st,'anchor');need(ref==self.f(self.owner,'li2_pe_epoch','ref'),'actual source anchor owner/ref')
        self.maps(self.f(b,t,'preparation'));self.maps(self.f(b,t,'validation'))
        for bb in self.r.items(b,t,'last_backing','li2_fetch_backing'):self.backing(bb)
        self.query(self.f(b,t,'opened'),self.generated,5,pages=8)
        if terminal:self.query(self.f(b,t,'closed'),self.generated,1,pages=8)
        else:zero(self.f(b,t,'closed'),'no premature source release query')
        return self.i(b,t,'validations')

    def pin(self,b,state,terminal,failed):
        t='li2_pe_rseq_progress';self.eq(b,t,active=int(not terminal or failed),checking=0,first_error=0,unsafe_terminal=0,seed_complete=1,entry_complete=1,close_complete=int(terminal and not failed),first_detail=0,pid=self.pid,tid=self.pid,fs_result=0,gs_result=0,registration_epoch=1,address=RSEQ,page=RSEQ,length=32,signature=0x53053053,fs=self.app['machine'][1],gs=self.app['machine'][2],word_before=0,word_entry=0,word_after=0,cold_heads=6,cold_stores=1,fs_selector=0,gs_selector=0,session=self.symbol('selected_session'))
        self.eq(self.f(b,t,'token'),'li2_pe_token',owner=self.symbol('pe'),serial=1)
        need(self.i(b,t,'raw_checks')>0,'actual zero publication-word checks before returning RAW')
        rt='li2_rseq_state';self.eq(state,rt,initialized=1,registered=1,held=1,first_error=0,phase=3,first_detail=0,pid=self.pid,tid=self.pid,address=RSEQ,page=RSEQ,length=32,signature=0x53053053,epoch=1,fs_base=self.app['machine'][1],gs_base=self.app['machine'][2],fs_result=0,gs_result=0,tls_complete=1,registrations=1,unregistrations=0,kernel_errors=0)
        need(self.i(state,rt,'calls')==1,'actual one successful registration, no fabricated unregister')
        need(self.f(state,rt,'data')==self.f(b,t,'before'),'whole actual registration mapping is the pinned original receipt')
        identity=None
        for key in('before','observed')+(()if not terminal or failed else('after',)):
            data=self.f(b,t,key);dt='li2_rseq_data';self.eq(data,dt,address=RSEQ,page=RSEQ,pid=self.pid,tid=self.pid,attempted=1,complete=1,error=0,detail=0)
            value=self.v(data,dt,'address page allocation generation offset pid tid');need(value[2]>0 and value[3]>0 and value[4]==0,'actual registered data page identity')
            if identity is None:identity=value
            else:need(value==identity,'unchanged registered data identity through pin')
            self.maps(self.f(data,dt,'maps'))
        if not terminal or failed:zero(self.f(b,t,'after'),'no invented closing registration observation')
        return self.i(b,t,'raw_checks')

    def live_rseq(self,b,state,frame):
        t='li2_link_rseq_live';self.eq(b,t,attempted=1,complete=1,result=0,session=self.symbol('selected_session'),epoch=1,registered=1)
        regs=self.f(b,t,'registers');self.eq(regs,'li2_write_registers',fs_base=self.i(state,'li2_rseq_state','fs_base'),gs_base=self.i(state,'li2_rseq_state','gs_base'))
        need(q(self.f(regs,'li2_write_registers','gpr'))==tuple(frame['greg'][i]for i in GREG),'every actual live rseq GPR')
        need(self.v(regs,'li2_write_registers','fs_base gs_base')==(frame['fs'],frame['gs']),'registered current TLS bound to actual frame')

    def plan(self):
        c=self.compact;t='li2_pe_compact';self.eq(c,t,version=1,bytes=182168,ready=1,result=0,heads=6,exits=1,stores=1,source_bytes=25,source_mask=3,decoder_result=0,guard_result=0,reserved=0,entry=self.head,generated=self.generated,spill=self.spill)
        need(q(self.f(c,t,'page'))==(self.page,self.page+PAGE)and self.f(c,t,'source')==self.app['source'],'both original source pages in immutable primary')
        expected_table=plan.table(self.ranges+[(self.page,self.page+PAGE),(self.page+PAGE,self.page+2*PAGE),(RSEQ+8,RSEQ+16)],self.table)
        need(self.f(c,t,'table')==expected_table,'whole independent balanced exclusion tree and all unused nodes')
        expected=plan.image(self.page,self.generated,self.spill,expected_table)
        need(self.f(c,t,'image')==expected['code']and self.f(c,t,'head')==expected['heads'],'every actual cyclic head/edge/image byte')
        need(q(self.f(c,t,'exit_pc'))==(self.page+0x210,0,0,0,0,0,0,0),'exact original unsupported frontier')
        guards=self.r.items(c,t,'guard','li2_pe_guard_record');g=guards[0];gt='li2_pe_guard_record'
        self.eq(g,gt,version=1,ready=1,result=0,image_bytes=len(expected['guard']),boundaries=37,store_offset=expected['store'],reject_offset=expected['reject'],reserved=0)
        need(struct.unpack('<4I',self.f(g,gt,'scratch_regs'))==(0,1,2,3)and self.f(g,gt,'boundary')==expected['boundaries'],'every independent recovery row, scratch register and dirty-spill prefix')
        for g in guards[1:]:zero(g,'all unused MOV guard rows')
        expected_original,expected_frontier=plan.descriptors(self.app['source'],self.page)
        need(self.f(c,t,'original')==expected_original and self.f(c,t,'frontier')==expected_frontier,'whole independent336-byte descriptors: code/operands/flags/GPR/static-NONE and refusals')
        originals=self.r.items(c,t,'original','li2_span_decoded');stores=self.r.items(c,t,'store_original','li2_mg_store')
        offsets=(0x200,0x203,0x207,0x20a,0x1100,0x1104);lengths=(3,4,3,6,4,5)
        for i,(off,n)in enumerate(zip(offsets,lengths,strict=True)):
            d=originals[i];decoded=self.f(d,'li2_span_decoded','decoded');self.eq(decoded,'li2_decoded',pc=self.page+off,next_pc=self.page+off+n,abi_version=1,decode_status=0,available=15,length=n,reserved=0)
            need(self.f(decoded,'li2_decoded','bytes')==self.app['source'][off:off+15]+b'\0','whole real decoder input window')
            self.eq(d,'li2_span_decoded',version=1,ready=int(i!=0),refusal=5 if i==0 else 0,reserved=0)
            if i:zero(stores[i],'NONE head has no invented store descriptor')
        for d in originals[6:]:zero(d,'whole unused original descriptor')
        for d in stores[6:]:zero(d,'whole unused store descriptor')
        s=stores[0];st='li2_mg_store';self.eq(s,st,version=1,ready=1,refusal=0,available=15,width_bytes=8,source_kind=1,source_reg=0,base=7,index=16,scale=1,rip_relative=0,displacement=0,rip_target=0,immediate=0,displacement_offset=0,displacement_bytes=0,modrm_offset=2,opcode_offset=1,reserved=0)
        need(self.f(s,st,'bytes')==self.app['source'][0x200:0x20f]+b'\0','actual four-Code store input')
        self.eq(self.f(s,st,'tf'),'li2_mg_tf',pc=self.head,next_pc=self.head+3,abi_version=1,policy=1,code=282,length=3,flow=1,family=1)
        frontiers=self.r.items(c,t,'frontier','li2_span_decoded')
        self.eq(frontiers[0],'li2_span_decoded',version=1,ready=0,refusal=1,reserved=0)
        f=self.f(frontiers[0],'li2_span_decoded','decoded');self.eq(f,'li2_decoded',pc=self.page+0x210,next_pc=self.page+0x216,abi_version=1,decode_status=0,available=15,length=6,reserved=0)
        need(self.f(f,'li2_decoded','bytes')==self.app['source'][0x210:0x21f]+b'\0','whole original unexecuted unsupported exit')
        for f in frontiers[1:]:zero(f,'whole unused frontier descriptor')
        cold=self.f(self.owner,'li2_pe_epoch','cold');rebuilt=self.f(self.owner,'li2_pe_epoch','rebuild')
        need(cold==rebuilt and self.f(self.owner,'li2_pe_epoch','compact_rebuild')==c,'whole independently retained cold reconstructions')
        ct='li2_pe_plan'
        for key in('version','ready','result','heads','exits','stores','source_bytes','source_mask','decoder_result','guard_result','reserved','page','entry','generated','spill','source','image','head','original','frontier','store_original','exit_pc','table'):
            need(self.f(cold,ct,key)==self.f(c,t,key),'whole cold/compact exact shared field '+key)
        self.eq(cold,ct,bytes=496024)
        full=self.r.items(cold,ct,'guard','li2_mg_plan');m=full[0];mt='li2_mg_plan'
        for key in('version','ready','result','image_bytes','boundaries','store_offset','reject_offset','reserved','scratch_regs','boundary'):
            need(self.f(m,mt,key)==self.f(guards[0],gt,key),'exact materialized donor field '+key)
        self.eq(m,mt,generated=self.generated,spill=self.spill,successor=self.generated+512)
        need(self.f(m,mt,'original')==s and self.f(m,mt,'table')==expected_table and self.f(m,mt,'image')==expected['guard']+bytes(512-len(expected['guard'])),'whole6488-byte immutable donor materialization')
        for m in full[1:]:zero(m,'unused full cold guard')
        return expected,full[0]

    def finish(self,status):
        h=self.h;r=self.r;t='peo_wire';mode=self.app['mode'];failed=mode!=0
        code,detail=(3304,11 if mode==1 else 4)if failed else(0,0)
        need(type(status)is int and status==(125 if failed else 0),'actual required process outcome')
        need(h[:9]==(0x314f455049324c,2,r.types[t]['bytes'],r.types['li2_pe_epoch']['bytes'],r.types['pe_payload']['bytes'],192512,32768,968,128),'exact actual capture version and extents')
        need(canonical(self.bias)and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(n)for n in('li2_raw6','li2_gateway_start','li2_gateway_end'))and h[10]<=h[9]<h[11],'actual compiled gateway/bias')
        need(h[12]%PAGE==0 and h[13]==524288 and h[14:16]==(1,0)and h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,mode),'actual stack/FD3/source mode')
        need(h[20:26]==(self.symbol('pe'),self.symbol('peo_wire'),self.symbol('pe_source'),self.symbol('pe_rseq'),self.symbol('selected_chain'),self.symbol('span_progress')),'actual runtime protected singleton addresses')
        self.generated,self.proof,self.spill=h[26:29];self.table=self.proof+r.types['pe_payload']['fields']['plan']['offset']+r.types['li2_pe_compact']['fields']['table']['offset']
        need(PAGE<=self.generated<1<<31 and self.generated%PAGE==self.proof%PAGE==0 and self.spill==self.generated+32768 and canonical(self.proof,192512)and(self.proof+192512<=self.generated or self.spill+4096<=self.proof),'complete actual separate anonymous allocations')
        need(h[29]==h[31]==h[32]==h[35]==h[36]==h[41]==h[47]==1 and h[30]==h[33]>0 and h[38]==h[33]+1,'exact one genuine entry and one exit signal, zero interior signals')
        need(h[34]==h[39]==h[40]==0 and h[37]==int(failed)and h[42:45]==(1,1,int(failed))and h[46]==1 and h[48:53]==(status,code,detail,h[16],0)and h[53:]==(0,)*11,'actual terminal prefix and zero word/no invented cleanup')
        need(0<h[45]<32,'actual distinct pending generated route')
        raw=q(self.f(self.b,t,'raw_ingress'));need(sum(raw[1:])==raw[0]>=h[38],'complete bounded ingress accounting')
        for k in('sink_initial','sink_terminal'):
            b=self.f(self.b,t,k);st=self.stat(b);need(st['mode']&0xffff==0x8180 and st['size']==0,'actual empty regular0600 sink');self.eq(b,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(self.f(self.b,t,'sink_initial'),self.f(self.b,t,'sink_terminal'),'stat',observed=('st_atim','st_mtim','st_ctim'))
        footer=q(r.data[-64:]);need(footer[:4]==(0x3146455049324c,2,len(self.b),len(self.b))and 1<=footer[4]<=64 and 0<footer[5]<=len(self.b)and footer[6:]==(status,code),'complete actual write footer')
        if footer[4]==1:need(footer[5]==len(self.b),'single complete actual wire write')
        hardware=self.f(self.b,t,'hardware');self.eq(hardware,'li2_selected_hardware',abi_version=1,reserved=0)
        for i,key in enumerate(('leaf0','leaf1','leaf7')):
            need(struct.unpack('<4I',self.f(hardware,'li2_selected_hardware',key))==tuple(self.app['hardware'][i][2:]),'actual bridge/app hardware equality')
        for key,objid in(('main',self.image['main_object']),('interpreter',self.image['interpreter_object'])):self.image_header(self.f(self.b,t,key),objid)
        self.eq(self.f(self.b,t,'session'),'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        need(self.i(self.f(self.b,t,'session'),'li2_step_session','sync_query')&96==96,'actual registered membarrier support')
        need(self.f(self.b,t,'initial_registry')==self.f(self.b,t,'terminal_registry'),'entire protected range registry unchanged')
        self.startup_registry()
        self.ranges,kinds=self.registry(self.f(self.b,t,'initial_registry'))
        for a,z in((self.generated,self.spill+4096),(self.proof,self.proof+192512)):
            need(self.ranges.count((a,z))==1 and kinds[self.ranges.index((a,z))]==0,'actual strict dynamic code/spill/proof registration')
        source_rows=r.items(self.source_key,'li2_pe_source_key','page','li2_pe_source_page');self.eq(self.source_key,'li2_pe_source_key',entry=self.head)
        for i,b in enumerate(source_rows):
            self.page_row(self.f(b,'li2_pe_source_page','identity'),i);self.backing(self.f(b,'li2_pe_source_page','backing'))
            need(self.f(b,'li2_pe_source_page','bytes')==self.app['source'][i*PAGE:(i+1)*PAGE],'both whole independent original-source pages')
        obj,_,loads=self.objects[self.image['main_object']];bias=self.bases[self.image['main_object']]
        owners=[p for p in loads if p[1]==5 and bias+p[3]<=self.page and self.page+8192<=bias+p[3]+p[5]]
        need(len(owners)==1 and self.source_offset==owners[0][2]+self.page-bias-owners[0][3]and obj['data'][self.source_offset:self.source_offset+8192]==self.app['source'],'actual full two-page ELF/source join')
        payload=self.payload;need(payload==self.f(self.b,t,'terminal_payload')==self.f(self.owner,'li2_pe_epoch','publication'),'whole immutable generation payload retained through terminal')
        for k in('initial_tail','terminal_tail'):zero(self.f(self.b,t,k),'whole sealed proof padding')
        ph=self.f(payload,'pe_payload','header');ht='pe_header';self.eq(ph,ht,version=1,serial=1,generation=1,registry=self.symbol('pe'),generated=self.generated,spill=self.spill,table=self.table,plan_proof=2,none_proof=1,registered_epoch=1)
        zero(self.f(ph,ht,'reserved'),'whole immutable header reserved tail')
        binding=self.image['persistent_binding'];need(binding['version']==1 and binding['profile']=='persistent-registered-two-page-v1','actual explicit compiled profile')
        need(self.f(ph,ht,'archive')==bytes.fromhex(binding['archive']['sha256'])and self.f(ph,ht,'policy')==bytes.fromhex(binding['policy_sha256']),'actual archive/policy immutable authority')
        expected,donor=self.plan()
        need(self.f(self.b,t,'initial_code')==self.f(self.b,t,'terminal_code')==expected['code'],'every actual published code byte unchanged')
        p=self.p;pt='li2_pe_progress';self.eq(p,pt,serial=1,registration_epoch=1,publication=1,generation=1,phase=15 if failed else 13,first_error=code,source_count=2,opened_pages=8,closed_pages=8,anchor_released=1,registration_rechecked=int(not failed),completion_permit=int(not failed),first_detail=detail,generated=self.generated,proof=self.proof,table=self.table,spill=self.spill)
        need(q(self.f(p,pt,'source'))==(self.page,self.page+PAGE),'actual two-page source owner')
        entry=self.f(self.b,t,'entered_progress');self.r.change(entry,p,pt,values=dict(phase=15 if failed else 13,first_error=code,first_detail=detail,closed_pages=8,anchor_released=1,registration_rechecked=int(not failed),completion_permit=int(not failed)))
        self.eq(entry,pt,phase=9,closed_pages=0,anchor_released=0,registration_rechecked=0,completion_permit=0,first_error=0,first_detail=0)
        ot='li2_pe_epoch';o=self.owner
        self.eq(o,ot,initialized=1,registered=1,code_allocated=1,proof_allocated=1,code_registered=1,proof_registered=1,close_started=1,close_complete=1,prepare_started=1,prepare_complete=1,build_started=1,build_returned=1,redirected=1,exit_seen=int(not failed),exit_index=0,recovery_started=1,recovery_complete=1,guest_data_fault=int(mode==1),cleanup_started=int(failed),cleanup_complete=int(failed),consumed=1,plan_proofs=2,none_proofs=1,code_allocation=self.generated,proof_allocation=self.proof,build_result=0,recovery_result=0,release_result=0,flags=self.app['seed'][1],gpr_written=(1<<0)|(1<<7),flags_written=0x8d5,entries=1,completed=int(not failed),unexpected=int(failed))
        self.eq(o,ot,ticket=self.symbol('span_transfer'))
        self.eq(self.f(o,ot,'token'),'li2_pe_token',owner=self.symbol('pe'),serial=1)
        need(self.f(o,ot,'session')==self.f(self.b,t,'session'),'actual unchanged selected session')
        n=self.i(o,ot,'registry_count');need(n==len(self.ranges),'actual table source population')
        need(self.f(o,ot,'registry')==self.f(self.f(self.b,t,'initial_registry'),'peo_registry','ranges'),'whole actual registry copied before static proof')
        exclusions=self.r.items(o,ot,'exclusions','li2_mg_range');expected_ranges=self.ranges+[(self.page,self.page+4096),(self.page+4096,self.page+8192),(RSEQ+8,RSEQ+16)]
        need([self.v(x,'li2_mg_range','first end')for x in exclusions[:n+3]]==expected_ranges,'every actual guard exclusion, including both sources and live rseq word')
        for x in exclusions[n+3:]:zero(x,'unused exclusion capacity')
        g=self.f(o,ot,'generation');gt='li2_pe_generation';self.eq(g,gt,installed=1,complete=1,proof_complete=1,generation=1,ready_generation=int(not failed),generated=self.generated,proof=self.proof,spill=self.spill,code_copied=32768,code_verified=32768,proof_zeroed=192512,proof_copied=r.types['pe_payload']['bytes'],proof_verified=192512)
        self.query(self.f(g,gt,'code_writable'),self.generated,3,pages=8);self.query(self.f(g,gt,'proof_writable'),self.proof,3,pages=47);self.query(self.f(g,gt,'spill_query'),self.spill,3)
        self.permission(self.f(g,gt,'code_sealed'),self.generated,1,8);self.permission(self.f(g,gt,'proof_sealed'),self.proof,1,47);self.permission(self.f(g,gt,'open'),self.generated,5,8)
        self.permission(self.f(g,gt,'cleanup'if failed else'close'),self.generated,1,8)
        zero(self.f(g,gt,'close'if failed else'cleanup'),'no invented opposite close path')
        before_source=self.f(self.b,t,'entered_source');after_source=self.f(self.b,t,'terminal_source')
        a=self.source(before_source,False,False);z=self.source(after_source,True,failed)
        need(a==2 and z==3 and self.i(ph,ht,'source_validations')==1,'exact cold/header/open/terminal source proof chronology')
        need(self.f(before_source,'li2_pe_source_progress','source')==self.f(after_source,'li2_pe_source_progress','source'),'whole retained anchor/source/epoch identity')
        es=self.f(self.b,t,'entered_state');ts=self.f(self.b,t,'terminal_state')
        a=self.pin(self.f(self.b,t,'entered_rseq'),es,False,False);z=self.pin(self.f(self.b,t,'terminal_rseq'),ts,True,failed);need(z>a,'actual registered guard checks throughout close')
        need(es==ts,'all old rseq historical footprint and registration state unchanged during generated execution')
        self.eq(es,'li2_rseq_state',last_first=0,last_end=0,last_pc=self.page+0x1104,last_code=696,last_policy=1)
        self.eq(self.f(es,'li2_rseq_state','last_footprint'),'li2_write_footprint',pc=self.page+0x1104,next_pc=self.page+0x1109,first=0,end=0,abi_version=1,policy=1,code=696,length=5)
        ref=self.f(o,ot,'ref');seq=self.i(ref,'li2_fetch_ref','sequence')
        self.progress(self.f(self.b,t,'entered_fetch'),seq,True);self.progress(self.f(o,ot,'final_fetch'),seq,False)
        ingress=self.normalized(self.f(o,ot,'ingress'),self.frame(self.f(o,ot,'before')));before=self.frame(self.f(o,ot,'before'))
        self.trace(ingress,self.head,self.app['seed'][1]|TF);self.trace(before,self.head,self.app['seed'][1]);self.same_event(ingress,before,self.app['seed'][1])
        previous=self.f(self.b,t,'predecessor');closed=self.f(self.b,t,'closed_chain')
        index,slot,oldref,pbefore=self.closed_transition(previous,closed,self.head-2,ingress)
        tr=self.f(o,ot,'transfer');tt='li2_span_transfer_progress'
        self.eq(tr,tt,phase=3,issued=1,consume_attempted=1,consumed=1,resume_attempted=0,resumed=0,previous=index,next=0,successor_installed=0,first_error=0,first_detail=0,previous_generation=self.i(slot,'li2_tf_chain_slot','generation'),previous_borrow=self.i(oldref,'li2_fetch_ref','sequence'),fresh_borrow=seq,pc=self.head,flags=self.app['seed'][1],refault_attempted=0,refaulted=0,event=self.i(closed,'li2_tf_chain','event_id'))
        need(self.i(tr,tt,'serial')==self.i(p,pt,'transfer_serial')>0 and seq>self.i(oldref,'li2_fetch_ref','sequence'),'actual consumed completed transfer precedes newer publication')
        self.observation(self.f(tr,tt,'released'),self.head-2,False,oldref);self.observation(self.f(tr,tt,'fresh'),self.head,True,ref)
        returned=self.frame(self.f(self.b,t,'returned'));want=list(before['greg']);want[16]=self.generated
        need(returned['greg']==tuple(want)and returned['fp']==before['fp']and returned['si']==before['si']and(returned['fs'],returned['gs'])==tuple(self.app['machine'][1:3]),'actual entry edits only RIP, full AF/FP/TLS retained')
        expected_uc=bytearray(before['uc']);struct.pack_into('<Q',expected_uc,40+16*8,self.generated)
        need(returned['uc']==bytes(expected_uc),'entire actual return UC changes only entry RIP')
        after=self.frame(self.f(self.b,t,'terminal_frame'));saved=self.f(o,ot,'after')
        self.r.change(saved,self.f(self.b,t,'terminal_frame'),'le_frame',observed=('fs','gs','fs_result','gs_result','tls_complete'))
        need((after['fs'],after['gs'])==tuple(self.app['machine'][1:3]),'actual terminal TLS bases')
        need(after['fp']==before['fp']and after['fp_bytes']==before['fp_bytes']and after['mask']==before['mask']==MASK,'all65536 FP bytes and actual mask preserved')
        lives=r.items(o,ot,'live','li2_link_rseq_live')
        for live in lives[:2]:self.live_rseq(live,es,before)
        if failed:zero(lives[2],'no invented successful exit live-rseq guard')
        else:self.live_rseq(lives[2],ts,after)
        if failed:
            need(self.f(o,ot,'unexpected_frame')==saved,'same authentic failure frame retained before RAW cleanup')
            recovered=self.f(o,ot,'recovered');rt='li2_pe_recovered';phase=1 if mode==1 else 3
            self.eq(recovered,rt,original_pc=self.head,head=0,kind=4,phase=phase,complete=1)
            need(after['greg'][16]==self.generated+expected['store'if mode==1 else'reject'],'actual exact emitted store or rejection boundary')
            need(self.f(o,ot,'recovery_scratch')==donor,'whole protected6488-byte recovery materialization')
            gpr=q(self.f(recovered,rt,'gpr'));flags=self.i(recovered,rt,'flags')
            need(gpr==tuple(after['greg'][i]for i in GREG)and flags==after['greg'][17],'fully restored guard register/flag state at these two terminal boundaries')
            logical=list(after['greg']);logical[16]=self.head
            if mode==1:
                need(after['sig']==11 and struct.unpack_from('<iii',after['si'])==(11,0,2)and after['greg'][19:21]==(6,14)and after['greg'][22]==DATA+8192 and int.from_bytes(after['si'][16:24],'little')==DATA+8192,'actual third write data fault, never an invented store completion')
            else:
                need(after['sig']==4 and struct.unpack_from('<iii',after['si'])==(4,0,2)and after['greg'][19:21]==(0,6)and int.from_bytes(after['si'][16:24],'little')==after['greg'][16],'actual UD2 exclusion refusal')
                need(gpr==self.app['seed'][0]and flags==self.app['seed'][1]|RF,'rseq exclusion preserves original logical state with no store')
                expected_greg=list(before['greg']);expected_greg[16]=self.generated+expected['reject'];expected_greg[17]|=RF;expected_greg[19]=0;expected_greg[20]=6
                need(after['greg']==tuple(expected_greg),'guard refusal changes only authentic UD2 event fields; predecessor CR2 retained')
            logical=dict(after,greg=tuple(logical))
        else:
            self.nx(after,self.page+0x210);logical=after
            zero(self.f(o,ot,'recovered'),'no invented fault recovery');zero(self.f(o,ot,'recovery_scratch'),'no fault reconstruction on actual exit');zero(self.f(o,ot,'unexpected_frame'),'no invented unexpected frame')
            self.query(self.f(o,ot,'proof_exit'),self.proof,1,pages=47)
        zero(self.f(o,ot,'code_exit'),'unused code query is not success evidence')
        if failed:zero(self.f(o,ot,'proof_exit'),'failure has no invented ordinary-exit proof query')
        bm=self.memory(self.f(self.b,t,'before_memory'),False);am=self.memory(self.f(self.b,t,'after_memory'),failed)
        need(bm['data']==self.app['data']and bm['stack']==am['stack']==self.app['stack'],'entire actual seed data and conserved stack')
        want=bytearray(self.app['data'])
        for i in range(4 if mode==0 else 2 if mode==1 else 0):struct.pack_into('<Q',want,(0 if mode==0 else 8176)+8*i,i+1)
        need(am['data']==bytes(want),'exact completed writes, zero faulting/rejected store effect')
        terminal=dict(version=1,status=status,failure_code=code,detail_abs=detail,detail_negative=0,phase=15 if failed else 13,serial=1,entries=1,completed=int(not failed),unexpected=int(failed),permit=int(not failed),opened_pages=8,closed_pages=8,anchor_released=1,registration_rechecked=int(not failed),guest_data_fault=int(mode==1),recovery_complete=1,first_error=code)
        return dict(terminal=terminal,mode=mode,ingress=ingress,before=before,predecessor_before=pbefore,returned=returned,after=after,logical=logical,before_memory=bm,after_memory=am,completed=int(not failed),guest_data_fault=int(mode==1),guard_rejected=int(mode==2),interior_signals=0,source=self.app['source'],closed_pages=8,anchor_released=1,permit=int(not failed),word=0,code=code,detail=detail,status=status)

def read(data,layout,image,app,pid,cpu,exit_status):
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    return Check(wire.Reader(data,layout),image,app,pid,cpu).finish(exit_status)


CONTROL_COUNTS={0:20,1:20,2:20}

def terminal(parsed,owner):
    """Only the new row is directly protected; inherited rows remain separate."""
    expected=owner['terminal']
    need(type(parsed)is dict and set(parsed)==set(expected)and all(type(v)is int for v in parsed.values())and parsed==expected,'whole actual protected persistent terminal row')
    return dict(fields=len(expected),protected_persistent_row=1,inherited_row_protection=0)


def controls(data,layout,image,app,pid,cpu,exit_status):
    """Twenty bounded supplied-copy controls per actual generated record."""
    read(data,layout,image,app,pid,cpu,exit_status);mode=app['mode'];types=layout['types']
    def at(t,k,base=0,index=0,child=None):
        f=types[t]['fields'][k]
        return base+f['offset']+(index*types[child]['bytes']if child else index)
    w='peo_wire';ot='li2_pe_epoch';o=at(w,'owner');g=at(ot,'generation',o)
    p=at(ot,'p',o);initial=at(w,'initial_payload');cp=at('pe_payload','plan',initial)
    source=at(w,'terminal_source');pin=at(w,'terminal_rseq');mem=at(w,'after_memory')
    tests=[('wire_version',8),('footer_version',len(data)-56),('interior_event',38*8),
        ('actual_hardware',at('li2_selected_hardware','leaf0',at(w,'hardware'))),
        ('entry_publication_word',at('li2_pe_rseq_progress','word_entry',at(w,'entered_rseq'))),
        ('terminal_publication_word',at('li2_pe_rseq_progress','word_after',pin)),
        ('second_source_byte',at('li2_pe_compact','source',cp)+4096),
        ('whole_generated_code',at(w,'terminal_code')),
        ('proof_padding',at(w,'terminal_tail')),
        ('live_guard_GPR',at('li2_write_registers','gpr',at('li2_link_rseq_live','registers',at(ot,'live',o)))),
        ('guard_recovery_row',at('li2_mg_boundary','dirty',at('li2_pe_guard_record','boundary',at('li2_pe_compact','guard',cp)))),
        ('immutable_generation',at('pe_header','generation',at('pe_payload','header',initial))),
        ('static_plan_proof',at(ot,'plan_proofs',o)),('cold_NONE_proof',at(ot,'none_proofs',o)),
        ('actual_code_revoke',at('le_permission','complete',at('li2_pe_generation','cleanup'if mode else'close',g))),
        ('actual_anchor_release',at('li2_pe_source_progress','release_complete',source)),
        ('completion_permit',at('li2_pe_progress','completion_permit',p)),
        ('whole_terminal_FP',at('li2_step_frame','fp',at('le_frame','frame',at(w,'terminal_frame')))),
        ('actual_store_effect',at('li2_peo_memory','data',mem)+(8176 if mode==1 else 0))]
    need(len(tests)==19,'fixed supplied actual prefix controls')
    refused=[]
    for name,offset in tests:
        mutant=bytearray(data);mutant[offset]^=1
        try:read(bytes(mutant),layout,image,app,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('supplied persistent owner corruption accepted '+name)
    # Coherent descriptor forgery updates every actual immutable/cold copy.
    # Whole-copy equality still holds; only the independent complete descriptor
    # proves the static code/flags/GPR theorem instead of a Boolean proof flag.
    mutant=bytearray(data)
    copies=[(at('pe_payload','plan',at(w,k)),'li2_pe_compact')for k in('initial_payload','terminal_payload')]
    copies += [(at('pe_payload','plan',at(ot,'publication',o)),'li2_pe_compact'),(at(ot,'compact_rebuild',o),'li2_pe_compact')]
    copies += [(at(ot,k,o),'li2_pe_plan')for k in('cold','rebuild')]
    for base,t in copies:
        d=at(t,'original',base,1,'li2_span_decoded')
        mutant[at('li2_span_decoded','gpr_write',d)]^=2
    try:read(bytes(mutant),layout,image,app,pid,cpu,exit_status)
    except ValueError as error:
        need(str(error)=='whole independent336-byte descriptors: code/operands/flags/GPR/static-NONE and refusals','exact coherent static-proof refusal')
        refused.append('coherent_static_descriptor')
    else:raise ValueError('coherent descriptor corruption accepted')
    need(len(refused)==CONTROL_COUNTS[mode],'all twenty persistent owner controls')
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0,mode=mode)


REGISTRY_CONTROL_COUNTS={0:6,1:6,2:6}

def registry_controls(data,layout,image,app,pid,cpu,exit_status):
    """Six separately counted causal controls; the original twenty stay exact."""
    read(data,layout,image,app,pid,cpu,exit_status);types=layout['types'];mode=app['mode']
    def at(t,k,base=0):return base+types[t]['fields'][k]['offset']
    w='peo_wire';t='peo_registry';startup=at(w,'startup_registry');terminal=at(w,'terminal_registry')
    tests=[
        ('startup_population',at(t,'count',startup),'startup registry population is an exact predecessor',True),
        ('startup_table_headers',at(t,'ph',startup),'startup registry keeps exact table, bridge and program headers',False),
        ('startup_range_prefix',at(t,'ranges',startup),'startup registry retains every original range and classification',False),
        ('startup_classification_prefix',at(t,'initial_code',startup),'startup registry retains every original range and classification',False),
        ('epoch_terminal_population',at(t,'count',terminal),'entire protected range registry unchanged',False),
        ('epoch_owner_population',at('li2_pe_epoch','registry_count',at(w,'owner')),'actual table source population',False)]
    refused=[]
    for name,offset,message,clear in tests:
        mutant=bytearray(data)
        if clear:mutant[offset:offset+4]=bytes(4)
        else:mutant[offset]^=1
        try:read(bytes(mutant),layout,image,app,pid,cpu,exit_status)
        except ValueError as error:
            need(str(error)==message,'exact registry-boundary control refusal '+name);refused.append(name)
        else:raise ValueError('registry-boundary corruption accepted '+name)
    need(len(refused)==REGISTRY_CONTROL_COUNTS[mode],'all six separate registry-boundary controls')
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0,mode=mode)
