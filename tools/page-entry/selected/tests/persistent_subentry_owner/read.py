"""One immutable two-member certificate and its actual second-member subentry.
Exact separate lifetime tags; older registered reader remains byte-for-byte unchanged.
No descriptor, data-map receipt or zero-word observation is fabricated."""
import hashlib,struct,importlib.util
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
HERE=Path(__file__).resolve().parent
wire=load('persistent_subentry_wire',HERE/'wire.py');plan=load('persistent_subentry_plan',HERE/'plan.py')
base=load('persistent_registered_active_reader',HERE.parent/'persistent_active_domain_owner/read.py')
app_model=load('persistent_subentry_app_model',HERE.parent/'persistent_subentry_app/read.py')
old=wire.old
need,zero,q,canonical=old.need,old.zero,old.q,old.canonical
U64,PAGE,FP,TF,RF,MASK=old.U64,old.PAGE,old.FP,old.TF,old.RF,old.MASK
DATA,STACK,RSP=app_model.DATA,app_model.STACK,app_model.RSP
GREG=app_model.GREG

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


class Check(base.Check):
    def __init__(self,r,image,app,pid,cpu):
        self.r,self.image,self.app,self.pid,self.cpu=r,image,app,pid,cpu
        self.b=r.data[:-64];self.h=q(self.f(self.b,'pso_wire','h'));self.bias=self.h[9]-r.layout['symbols']['li2_raw6']
        self.page=app['head']&-PAGE;self.head=app['head'];self.objects={};self.bases={};self.backings={};self.maps_seen={};self.source_ids={}
        for key,obj in image['objects'].items():
            need(type(key)is int and type(obj)is dict,'actual complete object inventory');h,loads=old.elf(obj['data']);self.objects[key]=(obj,h,loads)
        need(image['main_object']in self.objects and image['interpreter_object']in self.objects,'actual source object identities')
        self.eh,self.ph,self.symbols=elf_symbols(image['bridge'])
        need(set(r.layout['symbols'])==set(self.symbols)|{'span_progress','pg_domain_source'}and all(r.layout['symbols'][k]==v[0]for k,v in self.symbols.items()),'same actual bridge/DWARF symbols')
        initial_epoch=r.items(self.b,'pso_wire','epochs','pso_epoch')[0]
        initial_slots=r.items(self.f(initial_epoch,'pso_epoch','prior'),'pso_slots','slots','pso_slot')
        self.bank_layouts=[[self.f(bank,'ped_bank','layout')for bank in r.items(slot,'pso_slot','banks','ped_bank')]for slot in initial_slots]
        self.certificates=r.items(self.b,'pso_wire','certificates','pso_certificate')
        payload=self.f(self.certificates[0],'pso_certificate','payload');key=self.f(payload,'pe_payload','source')
        row=r.items(key,'li2_pg_source_key','page','li2_pg_source_page')[0]
        self.main_backing=self.f(row,'li2_pg_source_page','backing');self.source_offset=self.i(self.f(row,'li2_pg_source_page','identity'),'li2_fetch_page','offset')
        self.main_vma_identity=self.v(self.f(row,'li2_pg_source_page','identity'),'li2_fetch_page','vma_major vma_minor vma_inode')
        binding=image['persistent_binding'];need(binding['version']==1 and binding['unregistered']is True and binding['mode']in('capture','differential')and binding['profile']=='persistent-subentry-'+binding['mode']+'-v1','actual distinct active-domain build mode')
        self.differential=binding['mode']=='differential';self.geometry=self.layout(self.f(self.f(payload,'pe_payload','header'),'pe_header','layout'))

    def observation(self,b,pc,held,ref=None):
            t='li2_span_fetch_observation';self.eq(b,t,complete=1,pc=pc,length=15,page_count=1,pid=self.pid,tid=self.pid)
            actual=self.f(b,t,'ref');a,n=self.v(actual,'li2_fetch_ref','owner sequence');need(canonical(a)and n>0,'actual protected singleton identity')
            if ref is not None:need(actual==ref,'exact real ref, not caller sequence assertion')
            self.progress(self.f(b,t,'progress'),n,held)
            off=pc-self.page;need(0<=off<2*PAGE and off%PAGE<=PAGE-15 and self.f(b,t,'bytes')==self.app['source'][off:off+15],'all actual requested15 bytes')
            pages=self.r.items(b,t,'pages','li2_fetch_page');backs=self.r.items(b,t,'backing','li2_fetch_backing');self.page_row(pages[0],off//PAGE);self.backing(backs[0]);self.backing(self.f(b,t,'last_backing'));zero(pages[1],'unused singleton page');zero(backs[1],'unused singleton backing')
            return a,n


    def chain_fetch(self,b,pc,held):
            t='li2_chain_fetch';self.eq(b,t,pc=pc,length=15,page_count=1,pid=self.pid,tid=self.pid,identity_observed=1)
            ref=self.f(b,t,'ref');a,n=self.v(ref,'li2_fetch_ref','owner sequence');need(canonical(a)and n>0,'actual ordinary fetch origin')
            self.progress(self.f(b,t,'progress'),n,held)
            need(self.f(b,t,'bytes')==self.app['source'][pc-self.page:pc-self.page+15],'whole actual ordinary window')
            pages=self.r.items(b,t,'pages','li2_fetch_page');back=self.r.items(b,t,'backing','li2_fetch_backing')
            self.page_row(pages[0],(pc-self.page)//PAGE);self.backing(back[0]);self.backing(self.f(b,t,'last_backing'));zero(pages[1],'unused ordinary page');zero(back[1],'unused ordinary backing')
            return ref


    def source(self,b,serial,entry,key,ref,terminal=False,cancel=False):
        t='li2_pg_source_progress';phase=(8 if cancel else 6)if terminal else(3 if cancel else 4)
        self.eq(b,t,initialized=1,phase=phase,first_error=0,pages_copied=2,release_started=int(terminal),release_complete=int(terminal),aborted=0,first_detail=0,serial=serial,
                opened_extents=0 if cancel else 3,opened_pages=0 if cancel else 17,closed_extents=3 if terminal and not cancel else 0,closed_pages=17 if terminal and not cancel else 0,
                cancel_started=int(terminal and cancel),cancel_complete=int(terminal and cancel),cancel_extents=3 if terminal and cancel else 0,cancel_pages=17 if terminal and cancel else 0)
        need(self.layout(self.f(b,t,'layout'))==self.geometry and struct.unpack('<2I',self.f(b,t,'bytes_copied'))==(4096,4096),'actual group source layout/full copies')
        s=self.f(b,t,'source');self.eq(s,'li2_pg_sources',complete=1,reserved=0,serial=serial)
        for name in('allocation_epoch','generation_epoch','records_epoch'):need(self.i(s,'li2_pg_sources',name)>0,'actual lifecycle generation epochs')
        actual=self.f(s,'li2_pg_sources','key');self.source_key(actual,entry);self.pair_key(actual,key)
        if entry==self.i(key,'li2_pg_source_key','entry'):self.key_identity(actual,key)
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

        saved=self.f(b,t,'entry');first=refs[0]
        self.entry_value(saved,None,self.f(source,'li2_pg_source_progress','source'),self.f(first,'li2_pgd_ref','layout'),root=self.i(first,'li2_pgd_ref','root'))
        need(self.i(saved,'li2_pgs_entry','slot')==self.i(first,'li2_pgd_ref','slot')and self.i(saved,'li2_pgs_entry','bank')==self.i(first,'li2_pgd_ref','bank')and self.i(saved,'li2_pgs_entry','generation')==self.i(first,'li2_pgd_ref','generation'),'entry receipt binds actual primary slot/bank/generation')


    def counts(self,b):
        t='pso_counts';names='next_serial next_generation offers publications hits cold_attempts cancelled retirements permit_claims entries completed unexpected subentry_selections subentry_hits subentry_entries subentry_completed'.split()
        d={k:self.i(b,t,k)for k in names};d['misses']=q(self.f(b,t,'misses'));need(len(d['misses'])==18 and d['misses'][0]==0,'exact eighteen descriptive reason buckets')
        need(all(0<=x<U64 for x in d.values()if type(x)is int)and all(0<=x<U64 for x in d['misses']),'bounded exact dynamic counters')
        return d


    def delta(self,a,b,**increments):
        x,y=self.counts(a),self.counts(b)
        for k in x:
            if k=='misses':
                ds=increments.get('miss_deltas',tuple(1 if i==increments.get('miss_reason',-1)else 0 for i in range(18)))
                need(len(ds)==18 and all(type(v)is int and v>=0 for v in ds)and sum(ds)==increments.get('cancelled',0)and y[k]==tuple(v+d for v,d in zip(x[k],ds,strict=True)),'exact classified miss bucket delta')
            else:need(y[k]==x[k]+increments.get(k,0),'exact focal dynamic counter delta '+k)

    def entry_value(self,e,key,actual,layout,root=None,focal=False):
        t='li2_pgs_entry';v=self.f(e,t,'target');vt='li2_pgs_target';row=self.f(e,t,'row');d=self.f(self.f(e,t,'original'),'li2_span_decoded','decoded')
        serial=self.i(actual,'li2_pg_sources','serial');root=self.i(key,'li2_pg_source_key','entry')if key is not None else root
        self.eq(e,t,complete=1,reserved=0);self.eq(self.f(e,t,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
        transfer,gen,build=self.v(e,t,'transfer_serial generation build_serial');slot,bank=self.v(e,t,'slot bank')
        need(0<transfer<U64 and 0<gen<U64 and 0<build<=serial and slot in(0,1)and bank in(0,1),'bounded actual entry token/generation/build/slot/bank')
        need(layout==self.bank_layouts[slot][bank],'actual entry bank names immutable fixed allocation')
        need(self.f(e,t,'anchor')==self.f(actual,'li2_pg_sources','anchor'),'actual entry retains fresh source anchor')
        self.eq(actual,'li2_pg_sources',complete=1,reserved=0)
        anchor=self.f(e,t,'anchor');need(self.i(anchor,'li2_fetch_ref','owner')!=0 and self.i(anchor,'li2_fetch_ref','sequence')>0,'actual entry owns a nonempty source reference')
        heads,head,member,local,page=self.v(v,vt,'heads head member local source_page');pc=self.i(v,vt,'pc')
        need(1<=heads<=128 and head<heads and member==head//64 and local==head%64 and page in(0,1),'exact entry head/member/local/source coordinates')
        pages=q(self.f(v,vt,'page'));actual_key=self.f(actual,'li2_pg_sources','key');self.eq(v,vt,version=1,root=root,generated=q(layout)[member]+local*512,pc=self.i(actual_key,'li2_pg_source_key','entry'))
        need((pc==root)==(head==0),'compiled root remains distinct from actual subentry')
        offset,length,generated=self.v(row,'li2_pe_head','source_offset source_length generated_length');need(offset<=PAGE-15 and 1<=length<=15 and 1<=generated<=512,'whole external head window and generated slot')
        self.eq(row,'li2_pe_head',source_page=page);need(self.i(row,'li2_pe_head','kind')in(1,2,3),'actual supported entry kind')
        self.eq(d,'li2_decoded',abi_version=1,decode_status=0,pc=pc,next_pc=pc+length,length=length,available=15)
        source_rows=self.r.items(actual_key,'li2_pg_source_key','page','li2_pg_source_page')
        need(pages==tuple(self.i(self.f(x,'li2_pg_source_page','identity'),'li2_fetch_page','address')for x in source_rows)and pc==pages[page]+offset,'entry keeps actual source pair')
        need(self.f(d,'li2_decoded','bytes')[:15]==self.f(source_rows[page],'li2_pg_source_page','bytes')[offset:offset+15],'actual entry decoder window equals fresh complete source')
        if key is not None:
            self.pair_key(actual_key,key)
            if pc==root:self.key_identity(actual_key,key)
        if focal:
            need(heads==66 and row==self.graph_model['head'][head*32:(head+1)*32]and self.f(e,t,'original')==self.graph_model['original'][head*336:(head+1)*336],'whole actual entry row and descriptor equal immutable certificate')
        return head

    def scan(self,b,n):
        self.eq(b,'pso_scan',started=1,complete=1,expected=n,compared=n,differences=0,first_offset=0,expected_value=0,actual_value=0)

    def checkpoint(self,slot,index,known):
        t='pso_slot';g=self.f(slot,t,'generation');ref=self.f(slot,t,'identity');gen=self.i(ref,'li2_ptr_slot_ref','generation')
        self.eq(ref,'li2_ptr_slot_ref',owner=self.symbol('pe'),index=index,reserved=0)
        self.eq(g,'li2_pg_generation',generation=gen,proof=self.i(slot,t,'proof'))
        check=self.f(slot,t,'check');self.eq(check,'pso_check',slot=index,generation=gen)
        matches=[i for i,c in enumerate(self.certificates)if self.i(c,'pso_certificate','slot')==index and self.i(c,'pso_certificate','generation')==gen]
        expected=next((i for i in matches if i in known),None)
        if expected is None:
            self.eq(check,'pso_check',certificate=0)
            for k in('proof','code','publication'):zero(self.f(check,'pso_check',k),'explicit unavailable unrelated-startup immutable comparison')
            need(not matches,'known focal generation cannot claim unavailable certificate')
            if self.i(g,'li2_pg_generation','installed'):
                _,member,_,_=self.claim(slot,self.current_domain);key=self.f(member,'pda_member_completion','source')
                need(self.i(key,'li2_pg_source_key','entry')!=self.head,'unrelated startup identity is not an unobserved focal root')
        else:
            c=self.certificates[expected];self.eq(check,'pso_check',certificate=expected+1)
            self.eq(g,'li2_pg_generation',installed=1,complete=1,proof_complete=1,ready_generation=gen)
            payload=self.f(c,'pso_certificate','payload');header=self.f(payload,'pe_payload','header')
            need(self.f(g,'li2_pg_generation','layout')==self.f(header,'pe_header','layout')and self.i(g,'li2_pg_generation','build_serial')==self.i(header,'pe_header','serial'),'certificate binds actual immutable generation layout/build')
            for k,n in(('proof',364544),('code',69632),('publication',362656)):self.scan(self.f(check,'pso_check',k),n)
        return gen

    def prior_completed(self,slot,counts):
        t='pso_slot';g=self.f(slot,t,'generation');c,m,_,_=self.claim(slot,self.current_domain);gt='li2_pg_generation'
        generation=self.i(g,gt,'generation');serial=self.i(c,'pda_completion','serial');self.setup(slot)
        self.eq(g,gt,installed=1,complete=1,proof_complete=1,ready_generation=generation,plan_proofs=2,none_proofs=1,active_refs=0,linked=0,domain_refs=0,proof=self.proof,code_copied=69632,code_verified=69632,proof_zeroed=364544,proof_copied=362656,proof_verified=364544)
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

    def member_transition(self,entry,end,serial,cold):
        t='pso_slot';gt='li2_pg_generation';g=self.f(entry,t,'generation');z=self.f(end,t,'generation');self.setup(entry);gen=self.i(g,gt,'generation');build=self.i(g,gt,'build_serial')
        self.eq(g,gt,installed=1,complete=1,proof_complete=1,ready_generation=gen,plan_proofs=2,none_proofs=1,generated=self.generated,proof=self.proof,spill=self.spill,active_refs=1,linked=1,domain_refs=1,code_copied=69632,code_verified=69632,proof_zeroed=364544,proof_copied=362656,proof_verified=364544)
        need(q(self.f(g,gt,'member_generation'))==(2*gen,2*gen+1)and q(self.f(g,gt,'member_refs'))==(1,1),'exact typed internal member refs');need(q(self.f(g,gt,'incoming'))==(0,1),'one actual cross-member incoming link')
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

    def certificate(self,index,slot,entry,serial,gen):
        c=self.certificates[index];t='pso_certificate';self.setup(slot)
        self.eq(c,t,complete=1,index=index,slot=self.i(self.f(slot,'pso_slot','identity'),'li2_ptr_slot_ref','index'),generation=gen,entry=entry,proof_bytes=364544,code_bytes=69632,publication_bytes=362656)
        zero(self.f(c,t,'tail'),'whole literal immutable proof tail zero')
        payload=self.f(c,t,'payload');ph=self.f(payload,'pe_payload','header')
        self.eq(ph,'pe_header',version=1,serial=serial,generation=gen,registry=self.symbol('pe'),generated=self.generated,spill=self.spill,table=self.table,plan_proof=2,none_proof=1,source_validations=1,registered_epoch=0,rseq_address=0,rseq_length=0,rseq_signature=0,lifetime_version=1,lifetime_mode=2)
        need(self.layout(self.f(ph,'pe_header','layout'))==self.geometry and q(self.f(ph,'pe_header','member_generation'))==(2*gen,2*gen+1),'immutable actual retained member identities/layout');zero(self.f(ph,'pe_header','reserved'),'whole header reserved')
        binding=self.image['persistent_binding'];need(binding['version']==1 and binding['unregistered']is True and binding['profile']=='persistent-subentry-'+binding['mode']+'-v1','explicit retained-two source binding')
        need(self.f(ph,'pe_header','archive')==bytes.fromhex(binding['archive']['sha256'])and self.f(ph,'pe_header','policy')==bytes.fromhex(binding['policy_sha256']),'whole actual retained archive/policy authority')
        key=self.f(payload,'pe_payload','source');self.source_key(key,entry);expected=self.compact(payload,entry)
        need(self.f(c,t,'code')==expected['image']+expected['stub_image'],'all17 actual code pages in shared literal certificate')
        return payload

    def memory(self,b,failed):
        t='li2_pso_memory';self.eq(b,t,attempted=1,complete=1,after_abort=int(failed),rows_checked=6,data_copied=8192,stack_copied=224,result=0,detail=0,rsp=RSP,data_first=DATA,stack_first=RSP-128)
        m=self.maps(self.f(b,t,'maps'),0)
        before,after=(self.f(b,t,k)for k in('before','after'));mt='li2_maps_stats'
        self.eq(before,mt,active=0,poisoned=0,reserved=0);self.eq(after,mt,active=0,poisoned=0,reserved=0,valid=1)
        self.r.change(before,after,mt,values=dict(fresh_calls=self.i(before,mt,'fresh_calls')+1,acquisitions=self.i(before,mt,'acquisitions')+1),observed=('valid','invalidations','mutation_epoch'))
        invalidations=self.i(after,mt,'invalidations')-self.i(before,mt,'invalidations')
        need(invalidations>=1 and self.i(after,mt,'mutation_epoch')-self.i(before,mt,'mutation_epoch')==invalidations,'actual explicit fresh invalidation and every gateway invalidation')
        need(m[:3]==(self.i(after,mt,'acquisitions'),0,self.i(after,mt,'mutation_epoch')),'memory acquisition actual stats join')
        rows=self.r.items(b,t,'rows','li2_pso_map_row')
        for i,row in enumerate(rows):
            self.eq(row,'li2_pso_map_row',offset=0,major=0,minor=0,inode=0,private=1)
            a,z,prot=self.v(row,'li2_pso_map_row','first end prot');need(a%PAGE==z%PAGE==0 and a<z,'actual page-aligned memory extent')
            if i<2:need((a,z,prot)==(DATA,DATA+8192,3),'actual two-page writable data')
            elif i==4:need((a,z,prot)==(STACK+4096,STACK+4096+131072,3),'actual fixed writable guest stack')
            else:
                point=(DATA+8192,STACK,STACK+4096+131072)[(2,3,5).index(i)]
                need(a<=point and point+PAGE<=z and prot==0,'actual inaccessible data/stack guard')
        return dict(data=self.f(b,t,'data'),stack=self.f(b,t,'stack'))

    def predecessor(self,slot,pc,ingress,closed=True,original_flags=None):
        t='li2_tf_chain_slot';index=self.i(slot,t,'index');need(index in(0,1),'actual predecessor slot index')
        self.eq(slot,t,chain=self.symbol('selected_chain'),phase=5 if closed else 3,fallback=0,prepare_complete=1,decode_attempted=1,decode_complete=1,retry=0,unexpected_frame_observed=0,unexpected_signal=0,unexpected_code=0,unexpected_errno=0,unexpected_address=0,prepare_result=0,decode_result=0,classify_result=0)
        need(self.i(slot,t,'generation')>0 and self.i(slot,t,'event_id')>0,'actual predecessor generation/event')
        origin=self.i(slot,t,'origin');need(origin in(1,2)and self.i(slot,t,'prepare_attempted')==int(origin==2),'actual predecessor NX/TRACE preparation')
        for k in('first_decoded','first_fetch','first_release','unexpected'):zero(self.f(slot,t,k),'no unused predecessor '+k)
        kind='nop'if pc==self.page+0x1fe else'jmp';code,length=self.decoded(self.f(slot,t,'decoded'),pc,kind)
        ref=self.chain_fetch(self.f(slot,t,'fetch'),pc,not closed);o=self.f(slot,t,'owner');st=self.f(o,'li2_tf_owner','step');qt='li2_step_owner'
        flags=(ingress['greg'][17]&~TF)if original_flags is None else original_flags
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
        self.eq(pages[0],'li2_step_page',address=pc&-PAGE,object=self.i(src,'li2_fetch_page','allocation'),generation=self.i(src,'li2_fetch_page','generation'),offset=self.source_offset+((pc&-PAGE)-self.page),closed_prot=1,open_prot=5);zero(pages[1],'unused predecessor permission page')
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

    def completion(self,c,next_id,next_serial):
        t='pda_completion';cid,serial=self.v(c,t,'id serial');count=self.i(c,t,'count')
        need(0<cid<=next_id and 0<serial<=next_serial and count in(1,2),'bounded actual immutable completion identity')
        self.eq(c,t,complete=1);members=self.r.items(c,t,'member','pda_member_completion');refs=[];seen=[]
        pin=self.f(c,t,'rseq');self.eq(pin,'li2_pg_rseq_progress',active=0,checking=0,first_error=0,unsafe_terminal=0,seed_complete=1,entry_complete=1,close_complete=1,first_detail=0,cancel_started=0,cancel_complete=0,word_before=0,word_entry=0,word_after=0,domain_bound=1,domain_count=count)
        self.eq(self.f(pin,'li2_pg_rseq_progress','token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
        self.unregistered_pin(pin,serial,terminal=True,focal=False)
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
            if i==0:self.entry_value(self.f(self.f(c,t,'domain_source'),'li2_pgd_source_progress','entry'),key,saved_source,self.f(v,'li2_pgd_ref','layout'))
            # Pair identity excludes only separately authenticated root, never source bytes or stable backing identity.
            self.pair_key(source_key,key)
            gen=self.i(g,'li2_pg_generation','generation');self.eq(g,'li2_pg_generation',installed=1,complete=1,proof_complete=1,ready_generation=gen,linked=0,active_refs=0,domain_refs=0)
            for k in('member_refs','incoming','cleanup'):zero(self.f(g,'li2_pg_generation',k),'completed member has no live reference or failed cleanup')
            self.permission3(self.f(g,'li2_pg_generation','open'),5);self.permission3(self.f(g,'li2_pg_generation','close'),1)
            self.proof_query(self.f(m,mt,'proof'),self.i(g,'li2_pg_generation','proof'),1)
            if i==0:
                saved_entry=self.f(self.f(c,t,'domain_source'),'li2_pgd_source_progress','entry');self.eq(saved_entry,'li2_pgs_entry',generation=gen,build_serial=self.i(g,'li2_pg_generation','build_serial'),slot=slot,bank=bank)
            self.eq(h,'pe_header',lifetime_version=1,lifetime_mode=2,version=1,serial=self.i(g,'li2_pg_generation','build_serial'),generation=gen,registry=self.symbol('pe'),generated=self.geometry[0],spill=self.geometry[4],registered_epoch=self.i(pin,'li2_pg_rseq_progress','registration_epoch'),rseq_address=self.i(pin,'li2_pg_rseq_progress','address'),rseq_length=self.i(pin,'li2_pg_rseq_progress','length'),rseq_signature=self.i(pin,'li2_pg_rseq_progress','signature'))
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

    def work(self,w,rows,count,serial,terminal=False):
        t='pda_work';v=self.f(w,t,'view');vt='li2_pgd_view';self.eq(w,t,bound=1,completion=int(terminal),aborting=0,recovery_member=2)
        self.eq(v,vt,count=count,reserved=0,directory=self.h[40]);self.eq(self.f(v,vt,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
        members=self.r.items(v,vt,'member','li2_pgd_member');refs=[];pairs=[]
        for i,m in enumerate(members):
            if i>=count:zero(m,'whole unused active-domain member');continue
            mt='li2_pgd_member';ref=self.f(m,mt,'identity');slot,bank=self.v(ref,'li2_pgd_ref','slot bank');need(slot in(0,1)and bank in(0,1),'actual member slot/bank')
            s=rows[slot];g=self.f(s,'pso_slot','generation');root=self.ref(ref,g,slot,bank);refs.append(ref)
            proof=self.i(s,'pso_slot','proof');self.eq(m,mt,plan=proof+self.r.types['pe_payload']['fields']['plan']['offset'],key=proof+self.r.types['pe_payload']['fields']['source']['offset'])
            ci=next((j for j,c in enumerate(self.certificates)if self.i(c,'pso_certificate','slot')==slot and self.i(c,'pso_certificate','generation')==self.i(g,'li2_pg_generation','generation')),None)
            need(ci is not None and root==self.i(self.certificates[ci],'pso_certificate','entry'),'actual active member joins its complete literal certificate')
            pairs.append((slot,self.i(g,'li2_pg_generation','generation'),self.i(g,'li2_pg_generation','build_serial')))
        need(len({x[0]for x in pairs})==count and len({x[1]for x in pairs})==count,'distinct actual domain generations')
        self.eq(w,t,primary=pairs[0][0],primary_bank=self.i(refs[0],'li2_pgd_ref','bank'),peer=2 if count==1 else pairs[1][0],exit_member=(count-1)if terminal else 2)
        receipt=self.i(w,t,'receipt');need(receipt<3,'bounded selected immutable completion cell')
        self.permission(self.f(w,t,'directory_write'),self.h[40],3,3);self.permission(self.f(w,t,'directory_seal'),self.h[40],1,3)
        if terminal:self.query(self.f(w,t,'directory_closed'),self.h[40],1,pages=3)
        else:zero(self.f(w,t,'directory_closed'),'no premature directory terminal query')
        d=self.f(w,t,'directory');dt='li2_jd_domain_directory';total=66;need(count==1 and self.i(refs[0],'li2_pgd_ref','root')==self.head,'one exact subentry domain member')
        self.eq(d,dt,version=1,count=total,serial=serial,reserved=0);expected=[]
        for r in refs:
            root=self.i(r,'li2_pgd_ref','root');offsets=self.graph_model['offsets'];bases=q(self.f(r,'li2_pgd_ref','layout'))[:2]
            for j,off in enumerate(offsets):expected.append(struct.pack('<3Q2I',self.page+off,bases[j//64]+512*(j%64),self.i(r,'li2_pgd_ref','generation'),self.i(r,'li2_pgd_ref','slot'),j))
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


    def decoded(self,b,pc,kind=None):
        off=pc-self.page;forms={0x1fe:(299,2,1),0x1128:(765,6,0),0x1107:(765,3,0)}
        need(off in forms,'one exact original subentry boundary');code,length,step=forms[off]
        self.eq(b,'li2_decoded',pc=pc,next_pc=pc+length,abi_version=1,decode_status=0,code=code,kind=0,destination=16,width_bits=0,step_disposition=step,available=15,length=length,reserved=0)
        need(self.f(b,'li2_decoded','bytes')==self.app['source'][off:off+15]+b'\0','whole actual ordinary subentry decoder window')
        return code,length

    def compact(self,payload,entry):
        c=self.f(payload,'pe_payload','plan');t='li2_pg_compact'
        need(entry==self.head==self.page+0x200,'only the exact immutable66-head root')
        table=plan.table(self.ranges+[(self.page,self.page+PAGE),(self.page+PAGE,self.page+2*PAGE)],self.table)
        need(self.f(c,t,'table')==table,'whole actual exclusions; no invented unregistered rseq word')
        expected=plan.graph(self.app['source'],self.page,entry,self.geometry,table,subentry_pointer=self.app['symbols']['region_app_subentry_pointer']);self.graph_model=expected
        self.eq(c,t,version=3,bytes=353608,ready=1,result=0,heads=66,exits=1,stores=1,source_bytes=expected['source_bytes'],source_mask=expected['source_mask'],decoder_result=0,guard_result=0,reserved=0,links=1,reserved2=0,entry=entry)
        need(struct.unpack('<2I',self.f(c,t,'member_heads'))==(64,2)and q(self.f(c,t,'page'))==(self.page,self.page+PAGE)and self.layout(self.f(c,t,'layout'))==self.geometry and self.f(c,t,'source')==self.app['source'],'whole independent source and64/2 partition')
        for k in('image','stub_image','head','original','frontier','edge','instruction','guard','exit_pc'):
            need(self.f(c,t,k)==expected[k],'whole independent startup '+k)
        need(self.table-64576==self.proof+self.r.types['pe_payload']['fields']['plan']['offset']+self.r.types[t]['fields']['original']['offset'],'actual immutable common full/compact row address')
        return expected

    def unregistered_pin(self,b,serial,terminal,focal=True):
        t='li2_pg_rseq_progress'
        self.eq(b,t,active=int(not terminal),checking=0,first_error=0,unsafe_terminal=0,seed_complete=1,entry_complete=1,
                close_complete=int(terminal),first_detail=0,pid=self.pid,tid=self.pid,fs_result=0,gs_result=0,
                registration_epoch=0,registration_calls=0,address=0,page=0,length=0,signature=0,
                word_before=0,word_entry=0,word_after=0,
                fs_selector=0,gs_selector=0,session=self.symbol('selected_session'),cancel_started=0,cancel_complete=0,
                lifetime_mode=2,word_observed=0,tls_complete=1,domain_bound=1)
        self.eq(self.f(b,t,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
        if focal:
            self.eq(b,t,fs=self.app['machine'][1],gs=self.app['machine'][2])
        else:
            # A saved completion can predate ARCH_SET_FS. It retains the two
            # actual successful GET bases by value; the later activation must
            # independently join its current bases to the application frames.
            need(all(0<=v<1<<47 for v in self.v(b,t,'fs gs')),'complete historical user TLS bases')
        for name in('before','observed','after','current_observed','current_after'):
            zero(self.f(b,t,name),'unregistered lifetime has no descriptor mapping or current-data observation')
        need(self.i(b,t,'raw_checks')>0,'actual positive unregistered binding checks; no word observation')
        return self.i(b,t,'raw_checks')

    def pin(self,b,state,serial,heads,refs,terminal=False):
        t='li2_pg_rseq_progress';checks=self.unregistered_pin(b,serial,terminal)
        self.eq(b,t,cold_heads=heads,cold_stores=1 if heads else 0,cold_stubs=1 if heads else 0,domain_count=len(refs))
        need(self.f(b,t,'domain_ref')==b''.join(refs)+bytes((2-len(refs))*80),'whole actual unregistered source member references')
        rt='li2_rseq_state'
        self.eq(state,rt,initialized=1,registered=0,held=0,first_error=0,phase=0,first_detail=0,pid=self.pid,tid=self.pid,
                address=0,page=0,length=0,signature=0,epoch=0,fs_base=self.app['machine'][1],gs_base=self.app['machine'][2],
                fs_result=0,gs_result=0,tls_attempted=1,tls_complete=1,calls=0,registrations=0,unregistrations=0,
                kernel_errors=0,instruction_checks=0,range_checks=0,repeat_checks=0,run_checks=0,syscall_checks=0)
        zero(self.f(state,rt,'data'),'no registered-data receipt before first registration')
        zero(self.f(state,rt,'transaction'),'no attempted registration transaction during focal execution')
        return checks

    def live_rseq(self,b,state,frame):
        t='li2_link_rseq_live';self.eq(b,t,attempted=1,complete=1,result=0,session=self.symbol('selected_session'),epoch=0,registered=0)
        regs=self.f(b,t,'registers');self.eq(regs,'li2_write_registers',fs_base=self.i(state,'li2_rseq_state','fs_base'),gs_base=self.i(state,'li2_rseq_state','gs_base'))
        need(q(self.f(regs,'li2_write_registers','gpr'))==tuple(frame['greg'][i]for i in GREG),'every actual unregistered live GPR')
        need(self.v(regs,'li2_write_registers','fs_base gs_base')==(frame['fs'],frame['gs']),'complete observed-unregistered TLS bound to actual frame')

    def epoch(self,b,index,baseline,previous=None):
        t='pso_epoch';st='pso_stage';gt='li2_pg_generation';pt='li2_pg_progress';it='pso_epoch_info';warm=index==1;count=1
        need(index in(0,1)and(previous is None)==(index==0),'exact cold and actual subentry chronology')
        entry=self.page+0x1100 if warm else self.head;ci=0;heads=66;exitpc=self.page+0x1107
        h=q(self.f(b,t,'h'));need(h[:3]==(1,index,entry)and h[3]>0 and h[4:11]==(1,1,h[3],0,0,1,0)and h[11]==h[3]+1 and h[12:15]==(0,0,1)and h[24]in(0,1)and h[25:]==(2,1,0,2,1,0,0),'actual accepted domain entry/exit with zero interior signal')
        need(h[15]in(0,1)and h[16]==self.symbol('selected_session')and h[17]>0 and h[18]<U64 and h[19:24]==(h[15],1,0,0,1),'actual selected preclose domain predecessor')
        initial=self.f(b,t,'initial_registry');need(initial==self.f(b,t,'terminal_registry'),'whole domain registry unchanged during epoch');self.ranges,_=self.registry_prefix(self.f(self.b,'pso_wire','startup_registry'),initial)
        prior=self.f(b,t,'prior_counts');pc=self.counts(prior);prior_slots=self.f(b,t,'prior');prior_domain=self.domain_checkpoint(self.f(b,t,'prior_domain'),baseline)
        self.domain_state(prior_domain,pc['next_serial'])
        need(pc['entries']==pc['completed']and pc['publications']==pc['next_generation']and pc['unexpected']==0,'all preceding domain epochs completed before focal entry')
        prior_rows,_=self.storage(prior_slots,pc,{0}if warm else set(),prior_domain)
        if warm:
            need(self.f(prior_slots,'pso_slots','slots')==self.f(previous['slots_raw'],'pso_slots','slots'),'both completed retained slots survive ordinary trampoline')
            old_counts=self.counts(previous['counts_raw']);misses=pc['cancelled']-old_counts['cancelled'];need(misses>=0,'monotonic intervening cancellations')
            self.delta(previous['counts_raw'],prior,next_serial=misses,offers=misses,cold_attempts=misses,cancelled=misses,miss_deltas=tuple(x-y for x,y in zip(pc['misses'],old_counts['misses'],strict=True)))
            self.r.change(baseline,prior_domain,'pda_state',observed=('work',))
            if self.f(prior_domain,'pda_state','work')!=self.f(baseline,'pda_state','work'):
                reset=bytearray(self.r.types['pda_work']['bytes'])
                for k,v in(('peer',2),('receipt',3),('exit_member',2),('recovery_member',2)):struct.pack_into('<I',reset,self.r.types['pda_work']['fields'][k]['offset'],v)
                need(self.f(prior_domain,'pda_state','work')==bytes(reset),'only exact completed-attempt work reset between focal activations')
            chosen=previous['slot']
            need(all(not self.i(self.f(x,'pso_slot','generation'),gt,'installed')or self.i(self.f(self.claim(x,prior_domain)[1],'pda_member_completion','source'),'li2_pg_source_key','entry')!=entry for x in prior_rows),'subentry does not bypass an exact-root retained candidate')
        else:chosen=self.choose(prior_rows,entry,prior_domain)
        need(chosen==h[24],'actual deterministic selected certificate')
        resident=prior_rows[chosen];rg=self.f(resident,'pso_slot','generation');installed=self.i(rg,gt,'installed')
        entered=self.f(b,t,'entered');end=self.f(b,t,'terminal');p=self.f(entered,st,'progress');ep=self.f(end,st,'progress');serial=self.i(p,pt,'serial');gen=self.i(p,pt,'generation')
        need(serial==pc['next_serial']+1 and 0<gen<U64//2,'actual monotonic domain attempt/member generation')
        inc=dict(next_serial=1,offers=1,entries=1,permit_claims=1 if warm else installed)
        if warm:inc.update(subentry_selections=1,subentry_hits=1,subentry_entries=1)
        else:inc.update(next_generation=1,publications=1,cold_attempts=1,retirements=installed)
        self.delta(prior,self.f(entered,st,'counts'),**inc);self.delta(self.f(entered,st,'counts'),self.f(end,st,'counts'),completed=1,subentry_completed=int(warm))
        ed=self.domain_checkpoint(self.f(entered,st,'domain'),baseline);zd=self.f(b,t,'terminal_domain');need(self.domain_checkpoint(self.f(end,st,'domain'),zd)==zd,'whole terminal domain checkpoint and literal state equality')
        self.domain_state(ed,serial);self.domain_state(zd,serial)
        self.r.change(prior_domain,ed,'pda_state',values=dict(dual_entries=self.i(prior_domain,'pda_state','dual_entries')+0),observed=('work','claimed'))
        eslots=self.f(entered,st,'slots');zslots=self.f(end,st,'slots');active=(chosen,)
        erows,selected=self.storage(eslots,self.counts(self.f(entered,st,'counts')),{0},ed,active)
        zrows,zselected=self.storage(zslots,self.counts(self.f(end,st,'counts')),{0},zd)
        need(selected==zselected==chosen and self.f(eslots,'pso_slots','previous_selection')==self.f(prior_slots,'pso_slots','selection')and self.f(zslots,'pso_slots','previous_selection')==self.f(eslots,'pso_slots','previous_selection'),'actual previous and selected typed slot identities')
        need(prior_rows[1-chosen]==erows[1-chosen]==zrows[1-chosen],'inactive retained slot unchanged through cold publication')
        actual=erows[chosen];terminal=zrows[chosen];self.setup(actual);g=self.f(actual,'pso_slot','generation');eg=self.f(terminal,'pso_slot','generation');buildserial=self.i(g,gt,'build_serial')
        payload=self.certificate(ci,actual,self.head,buildserial,gen);key=self.f(payload,'pe_payload','source');ph=self.f(payload,'pe_payload','header')
        need(gen==(self.i(rg,gt,'generation')if warm else pc['next_generation']+1)and buildserial==(self.i(rg,gt,'build_serial')if warm else serial),'exact cold publication or retained primary generation')
        need(not warm or installed==1,'subentry requires actual prior completed certificate')
        ew=self.f(ed,'pda_state','work');zw=self.f(zd,'pda_state','work');refs,members,cell=self.work(ew,erows,count,serial);zrefs,zmem,zcell=self.work(zw,zrows,count,serial,True)
        need(refs==zrefs and members==zmem and cell==zcell,'whole stable shared member set through closure')
        need(self.f(self.f(ew,'pda_work','view'),'li2_pgd_view','entry')==self.f(self.f(zw,'pda_work','view'),'li2_pgd_view','entry'),'immutable actual-entry receipt through full close')
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
        self.r.change(ed,zd,'pda_state',values=dict(next_id=nextid+1,dual_completed=self.i(ed,'pda_state','dual_completed')+0),observed=('work','completion','claimed'))
        need(struct.unpack('<3I',self.f(zd,'pda_state','claimed'))==tuple(masks),'one new completion resets only its own claim mask')
        zcells=self.state_cells(zd)
        for i in range(3):
            if i!=cell:need(zcells[i]==cells[i],'every still-live completion cell remains byte-exact')
        c=zcells[cell];self.eq(c,'pda_completion',id=nextid+1,serial=serial,count=count,complete=1)
        self.eq(p,pt,serial=serial,registration_epoch=0,publication=1,generation=gen,phase=9,first_error=0,source_count=2,opened_pages=17*count,closed_pages=0,anchor_released=0,registration_rechecked=0,completion_permit=0,first_detail=0,generated=self.generated,proof=self.proof,table=self.table,spill=self.spill)
        need(q(self.f(p,pt,'source'))==(self.page,self.page+PAGE)and self.layout(self.f(p,pt,'layout'))==self.geometry,'actual shared progress retains primary source/layout')
        self.r.change(p,ep,pt,values=dict(phase=13,closed_pages=17*count,anchor_released=1,registration_rechecked=1,completion_permit=1))
        for stage in(entered,end):self.eq(stage,st,busy=1,active=1,failing=0,resuming=0,pending=1);need(0<self.i(stage,st,'route')<32,'actual generated domain route')
        need(self.f(entered,st,'route')==self.f(end,st,'route'),'unchanged active route through shared close')
        for i,slot in enumerate(active):
            self.member_transition(erows[slot],zrows[slot],serial,not warm)
            claim,cm,claim_cell,claim_member=self.claim(zrows[slot],zd)
            need(claim==c and claim_cell==cell and claim_member==i and self.f(cm,'pda_member_completion','identity')==refs[i],'each member receives its exact joint completion claim')
            if warm:
                before=self.f(prior_rows[slot],'pso_slot','generation');current=self.f(erows[slot],'pso_slot','generation')
                self.r.change(before,current,gt,values=dict(active_refs=1,linked=1,domain_refs=1),observed=('member_refs','incoming','open','close','slots','cell'))
                self.r.change(prior_rows[slot],erows[slot],'pso_slot',observed=('generation','claim','banks'))
        self.setup(actual)
        info=self.f(b,t,'info');bank=self.i(refs[0],'li2_pgd_ref','bank');self.eq(info,it,selected_bank=bank,warm=int(warm),initialized=1,registered=1,code_allocated=2,proof_allocated=1,code_registered=2,proof_registered=1,close_started=1,close_complete=1,prepare_started=1,prepare_complete=1,build_started=int(not warm),build_returned=int(not warm),redirected=1,exit_seen=1,exit_index=q(self.graph_model['exit_pc']).index(exitpc),recovery_started=1,recovery_complete=1,guest_data_fault=0,cleanup_started=0,cleanup_complete=0,consumed=1,plan_proofs=0 if warm else 2,none_proofs=0 if warm else 1,code_allocation=self.h_alloc,proof_allocation=self.h_proof_alloc,build_result=0,recovery_result=0,release_result=0,gpr_written=self.graph_model['gpr_written'],flags_written=self.graph_model['flags_written'],ticket=self.symbol('span_transfer'),registry_count=len(self.ranges))
        self.eq(self.f(info,it,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
        need(self.f(info,it,'session')==self.f(self.b,'pso_wire','session')and self.f(info,it,'registry')==self.f(initial,'pso_registry','ranges')and self.f(info,it,'banks')==self.f(terminal,'pso_slot','banks'),'whole actual domain session/registry/banks')
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
        want=list(before['greg']);redirect=self.geometry[1]if warm else self.generated;want[16]=redirect;need(returned['greg']==tuple(want)and returned['fp']==before['fp']and returned['si']==before['si']and(returned['fs'],returned['gs'])==tuple(self.app['machine'][1:3]),'whole domain redirect changes only original RIP')
        uc=bytearray(before['uc']);struct.pack_into('<Q',uc,40+16*8,redirect);need(returned['uc']==bytes(uc),'whole returned UC except actual redirect')
        self.nx(after,exitpc);need(after['fp']==before['fp']and after['fp_bytes']==before['fp_bytes']and after['mask']==MASK and(after['fs'],after['gs'])==tuple(self.app['machine'][1:3]),'all domain FP/AF/mask/TLS preserved')
        projection=self.f(b,t,'predecessor');self.eq(projection,'pso_predecessor',complete=1,unexpected_compared=self.r.types['li2_step_frame']['bytes'],unexpected_nonzero=0)
        slot=self.f(projection,'pso_predecessor','closed')+bytes(self.r.types['li2_step_frame']['bytes']);self.r.walk(slot,'li2_tf_chain_slot')
        prefix=self.f(projection,'pso_predecessor','before_prefix');wanted=bytearray(prefix);sf=self.r.types['li2_tf_chain_slot']['fields'];of=self.r.types['li2_tf_owner']['fields'];tf=self.r.types['li2_step_owner']['fields'];struct.pack_into('<I',wanted,sf['phase']['offset'],5);at=sf['owner']['offset']+of['step']['offset']
        for k,v in(('phase',5),('trace_seen',1),('revoke_sync_started',1)):struct.pack_into('<I',wanted,at+tf[k]['offset'],v)
        need(bytes(wanted)==slot[:len(prefix)],'whole actual predecessor prefix close transition')
        need(self.i(slot,'li2_tf_chain_slot','index')==h[15]and self.i(slot,'li2_tf_chain_slot','event_id')<h[17],'actual predecessor older generation/event')
        predecessor_pc=self.page+(0x1128 if warm else 0x1fe);predecessor,_=self.predecessor(slot,predecessor_pc,ingress);self.eq(slot,'li2_tf_chain_slot',origin=2 if warm else 1)
        ref=self.f(info,it,'ref');seq=self.i(ref,'li2_fetch_ref','sequence');tr=self.f(entered,st,'transfer');self.transfer(tr,slot,ingress,before,ref)
        need(tr==self.f(end,st,'transfer')and self.i(tr,'li2_span_transfer_progress','event')==h[17]and self.i(tr,'li2_span_transfer_progress','serial')==self.i(p,pt,'transfer_serial'),'whole actual consumed domain transfer')
        es=self.f(entered,st,'source');zs=self.f(end,st,'source');self.source(es,serial,entry,key,ref);self.source(zs,serial,entry,key,ref,terminal=True);need(self.f(es,'li2_pg_source_progress','source')==self.f(zs,'li2_pg_source_progress','source'),'one complete source anchor held through all internal transfers')
        self.domain_source(self.f(entered,st,'domain_source'),refs,serial,False,es);self.domain_source(self.f(end,st,'domain_source'),refs,serial,True,zs)
        actual_entry=self.f(entered,st,'entry')
        need(actual_entry==self.f(end,st,'entry')==self.f(self.f(ew,'pda_work','view'),'li2_pgd_view','entry')==self.f(self.f(entered,st,'domain_source'),'li2_pgd_source_progress','entry'),'whole actual entry receipt retained across owner/source/domain')
        self.entry_value(actual_entry,key,self.f(es,'li2_pg_source_progress','source'),self.f(g,gt,'layout'),focal=True)
        self.eq(actual_entry,'li2_pgs_entry',transfer_serial=self.i(tr,'li2_span_transfer_progress','serial'),generation=gen,build_serial=buildserial,slot=chosen,bank=self.i(info,it,'selected_bank'))
        self.eq(self.f(actual_entry,'li2_pgs_entry','target'),'li2_pgs_target',head=64 if warm else 0,member=int(warm),local=0,source_page=int(warm),pc=entry,generated=redirect)
        er=self.f(entered,st,'rseq');zr=self.f(end,st,'rseq');estate=self.f(entered,st,'state');zstate=self.f(end,st,'state');a=self.pin(er,estate,serial,0 if warm else heads,refs);z=self.pin(zr,zstate,serial,0 if warm else heads,refs,terminal=True);need(z>a and estate==zstate,'actual observed-unregistered pin and complete state unchanged throughout lifetime')
        # Cold proof checks the real cross-member stub after all66 heads;
        # unregistered ordinary steps do not replace this saved footprint.
        lastpc,length,code=self.geometry[2],6,765
        self.eq(estate,'li2_rseq_state',last_first=0,last_end=0,last_pc=lastpc,last_code=code,last_policy=1)
        self.eq(self.f(estate,'li2_rseq_state','last_footprint'),'li2_write_footprint',pc=lastpc,next_pc=lastpc+length,first=0,end=0,abi_version=1,policy=1,code=code,length=length)
        self.progress(self.f(entered,st,'fetch'),seq,True);self.progress(self.f(end,st,'fetch'),seq,False);need(self.f(info,it,'final_fetch')==self.f(end,st,'fetch'),'whole actual released shared fetch')
        for k,actual_value in(('source',zs),('domain_source',self.f(end,st,'domain_source')),('rseq',zr),('fetch',self.f(end,st,'fetch'))):need(self.f(c,'pda_completion',k)==actual_value,'joint completion retains whole actual '+k)
        lives=self.r.items(info,it,'live','li2_link_rseq_live')
        for x in lives[:2]:self.live_rseq(x,estate,before)
        self.live_rseq(lives[2],zstate,after);self.proof_query(self.f(info,it,'proof_exit'),self.proof,1)
        for k in('code_exit','recovered','recovery_scratch'):zero(self.f(info,it,k),'normal domain exit invents no unexpected recovery')
        bm=self.memory(self.f(b,t,'before_memory'),False);am=self.memory(self.f(b,t,'after_memory'),False);model=app_model.trace_model(self.app);first,last=(72,74)if warm else(1,67);need(bm==dict(data=model[first][3],stack=model[first][4])and am==dict(data=model[last][3],stack=model[last][4]),'all actual compiled guest memory effects match original instructions')
        # Directory pages are sealed exact bytes at entry and drain, including all padding.
        directory=self.f(ew,'pda_work','directory')+bytes(12288-self.r.types['li2_jd_domain_directory']['bytes']);need(self.f(b,t,'initial_directory')==self.f(b,t,'terminal_directory')==directory,'whole actual immutable directory throughout shared lifetime')
        need(self.f(b,t,'initial_slots')==self.graph_model['initial_slots']+bytes(PAGE)and self.f(b,t,'terminal_slots')==self.graph_model['terminal_slots']+bytes(PAGE),'whole actual cross-member link publication and reset')
        initial_spill=self.f(b,t,'initial_spill');terminal_spill=self.f(b,t,'terminal_spill')
        zero(initial_spill[32:],'initial shared spill tail and dispatch cell');zero(terminal_spill[32:],'terminal shared spill tail and dispatch cell')
        record=self.graph_model['guard'][64*1584:65*1584];scratch=struct.unpack_from('<4I',record,32)
        state=model[72 if warm else 65][1]
        need(terminal_spill[:32]==struct.pack('<4Q',*(state[j]for j in scratch)),'whole saved MOV scratch at its actual original prestate')
        if warm:need(initial_spill==previous['terminal_spill'],'same completed spill reused without invented initialization')
        else:zero(initial_spill,'actual cold spill initialization')
        final_cell=self.r.items(eg,gt,'cell','pg_dispatch_cell_transition')[2]
        self.eq(final_cell,'pg_dispatch_cell_transition',before=0)
        return dict(kind='subentry'if warm else'cold',mode=0,terminal_spill=terminal_spill,slot=chosen,generation=gen,build_serial=buildserial,prior_generation_installed=installed,begin=h[3],event=h[17],terminal_ordinal=h[11],ingress=ingress,before=before,returned=returned,logical=after,after=after,predecessor_before=predecessor,before_memory=bm,after_memory=am,completed=1,closed_pages=17*count,domain_members=count,anchor_released=1,permit=1,interior_signals=0,members=members,shared_lifetime=1,completion_id=nextid+1,claim_members=tuple(range(count)),joint_complete=1,slots_raw=zslots,counts_raw=self.f(end,st,'counts'),serial=serial,closed_slot=slot,dispatch_pc=exitpc,domain_raw=zd)


    def next_trace(self,b,last,epoch):
        t='pso_next';slot=self.f(b,t,'closed');st='li2_tf_chain_slot'
        self.eq(b,t,expected_ordinal=last['terminal_ordinal']+1,raw_ordinal=last['terminal_ordinal']+1,capture_result=0,ingress_complete=1,closed_complete=1,tls_complete=1)
        index=self.i(b,t,'slot_index');event=self.i(b,t,'event_id')
        need(index in(0,1)and self.i(slot,st,'index')==index and event>self.i(slot,st,'event_id')>0,'actual next TRACE chain/index/event and closed predecessor')
        self.eq(slot,st,origin=1);frame=self.frame(self.f(b,t,'frame'));model=app_model.trace_model(self.app)
        step=68 if last['kind']=='cold'else 75;target=self.page+0x1120 if step==68 else self.h[39]
        self.trace(frame,target,model[step][2]|TF)
        need(frame['greg'][22]==self.page+0x1107 and(frame['fs'],frame['gs'])==tuple(self.app['machine'][1:3]),'actual next TRACE retains original memory JMP NX CR2 and observed TLS')
        before,ref=self.predecessor(slot,self.page+0x1107,frame,original_flags=last['logical']['greg'][17]&~RF)
        owner=self.f(slot,st,'owner');step=self.f(owner,'li2_tf_owner','step');self.step_frame(self.f(step,'li2_step_owner','before'),last['logical'])
        need(before['greg']==last['logical']['greg']and before['fp']==last['logical']['fp'],'ordinary original memory JMP begins at actual compiled exit before any effect')
        fetch=self.f(self.f(epoch,'pso_epoch','terminal'),'pso_stage','fetch')
        need(self.i(ref,'li2_fetch_ref','sequence')>self.i(fetch,'li2_fetch_progress','sequence'),'ordinary memory JMP borrows only after actual compiled source release')
        last['next_trace']=frame;last['next_trace_ordinal']=self.i(b,t,'raw_ordinal')

    def finish(self,status):
        h=self.h;t='pso_wire';r=self.r
        need(type(status)is int and status==0 and self.app['mode']==0,'actual successful loop-only process and mode')
        need(h[:9]==(0x374f53555049324c,7,3057152,3926272,362656,364544,69632,968,128),'actual distinct group record version and complete extents')
        need(canonical(self.bias)and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(n)for n in('li2_raw6','li2_gateway_start','li2_gateway_end'))and h[10]<=h[9]<h[11],'actual emitted gateway identity')
        need(h[12]%PAGE==0 and h[13]==524288 and h[14:16]==(1,0)and h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,0),'actual altstack and FD3/profile')
        need(h[20:26]==tuple(self.symbol(n)for n in('pe','pso_wire','pg_source','pg_rseq','selected_chain','span_progress')),'actual protected group addresses')
        storage=r.layout['retained_storage'];size=r.types['li2_ptr_slot']['bytes'];prefix=((2*r.types['li2_pg_progress']['bytes']+9*8+18*8+3*4+7)&-8)+544
        selected=prefix+2*size;selection=(selected+4+7)&-8
        need({k:v for k,v in storage.items()if k!='domain'}==dict(retained=dict(offset=prefix,bytes=2*size),selected_slot=dict(offset=selected,bytes=4),selection=dict(offset=selection,bytes=24),previous_selection=dict(offset=selection+24,bytes=24)),'actual owner retained-array fields match independent source prefix')
        need(storage['domain']['bytes']==164080 and storage['domain']['offset']+164080<=h[3]and h[33]==self.symbol('pe')+storage['domain']['offset']and h[34]==self.symbol('pg_domain_source'),'actual protected domain field and separate shared source state')
        need(h[26:31]==(self.symbol('pe')+prefix,self.symbol('pe')+prefix+size,2,size,24)and prefix+2*size<=h[3],'actual fixed retained-slot addresses/extent')
        need(h[3]==r.layout['registrations']['pe']['bytes']and self.head==self.page+0x200 and self.page+8192<1<<31 and
             h[31:33]==(self.head,self.page+0x1100)and h[35]==2 and h[37]>=1 and h[38]==0 and h[39]==self.app['expected_exit_pc'] and
             canonical(h[40],12288)and h[40]%PAGE==0 and h[41:47]==(164080,50784,11312,12288,3,0)and
             h[47:53]==(1,0,0,0,h[16],0)and h[53:55]==(self.page+0x1107,self.page+0x1120)and not any(h[55:]),'exact two subentry epochs and successful complete record')
        raw=q(self.f(self.b,t,'raw_ingress'));need(sum(raw[1:])==raw[0]>0,'whole actual signal population')
        for k in('sink_initial','sink_terminal'):
            st=self.f(self.b,t,k);d=self.stat(st);need(d['mode']&0xffff==0x8180 and d['size']==0,'actual empty regular0600 sink');self.eq(st,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(self.f(self.b,t,'sink_initial'),self.f(self.b,t,'sink_terminal'),'stat',observed=('st_atim','st_mtim','st_ctim'))
        footer=q(r.data[-64:]);need(footer[:4]==(0x374653555049324c,7,len(self.b),len(self.b))and 1<=footer[4]<=64 and 0<footer[5]<=len(self.b)and footer[6:]==(0,0),'complete actual group output footer')
        if footer[4]==1:need(footer[5]==len(self.b),'single actual complete group write')
        hardware=self.f(self.b,t,'hardware');self.eq(hardware,'li2_selected_hardware',abi_version=1,reserved=0)
        for i,k in enumerate(('leaf0','leaf1','leaf7')):need(struct.unpack('<4I',self.f(hardware,'li2_selected_hardware',k))==tuple(self.app['hardware'][i][2:]),'actual bridge/app CPUID hardware equality')
        for key,objid in(('main',self.image['main_object']),('interpreter',self.image['interpreter_object'])):self.image_header(self.f(self.b,t,key),objid)
        self.eq(self.f(self.b,t,'session'),'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        need(self.i(self.f(self.b,t,'session'),'li2_step_session','sync_query')&96==96,'actual registered membarrier support')
        obj,_,loads=self.objects[self.image['main_object']];bias=self.bases[self.image['main_object']]
        owners=[p for p in loads if p[1]==5 and bias+p[3]<=self.page and self.page+8192<=bias+p[3]+p[5]]
        need(len(owners)==1 and self.source_offset==owners[0][2]+self.page-bias-owners[0][3]and obj['data'][self.source_offset:self.source_offset+8192]==self.app['source'],'whole source two-page original ELF bytes')

        epochs=r.items(self.b,t,'epochs','pso_epoch');self.epochs=epochs
        initial_slots=r.items(self.f(epochs[0],'pso_epoch','prior'),'pso_slots','slots','pso_slot')
        self.h_alloc=self.i(r.items(initial_slots[1],'pso_slot','banks','ped_bank')[1],'ped_bank','generated');self.h_proof_alloc=self.i(initial_slots[1],'pso_slot','proof')
        initial_domain=self.f(self.b,t,'initial_domain')
        need(len(epochs)==2 and len(self.certificates)==1,'two actual epochs and one complete immutable certificate')
        a=self.epoch(epochs[0],0,initial_domain)
        nexts=r.items(self.b,t,'next','pso_next');self.next_trace(nexts[0],a,epochs[0])
        b=self.epoch(epochs[1],1,a['domain_raw'],a);self.next_trace(nexts[1],b,epochs[1]);need(raw[0]>=b['next_trace_ordinal']>b['begin']>a['next_trace_ordinal'],'whole chronological subentry ingress ordinals')
        final=self.counts(self.f(self.b,t,'final_counts'));last=self.counts(b['counts_raw'])
        need(all(final[k]>=last[k]for k in final if k!='misses')and all(x>=y for x,y in zip(final['misses'],last['misses'],strict=True)),'final counters retain every focal event without attributing later work')
        names='version status failure_code detail_abs detail_negative phase serial generation build_serial offers cold_attempts publications hits cancelled retirements permit_claims entries completed unexpected permit opened_pages closed_pages anchor_released registration_rechecked guest_data_fault recovery_complete first_error active busy selected_slot slot0_generation slot1_generation slot0_permit slot1_permit slot0_completed_serial slot1_completed_serial domain_members dual_entries dual_completed'.split()
        values=q(self.f(self.b,t,'final_row'));need(len(values)==len(names),'whole exact retained terminal schema');row=dict(zip(names,values,strict=True));row['misses']=list(final['misses'])
        need((row['version'],row['status'],row['failure_code'],row['detail_abs'],row['detail_negative'])==(1,0,0,0,0),'actual protected retained terminal outcome')
        for k in('offers','cold_attempts','publications','hits','cancelled','retirements','permit_claims','entries','completed','unexpected'):need(row[k]==final[k],'whole final counter-to-report join '+k)
        p=self.f(self.b,t,'final_progress');pt='li2_pg_progress'
        for k in('phase','serial','opened_pages','closed_pages','anchor_released','registration_rechecked','first_error'):need(row[k]==self.i(p,pt,k),'actual retained progress-to-report join '+k)
        need(row['selected_slot']in(0,1)and 0<row['build_serial']<=row['serial'],'actual final selected slot/build serial')
        gs=(row['slot0_generation'],row['slot1_generation']);ps=(row['slot0_permit'],row['slot1_permit']);cs=(row['slot0_completed_serial'],row['slot1_completed_serial'])
        occupied=sum(g!=0 for g in gs)
        need(occupied in(1,2)and(not all(gs)or gs[0]!=gs[1])and
             all((0<g<=final['next_generation']and p==1 and 0<c<=final['next_serial'])if g else(p==0 and c==0)
                 for g,p,c in zip(gs,ps,cs,strict=True))and gs[row['selected_slot']]>0 and
             row['generation']==gs[row['selected_slot']]and row['permit']==ps[row['selected_slot']],
             'actual final occupied retained identities and completed permits')
        need(final['offers']==final['entries']+final['cancelled']and final['entries']==final['publications']+final['hits']+final['subentry_hits']and final['cold_attempts']==final['publications']+final['cancelled']and sum(final['misses'])==final['cancelled']and final['next_serial']==final['offers']and final['next_generation']==final['publications'],'whole completed/cancelled retained partition')
        need(final['entries']==final['completed']and final['unexpected']==0 and final['retirements']==final['publications']-occupied and final['permit_claims']==final['retirements']+final['hits']+final['subentry_hits']+row['dual_entries'],'whole two-resident permit/publication accounting')
        need(row['phase']in(13,14)and row['active']==row['busy']==row['first_error']==row['guest_data_fault']==0 and row['anchor_released']==row['registration_rechecked']==1,'actual final closed retained epoch or completed cancellation')
        need((row['opened_pages'],row['closed_pages'],row['recovery_complete'])==((17*row['domain_members'],17*row['domain_members'],1)if row['phase']==13 else(0,0,0)),'exact final retained extent and recovery for its terminal phase')
        need(row['dual_entries']==row['dual_completed']==h[36]and 0<=row['dual_entries']<=final['hits']+final['subentry_hits']and row['domain_members']in((1,2)if row['phase']==13 else(0,))and h[37]==final['completed'],'exact actual joint completion/member accounting')
        replacements=a['prior_generation_installed']
        subvalues=q(self.f(self.b,t,'final_subentry'));subnames='version status failure_code selections hits entries completed serial generation root pc head slot bank complete'.split();sub=dict(zip(subnames,subvalues,strict=True))
        need(subvalues[:7]==(1,0,0,final['subentry_selections'],final['subentry_hits'],final['subentry_entries'],final['subentry_completed']),'whole protected subentry counter row')
        need(final['subentry_selections']>=final['subentry_hits']==final['subentry_entries']==final['subentry_completed']>=1 ,'completed global subentry events retain focal observation')
        if sub['complete']:
            need(sub['complete']==1 and sub['serial']==row['serial']and sub['generation']==row['generation']and sub['slot']==row['selected_slot']and sub['bank']in(0,1)and sub['head']<128 and canonical(sub['root'])and canonical(sub['pc'])and(sub['pc']==sub['root'])==(sub['head']==0),'actual final completed entry names final selected generation')
        else:need(not any(subvalues[7:]),'last cancelled attempt has no invented entry receipt')
        return dict(terminal=row,subentry_terminal=sub,mode=0,attempts=[a,b],cold_publications=1,warm_entries=1,subentry_entries=1,dual_entries=0,
                    replacements=replacements,permit_claims=replacements+1,interior_signals=0,source=self.app['source'],
                    lifetime_mode=2,registration_epoch=0,registration_calls=0,word_observed=0,word_available=False,
                    tls_complete=1,status=0,code=0,detail=0,qualification_credit=False)

def read(data,layout,image,app,pid,cpu,exit_status):
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    return Check(wire.Reader(data,layout),image,app,pid,cpu).finish(exit_status)


def terminal(parsed,owner):
    expected=owner['terminal'];need(type(parsed)is dict and set(parsed)==set(expected)and all(type(v)is int for k,v in parsed.items()if k!='misses')and type(parsed['misses'])is list and all(type(v)is int for v in parsed['misses'])and parsed==expected,'whole actual protected subentry terminal row')
    return dict(fields=len(expected),protected_subentry_row=1,inherited_row_protection=0)


def subentry_terminal(parsed,owner):
    expected=owner['subentry_terminal']
    need(type(parsed)is dict and list(parsed)==list(expected)and all(type(v)is int for v in parsed.values())and parsed==expected,'whole actual protected subentry event row')
    return dict(fields=15,protected_subentry_event_row=1)

CONTROL_COUNTS={0:200}

def controls(data,layout,image,app,pid,cpu,exit_status):
    """Supplied corruptions of this separate one-epoch, explicitly unavailable-word record."""
    read(data,layout,image,app,pid,cpu,exit_status);types=layout['types']
    def at(t,k,base=0,index=0,child=None):return base+types[t]['fields'][k]['offset']+(index*types[child]['bytes']if child else index)
    w='pso_wire';et='pso_epoch';st='pso_stage';it='pso_epoch_info';gt='li2_pg_generation';pt='li2_pg_progress';ct='li2_pg_compact';ss='pso_slots';sl='pso_slot';rt='li2_pg_rseq_progress'
    e=at(w,'epochs');ent=at(et,'entered',e);end=at(et,'terminal',e);info=at(et,'info',e);p=at(st,'progress',end)
    def selected(stage):
        slots=at(st,'slots',stage);index=struct.unpack_from('<I',data,at(ss,'selected_slot',slots))[0];need(index in(0,1),'control actual selected slot');return at(ss,'slots',slots,index,sl)
    es=selected(ent);zs=selected(end);g=at(sl,'generation',zs);eg=at(sl,'generation',es)
    cert=at(w,'certificates');payload=at('pso_certificate','payload',cert);cp=at('pe_payload','plan',payload);header=at('pe_payload','header',payload)
    pred=at(et,'predecessor',e);closed=at('pso_predecessor','closed',pred);owner=at('li2_tf_chain_slot','owner',closed);step=at('li2_tf_owner','step',owner)
    n=at(w,'next');ns=at('pso_next','closed',n);no=at('li2_tf_chain_slot','owner',ns);nt=at('li2_tf_owner','step',no);nf=at('pso_next','frame',n)
    er=at(st,'rseq',ent);zr=at(st,'rseq',end)
    tests=[
      ('wire_version',8),('footer_version',len(data)-56),
      ('actual_hardware',at('li2_selected_hardware','leaf0',at(w,'hardware'))),
      ('interior_signal',at(et,'h',e)+11*8),
      ('full_terminal_FP',at('li2_step_frame','fp',at('le_frame','frame',at(et,'after',e)))),
      ('full_data',at('li2_pso_memory','data',at(et,'after_memory',e))),
      ('full_stack',at('li2_pso_memory','stack',at(et,'after_memory',e))),
      ('source_second_page',at(ct,'source',cp)+4096),('proof_padding',at('pso_certificate','tail',cert)),
      ('literal_second_image',at('pso_certificate','code',cert)+32768),('literal_stub',at('pso_certificate','code',cert)+65536),
      ('initial_slot_zero',at(et,'initial_slots',e)),('terminal_slot_zero',at(et,'terminal_slots',e)),
      ('member_generation',at('pe_header','member_generation',header)+8),
      ('global_head_population',at(ct,'heads',cp)),('member_partition',at(ct,'member_heads',cp)+4),
      ('typed_edge_unused',at('li2_pg_edge','target_head',at(ct,'edge',cp))),
      ('cold_head_proof',at(rt,'cold_heads',er)),('cold_store_proof',at(rt,'cold_stores',er)),('no_invented_stub_proof',at(rt,'cold_stubs',er)),
      ('live_GPR',at('li2_write_registers','gpr',at('li2_link_rseq_live','registers',at(it,'live',info)))),
      ('live_unregistered',at('li2_link_rseq_live','registered',at(it,'live',info))),
      ('active_member_reference',at(gt,'member_refs',eg)+8),('closed_incoming_reference',at(gt,'incoming',g)),
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
      ('predecessor_zero_scan',at('pso_predecessor','unexpected_compared',pred)),
      ('slot_owner',at('li2_ptr_slot_ref','owner',at(sl,'identity',es))),
      ('slot_index',at('li2_ptr_slot_ref','index',at(sl,'identity',es))),
      ('slot_generation',at('li2_ptr_slot_ref','generation',at(sl,'identity',es))),
      ('selected_slot',at(ss,'selected_slot',at(st,'slots',ent))),('actual_victim',at(et,'h',e)+24*8),
      ('known_certificate_required',at('pso_check','certificate',at(sl,'check',es))),
      ('certificate_generation',at('pso_certificate','generation',cert)),('certificate_literal_extent',at('pso_certificate','proof_bytes',cert)),
      ('cell_generation',at('pg_dispatch_cell_transition','generation',at(gt,'cell',g,2,'pg_dispatch_cell_transition'))),
      ('cell_zero',at('pg_dispatch_cell_transition','after',at(gt,'cell',g,2,'pg_dispatch_cell_transition'))),
      ('next_ordinal',at('pso_next','raw_ordinal',n)),('next_close',at('pso_next','closed_complete',n)),
      ('next_TLS',at('pso_next','tls_complete',n)),('next_FP',at('li2_step_frame','fp',at('le_frame','frame',nf))),
      ('next_original_before_FP',at('li2_step_frame','fp',at('li2_step_owner','before',nt))),
      ('next_original_revoke',at('li2_step_owner','revoked',nt)),
      ('final_partition',at('pso_counts','publications',at(w,'final_counts'))),('whole_terminal_row',at(w,'final_row')+17*8),
      ('header_lifetime_version',at('pe_header','lifetime_version',header)),('header_lifetime_mode',at('pe_header','lifetime_mode',header)),
      ('header_no_registered_epoch',at('pe_header','registered_epoch',header)),('header_no_rseq_address',at('pe_header','rseq_address',header)),
      ('entry_tag_mode',at(et,'h',e)+25*8),('entry_tag_TLS',at(et,'h',e)+26*8),('terminal_tag_mode',at(et,'h',e)+28*8),
      ('terminal_tag_TLS',at(et,'h',e)+29*8),('no_word_snapshot',at(et,'h',e)+7*8),
      ('actual_terminal_scratch',at(et,'terminal_spill',e)),('unused_member_scratch',at(et,'terminal_spill',e)+4096),
      ('actual_directory_literal',at(et,'terminal_directory',e)+32),
    ]
    refused=[]
    def reject(name,mutant,expected=None):
        try:read(bytes(mutant),layout,image,app,pid,cpu,exit_status)
        except ValueError as error:
            if expected is not None:need(str(error)==expected,'exact source-causal startup refusal '+name)
            refused.append(name)
        else:raise ValueError('supplied startup corruption accepted '+name)
    for name,offset in tests:
        mutant=bytearray(data);mutant[offset]^=1;reject(name,mutant)
    for name,slot in(('predecessor',closed),('next_original',ns)):
        mutant=bytearray(data);struct.pack_into('<I',mutant,at('li2_decoded','step_disposition',at('li2_tf_chain_slot','decoded',slot)),0 if name=='predecessor'else 1)
        if name=='predecessor':
            struct.pack_into('<I',mutant,at('pso_predecessor','before_prefix',pred)+at('li2_decoded','step_disposition',at('li2_tf_chain_slot','decoded')),0)
        reject(name+'_exact_generic_step',mutant,'exact li2_decoded.step_disposition')
    startup=at(w,'startup_registry');reg=at(et,'terminal_registry',e);registry_type='pso_registry'
    registry=[('startup_population',at(registry_type,'count',startup),'startup registry population is an exact predecessor',True),
      ('startup_table_headers',at(registry_type,'ph',startup),'startup registry keeps exact table, bridge and program headers',False),
      ('startup_range_prefix',at(registry_type,'ranges',startup),'startup registry retains every original range and classification',False),
      ('startup_classification_prefix',at(registry_type,'initial_code',startup),'startup registry retains every original range and classification',False),
      ('epoch_terminal_population',at(registry_type,'count',reg),'whole domain registry unchanged during epoch',False),
      ('epoch_owner_population',at(it,'registry_count',info),'exact pso_epoch_info.registry_count',False)]
    for name,offset,message,clear in registry:
        mutant=bytearray(data)
        if clear:mutant[offset:offset+4]=bytes(4)
        else:mutant[offset]^=1
        reject(name,mutant,message)
    for field,nbytes in(('proof',364544),('code',69632),('publication',362656)):
        scan=at('pso_check',field,at(sl,'check',es))
        for name,k,value in(('completion','complete',0),('coverage','compared',nbytes-1),('actual_difference','differences',1)):
            mutant=bytearray(data);struct.pack_into('<Q',mutant,at('pso_scan',k,scan),value);reject(field+'_'+name,mutant,'exact pso_scan.'+k)
    for name,array,child,index,field in(('descriptor','original','li2_span_decoded',0,'gpr_write'),('alternate_descriptor','original','li2_span_decoded',65,'flags_read'),('frontier','frontier','li2_span_decoded',0,'refusal'),('head_kind','head','li2_pe_head',0,'kind')):
        mutant=bytearray(data);mutant[at(child,field,at(ct,array,cp,index,child))]^=1;reject('independent_'+name,mutant,'whole independent startup '+array)
    # Every MOV guard is independently materialized, including both alternate paths.
    for field_offset in(0,4,32,48,64):
        mutant=bytearray(data);mutant[at(ct,'guard',cp)+64*1584+field_offset]^=1;reject('independent_MOV_guard_field_'+str(field_offset),mutant,'whole independent startup guard')
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
    # Distinct unregistered identity, not an allowed set containing registered or unknown state.
    identity=('lifetime_mode','word_observed','tls_complete','registration_epoch','registration_calls','address','page','length','signature','fs','gs','word_before','word_entry','word_after')
    for field in identity:
        mutant=bytearray(data);mutant[at(rt,field,er)]^=1;reject('unregistered_'+field,mutant,'exact '+rt+'.'+field)
    for field in('before','observed','after','current_observed','current_after'):
        mutant=bytearray(data);mutant[at(rt,field,er)]^=1;reject('no_synthetic_'+field,mutant,'unregistered lifetime has no descriptor mapping or current-data observation')
    state=at(st,'state',ent)
    for field in('registered','epoch','calls','tls_complete'):
        mutant=bytearray(data);mutant[at('li2_rseq_state',field,state)]^=1;reject('actual_global_'+field,mutant,'exact li2_rseq_state.'+field)
    for field in('data','transaction'):
        mutant=bytearray(data);mutant[at('li2_rseq_state',field,state)]^=1
        reject('absent_global_'+field,mutant,'no registered-data receipt before first registration'if field=='data'else'no attempted registration transaction during focal execution')
    # Exercise the exact production saved-pin predicate on supplied copies of
    # the actual closed pin. A pre-TLS base0 is legal history, never focal TLS.
    context=Check(wire.Reader(data,layout),image,app,pid,cpu)
    saved=bytearray(data[zr:zr+types[rt]['bytes']]);serial=context.i(context.f(saved,rt,'token'),'li2_pg_token','serial')
    struct.pack_into('<Q',saved,at(rt,'fs'),0)
    context.unregistered_pin(bytes(saved),serial,True,focal=False)
    for field,value,error in(('fs',1<<63,'complete historical user TLS bases'),
        ('fs_result',1,'exact '+rt+'.fs_result'),('tls_complete',0,'exact '+rt+'.tls_complete'),
        ('word_observed',1,'exact '+rt+'.word_observed'),('registration_calls',1,'exact '+rt+'.registration_calls')):
        mutant=bytearray(saved);f=types[rt]['fields'][field]
        mutant[f['offset']:f['offset']+f['bytes']]=value.to_bytes(f['bytes'],'little')
        try:context.unregistered_pin(bytes(mutant),serial,True,focal=False)
        except ValueError as actual:
            need(str(actual)==error,'exact historical by-value pin refusal');refused.append('historical_'+field)
        else:raise ValueError('accepted changed historical pin '+field)
    struct.pack_into('<Q',saved,at(rt,'fs'),app['machine'][1]^PAGE)
    context.unregistered_pin(bytes(saved),serial,True,focal=False)
    try:context.unregistered_pin(bytes(saved),serial,True)
    except ValueError as actual:
        need(str(actual)=='exact '+rt+'.fs','historical TLS must not satisfy the focal app join');refused.append('historical_TLS_is_not_focal')
    else:raise ValueError('accepted historical TLS as actual focal app TLS')
    # Actual immutable completion survives the terminal ref releases; no peer is invented.
    domain=at(et,'terminal_domain',e);entry_domain=at(st,'domain',ent);work=at('pso_domain_checkpoint','work',entry_domain);terminal_work=at('pda_state','work',domain)
    cell_index=struct.unpack_from('<I',data,at('pda_work','receipt',terminal_work))[0];need(cell_index<3,'actual control receipt cell')
    receipt=at('pda_state','completion',domain,cell_index,'pda_completion');member=at('pda_completion','member',receipt)
    extra=[
      ('completion_count',at('pda_completion','count',receipt)),
      ('completion_generation',at('li2_pgd_ref','generation',at('pda_member_completion','identity',member))),
      ('completion_source_pair',at('li2_pg_source_key','page',at('pda_member_completion','source',member))),
      ('completion_saved_revoke',at('le_permission','complete',at('li2_pg_generation','close',at('pda_member_completion','generation',member)))),
      ('completion_directory_close',at('li2_private_code_query','complete',at('pda_completion','directory_closed',receipt))),
      ('receipt_claim_bit',at('pda_state','claimed',domain)+cell_index*4),
      ('directory_target',at('li2_jd_domain_row','generated',at('li2_jd_domain_directory','row',at('pda_work','directory',work)))),
      ('directory_seal',at('le_permission','complete',at('pda_work','directory_seal',work))),
      ('no_peer_claim',at('pda_work','peer_claim',work)),
      ('shared_source_release',at('li2_pgd_source_progress','released',at(st,'domain_source',end))),
    ]
    for name,offset in extra:
        mutant=bytearray(data);mutant[offset]^=1;reject(name,mutant)
    scan=at('pso_domain_checkpoint','cells',entry_domain)
    for name,field,value in(('saved_cells_incomplete','complete',0),('saved_cells_short','compared',3*types['pda_completion']['bytes']-1),('saved_cells_different','differences',1)):
        mutant=bytearray(data);struct.pack_into('<Q',mutant,at('pso_scan',field,scan),value);reject(name,mutant,'exact pso_scan.'+field)
    # Rename one bank coherently without changing any fixed allocation or generation bytes.
    mutant=bytearray(data);refs=[];works=[]
    for stage in(ent,end):
        works.append(at('pso_domain_checkpoint','work',at(st,'domain',stage)))
        refs.append(at('li2_pgd_source_progress','ref',at(st,'domain_source',stage)))
        refs.append(at(rt,'domain_ref',at(st,'rseq',stage)))
    works.append(terminal_work)
    for item in works:
        refs.append(at('li2_pgd_member','identity',at('li2_pgd_view','member',at('pda_work','view',item))))
        mutant[at('pda_work','primary_bank',item)]^=1
    refs.extend((at('pda_member_completion','identity',member),at('li2_pgd_source_progress','ref',at('pda_completion','domain_source',receipt)),at(rt,'domain_ref',at('pda_completion','rseq',receipt))))
    for item in refs:mutant[at('li2_pgd_ref','bank',item)]^=1
    mutant[at(it,'selected_bank',info)]^=1
    reject('coherent_fixed_bank_identity',mutant,'actual domain reference bank matches its fixed slot layout')
    second=at(w,'epochs',index=1,child=et);se=at(et,'entered',second);sz=at(et,'terminal',second)
    entry=at(st,'entry',se);target=at('li2_pgs_entry','target',entry)
    # Twenty-one supplied current-entry fields, exact validator must refuse.
    for field in('transfer_serial','generation','build_serial','slot','bank','complete','reserved'):
        mutant=bytearray(data);mutant[at('li2_pgs_entry',field,entry)]^=1;reject('subentry_'+field,mutant)
    for field in('version','heads','head','member','local','source_page','root','pc','generated','page'):
        mutant=bytearray(data);mutant[at('li2_pgs_target',field,target)]^=1;reject('subentry_target_'+field,mutant)
    for field,child,parent in(('owner','li2_pg_token','token'),('serial','li2_pg_token','token'),('owner','li2_fetch_ref','anchor'),('sequence','li2_fetch_ref','anchor')):
        mutant=bytearray(data);mutant[at(child,field,at('li2_pgs_entry',parent,entry))]^=1;reject('subentry_'+parent+'_'+field,mutant)
    # Ten actual second-activation frame/lifetime and immutable-byte obligations.
    for name,offset in(
      ('warm_PC',at('li2_step_frame','greg',at('le_frame','frame',at(et,'returned',second)))+16*8),
      ('warm_FP',at('li2_step_frame','fp',at('le_frame','frame',at(et,'after',second)))),
      ('warm_data',at('li2_pso_memory','data',at(et,'after_memory',second))+16),
      ('warm_stack',at('li2_pso_memory','stack',at(et,'after_memory',second))),
      ('warm_entry_copy',at(st,'entry',sz)),
      ('warm_domain_entry',at('li2_pgd_source_progress','entry',at(st,'domain_source',se))),
      ('warm_lifetime',at(rt,'lifetime_mode',at(st,'rseq',se))),
      ('warm_calls',at(rt,'registration_calls',at(st,'rseq',se))),
      ('warm_link',at(et,'initial_slots',second)),
      ('warm_spill',at(et,'terminal_spill',second))):
        mutant=bytearray(data);mutant[offset]^=1;reject(name,mutant)
    # Fifteen independently retained second-epoch source/ref/query/close joins.
    warm_slot=selected(sz);warm_generation=at(sl,'generation',warm_slot)
    warm_source=at(st,'source',se);warm_end_source=at(st,'source',sz)
    warm_actual=at('li2_pg_source_progress','source',warm_source);warm_key=at('li2_pg_sources','key',warm_actual)
    warm_next=at(w,'next',index=1,child='pso_next');warm_info=at(et,'info',second)
    for name,offset in(
      ('warm_source_entry',at('li2_pg_source_key','entry',warm_key)),
      ('warm_source_page',at('li2_pg_source_key','page',warm_key)),
      ('warm_source_bytes',at('li2_pg_source_page','bytes',at('li2_pg_source_key','page',warm_key))),
      ('warm_anchor_owner',at('li2_fetch_ref','owner',at('li2_pg_sources','anchor',warm_actual))),
      ('warm_open',at('li2_pg_source_progress','opened_pages',warm_source)),
      ('warm_close',at('li2_pg_source_progress','closed_pages',warm_end_source)),
      ('warm_release',at('li2_pg_source_progress','release_complete',warm_end_source)),
      ('warm_completion',at(pt,'completion_permit',at(st,'progress',sz))),
      ('warm_cold_proof',at(rt,'cold_heads',at(st,'rseq',se))),
      ('warm_cell_reset',at('pg_dispatch_cell_transition','after',at(gt,'cell',warm_generation,2,'pg_dispatch_cell_transition'))),
      ('warm_member_reference',at(gt,'member_refs',warm_generation)),
      ('warm_proof_exit',at('pg_proof_query','part',at(it,'proof_exit',warm_info))),
      ('warm_next_FP',at('li2_step_frame','fp',at('le_frame','frame',at('pso_next','frame',warm_next)))),
      ('warm_next_close',at('pso_next','closed_complete',warm_next)),
      ('warm_next_TLS',at('pso_next','tls_complete',warm_next))):
        mutant=bytearray(data);mutant[offset]^=1;reject(name,mutant)
    # Five decoded/source corruption classes on the actual nonroot entry.
    for name,offset in(('row_kind',at('li2_pe_head','kind',at('li2_pgs_entry','row',entry))),
        ('row_page',at('li2_pe_head','source_page',at('li2_pgs_entry','row',entry))),
        ('row_length',at('li2_pe_head','source_length',at('li2_pgs_entry','row',entry))),
        ('decoded_PC',at('li2_decoded','pc',at('li2_span_decoded','decoded',at('li2_pgs_entry','original',entry)))),
        ('decoded_bytes',at('li2_decoded','bytes',at('li2_span_decoded','decoded',at('li2_pgs_entry','original',entry))))):
        mutant=bytearray(data);mutant[offset]^=1;reject('subentry_'+name,mutant)
    need(len(refused)==CONTROL_COUNTS[0],'all exact separately counted startup owner controls')
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0,mode=0)
