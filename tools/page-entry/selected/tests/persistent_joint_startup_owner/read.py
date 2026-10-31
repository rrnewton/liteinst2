"""Distinct startup-enabled joint profile; original registered oracle remains exact.
Focal mode1/epoch1/calls1 uses actual registered mapping/word receipts. Earlier
mode2 completions retain unavailable-word evidence and their own TLS by value.
"""
import hashlib,struct,importlib.util
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
HERE=Path(__file__).resolve().parent
wire=load('joint_startup_wire',HERE/'wire.py')
base=load('joint_registered_donor',HERE.parent/'persistent_active_domain_owner/read.py')
old=wire.old
need,zero,q,canonical=old.need,old.zero,old.q,old.canonical
U64,PAGE,FP,TF,RF,MASK=old.U64,old.PAGE,old.FP,old.TF,old.RF,old.MASK
DATA,STACK,RSP,RSEQ,GREG=base.DATA,base.STACK,base.RSP,base.RSEQ,base.GREG
elf_symbols=base.elf_symbols

class Check(base.Check):
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
        binding=image['persistent_binding'];need(binding['version']==1 and binding['unregistered']is True and binding['subentry']is True and binding['mode']in('capture','differential')and binding['profile']=='persistent-joint-subentry-'+binding['mode']+'-v1','actual distinct active-domain build mode')
        self.differential=binding['mode']=='differential';self.geometry=self.layout(self.f(self.f(payload,'pe_payload','header'),'pe_header','layout'))


    def counts(self,b):
        t='pdao_counts';names='next_serial next_generation offers publications hits cold_attempts cancelled retirements permit_claims entries completed unexpected subentry_selections subentry_hits subentry_entries subentry_completed'.split()
        d={k:self.i(b,t,k)for k in names};d['misses']=q(self.f(b,t,'misses'));need(len(d['misses'])==18 and d['misses'][0]==0,'exact eighteen descriptive reason buckets')
        need(all(0<=x<U64 for x in d.values()if type(x)is int)and all(0<=x<U64 for x in d['misses']),'bounded exact dynamic counters')
        return d


    def entry_value(self,e,key,actual,layout,root=None):
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
        return head


    def domain_source(self,b,refs,serial,terminal,source):
        super().domain_source(b,refs,serial,terminal,source)
        t='li2_pgd_source_progress';saved=self.f(b,t,'entry');first=refs[0]
        self.entry_value(saved,None,self.f(source,'li2_pg_source_progress','source'),self.f(first,'li2_pgd_ref','layout'),root=self.i(first,'li2_pgd_ref','root'))
        need(self.i(saved,'li2_pgs_entry','slot')==self.i(first,'li2_pgd_ref','slot')and self.i(saved,'li2_pgs_entry','bank')==self.i(first,'li2_pgd_ref','bank')and self.i(saved,'li2_pgs_entry','generation')==self.i(first,'li2_pgd_ref','generation'),'entry receipt binds actual primary slot/bank/generation')

    def epoch(self,b,index,baseline,previous=None):
        # Run the complete inherited focal proof before the additive actual-entry
        # joins. The two cold roots and warm joint root remain the original case.
        result=super().epoch(b,index,baseline,previous)
        t='pdao_epoch';st='pdao_stage';et='li2_pgs_entry';target='li2_pgs_target'
        ci=int(index==1);payload=self.f(self.certificates[ci],'pdao_certificate','payload')
        key=self.f(payload,'pe_payload','source');plan=self.f(payload,'pe_payload','plan')
        root=self.page+(0x400 if index==1 else 0x200);headcount=5 if index==1 else 2
        saved_entries=[]
        for name in('entered','terminal'):
            stage=self.f(b,t,name);e=self.f(stage,st,'entry');saved_entries.append(e)
            source=self.f(stage,st,'source');actual=self.f(source,'li2_pg_source_progress','source')
            domain=self.f(stage,st,'domain');work=self.f(domain,'pdao_domain_checkpoint','work');view=self.f(work,'pda_work','view')
            first=self.r.items(view,'li2_pgd_view','member','li2_pgd_member')[0];ref=self.f(first,'li2_pgd_member','identity');layout=self.f(ref,'li2_pgd_ref','layout')
            self.entry_value(e,key,actual,layout)
            self.eq(e,et,generation=result['generation'],build_serial=result['build_serial'],slot=result['slot'],bank=self.i(work,'pda_work','primary_bank'),transfer_serial=self.i(self.f(stage,st,'progress'),'li2_pg_progress','transfer_serial'))
            self.eq(self.f(e,et,'target'),target,heads=headcount,head=0,member=0,local=0,source_page=0,root=root,pc=root,generated=q(layout)[0])
            need(self.f(e,et,'row')==self.r.items(plan,'li2_pg_compact','head','li2_pe_head')[0]and self.f(e,et,'original')==self.r.items(plan,'li2_pg_compact','original','li2_span_decoded')[0],'focal actual entry equals whole certified root row and descriptor')
            need(e==self.f(view,'li2_pgd_view','entry')==self.f(self.f(stage,st,'domain_source'),'li2_pgd_source_progress','entry'),'whole focal entry retained in stage, owner view and source authority')
        need(saved_entries[0]==saved_entries[1],'whole focal actual entry remains immutable through drain')
        result['actual_entry']=dict(pc=root,compiled_root=root,head=0,slot=result['slot'],generation=result['generation'],build_serial=result['build_serial'],subentry=False)
        return result

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
            for k,n in(('proof',364544),('code',69632),('publication',362656)):self.scan(self.f(check,'pdao_check',k),n)
        return gen


    def certificate(self,index,slot,entry,serial,gen):
        c=self.certificates[index];t='pdao_certificate';self.setup(slot)
        self.eq(c,t,complete=1,index=index,slot=self.i(self.f(slot,'pdao_slot','identity'),'li2_ptr_slot_ref','index'),generation=gen,entry=entry,proof_bytes=364544,code_bytes=69632,publication_bytes=362656)
        zero(self.f(c,t,'tail'),'whole literal immutable proof tail zero')
        payload=self.f(c,t,'payload');ph=self.f(payload,'pe_payload','header')
        self.eq(ph,'pe_header',lifetime_version=1,lifetime_mode=1,version=1,serial=serial,generation=gen,registry=self.symbol('pe'),generated=self.generated,spill=self.spill,table=self.table,plan_proof=2,none_proof=1,source_validations=1,registered_epoch=1,rseq_address=RSEQ,rseq_length=32,rseq_signature=0x53053053)
        need(self.layout(self.f(ph,'pe_header','layout'))==self.geometry and q(self.f(ph,'pe_header','member_generation'))==(2*gen,2*gen+1),'immutable actual retained member identities/layout');zero(self.f(ph,'pe_header','reserved'),'whole header reserved')
        binding=self.image['persistent_binding'];need(binding['version']==1 and binding['unregistered']is True and binding['subentry']is True and binding['profile']=='persistent-joint-subentry-'+binding['mode']+'-v1','explicit retained-two source binding')
        need(self.f(ph,'pe_header','archive')==bytes.fromhex(binding['archive']['sha256'])and self.f(ph,'pe_header','policy')==bytes.fromhex(binding['policy_sha256']),'whole actual retained archive/policy authority')
        key=self.f(payload,'pe_payload','source');self.source_key(key,entry);expected=self.compact(payload,entry)
        need(self.f(c,t,'code')==expected['image']+expected['stub_image'],'all17 actual code pages in shared literal certificate')
        return payload


    def prior_completed(self,slot,counts):
        t='pdao_slot';g=self.f(slot,t,'generation');c,m,_,_=self.claim(slot,self.current_domain);gt='li2_pg_generation'
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
        t='pdao_slot';gt='li2_pg_generation';g=self.f(entry,t,'generation');z=self.f(end,t,'generation');self.setup(entry);gen=self.i(g,gt,'generation');build=self.i(g,gt,'build_serial')
        self.eq(g,gt,installed=1,complete=1,proof_complete=1,ready_generation=gen,plan_proofs=2,none_proofs=1,generated=self.generated,proof=self.proof,spill=self.spill,active_refs=1,linked=1,domain_refs=1,code_copied=69632,code_verified=69632,proof_zeroed=364544,proof_copied=362656,proof_verified=364544)
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


    def completion(self,c,next_id,next_serial):
        t='pda_completion';cid,serial=self.v(c,t,'id serial');count=self.i(c,t,'count')
        need(0<cid<=next_id and 0<serial<=next_serial and count in(1,2),'bounded actual immutable completion identity')
        self.eq(c,t,complete=1);members=self.r.items(c,t,'member','pda_member_completion');refs=[];seen=[]
        pin=self.f(c,t,'rseq');self.eq(pin,'li2_pg_rseq_progress',active=0,checking=0,first_error=0,unsafe_terminal=0,seed_complete=1,entry_complete=1,close_complete=1,first_detail=0,cancel_started=0,cancel_complete=0,word_before=0,word_entry=0,word_after=0,domain_bound=1,domain_count=count)
        self.eq(self.f(pin,'li2_pg_rseq_progress','token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
        lifetime=self.i(pin,'li2_pg_rseq_progress','lifetime_mode')
        if lifetime==2:
            self.unregistered_pin(pin,serial,terminal=True,focal=False)
        else:
            self.registered_identity(pin)
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
            if i==0:
                # A historical activation may start at a certified internal head;
                # its compiled root remains immutable in this saved member.
                actual_entry=self.f(self.f(c,t,'domain_source'),'li2_pgd_source_progress','entry')
                self.entry_value(actual_entry,key,saved_source,self.f(v,'li2_pgd_ref','layout'))
                self.eq(actual_entry,'li2_pgs_entry',generation=self.i(g,'li2_pg_generation','generation'),build_serial=self.i(g,'li2_pg_generation','build_serial'),slot=slot,bank=bank)
                if self.i(source_key,'li2_pg_source_key','entry')==root:self.key_identity(source_key,key)
            # Pair identity excludes only separately authenticated root, never source bytes or stable backing identity.
            self.pair_key(source_key,key)
            gen=self.i(g,'li2_pg_generation','generation');self.eq(g,'li2_pg_generation',installed=1,complete=1,proof_complete=1,ready_generation=gen,linked=0,active_refs=0,domain_refs=0)
            for k in('member_refs','incoming','cleanup'):zero(self.f(g,'li2_pg_generation',k),'completed member has no live reference or failed cleanup')
            self.permission3(self.f(g,'li2_pg_generation','open'),5);self.permission3(self.f(g,'li2_pg_generation','close'),1)
            self.proof_query(self.f(m,mt,'proof'),self.i(g,'li2_pg_generation','proof'),1)
            self.eq(h,'pe_header',lifetime_version=1,lifetime_mode=lifetime,version=1,serial=self.i(g,'li2_pg_generation','build_serial'),generation=gen,registry=self.symbol('pe'),generated=self.geometry[0],spill=self.geometry[4],registered_epoch=self.i(pin,'li2_pg_rseq_progress','registration_epoch'),rseq_address=self.i(pin,'li2_pg_rseq_progress','address'),rseq_length=self.i(pin,'li2_pg_rseq_progress','length'),rseq_signature=self.i(pin,'li2_pg_rseq_progress','signature'))
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


    def registered_identity(self,b):
        t='li2_pg_rseq_progress'
        self.eq(b,t,lifetime_mode=1,registration_epoch=1,registration_calls=1,word_observed=1,tls_complete=1,
                pid=self.pid,tid=self.pid,session=self.symbol('selected_session'),fs_result=0,gs_result=0,
                fs_selector=0,gs_selector=0,address=RSEQ,page=RSEQ,length=32,signature=0x53053053)
        need(all(0<=v<1<<47 for v in self.v(b,t,'fs gs')),'complete historical registered user TLS bases')

    def pin(self,b,state,serial,heads,refs,terminal=False):
        self.registered_identity(b)
        return super().pin(b,state,serial,heads,refs,terminal)


    def finish(self,status):
        h=self.h;t='pdao_wire';r=self.r
        need(type(status)is int and status==0 and self.app['mode']==0,'actual successful loop-only process and mode')
        need(h[:9]==(0x384f41445049324c,8,4181824,r.layout['registrations']['pe']['bytes'],362656,364544,69632,968,128),'actual distinct group record version and complete extents')
        need(canonical(self.bias)and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(n)for n in('li2_raw6','li2_gateway_start','li2_gateway_end'))and h[10]<=h[9]<h[11],'actual emitted gateway identity')
        need(h[12]%PAGE==0 and h[13]==524288 and h[14:16]==(1,0)and h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,0),'actual altstack and FD3/profile')
        need(h[20:26]==tuple(self.symbol(n)for n in('pe','pdao_wire','pg_source','pg_rseq','selected_chain','span_progress')),'actual protected group addresses')
        storage=r.layout['retained_storage'];size=r.types['li2_ptr_slot']['bytes'];prefix=((2*r.types['li2_pg_progress']['bytes']+9*8+18*8+3*4+7)&-8)+544
        selected=prefix+2*size;selection=(selected+4+7)&-8
        need({k:v for k,v in storage.items()if k!='domain'}==dict(retained=dict(offset=prefix,bytes=2*size),selected_slot=dict(offset=selected,bytes=4),selection=dict(offset=selection,bytes=24),previous_selection=dict(offset=selection+24,bytes=24)),'actual owner retained-array fields match independent source prefix')
        need(storage['domain']['bytes']==164080 and storage['domain']['offset']+164080<=h[3]and h[33]==self.symbol('pe')+storage['domain']['offset']and h[34]==self.symbol('pg_domain_source'),'actual protected domain field and separate shared source state')
        need(h[26:31]==(self.symbol('pe')+prefix,self.symbol('pe')+prefix+size,2,size,24)and prefix+2*size<=h[3],'actual fixed retained-slot addresses/extent')
        need(self.head==self.page+0x200 and self.page+8192<1<<31 and h[31:33]==(self.head,self.page+0x400)and h[35]==3 and h[36]>=1 and h[37]>=3 and h[38]==0 and h[39]==self.app['expected_exit_pc']and canonical(h[40],12288)and h[40]%PAGE==0 and h[41:47]==(164080,50784,11312,12288,3,0)and h[47:53]==(1,0,0,0,h[16],0)and not any(h[53:]),'exact three shared-domain epochs and successful complete record')
        raw=q(self.f(self.b,t,'raw_ingress'));need(sum(raw[1:])==raw[0]>0,'whole actual signal population')
        for k in('sink_initial','sink_terminal'):
            st=self.f(self.b,t,k);d=self.stat(st);need(d['mode']&0xffff==0x8180 and d['size']==0,'actual empty regular0600 sink');self.eq(st,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(self.f(self.b,t,'sink_initial'),self.f(self.b,t,'sink_terminal'),'stat',observed=('st_atim','st_mtim','st_ctim'))
        footer=q(r.data[-64:]);need(footer[:4]==(0x384641445049324c,8,len(self.b),len(self.b))and 1<=footer[4]<=64 and 0<footer[5]<=len(self.b)and footer[6:]==(0,0),'complete actual group output footer')
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
        need((row['version'],row['status'],row['failure_code'],row['detail_abs'],row['detail_negative'])==(1,0,0,0,0),'actual protected retained terminal outcome')
        for k in('offers','cold_attempts','publications','hits','cancelled','retirements','permit_claims','entries','completed','unexpected'):need(row[k]==final[k],'whole final counter-to-report join '+k)
        p=self.f(self.b,t,'final_progress');pt='li2_pg_progress'
        for k in('phase','serial','opened_pages','closed_pages','anchor_released','registration_rechecked','first_error'):need(row[k]==self.i(p,pt,k),'actual retained progress-to-report join '+k)
        need(row['selected_slot']in(0,1)and 0<row['build_serial']<=row['serial'],'actual final selected slot/build serial')
        gs=(row['slot0_generation'],row['slot1_generation']);ps=(row['slot0_permit'],row['slot1_permit']);cs=(row['slot0_completed_serial'],row['slot1_completed_serial'])
        need(all(0<g<=final['next_generation']for g in gs)and gs[0]!=gs[1]and ps==(1,1)and all(0<c<=final['next_serial']for c in cs)and row['generation']==gs[row['selected_slot']]and row['permit']==ps[row['selected_slot']],'actual final two retained identities and completed permits')
        need(final['offers']==final['entries']+final['cancelled']and final['entries']==final['publications']+final['hits']+final['subentry_hits']and final['cold_attempts']==final['publications']+final['cancelled']and sum(final['misses'])==final['cancelled']and final['next_serial']==final['offers']and final['next_generation']==final['publications'],'whole completed/cancelled retained partition')
        need(final['entries']==final['completed']and final['unexpected']==0 and final['retirements']==final['publications']-2 and final['permit_claims']==final['retirements']+final['hits']+final['subentry_hits']+row['dual_entries'],'whole two-resident permit/publication accounting')
        need(row['phase']in(13,14)and row['active']==row['busy']==row['first_error']==row['guest_data_fault']==0 and row['anchor_released']==row['registration_rechecked']==1,'actual final closed retained epoch or completed cancellation')
        need((row['opened_pages'],row['closed_pages'],row['recovery_complete'])==((17*row['domain_members'],17*row['domain_members'],1)if row['phase']==13 else(0,0,0)),'exact final retained extent and recovery for its terminal phase')
        need(row['dual_entries']==row['dual_completed']==h[36]and 1<=row['dual_entries']<=final['hits']+final['subentry_hits']and row['domain_members']in((1,2)if row['phase']==13 else(0,))and h[37]==final['completed'],'exact actual joint completion/member accounting')
        subvalues=q(self.f(self.b,t,'final_subentry'));subnames='version status failure_code selections hits entries completed serial generation root pc head slot bank complete'.split();sub=dict(zip(subnames,subvalues,strict=True))
        need(subvalues[:7]==(1,0,0,final['subentry_selections'],final['subentry_hits'],final['subentry_entries'],final['subentry_completed']),'whole protected subentry counter row')
        need(final['subentry_selections']>=final['subentry_hits']==final['subentry_entries']==final['subentry_completed'],'completed global subentry events form their own exact bucket')
        if sub['complete']:
            need(sub['complete']==1 and sub['serial']==row['serial']and sub['generation']==row['generation']and sub['slot']==row['selected_slot']and sub['bank']in(0,1)and sub['head']<128 and canonical(sub['root'])and canonical(sub['pc'])and(sub['pc']==sub['root'])==(sub['head']==0),'actual final completed entry names final selected generation')
        else:need(not any(subvalues[7:]),'last cancelled attempt has no invented entry receipt')
        replacements=a['prior_generation_installed']+b['prior_generation_installed']
        mapping=a['rseq_mapping']+b['rseq_mapping']+warm['rseq_mapping'];need(len(mapping)==6 and any(x['query_kind']==(3 if self.differential else 4)for x in mapping),'actual projected or differential-verified focal rseq observation')
        return dict(lifetime_mode=1,registration_epoch=1,registration_calls=1,word_observed=1,word_available=True,tls_complete=1,rseq_mapping=mapping,terminal=row,subentry_terminal=sub,subentry_entries=0,mode=0,attempts=[a,b,warm],cold_publications=2,warm_entries=1,dual_entries=1,replacements=replacements,permit_claims=replacements+2,interior_signals=0,source=self.app['source'],word=0,status=0,code=0,detail=0,qualification_credit=False)


def read(data,layout,image,app,pid,cpu,exit_status):
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    return Check(wire.Reader(data,layout),image,app,pid,cpu).finish(exit_status)


def terminal(parsed,owner):
    expected=owner['terminal'];need(type(parsed)is dict and set(parsed)==set(expected)and all(type(v)is int for k,v in parsed.items()if k!='misses')and type(parsed['misses'])is list and all(type(v)is int for v in parsed['misses'])and parsed==expected,'whole actual protected joint-startup terminal row')
    return dict(fields=len(expected),protected_joint_startup_row=1,inherited_row_protection=0)


REGISTERED_CONTROL_COUNTS={0:121}
LIFETIME_CONTROL_COUNTS={0:153}
CONTROL_COUNTS={0:193}

def registered_controls(data,layout,image,app,pid,cpu,exit_status):
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
    for field,nbytes in(('proof',364544),('code',69632),('publication',362656)):
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
    need(len(refused)==REGISTERED_CONTROL_COUNTS[0],'all exact separately counted retained-two owner controls')
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0,mode=0)


def lifetime_controls(data,layout,image,app,pid,cpu,exit_status):
    """Keep all121 registered controls; add exact new-profile identity refusals."""
    result=registered_controls(data,layout,image,app,pid,cpu,exit_status)
    refused=list(result['refusals']);types=layout['types']
    need(len(refused)==REGISTERED_CONTROL_COUNTS[0],'all original registered owner controls retained')
    def at(t,k,base=0,index=0,child=None):
        return base+types[t]['fields'][k]['offset']+(index*types[child]['bytes']if child else index)
    def reject(name,offset,error):
        mutant=bytearray(data);mutant[offset]^=1
        try:read(bytes(mutant),layout,image,app,pid,cpu,exit_status)
        except ValueError as actual:
            need(str(actual)==error,'exact causal joint-startup lifetime refusal '+name)
            refused.append(name)
        else:raise ValueError('accepted changed joint-startup lifetime '+name)
    # All six actual focal pins must name the registered lifetime and its real
    # first registration call. No unavailable word is treated as observed zero.
    for index in range(3):
        epoch=at('pdao_wire','epochs',index=index,child='pdao_epoch')
        for stage in('entered','terminal'):
            pin=at('pdao_stage','rseq',at('pdao_epoch',stage,epoch))
            for field in('lifetime_mode','word_observed','tls_complete','registration_calls'):
                reject('joint_focal_'+str(index)+'_'+stage+'_'+field,
                    at('li2_pg_rseq_progress',field,pin),'exact li2_pg_rseq_progress.'+field)
    # Both immutable code certificates carry the distinct lifetime binding.
    for index in range(2):
        cert=at('pdao_wire','certificates',index=index,child='pdao_certificate')
        header=at('pe_payload','header',at('pdao_certificate','payload',cert))
        for field in('lifetime_version','lifetime_mode'):
            reject('joint_certificate_'+str(index)+'_'+field,at('pe_header',field,header),'exact pe_header.'+field)
    # This is the literal completion made by the first registered focal epoch,
    # selected from its actual work cell. Historical receipts remain separate.
    epoch=at('pdao_wire','epochs');domain=at('pdao_epoch','terminal_domain',epoch)
    work=at('pda_state','work',domain)
    cell=struct.unpack_from('<I',data,at('pda_work','receipt',work))[0]
    need(cell<3,'actual registered completion control cell')
    completion=at('pda_state','completion',domain,cell,'pda_completion')
    pin=at('pda_completion','rseq',completion)
    for field in('lifetime_mode','word_observed','tls_complete','registration_calls'):
        reject('joint_saved_registered_'+field,at('li2_pg_rseq_progress',field,pin),
            'exact li2_pg_rseq_progress.'+field)
    need(len(refused)==len(set(refused))==LIFETIME_CONTROL_COUNTS[0],'all153 distinct joint-startup owner controls')
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0,mode=0)


def subentry_terminal(parsed,owner):
    expected=owner['subentry_terminal']
    need(type(parsed)is dict and list(parsed)==list(expected)and all(type(v)is int for v in parsed.values())and parsed==expected,'whole actual protected subentry event row')
    return dict(fields=15,protected_subentry_event_row=1)



def controls(data,layout,image,app,pid,cpu,exit_status):
    """All153 prior controls plus40 actual-entry/counter joins for this profile."""
    result=lifetime_controls(data,layout,image,app,pid,cpu,exit_status)
    refused=list(result['refusals']);types=layout['types']
    need(len(refused)==LIFETIME_CONTROL_COUNTS[0],'all153 original joint controls retained')
    def at(t,k,base=0,index=0,child=None):
        return base+types[t]['fields'][k]['offset']+(index*types[child]['bytes']if child else index)
    def reject(name,mutant,error=None):
        try:read(bytes(mutant),layout,image,app,pid,cpu,exit_status)
        except ValueError as actual:
            if error is not None:need(str(actual)==error,'exact causal joint actual-entry refusal '+name)
            refused.append(name)
        else:raise ValueError('accepted changed joint actual-entry evidence '+name)
    e=at('pdao_wire','epochs',index=2,child='pdao_epoch')
    entered=at('pdao_epoch','entered',e);terminal_stage=at('pdao_epoch','terminal',e)
    entry=at('pdao_stage','entry',entered);t='li2_pgs_entry';tt='li2_pgs_target'
    target=at(t,'target',entry);row=at(t,'row',entry);original=at(t,'original',entry)
    token=at(t,'token',entry);anchor=at(t,'anchor',entry)
    direct=[('owner',at('li2_pg_token','owner',token)),('serial',at('li2_pg_token','serial',token)),
        ('transfer',at(t,'transfer_serial',entry)),('anchor',at('li2_fetch_ref','sequence',anchor)),
        ('generation',at(t,'generation',entry)),('build',at(t,'build_serial',entry)),
        ('slot',at(t,'slot',entry)),('bank',at(t,'bank',entry)),
        ('complete',at(t,'complete',entry)),('reserved',at(t,'reserved',entry))]
    direct += [('target_'+k,at(tt,k,target))for k in('version','heads','head','member','local','source_page','root','pc','generated','page')]
    direct += [('row_'+k,at('li2_pe_head',k,row))for k in('source_offset','generated_length','kind')]
    direct += [('descriptor_'+k,at('li2_span_decoded',k,original))for k in('gpr_read','flags_read')]
    need(len(direct)==25,'exact actual-entry field corruption population')
    for name,offset in direct:
        mutant=bytearray(data);mutant[offset]^=1;reject('actual_entry_'+name,mutant)
    domain=at('pdao_epoch','terminal_domain',e);work=at('pda_state','work',domain)
    cell=struct.unpack_from('<I',data,at('pda_work','receipt',work))[0];need(cell<3,'actual joint entry completion cell')
    completion=at('pda_state','completion',domain,cell,'pda_completion')
    checkpoint=at('pdao_stage','domain',entered)
    view_entry=at('li2_pgd_view','entry',at('pda_work','view',at('pdao_domain_checkpoint','work',checkpoint)))
    source_entry=at('li2_pgd_source_progress','entry',at('pdao_stage','domain_source',entered))
    terminal_entry=at('pdao_stage','entry',terminal_stage)
    saved_entry=at('li2_pgd_source_progress','entry',at('pda_completion','domain_source',completion))
    for name,offset in(('view',view_entry),('source',source_entry),('terminal',terminal_entry),('completion',saved_entry)):
        mutant=bytearray(data);mutant[at('li2_fetch_ref','sequence',at(t,'anchor',offset))]^=1
        reject('whole_entry_copy_'+name,mutant)
    # Mutate every copy of this one focal receipt together. The original source,
    # real transfer and immutable member generation remain authoritative.
    copies=[entry,terminal_entry,saved_entry]
    for stage in(entered,terminal_stage):
        copies.append(at('li2_pgd_source_progress','entry',at('pdao_stage','domain_source',stage)))
        w=at('pdao_domain_checkpoint','work',at('pdao_stage','domain',stage))
        copies.append(at('li2_pgd_view','entry',at('pda_work','view',w)))
    copies.append(at('li2_pgd_view','entry',at('pda_work','view',work)))
    need(len(copies)==len(set(copies))==8,'all actual focal receipt copies are distinct')
    for field in('transfer_serial','build_serial','generation','anchor'):
        mutant=bytearray(data)
        for base_offset in copies:
            offset=at(t,field,base_offset)
            if field=='anchor':offset=at('li2_fetch_ref','sequence',offset)
            value=struct.unpack_from('<Q',data,offset)[0];need(value<U64,'bounded coherent entry control increment')
            struct.pack_into('<Q',mutant,offset,value+1)
        reject('coherent_actual_entry_'+field,mutant)
    count=at('pdao_stage','counts',entered)
    for field in('subentry_selections','subentry_hits','subentry_entries','subentry_completed'):
        mutant=bytearray(data);mutant[at('pdao_counts',field,count)]^=1
        reject('focal_root_does_not_count_'+field,mutant,'exact focal dynamic counter delta '+field)
    for name,offset in(
        ('final_bucket',at('pdao_counts','subentry_hits',at('pdao_wire','final_counts'))),
        ('final_row_hits',at('pdao_wire','final_subentry')+4*8),
        ('final_entry_completeness',at('pdao_wire','final_subentry')+14*8)):
        mutant=bytearray(data);mutant[offset]^=1;reject(name,mutant)
    need(len(refused)==len(set(refused))==CONTROL_COUNTS[0],'all193 original and additive joint owner controls')
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0,mode=0)
