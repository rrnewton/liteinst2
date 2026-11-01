"""Two real owner completions; literal full state and unchanged old pair checks.

Each RecordView is a readonly member of one fully authenticated typed bundle.
No counter, context byte or evidence row is rewritten into an old observation.
"""
import hashlib,struct,importlib.util
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
HERE=Path(__file__).resolve().parent
base=load('resident_generation_semantic_donor',HERE.parent/'resident_three_owner/read.py')
wire=load('resident_generation_wire',HERE/'wire.py')
plan=base.plan;old=base.old
need,zero,q,canonical=base.need,base.zero,base.q,base.canonical
PAGE,FP,TF,RF,MASK=base.PAGE,base.FP,base.TF,base.RF,base.MASK
T,STATE,CERT,STEP=base.T,base.STATE,base.CERT,base.STEP
GREG=base.GREG

def elf_symbols(data):
    h,loads=old.elf(data)
    need(h[11]==64 and h[12]>0 and h[6]+h[12]*64<=len(data),'whole actual bridge section table')
    sections=[struct.unpack_from('<IIQQQQIIQQ',data,h[6]+64*i)for i in range(h[12])]
    wanted=set(wire.REGISTERED)|{'li2_raw6','li2_gateway_start','li2_gateway_end','span_transfer','selected_chain','protected','maps_current','rows'}
    symbols={}
    for s in sections:
        if s[1]!=2:continue
        need(s[9]==24 and s[5]%24==0 and s[6]<len(sections)and s[4]+s[5]<=len(data),'actual complete ELF symbol table')
        tab=sections[s[6]];need(tab[1]==3 and tab[4]+tab[5]<=len(data),'actual symbol string table');strings=data[tab[4]:tab[4]+tab[5]]
        for at in range(s[4],s[4]+s[5],24):
            name,info,other,section,address,size=struct.unpack_from('<IBBHQQ',data,at)
            if not section or not name:continue
            end=strings.find(b'\0',name);need(0<=name<end<len(strings),'bounded symbol name')
            name=strings[name:end].decode('ascii')
            if name in wanted:
                need(name not in symbols,'unique actual bridge symbol');symbols[name]=(address,size)
    need(set(symbols)==wanted,'whole required compiled object inventory')
    ph=[struct.unpack_from('<IIQQQQQQ',data,h[5]+56*i)for i in range(h[10])]
    return h,ph,symbols


class Check(base.Check):
    def __init__(self,r,image,app,pid,cpu):
        self.r,self.image,self.app,self.pid,self.cpu=r,image,app,pid,cpu
        self.ordinal=r.ordinal;self.serial=self.ordinal+1
        self.b=r.data;self.h=q(self.f(self.b,T,'h'));self.maps_seen={};self.source_ids={};self.backings={};self.bases={};self.objects={}
        self.eh,self.ph,self.symbols=elf_symbols(image['bridge'])
        need(set(r.layout['symbols'])==set(self.symbols)|{'r3_owner','span_progress','pg_domain_source'}and all(r.layout['symbols'][k]==v[0]for k,v in self.symbols.items()),'same complete actual ELF and DWARF symbols')
        need(r.layout['symbols']['r3_owner']==r.layout['symbols']['r3_memory'],'actual aligned owner union starts at its real symbol')
        self.bias=self.h[9]-r.layout['symbols']['r3_owner']
        need(canonical(self.bias)and self.bias%PAGE==0,'actual bridge load bias')
        for key,obj in image['objects'].items():
            need(type(key)is int and type(obj)is dict,'actual complete object inventory');h,loads=old.elf(obj['data']);self.objects[key]=(obj,h,loads)
        need(image['main_object']in self.objects and image['interpreter_object']in self.objects and image['main_object']!=image['interpreter_object'],'actual distinct original objects')
        for key,objid in(('main',image['main_object']),('interpreter',image['interpreter_object'])):self.image_header(self.f(self.b,T,key),objid)
        need(self.bases[image['main_object']]==0,'fixed ET_EXEC original main')
        self.page=0x410000;self.head=0x410200
        need(app['source']==plan.source_image()and app['head']==self.head and app['terminal_pc']==0x41420e and app['role']=='gated'and app['pid']==pid and app['cpu']==cpu,'whole actual finite gated application identity')
        self.binding=image['persistent_binding']
        need(self.binding['version']==1 and self.binding['profile']=='resident-generation-two-flags-capture-v1'and self.binding['mode']=='release'and all(self.binding[k]is True for k in('native_probe','parse_memo','unregistered','subentry','cross_pair','direct_frontier','resident_three','sealed_storage','source_lease','flag_stack','helper_tf','stable_generation','generation_capture','tf_nx_page_boundary'))and self.binding['activations']==2,'actual distinct capture build binding')
        need(image['maps_mode']in('maintained','differential'),'actual maps build mode');self.differential=image['maps_mode']=='differential'
        geom=self.binding['geometry'];need(geom['root']==self.head and geom['roots']==[self.head,0x412200,0x414200]and geom['source']==dict(bytes=24576,sha256=hashlib.sha256(app['source']).hexdigest()),'exact bound complete source geometry')
        self.certificates=r.items(self.b,T,'certificate',CERT)
        key=self.f(self.f(self.certificates[0],CERT,'payload'),'r3_payload','source');row=r.items(key,'li2_pg_source_key','page','li2_pg_source_page')[0]
        self.main_backing=self.f(row,'li2_pg_source_page','backing');self.source_offset=self.i(self.f(row,'li2_pg_source_page','identity'),'li2_fetch_page','offset')
        self.before=self.frame(self.f(self.b,T,'before'));self.after=self.frame(self.f(self.b,T,'after'));self.next=self.frame(self.f(self.b,T,'next'))
        self.entered=self.f(self.b,T,'entered');self.terminal=self.f(self.b,T,'terminal');self.closed=self.f(self.b,T,'closed');self.handoff=self.f(self.b,T,'handoff')
        self.source_count=self.i(self.entered,STATE,'source_pages');need(0<self.source_count<=64,'actual bounded declared source union')
        self.source_before=self.f(self.b,T,'h')[328:384]
        self.source_rows=r.items(self.b,T,'source','li2_pg_source_page')
        self.layouts=[q(self.f(self.f(self.f(c,CERT,'payload'),'r3_payload','header'),'r3_header','layout'))for c in self.certificates]

        self.resident_before=self.f(self.b,T,'resident_before')
        self.generation_before=self.f(self.b,T,'generation_before')
        self.content=self.f(self.entered,STATE,'content')
        self.publication_epoch=self.i(self.content,'li2_rsl_content_ref','publication_epoch')

    def registry(self):
        count=self.i(self.entered,STATE,'registry_count');need(0<count<=128,'whole bounded actual protected registry')
        rows=self.r.items(self.b,T,'registry','li2_fork_range');ranges=[self.v(x,'li2_fork_range','first end')for x in rows[:count]]
        for row in rows[count:]:zero(row,'whole unused protected registry range')
        need(all(canonical(a,z-a)for a,z in ranges),'all actual protected intervals')
        declarations=self.r.layout['registrations'];need(set(declarations)==set(wire.REGISTERED),'whole exact compiled registration roster');objects=[]
        headers=self.image['headers'];need(type(headers)is dict and headers,'actual complete compiler-M header closure')
        for name,(source,tag)in wire.REGISTERED.items():
            d=declarations[name];at,n=self.symbols[name];a,z=self.bias+at,self.bias+at+n
            need(set(d)=={'address','bytes','alignment','tag','source'}and(d['address'],d['bytes'],d['tag'])==(at,n,tag)and type(d['alignment'])is int and 0<d['alignment']<=PAGE and not d['alignment']&(d['alignment']-1)and a%d['alignment']==0 and d['source'].endswith('/tools/page-entry/selected/'+source),'actual complete symbol/DWARF/source identity '+name)
            need(d['source']in headers and set(headers[d['source']])=={'bytes','sha256'},'registered DWARF origin belongs to actual compiler-M closure')
            objects.append((a,z))
            if name not in wire.LIFETIME:need(ranges.count((a,z))==1,'whole strict protected object '+name)
            loads=[p for p in self.ph if p[0]==1 and p[6]and self.bias+p[3]<z and a<self.bias+p[3]+p[6]]
            need(len(loads)==1 and loads[0][1]==6 and self.bias+loads[0][3]<=a<z<=self.bias+loads[0][3]+loads[0][6],'whole object in actual RW/NX bridge LOAD')
            p=loads[0];rounded=((self.bias+p[3])&-PAGE,(self.bias+p[3]+p[6]+PAGE-1)&-PAGE)
            need(ranges.count(rounded)==1,'whole containing bridge LOAD remains protected')
        need(all(a%PAGE==z%PAGE==0 or(a,z)in objects for a,z in ranges),'every non-page interval is an exact source registration')
        arena=self.i(self.entered,STATE,'arena');need(canonical(arena,327*PAGE)and arena%PAGE==0 and ranges.count((arena,arena+327*PAGE))==1,'whole independent three-certificate arena protection')
        need(self.symbol('r3_memory')==self.h[9]and self.symbols['r3_memory'][1]==1249280 and self.h[3]==wire.OWNER_BYTES and self.symbols['r3_work'][1]==2329264 and self.symbols['rsl'][1]==70*PAGE and self.symbols['rsl_initialization'][1]==72,'actual complete separate owner/source/bootstrap storage')
        self.ranges=ranges

    def certificate(self,index):
        b=self.certificates[index];payload=self.f(b,CERT,'payload');header=self.f(payload,'r3_payload','header');t='r3_header';layout=self.layouts[index]
        arena=self.i(self.entered,STATE,'arena');code=arena+index*108*PAGE;proof=code+19*PAGE;directory=arena+324*PAGE
        need(layout==(code,code+8*PAGE,code+16*PAGE,code+17*PAGE,code+18*PAGE,directory),'separate exact three-resident code/data/proof/directory geometry')
        self.eq(header,t,version=2,bytes=362568,generation=index+1,publication_serial=1,index=index,source_epoch=self.publication_epoch,root=self.head+index*8192,owner=self.h[9])
        need(self.f(header,t,'content')==self.content,'whole exact owner-issued immutable publication content reference')
        need(self.f(header,t,'archive')==bytes.fromhex(self.binding['archive']['sha256'])and self.f(header,t,'policy')==bytes.fromhex(self.binding['policy_sha256']),'whole actual archive/source-policy publication identity')
        identity=self.f(b,CERT,'identity');self.eq(identity,'li2_sealed_identity',bytes=106*PAGE,generation=index+1,code=code,proof=proof,code_bytes=69632,proof_bytes=364544,code_live=1,proof_live=1)
        need(self.i(identity,'li2_sealed_identity','fd')<1<<31 and self.i(identity,'li2_sealed_identity','inode')>0,'actual retained sealed descriptor and inode')
        self.source_key(self.f(payload,'r3_payload','source'),self.head+index*8192)
        compact=self.f(payload,'r3_payload','plan');ct='li2_pg_compact';table_address=proof+self.r.types['r3_payload']['fields']['plan']['offset']+self.r.types[ct]['fields']['table']['offset']
        table=plan.table(self.ranges+[(a,a+PAGE)for a in self.source_by_address],table_address)
        need(self.f(compact,ct,'table')==table,'whole independently reconstructed protected/source-union exclusion tree')
        expected=plan.graph(self.app['source'][index*8192:(index+1)*8192],self.page+index*8192,self.head+index*8192,layout,table,index)
        self.eq(compact,ct,version=5,bytes=self.r.types[ct]['bytes'],ready=1,result=0,heads=expected['heads'],exits=expected['exits'],stores=0,source_bytes=expected['source_bytes'],source_mask=1,decoder_result=0,guard_result=0,reserved=0,links=0,reserved2=0,entry=self.head+index*8192)
        need(struct.unpack('<2I',self.f(compact,ct,'member_heads'))==expected['member_heads']and q(self.f(compact,ct,'page'))==(self.page+index*8192,self.page+index*8192+PAGE)and q(self.f(compact,ct,'layout'))==layout,'whole compact partition and actual placement')
        for key in('source','image','stub_image','head','original','frontier','edge','instruction','guard'):
            need(self.f(compact,ct,key)==expected[key],'whole independently reconstructed '+key+' certificate '+str(index))
        need(self.f(compact,ct,'exit_pc')==expected['exit_pc_bytes'],'every exact ordered original frontier')
        zero(self.f(b,CERT,'proof_tail'),'every sealed proof tail byte')
        need(self.f(b,CERT,'code')==expected['image']+expected['stub_image'],'whole live code equals every immutable model byte including CC tails')
        need(self.f(b,CERT,'slots')==expected['initial_slots'],'whole readonly dispatch-slot page')
        expected_spill=bytes(PAGE)if self.ordinal==0 else plan.terminal_spill(index,self.app['seed'],self.layouts)
        need(self.f(b,CERT,'spill_entered')==expected_spill,'whole actual cold-zero or retained prior-completion spill page')
        need(self.f(b,CERT,'spill_closed')==plan.terminal_spill(index,self.app['seed'],self.layouts),'all final scratch bytes including C last external-arm provenance')
        for field,prot in(('published',1),('opened',5),('drained',1)):
            for i,row in enumerate(self.r.items(b,CERT,field,'li2_sealed_code_query')):self.sealed_query(row,identity,layout[i],prot,8 if i<2 else 1)
        for row,offset,pages in zip(self.r.items(b,CERT,'proof','li2_sealed_code_query'),(0,64*PAGE),(64,25),strict=True):self.sealed_query(row,identity,proof+offset,1,pages)
        for field,address,prot in(('slot_query',layout[3],1),('spill_query',layout[4],3)):
            for row in self.r.items(b,CERT,field,'li2_private_code_query'):self.query(row,address,prot)
        for field,size in(('proof_scan',364544),('code_scan',69632),('slot_scan',4096)):self.scan(self.f(b,CERT,field),size)
        return expected

    def prebind_content(self):
        r=self.resident_before;t='li2_rsl_resident_progress';g=self.generation_before;gt='li2_rsl_generation_progress'
        self.eq(r,t,last_serial=self.ordinal,bindings=self.ordinal,snapshots=self.ordinal)
        for k in('bound','seed','epoch'):zero(self.f(r,t,k),'actual preceding RAW has invalidated the resident execution lease '+k)
        if self.ordinal==0:
            zero(r,'first resident entry has no invented earlier resident authority or observations')
            self.eq(g,gt,generation=0,publication_epoch=0,state=0,preserved=0)
            need(self.publication_epoch==self.i(self.source_before,'li2_rsl_progress','epoch'),'first real HELD bind issued the immutable content identity')
        else:
            self.eq(g,gt,generation=1,publication_epoch=self.publication_epoch,state=1,preserved=9)
        self.eq(g,gt,invalidations=0,pending_epoch=0,number=0,result=0,pending=0)
        zero(self.f(g,gt,'args'),'no pending caller-selected preservation arguments')
        need(self.i(g,gt,'effects')>0 and self.i(g,gt,'source_mutations')==1,
             'actual startup effects and the independently reported one CPUID temporary patch')

    def state(self,b,which):
        active=which=='entered';t=STATE
        self.eq(b,t,phase=7 if active else 10,busy=int(active),active=int(active),consumed=1,released=int(not active),exit_seen=int(not active),first_error=0,first_detail=0,registry_bound=1,serial=self.serial,publications=3,entries=self.serial,completed=self.ordinal+int(not active),cancelled=0,unexpected=0,ingresses=self.ordinal+int(not active),root=self.head,count=3,planned=3,exit_member=0 if active and self.ordinal==0 else 2,exit_index=0 if active and self.ordinal==0 else 1,flags=0xad7,gpr_written=3,flags_written=0x8d5)
        for k in('arena','directory','registry_count','token','source','content','source_pages'):
            need(self.f(b,t,k)==self.f(self.entered,t,k),'whole stable resident identity '+k)
        need(struct.unpack('<3I',self.f(b,t,'references'))==(int(active),)*3 and struct.unpack('<3I',self.f(b,t,'closed'))==(int(not active),)*3 and struct.unpack('<3I',self.f(b,t,'installed'))==(1,1,1)and q(self.f(b,t,'generation'))==(1,2,3),'all three actual backing references, closure bits and generations')
        self.eq(self.f(b,t,'token'),'li2_r3_token',owner=self.h[9],serial=self.serial)
        self.eq(self.f(b,t,'source'),'li2_rsl_ref',owner=self.symbol('rsl'))
        epoch=self.i(self.f(b,t,'source'),'li2_rsl_ref','epoch');need(epoch>0,'real source lease epoch')
        p=self.f(b,t,'source_progress');pt='li2_rsl_progress'
        self.eq(p,pt,initialized=1,pages=self.source_count,reserved=0)
        need(self.i(p,pt,'bindings')>0 and self.i(p,pt,'epoch')==self.i(p,pt,'invalidations')+1,'actual source epoch/invalidation/bind population')
        resident=self.f(b,t,'resident_progress');rt='li2_rsl_resident_progress'
        auth=(4 if active else 5)+self.i(self.source_before,pt,'valid')
        plans=(12 if active else 15)if self.ordinal==0 else(9 if active else 12)
        seals=(16 if active else 20)if self.ordinal==0 else(13 if active else 17)
        prev=lambda k:self.i(self.resident_before,rt,k)
        self.eq(resident,rt,last_serial=self.serial,bindings=self.serial,snapshots=self.serial,plans=prev('plans')+plans,validations=prev('validations')+(3 if active else 4),authentications=prev('authentications')+auth,fresh_maps_passes=prev('fresh_maps_passes')+auth,source_bytes=prev('source_bytes')+auth*self.source_count*PAGE,plan_source_bytes=prev('plan_source_bytes')+plans*8192,guard_pages=prev('guard_pages')+plans*self.source_count,observation_seals=prev('observation_seals')+seals)
        self.eq(p,pt,epoch=epoch,valid=1,bindings=self.i(self.source_before,pt,'bindings')+1,invalidations=self.i(self.source_before,pt,'invalidations'));zero(self.f(p,pt,'bound'),'separate resident lease never forges the old two-member token')
        self.eq(resident,rt,epoch=epoch);need(self.f(resident,rt,'bound')==self.f(b,t,'token'),'actual resident source binding token')
        seed=self.f(resident,rt,'seed');self.eq(seed,'li2_r3_seed',complete=1,reserved=0,serial=self.serial,session=self.symbol('selected_session'),pid=self.pid,tid=self.pid,root=self.head)
        need(self.f(seed,'li2_r3_seed','held')==self.f(self.f(self.b,T,'held'),'li2_span_fetch_observation','ref'),'actual by-value seed preserves genuine held source reference')
        rr=self.f(b,t,'rseq');r='li2_r3_rseq_progress'
        self.eq(rr,r,session=self.symbol('selected_session'),active=int(active),checking=0,registered=0,seed_complete=1,entry_complete=1,close_complete=int(not active),epoch=0,calls=0,address=0,page=0,length=0,signature=0,pid=self.pid,tid=self.pid,fs_selector=0,gs_selector=0,tls_complete=1,word_observed=0,word_before=0,word_entry=0,word_after=0,fs=self.before['fs'],gs=self.before['gs'])
        need(self.f(rr,r,'token')==self.f(b,t,'token')and struct.unpack('<3I',self.f(rr,r,'cold'))==((1,1,1)if self.ordinal==0 else(0,0,0)),'separate actual rseq token and exact cold-only decode proof population')
        for k in('before','observed','after'):zero(self.f(rr,r,k),'unregistered lifetime does not invent rseq memory evidence')
        need(self.i(rr,r,'raw_checks')>0,'real trusted RAW checks while resident lifetime active')
        if which in('closed','handoff'):need(rr==self.f(self.terminal,t,'rseq'),'whole rseq completion remains unchanged after release')
        if which=='terminal':need(self.i(rr,r,'raw_checks')>=self.i(self.f(self.entered,t,'rseq'),r,'raw_checks'),'actual lifetime RAW checks are monotonic')
        fetch=self.f(b,t,'fetch');ft='li2_fetch_progress';ref=self.f(self.f(self.b,T,'held'),'li2_span_fetch_observation','ref');sequence=self.i(ref,'li2_fetch_ref','sequence')
        if which in('entered','terminal'):
            self.progress(fetch,sequence,active,validated=not active)
            self.eq(fetch,ft,validation_calls=0 if active else 1)
        else:
            self.eq(fetch,ft,held=0,complete=1,first_error=0,identity_observed=1,first_detail=0,last_backing_observed=1)
            need(self.i(fetch,ft,'sequence')>sequence and self.i(fetch,ft,'validation_calls')>0 and 1<=self.i(fetch,ft,'bytes_copied')<=15 and self.i(fetch,ft,'pages_copied')in(1,2),'actual later ordinary fetch released without overwriting saved source authority')
            self.maps(self.f(fetch,ft,'preparation'));self.maps(self.f(fetch,ft,'validation'))
        stats=self.f(b,t,'maps');self.eq(stats,'li2_maps_stats',poisoned=0,reserved=0)
        need(self.i(stats,'li2_maps_stats','active')in(0,1)and self.i(stats,'li2_maps_stats','valid')in(0,1)and self.i(stats,'li2_maps_stats','acquisitions')>0,'actual retained maps state')
        if which!='entered':
            prior=self.f(self.entered,t,'maps')
            for k in('fresh_calls','acquisitions','reuses','invalidations','handler_id','mutation_epoch'):need(self.i(stats,'li2_maps_stats',k)>=self.i(prior,'li2_maps_stats',k),'monotonic actual maps counter '+k)

        self.eq(self.content,'li2_rsl_content_ref',owner=self.symbol('rsl'),generation=1,publication_epoch=self.publication_epoch)
        need(0<self.publication_epoch<=epoch,'actual issued content identity predates this execution lease')
        generation=self.f(b,t,'generation_progress');gt='li2_rsl_generation_progress'
        self.eq(generation,gt,generation=1,publication_epoch=self.publication_epoch,state=1,pending=0,
            invalidations=0,pending_epoch=0,number=0,result=0,preserved=9*self.ordinal)
        zero(self.f(generation,gt,'args'),'no pending effect arguments at actual entry/completion')
        for k in('effects','source_mutations'):
            need(self.f(generation,gt,k)==self.f(self.generation_before,gt,k),'no guest effects or source writes inside generated activation '+k)
        need(generation==self.f(self.entered,t,'generation_progress'),'whole immutable content observation through this real activation')

    def finish(self,status):
        h=self.h;r=self.r
        need(type(status)is int and status==0,'actual successful complete finite D3 process')
        need(h[:9]==(0x334f47525732494c,3,wire.RECORD_BYTES,wire.OWNER_BYTES,362568,364544,69632,968,128),'exact distinct full D3 wire extents')
        record_at=self.r.types['rgo_bundle']['fields']['record']['offset']+self.ordinal*wire.RECORD_BYTES
        need(h[9:12]==(self.symbol('r3_owner'),self.symbol('rgo_bundle')+record_at,self.symbol('selected_chain'))and self.symbols['rgo_bundle'][1]==wire.RAW_BYTES,'actual owner/bundle/member/chain ELF identity')
        retained=r.layout['retained_storage'];need(set(retained)=={'retained','selected_slot','selection','previous_selection','domain'}and retained['retained']['bytes']==2*r.types['li2_ptr_slot']['bytes']and retained['selected_slot']['bytes']==4 and retained['selection']['bytes']==retained['previous_selection']['bytes']==24 and retained['selected_slot']['offset']==retained['retained']['offset']+retained['retained']['bytes'],'actual unchanged old two-slot storage extent remains distinct')
        need(h[12]%PAGE==0 and canonical(h[12],524288)and h[13:16]==(524288,1,0)and h[16]&(3|0x400|0x800)==1 and h[17:19]==(0,1),'actual altstack and owned regular sink flags')
        need(h[19:22]==(self.head,0x41420e,self.app['capture_pc'])and h[22]==self.app['rsp']and h[23]==self.app['capture_pointer']and h[24:28]==(1,1,1,1)and h[28]>0 and h[29]==h[28]+1 and h[30]==h[29]+1 and h[31]in(0,1)and h[32]>0,'actual one-entry/one-terminal/next-TRACE chronology')
        need(h[33:38]==(0,0,0,0,1)and h[38:41]==(h[16],0,1),'whole successful finish without incomplete or relabelled failure')
        ingress=q(self.f(self.b,T,'ingress'));need(sum(ingress[1:])==ingress[0]==h[30]and ingress[1]>=1 and ingress[2]>=2 and ingress[3:]==(1,0,0),'actual complete signal partition and finite focal chronology')
        need(q(self.f(self.b,T,'bootstrap'))==(self.pid,)*5+(0,0,24,1),'actual trusted clear-TID reset and robust-list startup observations')
        session=self.f(self.b,T,'session');self.eq(session,'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        need(self.i(session,'li2_step_session','sync_query')&96==96,'real private expedited sync availability')
        for key in('sink_initial','sink_terminal'):
            st=self.f(self.b,T,key);value=self.stat(st);need(value['mode']&0xffff==0x8180 and value['size']==0,'actual empty regular0600 record sink');self.eq(st,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(self.f(self.b,T,'sink_initial'),self.f(self.b,T,'sink_terminal'),'stat',observed=('st_atim','st_mtim','st_ctim'))
        hardware=self.f(self.b,T,'hardware');self.eq(hardware,'li2_selected_hardware',abi_version=1,reserved=0)
        for i,k in enumerate(('leaf0','leaf1','leaf7')):need(struct.unpack('<4I',self.f(hardware,'li2_selected_hardware',k))==tuple(self.app['hardware'][i][2:]),'actual same-CPU application/bridge CPUID')
        self.source_union();self.registry();self.source_bind();self.prebind_content()
        models=[self.certificate(i)for i in range(3)]
        identities=[self.f(c,CERT,'identity')for c in self.certificates]
        need(len({self.i(x,'li2_sealed_identity','fd')for x in identities})==3 and len({self.v(x,'li2_sealed_identity','device inode')for x in identities})==3,'three distinct actual sealed backings')
        directory=self.i(self.entered,STATE,'directory');need(directory==self.layouts[0][5]and self.f(self.b,T,'directory')==plan.directory(self.layouts),'all seven ordered original-to-generated rows and whole zero directory tail')
        for row in r.items(self.b,T,'directory_query','li2_private_code_query'):self.query(row,directory,1,3)
        self.scan(self.f(self.b,T,'directory_scan'),12288)
        for key in('entered','terminal','closed','handoff'):self.state(self.f(self.b,T,key),key)
        self.consumed_transfer();self.frames()
        stacks=[self.memory(b,i)for i,b in enumerate(r.items(self.b,T,'memory','li2_r3o_memory'))]
        anchor,first,end,_,_,_=self.stack_identity
        costs={k:{name:self.i(self.f(self.f(self.b,T,k),STATE,'resident_progress'),'li2_rsl_resident_progress',name)for name in('bindings','snapshots','plans','validations','authentications','fresh_maps_passes','source_bytes','plan_source_bytes','guard_pages','observation_seals')}for k in('entered','terminal','closed','handoff')}
        return dict(ordinal=self.ordinal,actual_serial=self.serial,cumulative_entries=self.serial,cumulative_completed=self.serial,content_reference=q(self.content),generation_progress={k:self.i(self.f(self.entered,STATE,'generation_progress'),'li2_rsl_generation_progress',k)for k in('generation','publication_epoch','effects','preserved','invalidations','source_mutations')},rsp=h[22],kernel_altstack=h[12],kernel_altstack_bytes=h[13],original_stack_anchor=anchor,original_stack_first=first,original_stack_end=end,before=self.before,terminal=self.after,next=self.next,before_stack=stacks[0],terminal_stack=stacks[1],next_stack=stacks[2],source=self.app['source'],source_page_address=self.page,entry_pc=self.head,terminal_pc=0x41420e,next_pc=self.app['capture_pc'],cold_publications=3,entries=1,completed=1,resident_certificates=3,old_active_domain_limit=2,closed_pages=51,anchor_released=1,interior_signals=0,terminal_ingresses=1,native_instructions=30,generated_guest_instructions=28,source_pages=self.source_count,source_epoch=self.i(self.f(self.entered,STATE,'source'),'li2_rsl_ref','epoch'),source_cost=costs,source_before=dict(zip(('epoch','bindings','invalidations','valid'),self.v(self.source_before,'li2_rsl_progress','epoch bindings invalidations valid'))),layout_rows=self.layouts,models=[dict(heads=x['heads'],exits=x['exits'])for x in models],signal_counts=ingress,status=0,code=0,detail=0,qualification_credit=False,performance_credit=False)



def read(data,layout,image,app,pid,cpu,exit_status):
    need(type(data)is bytes and type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0 and
         type(exit_status)is int and exit_status==0,'whole actual successful two-activation process')
    need(len(data)==wire.RAW_BYTES+64 and len(data)<4<<20,'complete bounded two-record generation transport')
    footer=q(data[-64:]);need(footer[:4]==(0x314647525732494c,1,wire.RAW_BYTES,wire.RAW_BYTES)and
        1<=footer[4]<=64 and 0<footer[5]<=wire.RAW_BYTES and footer[6:]==(0,0),'whole successful bounded bundle footer')
    r=wire.Reader(memoryview(data)[:-64],layout);h=q(r.field(r.data,'rgo_bundle','h'))
    need(h==(0x314247525732494c,1,wire.RAW_BYTES,wire.RECORD_BYTES,1,2,2,2,0,0,0,1,0,0,1,wire.OWNER_BYTES),
         'exact two completed records, unchanged publications, genuine process success')
    need(type(app)is dict and app['version']==1 and app['complete']is True and app['records']==2 and
         app['owner_credit']is False and len(app['applications'])==2,'two complete separately authenticated gated applications')
    checks=[Check(wire.RecordView(r,i),image,app['applications'][i],pid,cpu)for i in range(2)]
    values=[c.finish(exit_status)for c in checks]
    first,last=checks;a,b=values
    need(a['content_reference']==b['content_reference']and a['source_pages']==b['source_pages']and
         b['source_epoch']==a['source_epoch']+9,'one immutable content identity, nine genuine revoked execution leases')
    for k in('effects','preserved'):
        need(b['generation_progress'][k]==a['generation_progress'][k]+9,'all nine exact successful nonmapping queries '+k)
    need(a['generation_progress']['preserved']==0 and b['generation_progress']['preserved']==9 and
         a['generation_progress']['invalidations']==b['generation_progress']['invalidations']==0,
         'no dirty renewal or hidden source mutation between the two activations')
    prior=first.f(first.handoff,STATE,'resident_progress');current=last.resident_before
    r.change(prior,current,'li2_rsl_resident_progress',observed=('bound','seed','epoch'))
    for key in('source','directory'):
        need(first.f(first.b,T,key)==last.f(last.b,T,key),'whole retained source union/directory across the actual boundary '+key)
    for c,d in zip(first.certificates,last.certificates,strict=True):
        for key in('identity','payload','proof_tail','code','slots'):
            need(first.f(c,CERT,key)==last.f(d,CERT,key),'whole retained sealed publication across both entries '+key)
        need(first.f(c,CERT,'spill_closed')==last.f(d,CERT,'spill_entered'),
             'whole real prior scratch state survives without a fabricated reset')
    need(first.h[30]<last.h[28] and first.h[32]<last.h[32],
         'actual ordered close, intervening effects and later genuine entry')
    final=bytes(r.field(r.data,'rgo_bundle','final'));t=STATE
    for key in r.types[t]['fields']:
        if key not in('fetch','source_progress','resident_progress','generation_progress','maps'):
            need(last.f(final,t,key)==last.f(last.handoff,t,key),'whole actual final drained owner field '+key)
    sp=last.f(final,t,'source_progress');pt='li2_rsl_progress'
    last.eq(sp,pt,initialized=1,valid=0,pages=last.source_count,reserved=0)
    zero(last.f(sp,pt,'bound'),'actual exit invalidates old owner binding')
    need(last.i(sp,pt,'epoch')==last.i(sp,pt,'invalidations')+1 and
         last.i(sp,pt,'epoch')>b['source_epoch'] and
         last.i(sp,pt,'bindings')>=last.i(last.source_before,pt,'bindings')+1,
         'actual final execution-lease invalidation after the second owner completion')
    rp=last.f(final,t,'resident_progress');rt='li2_rsl_resident_progress'
    r.change(last.f(last.handoff,t,'resident_progress'),rp,rt,observed=('bound','seed','epoch'))
    for key in('bound','seed','epoch'):zero(last.f(rp,rt,key),'final effect clears actual resident authority '+key)
    g=last.f(final,t,'generation_progress');gt='li2_rsl_generation_progress'
    last.eq(g,gt,generation=2,publication_epoch=last.publication_epoch,state=3,pending=0,
        invalidations=1,source_mutations=1,pending_epoch=0,number=0,result=0,preserved=13)
    zero(last.f(g,gt,'args'),'final dirty identity carries no pending preservation arguments')
    need(last.i(g,gt,'effects')>=b['generation_progress']['effects']+9,
         'four final getters, four full app writes and exit remain actual invalidating effects')
    fetch=last.f(final,t,'fetch');ft='li2_fetch_progress'
    last.eq(fetch,ft,held=0,complete=1,first_error=0,identity_observed=1,first_detail=0,last_backing_observed=1)
    sequence=last.i(last.f(last.f(last.b,T,'held'),'li2_span_fetch_observation','ref'),'li2_fetch_ref','sequence')
    need(last.i(fetch,ft,'sequence')>sequence and last.i(fetch,ft,'validation_calls')>0 and
         1<=last.i(fetch,ft,'bytes_copied')<=15 and last.i(fetch,ft,'pages_copied')in(1,2),
         'final ordinary fetch is genuinely validated and released')
    last.maps(last.f(fetch,ft,'preparation'));last.maps(last.f(fetch,ft,'validation'))
    maps=last.f(final,t,'maps');last.eq(maps,'li2_maps_stats',poisoned=0,reserved=0)
    need(last.i(maps,'li2_maps_stats','active')in(0,1)and last.i(maps,'li2_maps_stats','valid')in(0,1),
         'actual final maps state remains a valid typed observation')
    for key in('fresh_calls','acquisitions','reuses','invalidations','handler_id','mutation_epoch'):
        need(last.i(maps,'li2_maps_stats',key)>=last.i(last.f(last.handoff,t,'maps'),'li2_maps_stats',key),
             'monotonic actual final maps counter '+key)
    ingress=q(r.field(r.data,'rgo_bundle','ingress'))
    need(sum(ingress[1:])==ingress[0]>=last.h[30]and ingress[1]>=2 and ingress[2]>=4 and
         ingress[3:]==(1,0,0),'complete final signal partition; both focal intervals stay literal')
    return dict(version=1,scope='two_actual_three_region_activations',activations=values,
        publications=3,entries=2,completed=2,interior_signals=0,content_reference=a['content_reference'],
        preserved_boundary_effects=9,final_content_generation=2,final_content_state='dirty_after_output',
        signal_counts=ingress,transport=dict(raw_bytes=wire.RAW_BYTES,body_bytes=footer[3],
        body_calls=footer[4],last_body_result=footer[5],status=0,code=0),
        qualification_credit=False,performance_credit=False)


def pair(native,gated,owner):
    need(type(native)is dict and type(gated)is dict and native['records']==gated['records']==2 and
         native['complete']is gated['complete']is True and len(owner['activations'])==2,
         'two complete independently authenticated applications and owner lifetimes')
    results=[]
    for i in range(2):
        actual=owner['activations'][i]
        need(actual['ordinal']==i and actual['actual_serial']==actual['cumulative_entries']==actual['cumulative_completed']==i+1,
             'real cumulative owner chronology is separate from per-activation state')
        results.append(base.pair(native['applications'][i],gated['applications'][i],actual))
    need(owner['publications']==3 and owner['entries']==owner['completed']==2 and
         owner['interior_signals']==0 and owner['preserved_boundary_effects']==9 and
         owner['final_content_generation']==2 and owner['final_content_state']=='dirty_after_output',
         'three publications, two actual full-state activations and honest final invalidation')
    return dict(version=1,activations=results,publications=3,entries=2,completed=2,
                native_full_frames=10,protected_full_frames=6,interior_signals=0,
                qualification_credit=False,performance_credit=False)


def pair_controls(native,gated,owner):
    pair(native,gated,owner)
    rows=[base.pair_controls(native['applications'][i],gated['applications'][i],owner['activations'][i])for i in range(2)]
    need(all(x['count']==44 for x in rows),'all44 original whole-state pair stimuli for each real activation')
    return dict(count=88,activations=rows,native_operations=0)


def record_controls(data,layout,image,app,pid,cpu,exit_status,ordinal):
    """Causal supplied corruptions of this new finite observation only."""
    read(data,layout,image,app,pid,cpu,exit_status);types=layout['types'];tests=[]
    need(type(ordinal)is int and ordinal in(0,1),'exact supplied-record control ordinal')
    start=types['rgo_bundle']['fields']['record']['offset']+ordinal*wire.RECORD_BYTES
    def at(path):
        t=T;offset=start
        for key,index in path:
            field=types[t]['fields'][key];offset+=field['offset'];child=layout['edges'][t].get(key)
            if child:offset+=index*types[child]['bytes'];t=child
            else:
                need(index<field['bytes'],'bounded supplied scalar-byte stimulus');offset+=index
        return offset
    def add(name,path):tests.append((name,at(path)))
    def scalar(name,*path):add(name,[(x,0)if type(x)is str else x for x in path])
    for name,index in(('magic',0),('version',8),('whole_extent',16),('owner_extent',24),('raw_owner',72),('wire_address',80),('altstack',96),('sink_registered',112),('root',152),('terminal_pc',160),('actual_stack',176),('entered_complete',192),('terminal_complete',200),('next_complete',208),('ordinary_close',216),('terminal_ordinal',232),('incomplete',264),('status',272),('footer_sink',320),('prebind_epoch',328)):
        add(name,[('h',index)])
    for name,offset in(('bindings',336),('invalidations',344),('initialized',352),('valid',356),('pages',360),('reserved',364),('old_owner',368)):
        add('prebind_'+name,[('h',offset)])
    for i in range(9):add('bootstrap_'+str(i),[('bootstrap',i*8)])
    scalar('sink_inode','sink_terminal','st_ino');scalar('hardware','hardware','leaf1');scalar('session_mask','session','application_mask')
    for state in('entered','terminal','closed','handoff'):
        for key in('phase','publications','entries','completed','references','closed','generation','source_pages','registry_count','first_error'):
            scalar(state+'_'+key,state,key)
        scalar(state+'_rseq',state,'rseq','active');scalar(state+'_source_epoch',state,'source_progress','epoch')
        scalar(state+'_source_cost',state,'resident_progress','source_bytes')
    scalar('token_owner','entered','token','owner');scalar('actual_source_owner','entered','source','owner')
    scalar('held_borrow','held','ref','sequence');scalar('held_source','held','bytes');scalar('consumed_ticket','transfer','consumed')
    scalar('old_released_borrow','transfer','released','progress','held');scalar('source_union_page',('source',0),'identity','address')
    scalar('source_union_byte',('source',0),'bytes');scalar('protected_range',('registry',0),'end')
    for index in range(3):
        c=('certificate',index)
        for name,path in(
            ('sealed_fd',('identity','fd')),('sealed_inode',('identity','inode')),('sealed_extent',('identity','bytes')),
            ('source_generation',('payload','header','source_epoch')),('publication',('payload','header','publication_serial')),
            ('archive',('payload','header','archive')),('policy',('payload','header','policy')),
            ('source_bytes',('payload','source',('page',0),'bytes')),('table',('payload','plan','table','node')),
            ('head',('payload','plan','head')),('original',('payload','plan','original')),('frontier',('payload','plan','frontier')),
            ('instruction',('payload','plan','instruction')),('recovery',('payload','plan','guard')),
            ('generated',('code',)),('code_tail',(('code',69631),)),('proof_tail',('proof_tail',)),
            ('slots',('slots',)),('initial_spill',('spill_entered',)),('final_spill',('spill_closed',)),
            ('published_NX',(('published',0),'expected_prot')),('opened_RX',(('opened',0),'actual_prot')),
            ('drained_NX',(('drained',0),'complete')),('seals',(('opened',0),'sealed','seals_result')),
            ('query_backing',(('opened',0),'sealed','identity','inode')),('alias_census',(('proof',0),'sealed','alias_pages')),
            ('proof_offset',(('proof',1),'sealed','offset')),('anonymous_sidecar',(('slot_query',0),'sealed','kind')),
            ('whole_byte_scan',('proof_scan','compared'))):
            scalar('certificate'+str(index)+'_'+name,c,*path)
    scalar('directory_row','directory');add('directory_tail',[('directory',12287)])
    scalar('directory_query',('directory_query',1),'actual_prot');scalar('directory_scan','directory_scan','compared')
    for key in('before','after','next'):
        scalar(key+'_GREG',key,'frame','greg');scalar(key+'_FP',key,'frame','fp')
        scalar(key+'_mask',key,'frame','mask');scalar(key+'_TLS',key,'fs')
        add(key+'_whole_FP_tail',[(key,0),('frame',0),('fp',65535)])
        add(key+'_UC_alias',[(key,0),('uc',304)])
    for i in range(3):
        m=('memory',i)
        scalar('memory'+str(i)+'_origin',m,'origin','anchor');scalar('memory'+str(i)+'_fresh',m,'after','acquisitions')
        scalar('memory'+str(i)+'_stack',m,'stack');add('memory'+str(i)+'_lastbyte',[m,('stack',519)])
    scalar('next_chain_phase','next_closed','phase');scalar('next_chain_release','next_closed','release','complete')
    scalar('next_chain_after','next_closed','owner','step','after','fp');scalar('next_chain_unexpected','next_closed','unexpected')
    scalar('next_target_identity','next_closed','query','page','object');scalar('next_close_scan','unexpected_scan','compared')
    refused=[]
    for name,offset in tests:
        changed=bytearray(data);changed[offset]^=1
        try:read(bytes(changed),layout,image,app,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted supplied finite D3 corruption '+name)
    changed=bytearray(data);valid=struct.unpack_from('<I',data,start+356)[0]
    struct.pack_into('<Q',changed,start+376,0 if valid else 1)
    try:read(bytes(changed),layout,image,app,pid,cpu,exit_status)
    except ValueError:refused.append('prebind_old_serial')
    else:raise ValueError('accepted actual prebind old-owner serial corruption')
    for name,changed in(('truncated',data[:-1]),('extra',data+b'\0'),('failed_footer',data[:-16]+struct.pack('<QQ',125,4900))):
        try:read(changed,layout,image,app,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted complete-record/failed-outcome corruption '+name)
    need(len(refused)==231,'all231 finite D3 owner supplied controls refused')
    return dict(refusals=refused,count=len(refused),source_sha256=hashlib.sha256(data).hexdigest(),native_operations=0)



def record_prepared_controls(data,layout,image,app,pid,cpu,exit_status,ordinal):
    """Separate exact prepared/released chronology mutations; original231 stay whole."""
    read(data,layout,image,app,pid,cpu,exit_status);types=layout['types'];refused=[]
    need(type(ordinal)is int and ordinal in(0,1),'exact prepared-record control ordinal')
    start=types['rgo_bundle']['fields']['record']['offset']+ordinal*wire.RECORD_BYTES
    def at(path):
        t=T;offset=start;size=types[t]['bytes']
        for item in path:
            key,index=(item,0)if type(item)is str else item
            field=types[t]['fields'][key];offset+=field['offset'];child=layout['edges'][t].get(key)
            if child:
                size=types[child]['bytes'];need((index+1)*size<=field['bytes'],'bounded prepared-fetch aggregate stimulus')
                offset+=index*size;t=child
            else:
                need(index<field['bytes'],'bounded prepared-fetch scalar stimulus');offset+=index;size=field['bytes']-index
        return offset,size
    def reject(name,changed):
        need(bytes(changed)!=data,'changed prepared-fetch stimulus '+name)
        try:read(bytes(changed),layout,image,app,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted supplied prepared/released fetch corruption '+name)
    def flip(name,path,tail=False):
        offset,size=at(path);changed=bytearray(data);changed[offset+(size-1 if tail else 0)]^=1;reject(name,changed)
    prepared=(('entered',('entered','fetch')),('fresh',('transfer','fresh','progress')),('held',('held','progress')))
    for name,path in prepared:
        for key in('validation_calls','last_backing_observed','validation'):
            flip(name+'_'+key,path+(key,))
    for name,path in(('fresh',('transfer','fresh')),('held',('held',))):
        flip(name+'_last_backing',path+('last_backing',))
        flip(name+'_last_backing_tail',path+('last_backing',),True)
        flip(name+'_initial_backing',path+(('backing',0),'seals'))
        flip(name+'_initial_page',path+(('pages',0),'address'))
        flip(name+'_source_bytes',path+('bytes',))
    offset,size=at(('terminal','fetch','validation_calls'));need(size==8,'actual validation-call counter width')
    for count in(0,2):
        changed=bytearray(data);struct.pack_into('<Q',changed,offset,count);reject('terminal_validation_calls_'+str(count),changed)
    flip('terminal_validation_closed',('terminal','fetch','validation','closed'))
    # Copy genuine later validation evidence into every prepared observation:
    # a coherent fabricated early validation must still refuse exact zero.
    changed=bytearray(data);source,size=at(('terminal','fetch','validation'))
    for name,path in prepared:
        target,n=at(path+('validation',));need(n==size,'same actual validation-map extent')
        changed[target:target+n]=data[source:source+n]
        target,n=at(path+('validation_calls',));need(n==8,'prepared validation-call width');struct.pack_into('<Q',changed,target,1)
        target,n=at(path+('last_backing_observed',));need(n==4,'prepared last-backing flag width');struct.pack_into('<I',changed,target,1)
    for name,path in(('fresh',('transfer','fresh')),('held',('held',))):
        source,n=at(path+(('backing',0),));target,m=at(path+('last_backing',));need(n==m,'whole backing extent')
        changed[target:target+m]=data[source:source+n]
    reject('coordinated_invented_preentry_validation',changed)
    changed=bytearray(data)
    for key in('validation_calls','last_backing_observed','validation'):
        offset,size=at(('terminal','fetch',key));changed[offset:offset+size]=bytes(size)
    reject('coordinated_missing_release_validation',changed)
    need(len(refused)==len(set(refused))==24,'all24 additional prepared/released fetch controls')
    return dict(count=24,refusals=refused,source_sha256=hashlib.sha256(data).hexdigest(),native_operations=0)


def generation_controls(data,layout,image,app,pid,cpu,exit_status):
    """Additive content/activation-boundary corruptions; old controls stay separate."""
    read(data,layout,image,app,pid,cpu,exit_status)
    types=layout['types'];refused=[]
    def at(path):
        t='rgo_bundle';offset=0
        for item in path:
            key,index=(item,0)if type(item)is str else item
            f=types[t]['fields'][key];offset+=f['offset'];child=layout['edges'][t].get(key)
            if child:
                need((index+1)*types[child]['bytes']<=f['bytes'],'whole generation stimulus member')
                offset+=index*types[child]['bytes'];t=child
            else:
                need(index<f['bytes'],'whole generation stimulus scalar');offset+=index
        return offset
    def reject(name,changed):
        need(bytes(changed)!=data,'causal changed generation stimulus '+name)
        try:read(bytes(changed),layout,image,app,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted supplied generation corruption '+name)
    def flip(name,path):
        b=bytearray(data);b[at(path)]^=1;reject(name,b)
    for i in range(2):
        root=(('record',i),)
        for key in('generation','state','pending'):
            flip(str(i)+'/prebind/'+key,root+('generation_before',key))
        for key in('owner','generation','publication_epoch'):
            flip(str(i)+'/content/'+key,root+('entered','content',key))
        for key in('effects','preserved','invalidations','source_mutations'):
            flip(str(i)+'/entry/'+key,root+('entered','generation_progress',key))
        for j in range(3):
            flip(str(i)+'/certificate/'+str(j),root+(('certificate',j),'payload','header','content','generation'))
        for key in('state','pending'):
            flip(str(i)+'/terminal/'+key,root+('terminal','generation_progress',key))
        flip(str(i)+'/handoff/state',root+('handoff','generation_progress','state'))
    for key in('generation','state','invalidations','preserved'):
        flip('final/'+key,('final','generation_progress',key))
    for i in(5,6):flip('bundle/count/'+str(i),(('h',i*8),))
    # Changing every copy cannot turn the fixed first identity into a renewal.
    changed=bytearray(data)
    for i in range(2):
        for state in('entered','terminal','closed','handoff'):
            struct.pack_into('<Q',changed,at((('record',i),state,'content','generation')),2)
        for j in range(3):
            struct.pack_into('<Q',changed,at((('record',i),('certificate',j),'payload','header','content','generation')),2)
    struct.pack_into('<Q',changed,at(('final','content','generation')),2)
    reject('coordinated_content_identity_renewal',changed)
    changed=bytearray(data)
    first=struct.unpack_from('<Q',data,at((('record',0),'entered','source','epoch')))[0]
    for state in('entered','terminal','closed','handoff'):
        for parent in('source','source_progress','resident_progress'):
            struct.pack_into('<Q',changed,at((('record',1),state,parent,'epoch')),first)
    reject('coordinated_reused_execution_lease',changed)
    need(len(refused)==len(set(refused))==40,'all40 additive actual generation-boundary controls')
    return dict(count=40,refusals=refused,source_sha256=hashlib.sha256(data).hexdigest(),native_operations=0)


def refusal(data,layout,image,pid,cpu,exit_status,effect):
    """Narrow failed prefix: actual second HELD refusal, no second-entry credit.

    This does not qualify either lane's full frames. That requires the separate
    complete positive read/pair. The full transport and real failed owner state
    are retained literally; none are projected into a successful old record.
    """
    need(type(effect)is int and effect in(1,2,3)and type(exit_status)is int and exit_status==125,
         'exact separate mapping, ABA or failed-getter refusal case')
    need(type(data)is bytes and len(data)==wire.RAW_BYTES+64 and len(data)<4<<20,
         'whole failed two-record transport inside original bound')
    footer=q(data[-64:]);need(footer[:4]==(0x314647525732494c,1,wire.RAW_BYTES,wire.RAW_BYTES)and
         1<=footer[4]<=64 and 0<footer[5]<=wire.RAW_BYTES and footer[6:]==(125,4902),
         'actual failed source-refusal footer, no success relabel')
    r=wire.Reader(memoryview(data)[:-64],layout);f=r.field;i=r.integer
    h=q(f(r.data,'rgo_bundle','h'))
    need(h[:8]==(0x314247525732494c,1,wire.RAW_BYTES,wire.RECORD_BYTES,1,1,1,2)and
         h[8:]==(125,4902,15,1,1,0,1,wire.OWNER_BYTES),'actual incomplete second HELD bundle')
    records=r.items(r.data,'rgo_bundle','record',T);a,b=records
    ah,bh=q(f(a,T,'h')),q(f(b,T,'h'))
    _,_,symbols=elf_symbols(image['bridge']);bias=ah[9]-symbols['r3_memory'][0]
    need(canonical(bias)and bias%PAGE==0 and symbols['rgo_bundle'][1]==wire.RAW_BYTES and
         image['persistent_binding']['profile']=='resident-generation-two-flags-capture-v1'and
         image['persistent_binding']['stable_generation']is True and
         image['persistent_binding']['generation_capture']is True,'actual separate compiled refusal profile')
    for ordinal,(record,header)in enumerate(zip(records,(ah,bh),strict=True)):
        need(header[:9]==(0x334f47525732494c,3,wire.RECORD_BYTES,wire.OWNER_BYTES,362568,364544,69632,968,128)and
             header[9]==bias+symbols['r3_memory'][0]and
             header[10]==bias+symbols['rgo_bundle'][0]+layout['types']['rgo_bundle']['fields']['record']['offset']+ordinal*wire.RECORD_BYTES,
             'exact actual ELF owner/member addresses and typed extents')
        need(header[33:38]==(1,125,4902,15,1)and header[38:41]==(header[16],0,1),
             'both records retain the same actual failed terminal outcome')
        session=f(record,T,'session');need(i(session,'li2_step_session','pid')==i(session,'li2_step_session','tid')==pid and
             i(session,'li2_step_session','application_mask')==MASK,'actual failed-prefix session identity')
    need(ah[24:28]==(1,1,1,1)and ah[29]==ah[28]+1 and ah[30]==ah[29]+1 and
         bh[24:33]==(0,)*9,'first actual completion; no invented second frame/entry/close')
    for name in('transfer','held','entered','terminal','closed','handoff','before','after','next','memory','registry','source','certificate','directory','directory_query','directory_scan','unexpected_scan','next_closed'):
        zero(f(b,T,name),'unreached second activation payload '+name)
    final=f(r.data,'rgo_bundle','final');t=STATE
    expected=dict(phase=12,busy=1,active=0,consumed=0,released=0,exit_seen=0,first_error=4902,first_detail=15,
                  registry_bound=1,serial=2,publications=3,entries=1,completed=1,cancelled=0,unexpected=0,ingresses=1,
                  count=3,planned=3,exit_member=2,exit_index=1)
    need(all(i(final,t,k)==v for k,v in expected.items()),'genuine pre-RX second-bind refusal and first completion')
    need(struct.unpack('<3I',f(final,t,'references'))==(0,0,0)and
         struct.unpack('<3I',f(final,t,'closed'))==struct.unpack('<3I',f(final,t,'installed'))==(1,1,1)and
         q(f(final,t,'generation'))==(1,2,3),'all three genuine retained generations remain closed without references')
    g=f(final,t,'generation_progress');gt='li2_rsl_generation_progress';before=f(b,T,'generation_before')
    need(g==before and all(i(g,gt,k)==v for k,v in dict(generation=2,state=3,preserved=4,
         invalidations=1,source_mutations=1,pending=0,pending_epoch=0,number=0,result=0).items()),
         'real dirty identity at attempted bind; errors and mapping ABA never renew content')
    zero(f(g,gt,'args'),'no pending preservation arguments after refusal')
    first=f(f(a,T,'entered'),t,'generation_progress')
    need(i(g,gt,'publication_epoch')==i(first,gt,'publication_epoch')and
         i(g,gt,'effects')==i(first,gt,'effects')+(9 if effect==2 else 8),
         'exact actual pre-effect/getter chronology for the selected negative case')
    return dict(status='failed_prefix',exit=125,code=4902,detail=15,effect=effect,
                entries=1,completed=1,publications=3,second_entry=False,content_state='dirty',
                equivalence_credit=False,qualification_credit=False,performance_credit=False)


def refusal_controls(data,layout,image,pid,cpu,exit_status,effect):
    """Supplied prefix mutations never promote the failed process or its frames."""
    refusal(data,layout,image,pid,cpu,exit_status,effect);refused=[];types=layout['types']
    final=types['rgo_bundle']['fields']['final']['offset']
    tests=[('footer_status',len(data)-16),('footer_code',len(data)-8)]
    for key in('phase','busy','active','consumed','released','first_error','serial','publications','entries','completed','references'):
        tests.append(('final_'+key,final+types[STATE]['fields'][key]['offset']))
    generation=final+types[STATE]['fields']['generation_progress']['offset']
    for key in('state','generation','effects','args'):
        tests.append(('content_'+key,generation+types['li2_rsl_generation_progress']['fields'][key]['offset']))
    tests.append(('invented_second_frame',types['rgo_bundle']['fields']['record']['offset']+
                  wire.RECORD_BYTES+types[T]['fields']['before']['offset']))
    for name,offset in tests:
        changed=bytearray(data);changed[offset]^=1
        try:refusal(bytes(changed),layout,image,pid,cpu,exit_status,effect)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted supplied failed-prefix corruption '+name)
    need(len(refused)==len(set(refused))==18,'all18 separate failed-prefix controls')
    return dict(count=18,refusals=refused,source_sha256=hashlib.sha256(data).hexdigest(),native_operations=0)
