"""Finite D3 owner: three sealed certificates, one actual four-cycle activation.

The caller authenticates process, source, whole ELF/DWARF and application output.
This reader executes no decoder/emitter and never dereferences captured addresses.
Original two-slot profiles and their qualification gates remain separate.
"""
import hashlib,struct,importlib.util
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
HERE=Path(__file__).resolve().parent
wire=load('resident_three_wire',HERE/'wire.py')
plan=load('resident_three_independent_plan',HERE/'plan.py')
donor=load('resident_three_frame_donor',HERE.parent/'persistent_direct_frontier_owner/read.py')
old=donor.old
need,zero,q,canonical=old.need,old.zero,old.q,old.canonical
PAGE,FP,TF,RF,MASK=old.PAGE,old.FP,old.TF,old.RF,old.MASK
T='r3o_wire';STATE='r3o_state';CERT='r3o_certificate';STEP='li2_step_frame'
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)


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


class Check(donor.Check):
    def __init__(self,r,image,app,pid,cpu):
        self.r,self.image,self.app,self.pid,self.cpu=r,image,app,pid,cpu
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
        need(self.binding['version']==1 and self.binding['profile']=='resident-three-direct-flags-capture-v1'and self.binding['mode']=='release'and all(self.binding[k]is True for k in('native_probe','parse_memo','unregistered','subentry','cross_pair','direct_frontier','resident_three','sealed_storage','source_lease','flag_stack','helper_tf')),'actual distinct capture build binding')
        need(image['maps_mode']in('maintained','differential'),'actual maps build mode');self.differential=image['maps_mode']=='differential'
        geom=self.binding['geometry'];need(geom['root']==self.head and geom['roots']==[self.head,0x412200,0x414200]and geom['source']==dict(bytes=24576,sha256=hashlib.sha256(app['source']).hexdigest()),'exact bound complete source geometry')
        self.certificates=r.items(self.b,T,'certificate',CERT)
        key=self.f(self.f(self.certificates[0],CERT,'payload'),'r3_payload','source');row=r.items(key,'li2_pg_source_key','page','li2_pg_source_page')[0]
        self.main_backing=self.f(row,'li2_pg_source_page','backing');self.source_offset=self.i(self.f(row,'li2_pg_source_page','identity'),'li2_fetch_page','offset')
        self.before=self.frame(self.f(self.b,T,'before'));self.after=self.frame(self.f(self.b,T,'after'));self.next=self.frame(self.f(self.b,T,'next'))
        self.entered=self.f(self.b,T,'entered');self.terminal=self.f(self.b,T,'terminal');self.closed=self.f(self.b,T,'closed');self.final=self.f(self.b,T,'final')
        self.source_count=self.i(self.entered,STATE,'source_pages');need(0<self.source_count<=64,'actual bounded declared source union')
        self.source_before=self.f(self.b,T,'h')[328:384]
        self.source_rows=r.items(self.b,T,'source','li2_pg_source_page')
        self.layouts=[q(self.f(self.f(self.f(c,CERT,'payload'),'r3_payload','header'),'r3_header','layout'))for c in self.certificates]

    def frame(self,b,tls=True):
        value=old.Check.frame(self,b,tls)
        need(value['uc'][304:432]==value['si'],'whole kernel ucontext-adjacent signal info, all128 bytes retained')
        value['fp_address']=self.i(self.f(b,'uh_frame','frame'),STEP,'fp_address')
        return value

    def query(self,b,entry,prot,pages=1,failed=False):
        need(not failed,'finite D3 uses successful whole private queries')
        old.Check.query(self,b,entry,prot,pages,failed)
        zero(self.f(b,'li2_private_code_query','sealed'),'anonymous query retains an explicitly zero sealed sidecar')

    def sealed_query(self,b,identity,entry,prot,pages):
        t='li2_sealed_code_query'
        self.eq(b,t,first=entry,end=entry+pages*PAGE,pages_checked=pages,attempted=1,complete=1,expected_prot=prot,actual_prot=prot,result=0,detail=0)
        a,z=self.v(b,t,'first_vma last_vma_end');need(a%PAGE==z%PAGE==0 and a<=entry<entry+pages*PAGE<=z and canonical(a,z-a),'whole actual sealed VMA envelope')
        self.maps(self.f(b,t,'maps'));e=self.f(b,t,'sealed');et='li2_sealed_evidence'
        self.eq(e,et,kind=1,version=1,seals_result=15,stat_result=0,alias_pages=106,alias_complete=1,reserved=0)
        need(self.f(e,et,'identity')==identity,'whole actual sealed query identity')
        code,proof=self.v(identity,'li2_sealed_identity','code proof');offset=entry-code if code<=entry<code+69632 else 69632+entry-proof
        need((code<=entry and entry+pages*PAGE<=code+69632)or(proof<=entry and entry+pages*PAGE<=proof+364544 and prot==1),'exact typed code/proof query extent and proof read-only rule')
        self.eq(e,et,offset=offset)
        need(2<=self.i(e,et,'alias_vmas')<=106,'complete nonoverlapping sealed code/proof alias census')

    def source_window(self,pc):
        need(pc in(0x4101fe,0x410200,0x41420e),'one actual ordinary D3 source boundary')
        value=self.app['source'][pc-self.page:pc-self.page+15];need(len(value)==15,'whole current-page ordinary window');return value,1

    def decoded(self,b,pc,kind=None):
        need(pc in(0x4101fe,0x41420e),'original D3 register/memory JMP boundary')
        n=2 if pc==0x4101fe else 3;window,_=self.source_window(pc)
        self.eq(b,'li2_decoded',pc=pc,next_pc=pc+n,abi_version=1,decode_status=0,code=765,kind=0,destination=16,width_bits=0,step_disposition=0,available=15,length=n,reserved=0)
        need(self.f(b,'li2_decoded','bytes')==window+b'\0','whole ordinary decoded input')
        return 765,n

    def file_page(self,page,backing):
        t='li2_fetch_page';address,allocation,generation,offset,objid=self.v(page,t,'address allocation generation offset object')
        need(address%PAGE==offset%PAGE==0 and canonical(address,PAGE)and allocation>0 and generation>0 and objid in(self.image['main_object'],self.image['interpreter_object']),'real initial source page/allocation/generation/object')
        self.eq(page,t,backing=1,closed_prot=1)
        need(self.i(page,t,'logical')in(1,5),'actual closed initial logical source permission')
        obj,_,loads=self.objects[objid];bias=self.bases[objid]
        rows=[p for p in loads if p[1]&1 and (bias+p[3])&-PAGE<=address<((bias+p[3]+p[6]+PAGE-1)&-PAGE)and offset==(p[2]&-PAGE)+address-((bias+p[3])&-PAGE)]
        need(len(rows)==1 and offset+PAGE<=obj['carrier_bytes'],'one actual original executable source-page mapping')
        initial=self.i(page,t,'initial_extent');need(initial==0,'initial main/interpreter page has no dependency loader extent')
        identity=self.backing_identity(backing);need(identity[-1]==obj['carrier_bytes'],'whole retained original carrier extent')
        if objid in self.backings:need(self.backings[objid]==identity,'stable complete backing identity per original image')
        else:self.backings[objid]=identity
        first,end,major,minor,inode,vmaoff=self.v(page,t,'vma_first vma_end vma_major vma_minor vma_inode vma_offset')
        dev=identity[2];need(first%PAGE==end%PAGE==vmaoff%PAGE==0 and first<=address<address+PAGE<=end and vmaoff+address-first==offset and (major,minor,inode)==(((dev>>8)&0xfff)|((dev>>32)&0xfffff000),(dev&255)|((dev>>12)&0xffffff00),identity[3]),'actual complete sealed source VMA offset/device/inode')
        want=obj['data'][offset:offset+PAGE]+bytes(max(0,offset+PAGE-len(obj['data'])))
        need(len(want)==PAGE,'complete original carrier source page')
        return address,want

    def source_union(self):
        addresses=[];self.source_by_address={}
        expected=set()
        for objid in(self.image['main_object'],self.image['interpreter_object']):
            for p in self.objects[objid][2]:
                if p[1]&1:
                    a=(self.bases[objid]+p[3])&-PAGE;z=(self.bases[objid]+p[3]+p[6]+PAGE-1)&-PAGE
                    expected.update(range(a,z,PAGE))
        for i,row in enumerate(self.source_rows):
            if i>=self.source_count:zero(row,'whole unused source-union row');continue
            a,want=self.file_page(self.f(row,'li2_pg_source_page','identity'),self.f(row,'li2_pg_source_page','backing'))
            need(a not in addresses and self.f(row,'li2_pg_source_page','bytes')==want,'every whole source-union byte and unique original page')
            addresses.append(a);self.source_by_address[a]=row
        need(set(addresses)==expected and len(addresses)==len(expected),'all and only original-main/interpreter executable pages in actual union')
        return addresses

    def source_key(self,b,entry):
        self.eq(b,'li2_pg_source_key',entry=entry)
        for i,row in enumerate(self.r.items(b,'li2_pg_source_key','page','li2_pg_source_page')):
            page=(entry&-PAGE)+PAGE*i;need(page in self.source_by_address,'certificate pages belong to the actual union')
            saved=self.source_by_address[page]
            need(self.f(row,'li2_pg_source_page','identity')==self.f(saved,'li2_pg_source_page','identity')and self.f(row,'li2_pg_source_page','bytes')==self.f(saved,'li2_pg_source_page','bytes')and self.backing_identity(self.f(row,'li2_pg_source_page','backing'))==self.backing_identity(self.f(saved,'li2_pg_source_page','backing')),'complete certificate source identity/bytes and stable sealed backing')

    def continuation_page(self,b,pc):
        need(pc==self.app['capture_pc'],'actual high ordinary continuation')
        t='li2_fetch_page';page=pc&-PAGE;row=self.source_by_address.get(page);need(row is not None,'actual continuation remains inside declared original source union')
        saved=self.f(row,'li2_pg_source_page','identity')
        for k in('address','allocation','offset','initial_extent','backing','object','logical','closed_prot','vma_major','vma_minor','vma_inode'):
            need(self.f(b,t,k)==self.f(saved,t,k),'ordinary target actual source identity '+k)
        need(self.i(b,t,'generation')>=self.i(saved,t,'generation'),'ordinary target observed actual lifecycle generation')
        a,z,off=self.v(b,t,'vma_first vma_end vma_offset');need(a%PAGE==z%PAGE==off%PAGE==0 and a<=page<page+PAGE<=z and off+page-a==self.i(saved,t,'offset'),'complete target VMA coordinate')

    def registry(self):
        count=self.i(self.entered,STATE,'registry_count');need(0<count<=128,'whole bounded actual protected registry')
        rows=self.r.items(self.b,T,'registry','li2_fork_range');ranges=[self.v(x,'li2_fork_range','first end')for x in rows[:count]]
        for row in rows[count:]:zero(row,'whole unused protected registry range')
        need(all(canonical(a,z-a)for a,z in ranges),'all actual protected intervals')
        declarations=self.r.layout['registrations'];need(set(declarations)==set(wire.REGISTERED),'whole exact compiled registration roster')
        headers=self.image['headers'];need(type(headers)is dict and headers,'actual complete compiler-M header closure')
        for name,(source,tag)in wire.REGISTERED.items():
            d=declarations[name];at,n=self.symbols[name];a,z=self.bias+at,self.bias+at+n
            need(set(d)=={'address','bytes','alignment','tag','source'}and(d['address'],d['bytes'],d['tag'])==(at,n,tag)and type(d['alignment'])is int and 0<d['alignment']<=PAGE and not d['alignment']&(d['alignment']-1)and a%d['alignment']==0 and d['source'].endswith('/tools/page-entry/selected/'+source),'actual complete symbol/DWARF/source identity '+name)
            need(d['source']in headers and set(headers[d['source']])=={'bytes','sha256'},'registered DWARF origin belongs to actual compiler-M closure')
            if name not in wire.LIFETIME:need(ranges.count((a,z))==1,'whole strict protected object '+name)
            loads=[p for p in self.ph if p[0]==1 and p[6]and self.bias+p[3]<z and a<self.bias+p[3]+p[6]]
            need(len(loads)==1 and loads[0][1]==6 and self.bias+loads[0][3]<=a<z<=self.bias+loads[0][3]+loads[0][6],'whole object in actual RW/NX bridge LOAD')
            p=loads[0];rounded=((self.bias+p[3])&-PAGE,(self.bias+p[3]+p[6]+PAGE-1)&-PAGE)
            need(ranges.count(rounded)==1,'whole containing bridge LOAD remains protected')
        arena=self.i(self.entered,STATE,'arena');need(canonical(arena,327*PAGE)and arena%PAGE==0 and ranges.count((arena,arena+327*PAGE))==1,'whole independent three-certificate arena protection')
        need(self.symbol('r3_memory')==self.h[9]and self.symbols['r3_memory'][1]==1249280 and self.h[3]==1246656 and self.symbols['r3_work'][1]==2329264 and self.symbols['rsl'][1]==70*PAGE and self.symbols['rsl_initialization'][1]==72,'actual complete separate owner/source/bootstrap storage')
        self.ranges=ranges

    def certificate(self,index):
        b=self.certificates[index];payload=self.f(b,CERT,'payload');header=self.f(payload,'r3_payload','header');t='r3_header';layout=self.layouts[index]
        arena=self.i(self.entered,STATE,'arena');code=arena+index*108*PAGE;proof=code+19*PAGE;directory=arena+324*PAGE
        need(layout==(code,code+8*PAGE,code+16*PAGE,code+17*PAGE,code+18*PAGE,directory),'separate exact three-resident code/data/proof/directory geometry')
        self.eq(header,t,version=1,bytes=362544,generation=index+1,publication_serial=1,index=index,source_epoch=self.i(self.f(self.entered,STATE,'source'),'li2_rsl_ref','epoch'),root=self.head+index*8192,owner=self.h[9])
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
        zero(self.f(b,CERT,'spill_entered'),'whole first-entry private spill page')
        need(self.f(b,CERT,'spill_closed')==plan.terminal_spill(index,self.app['seed'],self.layouts),'all final scratch bytes including C last external-arm provenance')
        for field,prot in(('published',1),('opened',5),('drained',1)):
            for i,row in enumerate(self.r.items(b,CERT,field,'li2_sealed_code_query')):self.sealed_query(row,identity,layout[i],prot,8 if i<2 else 1)
        for row,offset,pages in zip(self.r.items(b,CERT,'proof','li2_sealed_code_query'),(0,64*PAGE),(64,25),strict=True):self.sealed_query(row,identity,proof+offset,1,pages)
        for field,address,prot in(('slot_query',layout[3],1),('spill_query',layout[4],3)):
            for row in self.r.items(b,CERT,field,'li2_private_code_query'):self.query(row,address,prot)
        for field,size in(('proof_scan',364544),('code_scan',69632),('slot_scan',4096)):self.scan(self.f(b,CERT,field),size)
        return expected

    def scan(self,b,n):self.eq(b,'r3o_scan',compared=n,differences=0,first_offset=0,expected=0,actual=0)

    def memory(self,b,site):
        t='li2_r3o_memory';s=self.h[22];self.eq(b,t,attempted=1,complete=1,site=site,copied=520,result=0,rsp=s)
        origin=self.f(b,t,'origin');ot='li2_r3o_stack';anchor,a,z,first,end,acquisition=self.v(origin,ot,'anchor origin_first origin_end first end origin_acquisition')
        need(a%PAGE==z%PAGE==0 and canonical(a,z-a)and a<=anchor<z and (first,end)==(s-256,s+264)and a<=first<end<=z and acquisition>0,'actual retained original-stack anchor and complete520-byte interval')
        need(all(end<=x or y<=first for x,y in self.ranges),'whole stack capture disjoint from every protected range')
        if site:need((anchor,a,z,first,end,acquisition)==self.stack_identity,'same complete original-stack origin across all three events')
        else:self.stack_identity=(anchor,a,z,first,end,acquisition)
        before,after=(self.f(b,t,k)for k in('before','after'));st='li2_maps_stats'
        for v in(before,after):self.eq(v,st,poisoned=0,reserved=0);need(self.i(v,st,'active')in(0,1),'actual maps phase')
        active=self.i(before,st,'active');self.eq(after,st,valid=1,active=active,handler_id=self.i(before,st,'handler_id'),acquisitions=self.i(before,st,'acquisitions')+1,fresh_calls=self.i(before,st,'fresh_calls')+1,reuses=self.i(before,st,'reuses'))
        self.eq(self.f(origin,ot,'observation'),'li2_maps_observation',acquisition_id=self.i(after,st,'acquisitions'),handler_id=self.i(before,st,'handler_id')if active else 0,mutation_epoch=self.i(after,st,'mutation_epoch'),kind=1 if active else 0,io_performed=1)
        need(self.i(after,st,'acquisitions')>=acquisition and self.i(after,st,'mutation_epoch')>=self.i(before,st,'mutation_epoch')and self.i(after,st,'invalidations')>=self.i(before,st,'invalidations'),'fresh complete actual stack query counters')
        stack=self.f(b,t,'stack');need(stack==self.app['stack'],'every literal original-stack byte equals actual app')
        return stack

    def source_bind(self):
        before=self.source_before;t='li2_rsl_progress'
        need(len(before)==self.r.types[t]['bytes']==56,'whole actual source progress immediately before binding')
        self.eq(before,t,initialized=1,pages=self.source_count,reserved=0)
        epoch,bindings,invalidations,valid=self.v(before,t,'epoch bindings invalidations valid')
        need(0<epoch==invalidations+1 and bindings<(1<<64)-1 and valid in(0,1),'actual prior source epoch and literal binding state')
        token=self.f(before,t,'bound')
        if valid:
            self.eq(token,'li2_pg_token',owner=self.symbol('pe'))
            need(bindings>0 and self.i(token,'li2_pg_token','serial')>0,'actual prior old-owner source binding, not a resident authority')
        else:zero(token,'invalid source lease retains no old binding')
        p=self.f(self.entered,STATE,'source_progress')
        self.eq(p,t,epoch=epoch,bindings=bindings+1,invalidations=invalidations,initialized=1,valid=1,pages=self.source_count,reserved=0)
        zero(self.f(p,t,'bound'),'real resident bind cleared the old owner token')
        self.eq(self.f(self.entered,STATE,'source'),'li2_rsl_ref',epoch=epoch)
        return valid

    def state(self,b,which):
        active=which=='entered';final=which=='final';t=STATE
        self.eq(b,t,phase=7 if active else 10,busy=int(active),active=int(active),consumed=1,released=int(not active),exit_seen=int(not active),first_error=0,first_detail=0,registry_bound=1,serial=1,publications=3,entries=1,completed=int(not active),cancelled=0,unexpected=0,ingresses=int(not active),root=self.head,count=3,planned=3,exit_member=0 if active else 2,exit_index=0 if active else 1,flags=0xad7,gpr_written=3,flags_written=0x8d5)
        for k in('arena','directory','registry_count','token','source','source_pages'):
            need(self.f(b,t,k)==self.f(self.entered,t,k),'whole stable resident identity '+k)
        need(struct.unpack('<3I',self.f(b,t,'references'))==(int(active),)*3 and struct.unpack('<3I',self.f(b,t,'closed'))==(int(not active),)*3 and struct.unpack('<3I',self.f(b,t,'installed'))==(1,1,1)and q(self.f(b,t,'generation'))==(1,2,3),'all three actual backing references, closure bits and generations')
        self.eq(self.f(b,t,'token'),'li2_r3_token',owner=self.h[9],serial=1)
        self.eq(self.f(b,t,'source'),'li2_rsl_ref',owner=self.symbol('rsl'))
        epoch=self.i(self.f(b,t,'source'),'li2_rsl_ref','epoch');need(epoch>0,'real source lease epoch')
        p=self.f(b,t,'source_progress');pt='li2_rsl_progress'
        self.eq(p,pt,initialized=1,pages=self.source_count,reserved=0)
        need(self.i(p,pt,'bindings')>0 and self.i(p,pt,'epoch')==self.i(p,pt,'invalidations')+1,'actual source epoch/invalidation/bind population')
        resident=self.f(b,t,'resident_progress');rt='li2_rsl_resident_progress'
        auth=(4 if active else 5)+self.i(self.source_before,pt,'valid')
        self.eq(resident,rt,last_serial=1,bindings=1,snapshots=1,plans=12 if active else 15,validations=3 if active else 4,authentications=auth,fresh_maps_passes=auth,source_bytes=auth*self.source_count*PAGE,plan_source_bytes=(12 if active else 15)*8192,guard_pages=(12 if active else 15)*self.source_count,observation_seals=16 if active else 20)
        if final:
            self.eq(p,pt,valid=0);zero(self.f(p,pt,'bound'),'actual exit effect invalidated old source binding')
            need(self.i(p,pt,'bindings')>=self.i(self.source_before,pt,'bindings')+1,'actual final source binding population retains the witnessed resident bind')
            for k in('bound','seed','epoch'):zero(self.f(resident,rt,k),'actual exit effect invalidated resident execution lease '+k)
            need(self.i(p,pt,'epoch')>epoch,'post-activation actual RAW invalidation remains distinct from immutable source identity')
        else:
            self.eq(p,pt,epoch=epoch,valid=1,bindings=self.i(self.source_before,pt,'bindings')+1,invalidations=self.i(self.source_before,pt,'invalidations'));zero(self.f(p,pt,'bound'),'separate resident lease never forges the old two-member token')
            self.eq(resident,rt,epoch=epoch);need(self.f(resident,rt,'bound')==self.f(b,t,'token'),'actual resident source binding token')
            seed=self.f(resident,rt,'seed');self.eq(seed,'li2_r3_seed',complete=1,reserved=0,serial=1,session=self.symbol('selected_session'),pid=self.pid,tid=self.pid,root=self.head)
            need(self.f(seed,'li2_r3_seed','held')==self.f(self.f(self.b,T,'held'),'li2_span_fetch_observation','ref'),'actual by-value seed preserves genuine held source reference')
        rr=self.f(b,t,'rseq');r='li2_r3_rseq_progress'
        self.eq(rr,r,session=self.symbol('selected_session'),active=int(active),checking=0,registered=0,seed_complete=1,entry_complete=1,close_complete=int(not active),epoch=0,calls=0,address=0,page=0,length=0,signature=0,pid=self.pid,tid=self.pid,fs_selector=0,gs_selector=0,tls_complete=1,word_observed=0,word_before=0,word_entry=0,word_after=0,fs=self.before['fs'],gs=self.before['gs'])
        need(self.f(rr,r,'token')==self.f(b,t,'token')and struct.unpack('<3I',self.f(rr,r,'cold'))==(1,1,1),'separate actual rseq token and all three cold proofs')
        for k in('before','observed','after'):zero(self.f(rr,r,k),'unregistered lifetime does not invent rseq memory evidence')
        need(self.i(rr,r,'raw_checks')>0,'real trusted RAW checks while resident lifetime active')
        if which in('closed','final'):need(rr==self.f(self.terminal,t,'rseq'),'whole rseq completion remains unchanged after release')
        if which=='terminal':need(self.i(rr,r,'raw_checks')>=self.i(self.f(self.entered,t,'rseq'),r,'raw_checks'),'actual lifetime RAW checks are monotonic')
        fetch=self.f(b,t,'fetch');ft='li2_fetch_progress';ref=self.f(self.f(self.b,T,'held'),'li2_span_fetch_observation','ref');sequence=self.i(ref,'li2_fetch_ref','sequence')
        if which in('entered','terminal'):self.progress(fetch,sequence,active)
        else:
            self.eq(fetch,ft,held=0,complete=1,first_error=0,identity_observed=1,first_detail=0,last_backing_observed=1)
            need(self.i(fetch,ft,'sequence')>sequence and self.i(fetch,ft,'validation_calls')>0 and 1<=self.i(fetch,ft,'bytes_copied')<=15 and self.i(fetch,ft,'pages_copied')in(1,2),'actual later ordinary fetch released without overwriting saved source authority')
            self.maps(self.f(fetch,ft,'preparation'));self.maps(self.f(fetch,ft,'validation'))
        stats=self.f(b,t,'maps');self.eq(stats,'li2_maps_stats',poisoned=0,reserved=0)
        need(self.i(stats,'li2_maps_stats','active')in(0,1)and self.i(stats,'li2_maps_stats','valid')in(0,1)and self.i(stats,'li2_maps_stats','acquisitions')>0,'actual retained maps state')
        if which!='entered':
            prior=self.f(self.entered,t,'maps')
            for k in('fresh_calls','acquisitions','reuses','invalidations','handler_id','mutation_epoch'):need(self.i(stats,'li2_maps_stats',k)>=self.i(prior,'li2_maps_stats',k),'monotonic actual maps counter '+k)

    def consumed_transfer(self):
        tr=self.f(self.b,T,'transfer');t='li2_span_transfer_progress';held=self.f(self.b,T,'held')
        ref=self.f(held,'li2_span_fetch_observation','ref');sequence=self.i(ref,'li2_fetch_ref','sequence')
        self.eq(tr,t,phase=3,issued=1,consume_attempted=1,consumed=1,resume_attempted=0,resumed=0,next=0,successor_installed=0,first_error=0,first_detail=0,fresh_borrow=sequence,pc=self.head,flags=0xad7,refault_attempted=0,refaulted=0)
        need(self.i(tr,t,'previous')in(0,1)and self.i(tr,t,'previous_generation')>0 and self.i(tr,t,'serial')>0 and self.i(tr,t,'event')>0 and 0<self.i(tr,t,'previous_borrow')<sequence,'actual consumed previous-slot and strictly later held borrow')
        released=self.f(tr,t,'released');self.observation(released,0x4101fe,False)
        self.eq(self.f(released,'li2_span_fetch_observation','ref'),'li2_fetch_ref',sequence=self.i(tr,t,'previous_borrow'))
        self.observation(self.f(tr,t,'fresh'),self.head,True,ref);self.observation(held,self.head,True,ref)
        self.key_identity_observation(held,self.f(tr,t,'fresh'))

    def key_identity_observation(self,a,b):
        t='li2_span_fetch_observation'
        for k in('complete','ref','pc','length','page_count','bytes','pid','tid','pages'):need(self.f(a,t,k)==self.f(b,t,k),'whole same genuine held source field '+k)
        for x,y in zip(self.r.items(a,t,'backing','li2_fetch_backing'),self.r.items(b,t,'backing','li2_fetch_backing'),strict=True):
            if any(x)or any(y):need(self.backing_identity(x)==self.backing_identity(y),'same genuine held backing identity')
            else:need(x==y,'whole unused held backing')
        need(self.backing_identity(self.f(a,t,'last_backing'))==self.backing_identity(self.f(b,t,'last_backing')),'same last independently validated backing')

    def frames(self):
        h=self.h;s=h[22];a,b,c=self.before,self.after,self.next
        self.trace(a,self.head,0xad7);self.nx(b,0x41420e);self.trace(c,self.app['capture_pc'],0x246|TF)
        need(a['greg'][22]==0x4101fe and b['greg'][17]==0x246|RF and c['greg'][22]==0x41420e,'actual predecessor/terminal fault chronology')
        expected=list(a['greg'])
        need(tuple(a['greg'][i]for i in GREG)==self.app['seed']and a['greg'][15]==s==self.app['rsp']and a['greg'][3]==self.app['capture_pointer'],'all original seeded registers and actual original stack')
        expected[13]=29;expected[14]=0;expected[16]=0x41420e;expected[17]=0x246|RF;expected[19]=21;expected[20]=14;expected[22]=0x41420e
        need(b['greg']==tuple(expected),'all23 terminal GREGs with only exact four-cycle writes and genuine NX fields')
        expected[16]=self.app['capture_pc'];expected[17]=0x246|TF;expected[19]=0;expected[20]=1
        need(c['greg']==tuple(expected),'all23 next-TRACE GREGs after exact original memory JMP')
        need(a['fp']==b['fp']==c['fp']and a['fp_bytes']==b['fp_bytes']==c['fp_bytes']and a['mask']==b['mask']==c['mask']==MASK,'all65536 FP storage and actual kernel mask unchanged')
        need((a['fs'],a['gs'])==(b['fs'],b['gs'])==(c['fs'],c['gs'])==tuple(self.app['machine'][1:3]),'complete actual FS/GS bracket')
        for frame in(b,c):
            for first,last in((0,40),(232,304)):
                need(frame['uc'][first:last]==a['uc'][first:last],'whole unchanged UC flags/link/stack/reserved/mask extent')
        slot=self.f(self.b,T,'next_closed');st='li2_tf_chain_slot'
        need(self.i(slot,st,'index')==h[31]and h[32]>self.i(slot,st,'event_id')>self.i(self.f(self.b,T,'transfer'),'li2_span_transfer_progress','event'),'genuine successor slot and strictly later ordinary close event')
        self.eq(slot,st,origin=1)
        before,ref=self.predecessor(slot,0x41420e,c)
        owner=self.f(slot,st,'owner');step=self.f(owner,'li2_tf_owner','step')
        self.step_frame(self.f(step,'li2_step_owner','before'),b)
        need(before['greg']==b['greg']and before['fp']==b['fp'],'ordinary memory JMP starts at the complete actual resident terminal')
        need(self.i(ref,'li2_fetch_ref','sequence')>self.i(self.f(self.f(self.b,T,'held'),'li2_span_fetch_observation','ref'),'li2_fetch_ref','sequence'),'ordinary memory JMP borrows only after resident source release')
        self.scan(self.f(self.b,T,'unexpected_scan'),self.r.types['li2_step_frame']['bytes'])

    def finish(self,status):
        h=self.h;r=self.r
        need(type(status)is int and status==0,'actual successful complete finite D3 process')
        need(h[:9]==(0x3152334f5732494c,2,2063040,1246656,362544,364544,69632,968,128),'exact distinct full D3 wire extents')
        need(h[9:12]==(self.symbol('r3_owner'),self.symbol('r3o_wire'),self.symbol('selected_chain'))and self.symbols['r3o_wire'][1]==2063040,'actual owner/observer/chain ELF identity')
        retained=r.layout['retained_storage'];need(set(retained)=={'retained','selected_slot','selection','previous_selection','domain'}and retained['retained']['bytes']==2*r.types['li2_ptr_slot']['bytes']and retained['selected_slot']['bytes']==4 and retained['selection']['bytes']==retained['previous_selection']['bytes']==24 and retained['selected_slot']['offset']==retained['retained']['offset']+retained['retained']['bytes'],'actual unchanged old two-slot storage extent remains distinct')
        need(h[12]%PAGE==0 and canonical(h[12],524288)and h[13:16]==(524288,1,0)and h[16]&(3|0x400|0x800)==1 and h[17:19]==(0,1),'actual altstack and owned regular sink flags')
        need(h[19:22]==(self.head,0x41420e,self.app['capture_pc'])and h[22]==self.app['rsp']and h[23]==self.app['capture_pointer']and h[24:28]==(1,1,1,1)and h[28]>0 and h[29]==h[28]+1 and h[30]==h[29]+1 and h[31]in(0,1)and h[32]>0,'actual one-entry/one-terminal/next-TRACE chronology')
        need(h[33:38]==(0,0,0,0,1)and h[38:41]==(h[16],0,1),'whole successful finish without incomplete or relabelled failure')
        ingress=q(self.f(self.b,T,'ingress'));need(sum(ingress[1:])==ingress[0]>=h[30]and ingress[1]>=1 and ingress[2]>=2 and not any(ingress[3:]),'actual complete signal partition and finite focal chronology')
        need(q(self.f(self.b,T,'bootstrap'))==(self.pid,)*5+(0,0,24,1),'actual trusted clear-TID reset and robust-list startup observations')
        session=self.f(self.b,T,'session');self.eq(session,'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        need(self.i(session,'li2_step_session','sync_query')&96==96,'real private expedited sync availability')
        for key in('sink_initial','sink_terminal'):
            st=self.f(self.b,T,key);value=self.stat(st);need(value['mode']&0xffff==0x8180 and value['size']==0,'actual empty regular0600 record sink');self.eq(st,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(self.f(self.b,T,'sink_initial'),self.f(self.b,T,'sink_terminal'),'stat',observed=('st_atim','st_mtim','st_ctim'))
        hardware=self.f(self.b,T,'hardware');self.eq(hardware,'li2_selected_hardware',abi_version=1,reserved=0)
        for i,k in enumerate(('leaf0','leaf1','leaf7')):need(struct.unpack('<4I',self.f(hardware,'li2_selected_hardware',k))==tuple(self.app['hardware'][i][2:]),'actual same-CPU application/bridge CPUID')
        self.source_union();self.registry();self.source_bind()
        models=[self.certificate(i)for i in range(3)]
        identities=[self.f(c,CERT,'identity')for c in self.certificates]
        need(len({self.i(x,'li2_sealed_identity','fd')for x in identities})==3 and len({self.v(x,'li2_sealed_identity','device inode')for x in identities})==3,'three distinct actual sealed backings')
        directory=self.i(self.entered,STATE,'directory');need(directory==self.layouts[0][5]and self.f(self.b,T,'directory')==plan.directory(self.layouts),'all seven ordered original-to-generated rows and whole zero directory tail')
        for row in r.items(self.b,T,'directory_query','li2_private_code_query'):self.query(row,directory,1,3)
        self.scan(self.f(self.b,T,'directory_scan'),12288)
        for key in('entered','terminal','closed','final'):self.state(self.f(self.b,T,key),key)
        self.consumed_transfer();self.frames()
        stacks=[self.memory(b,i)for i,b in enumerate(r.items(self.b,T,'memory','li2_r3o_memory'))]
        anchor,first,end,_,_,_=self.stack_identity
        costs={k:{name:self.i(self.f(self.f(self.b,T,k),STATE,'resident_progress'),'li2_rsl_resident_progress',name)for name in('bindings','snapshots','plans','validations','authentications','fresh_maps_passes','source_bytes','plan_source_bytes','guard_pages','observation_seals')}for k in('entered','terminal','closed','final')}
        return dict(rsp=h[22],kernel_altstack=h[12],kernel_altstack_bytes=h[13],original_stack_anchor=anchor,original_stack_first=first,original_stack_end=end,before=self.before,terminal=self.after,next=self.next,before_stack=stacks[0],terminal_stack=stacks[1],next_stack=stacks[2],source=self.app['source'],source_page_address=self.page,entry_pc=self.head,terminal_pc=0x41420e,next_pc=self.app['capture_pc'],cold_publications=3,entries=1,completed=1,resident_certificates=3,old_active_domain_limit=2,closed_pages=51,anchor_released=1,interior_signals=0,terminal_ingresses=1,native_instructions=30,generated_guest_instructions=28,source_pages=self.source_count,source_epoch=self.i(self.f(self.entered,STATE,'source'),'li2_rsl_ref','epoch'),source_cost=costs,source_before=dict(zip(('epoch','bindings','invalidations','valid'),self.v(self.source_before,'li2_rsl_progress','epoch bindings invalidations valid'))),layout_rows=self.layouts,models=[dict(heads=x['heads'],exits=x['exits'])for x in models],signal_counts=ingress,status=0,code=0,detail=0,qualification_credit=False,performance_credit=False)


def read(data,layout,image,app,pid,cpu,exit_status):
    need(type(data)is bytes and type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'whole record and actual process/CPU identity')
    need(len(data)==2063040+64 and len(data)<4<<20,'complete distinct D3 raw record and footer')
    footer=q(data[-64:]);need(footer[:4]==(0x3152334f4632494c,2,2063040,2063040)and 1<=footer[4]<=64 and 0<footer[5]<=2063040 and footer[6:]==(0,0),'whole successful bounded record transport')
    r=wire.Reader(memoryview(data)[:-64],layout);out=Check(r,image,app,pid,cpu).finish(exit_status)
    out['transport']=dict(raw_bytes=2063040,body_bytes=footer[3],body_calls=footer[4],last_body_result=footer[5],status=footer[6],code=footer[7]);return out


def controls(data,layout,image,app,pid,cpu,exit_status):
    """Causal supplied corruptions of this new finite observation only."""
    read(data,layout,image,app,pid,cpu,exit_status);types=layout['types'];tests=[]
    def at(path):
        t=T;offset=0
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
    for state in('entered','terminal','closed','final'):
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
    changed=bytearray(data);valid=struct.unpack_from('<I',data,356)[0]
    struct.pack_into('<Q',changed,376,0 if valid else 1)
    try:read(bytes(changed),layout,image,app,pid,cpu,exit_status)
    except ValueError:refused.append('prebind_old_serial')
    else:raise ValueError('accepted actual prebind old-owner serial corruption')
    for name,changed in(('truncated',data[:-1]),('extra',data+b'\0'),('failed_footer',data[:-16]+struct.pack('<QQ',125,4900))):
        try:read(changed,layout,image,app,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted complete-record/failed-outcome corruption '+name)
    need(len(refused)==231,'all231 finite D3 owner supplied controls refused')
    return dict(refusals=refused,count=len(refused),source_sha256=hashlib.sha256(data).hexdigest(),native_operations=0)


def pair(native,gated,owner):
    """Whole state/968-byte UC; only authenticated lane coordinates and closed TF move."""
    need(native['role']=='native'and gated['role']=='gated'and native['complete']==gated['complete']==1 and len(native['frames'])==5 and gated['frames']==[],'complete actual native and gated applications')
    for key in('source','head','source_page_address','predecessor','terminal_pc','capture_pc','capture_pointer','hardware','xcr0','machine','stack','cpu'):
        need(native[key]==gated[key],'whole identical pair input '+key)
    for lane in(native,gated):need(lane['rsp']==lane['stack_base']+2056 and lane['stack_base']%64==0,'each authenticated original local-stack coordinate')
    delta=gated['rsp']-native['rsp']
    def translated(value):
        regs,flags,selectors=value;regs=list(regs);regs[4]+=delta;return tuple(regs),flags,selectors
    need(translated(native['seed_live'])==gated['seed_live']and translated(native['before'])==gated['before']and translated(native['after'])==gated['after']and native['live']==gated['live'],'all application GPR/selector/live vector bytes with RSP-only lane translation')
    need(owner['rsp']==gated['rsp']and owner['original_stack_first']<=owner['rsp']-256<owner['rsp']+264<=owner['original_stack_end']and owner['original_stack_first']<=owner['original_stack_anchor']<owner['original_stack_end'],'actual owner stack-origin lifetime and full envelope')
    for name,index in(('before',1),('terminal',3),('next',4)):
        value=owner[name];ref=native['frames'][index];want=list(ref['greg']);want[15]+=delta
        if name=='before':want[17]&=~TF
        need(type(value['greg'])is tuple and value['greg']==tuple(want)and type(value['fp'])is bytes and len(value['fp'])==65536 and value['fp']==ref['fp']and value['fp_bytes']==ref['header'][9],'all23 GREG/all65536 FP with only authenticated RSP and real closed-TF edit')
        need(value['mask']==MASK and (value['fs'],value['gs'])==tuple(gated['machine'][1:3]),'whole actual paired mask and TLS')
        need(value['si']==ref['si'],'all128 native/owner signal-info bytes for the same original event')
        need(q(value['uc'][40:224])==value['greg']and value['uc'][304:432]==value['si']and int.from_bytes(value['uc'][296:304],'little')==MASK,'complete per-event UC/GREG/mask/siginfo joins remain literal')
        native_uc=ref['uc'];actual_uc=value['uc'];nh=ref['header']
        need(type(native_uc)is bytes and len(native_uc)==1024 and nh[7]==968 and native_uc[968:]==bytes(56)and type(actual_uc)is bytes and len(actual_uc)==968,'whole native and owner ucontext extents, including reserved capacity')
        native_alt,native_cap,native_fp=nh[10],nh[11],nh[8]
        owner_alt,owner_cap,owner_fp=owner['kernel_altstack'],owner['kernel_altstack_bytes'],value['fp_address']
        for alt,cap,fp,extent,context in((native_alt,native_cap,native_fp,nh[9],native_uc),(owner_alt,owner_cap,owner_fp,value['fp_bytes'],actual_uc)):
            need(type(alt)is int and type(cap)is int and type(fp)is int and cap==524288 and alt%PAGE==0 and canonical(alt,cap)and fp%16==0 and alt<=fp and 580<=extent<=65536 and fp+extent<=alt+cap,'each actual paired FP address is independently bounded by its retained altstack')
            need(q(context[16:24])==(alt,)and q(context[32:40])==(cap,)and q(context[224:232])==(fp,),'each raw UC pointer is joined to its own retained frame and altstack fields')
        expected_uc=bytearray(native_uc[:968])
        for offset,word in((16,owner_alt),(224,owner_fp),(160,want[15]),(176,want[17])):struct.pack_into('<Q',expected_uc,offset,word)
        need(actual_uc==bytes(expected_uc),'all968 normalized UC bytes; only authenticated altstack/FP/RSP coordinates and actual before-TF closure translate')
        need(owner[name+'_stack']==gated['stack']==native['stack'],'all520 native/owner stack bytes at '+name)
    need((owner['entry_pc'],owner['terminal_pc'],owner['next_pc'])==(gated['head'],gated['terminal_pc'],gated['capture_pc'])and owner['source']==native['source'],'actual original entry/frontier/next and whole six source pages')
    need(owner['cold_publications']==owner['resident_certificates']==3 and owner['entries']==owner['completed']==owner['anchor_released']==1 and owner['closed_pages']==51 and owner['interior_signals']==0 and owner['terminal_ingresses']==1 and owner['old_active_domain_limit']==2,'three independent publications and one real all-three closed lifetime without enlarging the old owner')
    need(owner['models']==[dict(heads=2,exits=1),dict(heads=2,exits=1),dict(heads=3,exits=2)]and owner['native_instructions']==30 and owner['generated_guest_instructions']==28,'exact independent graph and four-cycle native/generated populations')
    return dict(observed_resident_three=1,cycles=4,native_trace_events=30,native_full_frames=5,protected_full_frames=3,fp_storage_per_frame=65536,ucontext_bytes_per_frame=968,stack_bytes=520,cold_publications=3,entries=1,completed=1,resident_certificates=3,old_active_domain_limit=2,closed_pages=51,interior_signals=0,terminal_ingresses=1,source_cost=owner['source_cost'],qualification_credit=False,performance_credit=False)


def pair_controls(native,gated,owner):
    import copy
    pair(native,gated,owner);tests=[]
    for which in('before','terminal','next'):
        for field in('greg','fp','mask','fs','gs','si','uc'):tests.append((which,field))
    refused=[]
    for which,field in tests:
        changed=copy.deepcopy(owner);value=changed[which][field]
        if type(value)is tuple:v=list(value);v[0]^=1;changed[which][field]=tuple(v)
        elif type(value)is bytes:
            v=bytearray(value);v[304 if field=='uc'else 0]^=1;changed[which][field]=bytes(v)
        else:changed[which][field]=value^1
        try:pair(native,gated,changed)
        except ValueError:refused.append(which+'_'+field)
        else:raise ValueError('accepted actual full-frame pair corruption '+which+'_'+field)
    for field in('rsp','cold_publications','entries','completed','resident_certificates','closed_pages','interior_signals','terminal_ingresses','anchor_released','old_active_domain_limit','native_instructions','generated_guest_instructions','terminal_pc','next_pc','source'):
        changed=copy.deepcopy(owner);value=changed[field]
        if type(value)is bytes:v=bytearray(value);v[0]^=1;changed[field]=bytes(v)
        else:changed[field]=value^1
        try:pair(native,gated,changed)
        except ValueError:refused.append(field)
        else:raise ValueError('accepted actual resident pair corruption '+field)
    for field in('before_stack','terminal_stack','next_stack'):
        changed=copy.deepcopy(owner);v=bytearray(changed[field]);v[-1]^=1;changed[field]=bytes(v)
        try:pair(native,gated,changed)
        except ValueError:refused.append(field)
        else:raise ValueError('accepted literal520 stack pair corruption '+field)
    need(len(refused)==39,'all39 finite D3 pair controls refused')
    for offset in(0,8,240,432,967):
        changed=copy.deepcopy(owner)
        for which in('before','terminal','next'):
            v=bytearray(changed[which]['uc']);v[offset]^=1;changed[which]['uc']=bytes(v)
        try:pair(native,gated,changed)
        except ValueError:refused.append('coordinated_full_UC_'+str(offset))
        else:raise ValueError('accepted coordinated unaliased full-UC corruption '+str(offset))
    need(len(refused)==44,'all39 original plus five coordinated whole-UC controls refused')
    return dict(refusals=refused,count=44,native_operations=0)
