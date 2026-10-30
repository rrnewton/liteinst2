"""Actual current-TF appendix. The old wire/reader and all native comparisons remain mandatory."""
import hashlib
import importlib.util
from pathlib import Path
import struct

_spec=importlib.util.spec_from_file_location('current_custody_wire',Path(__file__).with_name('wire.py'))
wire=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(wire)
old,need,zero,q=wire.old,wire.need,wire.zero,wire.q
PAGE,FP,TF,RF,MASK,U64=old.PAGE,old.FP,old.TF,old.RF,old.MASK,old.U64
canonical=old.canonical
COUNTERS='attempts current_stages current_seeds physical_fallbacks retained_stages retained_checks commits cancels'.split()
PHYSICAL='epoch seeds retained_stages retained_checks commits discards phase last_reason'.split()


def integers(b,width=4):
    need(len(b)%width==0,'whole typed scalar array')
    return tuple(int.from_bytes(b[i:i+width],'little')for i in range(0,len(b),width))


def elf_image(data):
    need(type(data)is bytes and 64<=len(data)<=64<<20,'retained actual bridge ELF bytes')
    def take(a,n):
        need(type(a)is int and type(n)is int and 0<=a<=len(data) and 0<=n<=len(data)-a,'complete ELF interval')
        return data[a:a+n]
    h=struct.unpack('<16sHHIQQQIHHHHHH',take(0,64))
    need(h[0][:7]==b'\x7fELF\2\1\1' and h[1:4]==(3,62,1) and h[8:10]==(64,56) and 0<h[10]<=32 and h[11]==64 and 0<h[12]<=4096,'exact x86-64 bridge geometry')
    ph=[struct.unpack('<IIQQQQQQ',take(h[5]+56*i,56))for i in range(h[10])]
    sections=[struct.unpack('<IIQQQQIIQQ',take(h[6]+64*i,64))for i in range(h[12])]
    tables=[s for s in sections if s[1]==2]
    need(len(tables)==1 and tables[0][9]==24 and tables[0][5]%24==0 and tables[0][6]<len(sections),'complete actual ELF symbols')
    t=tables[0];st=sections[t[6]];need(st[1]==3,'actual string table');names=take(st[4],st[5]);symbols={}
    for at in range(t[4],t[4]+t[5],24):
        n,info,other,section,address,size=struct.unpack('<IBBHQQ',take(at,24))
        need(n<len(names) and b'\0'in names[n:],'complete symbol name')
        name=names[n:names.index(b'\0',n)].decode()
        if name in wire.NAMES or name in wire.REGISTERED or name=='mv_custody_io':
            need(name not in symbols and info==1 and other==0 and 0<section<len(sections) and
                 0<size<16<<20 and (name not in wire.NAMES or size<=1<<20),'unique local storage definition')
            s=sections[section];need(s[1]in(1,8) and s[2]==3 and s[3]<=address and address+size<=s[3]+s[5]<=U64,'complete nonexecuting storage section')
            if name=='mv_custody_io':need(size==4 and address%4==0,'exact local four-byte aligned physical observer flag')
            symbols[name]=(address,size)
    need(set(symbols)==set(wire.NAMES)|set(wire.REGISTERED)|{'mv_custody_io'},'all nine storage, ten registered objects and separate physical observer flag')
    return h,ph,symbols


class Check(old.Check):
    def __init__(self,reader,legacy,image,app,pid,cpu,control,current_control,fallback,old_result):
        self.legacy=legacy
        super().__init__(legacy,image,app,pid,cpu,control)
        self.legacy,self.r=legacy,reader;self.cto=reader.data[:-64];self.ch=q(self.f(self.cto,'cto_wire','h'))
        self.current_control,self.fallback,self.old_result=current_control,fallback,old_result
        self.head,self.exit=self.ch[4:6];self.source=self.f(self.cto,'cto_wire','original_source')
        self.rows=self.r.items(self.cto,'cto_wire','rows','cto_row');self.samples=[];self.point_rows=[]
        self.cc_origin=None;self.physical_origin=None;self.prefix_slot=None;self.prefix_generation=None

    def typed(self,t):return self.r if t in self.r.types else self.legacy
    def f(self,b,t,k):return self.typed(t).field(b,t,k)
    def i(self,b,t,k):return self.typed(t).integer(b,t,k)
    def v(self,b,t,k):return self.typed(t).values(b,t,k)
    def eq(self,b,t,**values):self.typed(t).equal(b,t,**values)

    def registry(self,b):
        t='cto_registry';self.eq(b,t,complete=1,table=self.symbol('protected'))
        count=self.i(b,t,'count');need(0<count<=128,'actual bounded protected range table')
        ranges=self.r.items(b,t,'ranges','li2_fork_range');kinds=self.f(b,t,'initial_code');zero(kinds,'this distinct build has no initial-code exception')
        for value in ranges[count:]:zero(value,'whole unused protected row')
        for value in ranges[:count]:
            a,z=self.v(value,'li2_fork_range','first end');need(canonical(a,z-a),'whole actual protected byte interval')
        image=self.f(b,t,'bridge');eh,ph,symbols=elf_image(self.image['current_bridge'])
        self.eq(image,'image',bias=self.bias,entry=self.bias+eh[4],n=len(ph),source=0,source_size=0,backing_fd=(1<<32)-1,kind=3)
        zero(self.f(image,'image','source_hash'),'runtime bridge has no invented original-file hash')
        need(canonical(self.i(image,'image','ph'),len(ph)*56),'actual runtime program header pointer')
        need(self.f(b,t,'ph')==b''.join(struct.pack('<IIQQQQQQ',*p)for p in ph)+bytes((32-len(ph))*56),'every actual program header and complete unused tail')
        # protect()/selected_run_protect_add() record exact byte intervals for
        # these ten source-selected objects; only image/arena rows are rounded.
        declarations=self.r.layout['registrations']
        need(type(declarations)is dict and set(declarations)==set(wire.REGISTERED),'all and only actual registered object witnesses')
        object_ranges=[]
        actual_ranges=[self.v(x,'li2_fork_range','first end')for x in ranges[:count]]
        for name,(source,tag)in wire.REGISTERED.items():
            d=declarations[name];at,size=symbols[name]
            need(type(d)is dict and set(d)=={'address','bytes','alignment','tag','source'} and
                 all(type(d[k])is int for k in ('address','bytes','alignment')) and
                 (d['tag']is None if tag is None else type(d['tag'])is str and d['tag']==tag) and
                 type(d['source'])is str and d['source'].endswith('/tools/page-entry/selected/'+source),
                 'actual source-selected registration declaration '+name)
            alignment=d['alignment'];first,end=self.bias+at,self.bias+at+size
            need(d['address']==at and d['bytes']==size and 0<alignment<=PAGE and
                 not alignment&(alignment-1) and at%alignment==0 and first%alignment==0 and canonical(first,size),
                 'actual registered ELF and DWARF byte extent '+name)
            owners=[p for p in ph if p[0]==1 and p[6] and self.bias+p[3]<end and first<self.bias+p[3]+p[6]]
            need(len(owners)==1 and owners[0][1]==6 and owners[0][5]<=owners[0][6] and
                 canonical(self.bias+owners[0][3],owners[0][6]) and
                 self.bias+owners[0][3]<=first<end<=self.bias+owners[0][3]+owners[0][6],
                 'whole registered object inside one actual RW/NX load')
            need(actual_ranges.count((first,end))==1,'whole registered object equals actual symbol/DWARF extent')
            object_ranges.append((first,end))
        need(len(set(object_ranges))==len(wire.REGISTERED),'distinct actual registered objects')
        need(all(a%PAGE==z%PAGE==0 or (a,z)in object_ranges for a,z in actual_ranges),
             'every non-page protected row is one exact source-selected object')
        storage=self.r.items(b,t,'storage','li2_cto_storage');loads=integers(self.f(b,t,'load_indices'));indices=integers(self.f(b,t,'range_indices'))
        need(integers(self.f(b,t,'intersects'))==(1,)*9,'all actual private-intersects observations')
        metadata=self.r.layout['storage'];need(set(metadata)=={'version','symbols'} and type(metadata['version'])is int and metadata['version']==1 and set(metadata['symbols'])==set(wire.NAMES),'exact compiled storage metadata')
        seen=[]
        for i,(name,row)in enumerate(zip(wire.NAMES,storage,strict=True)):
            d=metadata['symbols'][name];at,size=symbols[name];a,n,alignment=self.v(row,'li2_cto_storage','address bytes alignment')
            need(d['address']==at and d['bytes']==size and a==self.bias+at and n==size and alignment==d['alignment'] and 0<alignment<=PAGE and not alignment&(alignment-1) and a%alignment==0,'whole actual storage equals ELF/DWARF/runtime bias '+name)
            need(canonical(a,n) and all(a+n<=x or x+y<=a for x,y in seen),'all nine actual objects distinct');seen.append((a,n))
            owners=[j for j,p in enumerate(ph)if p[0]==1 and p[6] and self.bias+p[3]<a+n and a<self.bias+p[3]+p[6]]
            need(owners==[loads[i]],'unique actual full PT_LOAD owner');p=ph[loads[i]];first,end=self.bias+p[3],self.bias+p[3]+p[6]
            need(p[1]==6 and p[5]<=p[6] and canonical(first,p[6]) and first<=a<a+n<=end<=U64-PAGE+1,'whole RW/NX p_memsz containment')
            rounded=(first&-PAGE,(end+PAGE-1)&-PAGE)
            exact=[j for j,x in enumerate(ranges[:count])if self.v(x,'li2_fork_range','first end')==rounded]
            need(exact==[indices[i]],'one exact whole rounded strict bridge row, not mere overlap')
        # Additional private flag, not a tenth captured storage object or an
        # eleventh exact-byte registration. Its actual ELF extent is protected
        # by the same observed whole bridge load and strict rounded table row.
        at,size=symbols['mv_custody_io'];a=self.bias+at
        need(size==4 and a%4==0 and canonical(a,size),'whole actual physical observer flag')
        owners=[j for j,p in enumerate(ph)if p[0]==1 and p[6] and self.bias+p[3]<a+size and a<self.bias+p[3]+p[6]]
        need(len(owners)==1 and owners[0]in loads,'physical observer uses an actually observed current-state bridge load')
        p=ph[owners[0]];first,end=self.bias+p[3],self.bias+p[3]+p[6]
        need(p[1]==6 and p[5]<=p[6] and canonical(first,p[6]) and first<=a<a+size<=end<=U64-PAGE+1,
             'complete physical observer in one actual RW/NX load')
        need(actual_ranges.count((first&-PAGE,(end+PAGE-1)&-PAGE))==1,
             'physical observer has exact whole rounded strict bridge protection')
        return count,ranges,image

    def view(self,b,retired):
        t='li2_cto_view_state';a,lo,end=self.v(b,t,'stack_anchor stack_first stack_end')
        need(canonical(a) and lo%PAGE==end%PAGE==0 and canonical(lo,end-lo) and lo<=a<end,'actual original-stack provenance')
        self.eq(b,t,stack_retired=int(retired));need(self.i(b,t,'stack_pending')in(0,1),'actual frontier probe pending bit')
        if retired:
            page=self.app['current']['header'][10]
            need(type(page)is int and page%PAGE==0 and lo<=page<page+PAGE<=end,'actual fallback protection page lies wholly in the original stack interval')
        v=self.f(b,t,'view');vt='li2_maps_view_stats';self.eq(v,vt,enabled=1,differential=0,poisoned=0,reserved=0,mismatches=0,comparisons=0)
        need(self.i(v,vt,'queries')==self.i(v,vt,'hits')+self.i(v,vt,'refreshes'),'whole current-view query partition')
        return v

    def current_maps(self,b,physical=False):
        t='li2_fetch_map_progress';self.eq(b,t,opened=1,close_started=1,closed=1,last_read=0,close_result=0)
        fd,n,rows=self.v(b,t,'fd bytes rows');need(fd<1<<31 and 0<n<=256<<10 and 0<rows<=2048,'complete bounded physical baseline receipt')
        o=self.f(b,t,'observation');a,h,e,k,io=self.v(o,'li2_maps_observation','acquisition_id handler_id mutation_epoch kind io_performed')
        need(a>0 and e>0 and (h==0 if k==0 else h>0) and k in((0,1)if physical else(1,4)) and io==int(k in(0,1)),'honest physical/current query provenance')
        return a,h,e,k

    def session(self,b):
        self.eq(b,'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        n=self.i(b,'li2_step_session','sync_query');need(n<1<<63 and n&96==96,'actual registered sync-core session')

    def decoded(self,b,offset):
        t='li2_decoded';branch=offset==6;n=6 if branch else 2
        self.eq(b,t,pc=self.head+offset,next_pc=self.head+offset+n,abi_version=1,decode_status=0,code=765 if branch else 299,kind=0,destination=16,width_bits=0,step_disposition=0 if branch else 1,available=15,length=n,reserved=0)
        need(self.f(b,t,'bytes')==self.source[offset:offset+15]+b'\0','whole actual15-byte decoder input')

    def page(self,b):
        t='li2_fetch_page';self.eq(b,t,address=self.head,object=self.image['main_object'],backing=1,logical=5,closed_prot=1,offset=self.i(self.cto,'cto_wire','source_offset'))
        need(all(self.i(b,t,k)>0 for k in ('allocation','generation','initial_extent')),'actual live source generations')
        first,end,major,minor,inode,offset=self.v(b,t,'vma_first vma_end vma_major vma_minor vma_inode vma_offset')
        need(first%PAGE==end%PAGE==offset%PAGE==0 and first<=self.head and self.head+PAGE<=end and offset+self.head-first==self.i(b,t,'offset'),'whole source VMA identity')
        st=self.stat(self.f(self.b,'uho_wire','main_backing'));dev=st['dev'];need((major,minor,inode)==(((dev>>8)&0xfff)|((dev>>32)&0xfffff000),(dev&255)|((dev>>12)&0xffffff00),st['ino']),'source page and retained original backing identity')

    def backing(self,b):
        t='li2_fetch_backing';self.eq(b,t,seals_observed=1,stat_observed=1,stat_result=0,seals=15)
        need(200<=self.i(b,t,'retained_fd')<1<<31 and self.stat(self.f(b,t,'stat'))==self.stat(self.f(self.b,'uho_wire','main_backing')),'actual four-sealed original descriptor/stat identity')

    def step_frame(self,b,frame,flags=None):
        t='li2_step_frame';want=list(frame['greg'])
        if flags is not None:want[17]=flags
        need(q(self.f(b,t,'greg'))==tuple(want) and self.f(b,t,'fp')==frame['fp'],'whole actual owner GREG/AF/fullFP frame')
        self.eq(b,t,mask=MASK,fp_address=int.from_bytes(frame['uc'][224:232],'little'),fp_bytes=frame['fp_bytes'],initialized=frame['fp_bytes'])

    def count(self,b):
        self.eq(b,'li2_current_custody_stats',first_error=0,first_detail=0)
        return self.v(b,'li2_current_custody_stats',' '.join(COUNTERS))

    def point(self,b,index,point,result,route,phase):
        t='cto_snapshot';self.eq(b,t,present=1,point=point,result=result,current_route=route,chain=self.symbol('selected_chain'),first_error=0,first_detail=0)
        active=self.i(b,t,'active');need(active in(0,1) and self.i(b,t,'pending')==1,'actual active pending TF owner')
        slot=self.f(b,t,'slot');slot_address=self.symbol('selected_chain')+self.r.types['li2_tf_chain']['fields']['slots']['offset']+active*self.r.types['li2_tf_chain_slot']['bytes']
        self.eq(slot,'li2_tf_chain_slot',chain=self.symbol('selected_chain'),index=active)
        ref=self.f(b,t,'ref');fetch=self.f(slot,'li2_tf_chain_slot','fetch')
        need(ref==self.f(fetch,'li2_chain_fetch','ref') and canonical(self.i(ref,'li2_fetch_ref','owner')) and self.i(ref,'li2_fetch_ref','sequence')>0,'whole actual occupied fetch reference')
        self.eq(b,t,argument=slot_address+self.r.types['li2_tf_chain_slot']['fields']['fetch']['offset'])
        self.session(self.f(b,t,'session'))
        owner=self.f(slot,'li2_tf_chain_slot','owner');step=self.f(owner,'li2_tf_owner','step')
        self.eq(step,'li2_step_owner',session=self.symbol('selected_session'))
        self.eq(self.f(step,'li2_step_owner','hooks'),'li2_step_hooks',context=slot_address)
        for key in ('authenticate','failure'):need(canonical(self.i(self.f(step,'li2_step_owner','hooks'),'li2_step_hooks',key)),'actual fixed owner callback')
        custody=self.f(b,t,'custody');self.eq(custody,'li2_page_custody_stats',phase=phase)
        need(self.i(custody,'li2_page_custody_stats','epoch')>0,'actual nonwrapped shared epoch')
        self.view(self.f(b,t,'view_state'),self.fallback)
        maps=self.f(b,t,'maps');self.eq(maps,'li2_maps_stats',active=1,poisoned=0,reserved=0)
        need(self.i(maps,'li2_maps_stats','handler_id')>0 and self.i(maps,'li2_maps_stats','mutation_epoch')>0,'actual handler maps lifetime')
        rs=self.f(b,t,'rseq');self.eq(rs,'li2_rseq_state',initialized=1,first_error=0,first_detail=0,pid=self.pid,tid=self.pid)
        registered=self.i(rs,'li2_rseq_state','registered');need(registered in(0,1),'actual registered state')
        self.eq(rs,'li2_rseq_state',held=registered,phase=3 if registered else 0)
        if registered:
            self.eq(rs,'li2_rseq_state',length=32,tls_attempted=1,tls_complete=1,fs_result=0,gs_result=0)
            self.pin(self.f(rs,'li2_rseq_state','data'),self.pid)
        need(self.i(rs,'li2_rseq_state','registered')in(0,1),'actual registration, never inferred from terminal only')
        if point in(6,7):self.eq(b,t,view=0,in_handler=0)
        elif result==1:self.eq(b,t,view=0,in_handler=1)
        else:
            need(canonical(self.i(b,t,'view')),'actual selected private stage pointer')
            self.eq(b,t,in_handler=int(point<4 or point==5))
        return dict(raw=b,slot=slot,step=step,ref=ref,custody=custody,event=self.i(b,t,'event'),active=active,slot_address=slot_address,owner_address=slot_address+self.r.types['li2_tf_chain_slot']['fields']['owner']['offset'])

    def transfer(self,s,index,phase,error=0):
        snap=s['raw'];t='li2_fetch_rx_view';v=self.f(snap,'cto_snapshot','physical'if self.fallback else'current')
        self.eq(v,t,phase=phase,complete=1,result=error,pc=self.head+2*index,length=15,pid=self.pid,tid=self.pid,maps_observed=int(index==1))
        need(self.f(v,t,'bytes')==self.source[2*index:2*index+15],'all15 live staged source bytes')
        self.page(self.f(v,t,'page'));self.backing(self.f(v,t,'backing'))
        serial,before,after=self.v(v,t,'serial before_sequence after_sequence');need(serial>0 and before>0,'actual nonzero stage/borrow identities')
        sequence=self.i(s['ref'],'li2_fetch_ref','sequence')
        need(sequence==(after if phase==4 else before) and (after>before if phase==4 else after==0),'fresh committed borrow only after actual commit')
        receipt=self.f(v,t,'custody');ct='li2_page_custody_receipt';kind=(1 if index==1 else 2)if self.fallback else(3 if index==1 else 4)
        expected_epoch=self.i(receipt,ct,'epoch')
        self.eq(receipt,ct,kind=kind,provenance=1 if self.fallback else 2,chain=self.symbol('selected_chain'),owner=s['owner_address'],session=self.symbol('selected_session'),slot=s['active'],owner_generation=self.i(s['slot'],'li2_tf_chain_slot','generation'),event=s['event'])
        self.eq(receipt,ct,checks=0 if index==1 else 2 if phase==4 else 1)
        need(expected_epoch>0 and self.i(receipt,ct,'origin_sequence')>0,'current original owner/epoch identity')
        shared_epoch=self.i(s['custody'],'li2_page_custody_stats','epoch')
        if phase in(2,4)and not error:need(shared_epoch==expected_epoch,'same authoritative shared epoch')
        else:need(shared_epoch>expected_epoch,'cancelled or failed phase has genuinely invalidated original epoch')
        pointer=self.i(snap,'cto_snapshot','view')
        if not self.fallback:
            d=self.r.layout['storage']['symbols']['rx_current'];want=self.bias+d['address']+d['fields']['stage']['offset']
            need(pointer==want,'actual new typed stage pointer')
            p=self.f(snap,'cto_snapshot','provenance');pt='li2_current_custody_provenance'
            self.eq(p,pt,version=1,kind=kind,consumed=1,complete=1,epoch=expected_epoch,origin_sequence=self.i(receipt,ct,'origin_sequence'),stage_serial=serial)
            origin=self.f(p,pt,'origin');ot='li2_maps_current_view';self.eq(origin,ot,version=1,complete=1,result=0,detail=0)
            need(self.i(origin,ot,'serial')>0 and self.i(origin,ot,'query_serial')>0 and canonical(self.i(origin,ot,'table')),'actual consumed query/table identity')
            ph=self.f(origin,ot,'physical');query=self.f(origin,ot,'query');a=self.current_maps(ph,True);z=self.current_maps(query)
            need(a[0]==z[0] and a[2]<=z[2] and self.i(origin,ot,'rows')==self.i(query,'li2_fetch_map_progress','rows') and ph==self.f(receipt,ct,'origin'),'separate actual physical baseline and current query')
            if self.cc_origin is None:
                need(index==1,'first current origin comes from seed');self.cc_origin=origin
                view=self.f(snap,'cto_snapshot','view_state');need(self.v(origin,ot,'stack_first stack_end')==self.v(view,'li2_cto_view_state','stack_first stack_end'),'consumed query actual stack frontier')
            need(origin==self.cc_origin,'retained current provenance never invents another query')
            if index==1:need(self.f(v,t,'maps')==query,'initial current stage retains exact consumed query receipt')
            else:zero(self.f(v,t,'maps'),'retained stage performs no invented maps query')
        else:
            need(canonical(pointer) and pointer!=self.bias+self.r.layout['storage']['symbols']['rx_current']['address']+self.r.layout['storage']['symbols']['rx_current']['fields']['stage']['offset'],'physical route never consumes current stage pointer')
            if self.physical_origin is None:self.physical_origin=(pointer,self.f(receipt,ct,'origin'))
            need((pointer,self.f(receipt,ct,'origin'))==self.physical_origin,'whole original physical custody provenance retained')
            self.current_maps(self.f(receipt,ct,'origin'),True)
            if index==1:need(self.f(v,t,'maps')==self.f(receipt,ct,'origin'),'physical seed exact fresh query')
            else:zero(self.f(v,t,'maps'),'physical retained stage has no new physical query')
        return v

    def live_owner(self,s,index,publish=False):
        slot,step=s['slot'],s['step'];st='li2_step_owner'
        self.eq(slot,'li2_tf_chain_slot',phase=3)
        self.eq(step,st,phase=3,first_error=0,first_detail=0,self_test=0,trace_seen=0,revoke_sync_started=0,open_sync=0,revoke_sync=0)
        need(integers(self.f(step,st,'open_started'))==integers(self.f(step,st,'opened'))==(1,0),'one actual opened original page')
        for k in ('revoke_started','revoked','open_result','revoke_result'):zero(self.f(step,st,k),'no invented second open/revoke/error '+k)
        request=self.f(step,st,'request');self.eq(request,'li2_step_request',page_count=1)
        off=2*index if publish else 2*max(0,index-1);self.decoded(self.f(request,'li2_step_request','decoded'),off)
        need(self.f(slot,'li2_tf_chain_slot','decoded')==self.f(request,'li2_step_request','decoded'),'active decoded/request whole identity')
        pages=self.r.items(request,'li2_step_request','pages','li2_step_page');p=pages[0]
        self.eq(p,'li2_step_page',address=self.head,closed_prot=1,open_prot=5);zero(pages[1],'unused whole page request')
        f=self.f(slot,'li2_tf_chain_slot','fetch');page=self.r.items(f,'li2_chain_fetch','pages','li2_fetch_page')[0];self.page(page)
        need(self.v(p,'li2_step_page','object generation offset')==self.v(page,'li2_fetch_page','allocation generation offset'),'actual immutable source allocation/generation')
        need(self.i(slot,'li2_tf_chain_slot','generation')>0,'real owner generation')
        identity=(s['active'],self.i(slot,'li2_tf_chain_slot','generation'),self.f(request,'li2_step_request','pages'),self.f(step,st,'hooks'),self.f(s['raw'],'cto_snapshot','session'))
        if self.prefix_slot is None:self.prefix_slot=identity
        need(identity==self.prefix_slot,'same original permission/session/hooks owner through all retained steps')
        self.step_frame(self.f(step,st,'before'),self.samples[index if publish else max(0,index-1)]['before'])
        if index:self.step_frame(self.f(step,st,'after'),self.samples[index]['before'])
        for k in ('release','query'):zero(self.f(slot,'li2_tf_chain_slot',k),'no early release or continuation query')

    def frame_rows(self):
        count=2 if self.current_control else 4
        for index,row in enumerate(self.rows):
            if index>=count:zero(row,'complete unused prefix event capacity');continue
            self.eq(row,'cto_row',present=1,index=index,after_present=int(not(self.current_control and index==1)),pc=self.head+2*index,source_bytes=PAGE if index==0 else 0,data_bytes=8192,stack_bytes=160)
            before=self.frame(self.f(row,'cto_row','before'),False);g=before['greg'];sig=11 if index==0 else 5
            need(before['sig']==sig and struct.unpack_from('<iii',before['si'])==(sig,0,2) and int.from_bytes(before['si'][16:24],'little')==self.head+2*index,'genuine exact NX/TRACE ingress')
            need(g[16]==self.head+2*index and g[17]==self.app['seed'][1]|(RF if index==0 else TF) and g[18]==0x2b000000000033 and g[19:21]==((21,14)if index==0 else(0,1)) and g[21]==MASK and before['mask']==MASK,'complete prefix signal-origin envelope')
            need(tuple(g[k]for k in(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7))==self.app['seed'][0],'all16 actual seeded GPRs')
            if index==0:need(g[22]==self.head,'NX actual fault address')
            else:need(g[22]==self.samples[0]['before']['greg'][22] and before['fp']==self.samples[0]['before']['fp'],'no-effect NOPs retain exact CR2/all65536FP')
            need(self.f(row,'cto_row','data')==self.app['data'] and self.f(row,'cto_row','stack')==self.app['stack'],'all actual per-ingress data8192/stack160')
            after=None
            if self.i(row,'cto_row','after_present'):
                raw=self.f(row,'cto_row','after');after=self.frame(raw,False);desired=bytearray(before['raw'])
                # The first begin ORs TF and retains the kernel's RF. Every other
                # raw SI/UC/GREG/fullFP byte at this same event remains exact.
                flags=g[17]|TF if index==0 else g[17]
                f=self.r.types['uh_frame']['fields'];st=self.r.types['li2_step_frame']['fields']
                struct.pack_into('<Q',desired,f['uc']['offset']+40+17*8,flags)
                struct.pack_into('<Q',desired,f['frame']['offset']+st['greg']['offset']+17*8,flags)
                need(raw==bytes(desired),'whole same-event frame exact except prescribed TF/RF')
            else:zero(self.f(row,'cto_row','after'),'stale failure has no handler return frame')
            self.samples.append(dict(before=before,after=after,stack=self.f(row,'cto_row','stack'),data=self.f(row,'cto_row','data')))
        origin=self.frame(self.f(self.cto,'cto_wire','tls_origin'));first=self.samples[0]['before'];desired=bytearray(origin['raw']);fields=self.r.types['uh_frame']['fields']
        for k in ('fs','gs','fs_result','gs_result','tls_complete'):
            f=fields[k];desired[f['offset']:f['offset']+f['bytes']]=bytes(f['bytes'])
        need(bytes(desired)==first['raw'] and (origin['fs'],origin['gs'])==tuple(self.app['machine'][1:3]),'actual pre-custody TLS getters and whole initial frame')
        if not self.current_control:
            if self.control==6:
                supplied=self.old_result['supplied_before'];need(supplied is not None and supplied['fs']==supplied['gs']==0,'pre-source supplied control has no invented later TLS getters')
                wanted=list(first['greg']);wanted[16]=wanted[22]=self.h[20]
                need(supplied['greg']==tuple(wanted) and supplied['fp']==first['fp'],'actual pre-source hash frame after the complete no-effect prefix')
            else:
                need(self.old_result['entries'] and all((x['before']['fs'],x['before']['gs'])==(origin['fs'],origin['gs'])for x in self.old_result['entries']),'later actual hash-entry TLS brackets custody without mid-lease RAW')
                hash_before=self.old_result['entries'][0]['before'];wanted=list(first['greg']);wanted[16]=wanted[22]=self.h[20]
                need(hash_before['greg']==tuple(wanted) and hash_before['fp']==first['fp'],'all23 actual hash-ingress registers and fullFP preserve the no-effect prefix')
        self.memory(self.f(self.cto,'cto_wire','initial_memory'))
        self.tls_origin=origin

    def chronology(self):
        count=len(self.samples);baseline=None;event0=None;previous_sequence=None;physical_baseline=None;opposite=None;fetch_owner=None
        for index,row in enumerate(self.rows[:count]):
            values=self.r.items(row,'cto_row','points','cto_snapshot');present={6,7}if index==0 else {1,2,3}if self.current_control else {1,2,5,6,7}if index==3 else {1,2,3,4,6,7}
            found={}
            for point,b in enumerate(values,1):
                if point not in present:zero(b,'entire absent API point '+str((index,point)));continue
                unavailable=bool(self.fallback and point==1);failed=bool(self.current_control and index==1 and point==3)
                route=int(not self.fallback) if index and point not in(6,7) else int(not self.fallback and index in(1,2))
                if unavailable:route=1
                phase=0 if index==0 or point==5 or(index==3 and point>=6)or failed else (0 if index==1 else 2)if unavailable else {1:4,2:4,3:5,4:6,6:6,7:1}[point]
                s=self.point(b,index,point,302 if failed else 1 if unavailable else 0,route,phase);found[point]=s
                untouched=self.f(b,'cto_snapshot','provenance'if self.fallback else'physical')
                if opposite is None:opposite=untouched
                need(untouched==opposite,'opposite API retains its actual historical evidence unchanged')
                if self.fallback and index:zero(self.f(b,'cto_snapshot','current'),'unavailable current acquisition publishes no stage')
                actual_owner=self.i(s['ref'],'li2_fetch_ref','owner')
                if fetch_owner is None:fetch_owner=actual_owner
                need(actual_owner==fetch_owner,'all observed stages use the same actual global fetch identity')
                if event0 is None:event0=s['event']
                need(s['event']==event0+index,'four consecutive genuine handler-event identities')
                counts=self.f(b,'cto_snapshot','counts');cc=self.v(counts,'li2_current_custody_stats',' '.join(COUNTERS))
                if baseline is None:baseline=cc;physical_baseline=self.v(s['custody'],'li2_page_custody_stats','seeds retained_stages retained_checks commits')
                if failed:self.eq(counts,'li2_current_custody_stats',first_error=302,first_detail=0)
                else:self.count(counts)
                if index==0:delta=(0,)*8
                elif self.fallback:delta=(1,0,0,1,0,0,0,0)
                elif index==1:delta=(1,1,int(point>=4),0,0,0,int(point>=4),0)
                elif index==2:delta=(1,1,1,0,1,1+int(point>=3),1+int(point>=4),0)
                else:delta=(1,1,1,0,2,3,2,int(point>=5))
                need(cc==tuple(a+d for a,d in zip(baseline,delta,strict=True)),'exact per-boundary current API counter deltas')
                physical=self.v(s['custody'],'li2_page_custody_stats','seeds retained_stages retained_checks commits')
                pd=(0,)*4
                if self.fallback and index:
                    pd=(int(index>1 or point>=4),max(index-1,0),0 if index==1 else 1+int(point>=3) if index==2 else 3,min(index-1,2)+int(index<3 and point>=4))
                    if unavailable and index>1:pd=(1,index-2,0 if index==2 else 2,index-1)
                need(physical==tuple(a+d for a,d in zip(physical_baseline,pd,strict=True)),'physical custody has its separate exact origin/counters')
                if index==0:self.live_owner(s,0)
                elif point in(1,2,3,4)and not unavailable:
                    self.transfer(s,index,2 if point<3 or failed else 4,302 if failed else 0)
                    self.live_owner(s,index,publish=point==4)
                elif point==5:self.transfer(s,index,5);self.live_owner(s,index)
                elif point in(6,7)and index<3:
                    # No view argument is passed to return; its actual progress
                    # must equal the previously published immutable receipt.
                    need(self.f(b,'cto_snapshot','current'if not self.fallback else'physical')==self.f(found[4]['raw'],'cto_snapshot','current'if not self.fallback else'physical'),'handler return retains the exact published stage')
                    self.live_owner(s,index,True)
            self.point_rows.append(found)
            if index:
                prior=self.f(self.point_rows[index-1][7]['raw'],'cto_snapshot','rseq')
                for p0 in (1,2):need(self.f(found[p0]['raw'],'cto_snapshot','rseq')==prior,'no hidden registration/footprint mutation before staged instruction')
                if index:
                    target=found[3 if index<3 else 6]['raw'];state=self.f(target,'cto_snapshot','rseq');rt='li2_rseq_state'
                    if self.i(prior,rt,'registered'):
                        self.r.change(prior,state,rt,dict(instruction_checks=self.i(prior,rt,'instruction_checks')+1,last_pc=self.head+2*index,last_code=765 if index==3 else 299,last_policy=1,last_first=0,last_end=0),observed=('last_footprint',))
                        self.eq(self.f(state,rt,'last_footprint'),'li2_write_footprint',pc=self.head+2*index,next_pc=self.head+(12 if index==3 else 2*index+2),first=0,end=0,abi_version=1,policy=1,code=765 if index==3 else 299,length=6 if index==3 else 2)
                    else:need(state==prior,'unregistered guard performs no invented footprint check')
                    if not self.current_control:
                        for p0 in ((4,6,7)if index<3 else(7,)):need(self.f(found[p0]['raw'],'cto_snapshot','rseq')==state,'whole actual guarded rseq state retained to return')
            if index==0:
                self.r.change(found[6]['raw'],found[7]['raw'],'cto_snapshot',dict(point=7))
                previous_sequence=self.i(found[7]['ref'],'li2_fetch_ref','sequence')
            else:
                need(self.i(found[2]['ref'],'li2_fetch_ref','sequence')==previous_sequence,'same occupied borrow enters each current/physical stage')
                if not self.fallback:
                    self.r.change(found[1]['raw'],found[2]['raw'],'cto_snapshot',dict(point=2),observed=('slot',))
                if not self.current_control and index<3:
                    after=self.i(found[3]['ref'],'li2_fetch_ref','sequence');need(after==previous_sequence+1,'one actual committed fetch sequence, no fabricated extra borrowing');previous_sequence=after
                    need(found[4]['ref']==found[3]['ref']and found[6]['ref']==found[3]['ref']and found[7]['ref']==found[3]['ref'],'publish/return retain exact committed ref')
                    self.r.change(found[6]['raw'],found[7]['raw'],'cto_snapshot',dict(point=7),observed=('custody',))
                    self.r.change(found[6]['custody'],found[7]['custody'],'li2_page_custody_stats',dict(phase=1))
                elif index==3:
                    self.r.change(found[6]['raw'],found[7]['raw'],'cto_snapshot',dict(point=7))
        self.baseline_counts=baseline
        if self.current_control:
            before=self.f(self.cto,'cto_wire','stale_before');after=self.f(self.cto,'cto_wire','stale_after');stage=self.point_rows[1][2]
            need(before==stage['raw'],'actual supplied stale boundary begins at exact successful stage')
            self.r.change(before,after,'cto_snapshot',observed=('custody',))
            a,b=(self.f(x,'cto_snapshot','custody')for x in(before,after));t='li2_page_custody_stats'
            self.r.change(a,b,t,dict(epoch=self.i(a,t,'epoch')+1,discards=self.i(a,t,'discards')+1,phase=0,last_reason=7))
            failed=self.point_rows[1][3];self.eq(failed['custody'],t,epoch=self.i(b,t,'epoch')+1,discards=self.i(b,t,'discards')+1,phase=0,last_reason=2)
            progress=self.f(self.f(failed['slot'],'li2_tf_chain_slot','fetch'),'li2_chain_fetch','progress')
            self.eq(progress,'li2_fetch_progress',held=1,complete=1,first_error=302,first_detail=0,sequence=previous_sequence)
        else:
            for key in ('stale_before','stale_after'):zero(self.f(self.cto,'cto_wire',key),'no invented stale injection')

    def chain(self,b,failed=False):
        t='li2_tf_chain';self.eq(b,t,session=self.symbol('selected_session'),initialized=1,first_error=903 if failed else 0,first_detail=302 if failed else 0)
        need(canonical(self.i(b,t,'failure'))and self.i(b,t,'active')in(0,1),'actual initialized chain identity')
        stats=self.f(b,t,'initial_stats');self.eq(stats,'li2_decoder_stats',abi_version=1,phase=2,first_fatal_reason=0,reserved=0)
        need(self.i(stats,'li2_decoder_stats','retained_high_water')<=self.i(stats,'li2_decoder_stats','arena_bytes'),'complete sealed decoder initial tuple')
        entry=self.f(b,t,'entry');self.eq(entry,'li2_tf_trace_entry',valid=0)
        slots=self.r.items(b,t,'slots','li2_tf_chain_slot')
        for i,slot in enumerate(slots):self.eq(slot,'li2_tf_chain_slot',chain=self.symbol('selected_chain'),index=i)
        return slots

    def close_slot(self,slot,failed=False):
        t='li2_tf_chain_slot';self.eq(slot,t,phase=7 if failed else 5)
        owner=self.f(slot,t,'owner');step=self.f(owner,'li2_tf_owner','step');st='li2_step_owner'
        self.eq(step,st,phase=6 if failed else 5,first_error=903 if failed else 0,first_detail=302 if failed else 0,revoke_sync_started=1,revoke_sync=0,open_sync=0)
        for k in ('open_started','opened','revoke_started','revoked'):need(integers(self.f(step,st,k))==(1,0),'actual original whole-page open/revoke '+k)
        for k in ('open_result','revoke_result'):zero(self.f(step,st,k),'every actual permission syscall succeeded')
        fetch=self.f(slot,t,'fetch');progress=self.f(fetch,'li2_chain_fetch','progress');self.eq(progress,'li2_fetch_progress',held=int(failed),complete=1,first_error=302 if failed else 0,first_detail=0)
        release=self.f(slot,t,'release')
        if failed:zero(release,'terminal failure retains occupied borrow, no invented release')
        else:
            self.eq(release,'li2_chain_release',started=1,complete=1,result=0)
            self.eq(step,st,trace_seen=1);self.eq(owner,'li2_tf_owner',continuation_started=1,continuation_complete=1,continuation_result=0)
            self.eq(self.f(slot,t,'query'),'li2_tf_continuation',attempted=1,page_observed=1,complete=1,result=0)
        return step,progress

    def prefix_closed(self):
        """The copy is taken before any successor can overwrite the old slot."""
        chain=self.f(self.cto,'cto_wire','prefix_chain');slots=self.chain(chain)
        last=self.point_rows[3][7];prior=self.point_rows[3][5]
        self.eq(chain,'li2_tf_chain',active=last['active'],pending=1,in_handler=0,event_id=last['event'])
        need(last['active']==(prior['active']^1) and slots[last['active']]==last['slot'],'actual post-close successor matches complete return snapshot')
        closed=slots[prior['active']];st='li2_tf_chain_slot';step,progress=self.close_slot(closed)
        self.eq(closed,st,generation=self.i(prior['slot'],st,'generation'),event_id=self.i(prior['slot'],st,'event_id'))
        self.decoded(self.f(closed,st,'decoded'),4)
        self.step_frame(self.f(step,'li2_step_owner','before'),self.samples[2]['before'])
        self.step_frame(self.f(step,'li2_step_owner','after'),self.samples[3]['before'])
        old_step=prior['step'];self.r.change(old_step,step,'li2_step_owner',dict(phase=5,in_handler=0,trace_seen=1,revoke_sync_started=1,revoke_started=struct.pack('<II',1,0),revoked=struct.pack('<II',1,0)))
        owner=self.f(closed,st,'owner');before_owner=self.f(prior['slot'],st,'owner')
        self.r.change(before_owner,owner,'li2_tf_owner',dict(step=step,actual_post_pc=self.head+6,actual_post_flags=self.samples[3]['before']['greg'][17],continuation_started=1,continuation_complete=1))
        self.r.change(prior['slot'],closed,st,dict(phase=5,owner=owner),observed=('fetch','release','query'))
        fetch=self.f(closed,st,'fetch');previous=self.f(prior['slot'],st,'fetch')
        self.r.change(previous,fetch,'li2_chain_fetch',observed=('progress','last_backing'))
        self.backing(self.f(fetch,'li2_chain_fetch','last_backing'))
        self.eq(progress,'li2_fetch_progress',sequence=self.i(prior['ref'],'li2_fetch_ref','sequence'),identity_observed=1,pages_copied=1,bytes_copied=15,last_backing_page=0,last_backing_observed=1)
        need(self.i(progress,'li2_fetch_progress','validation_calls')>self.i(self.f(previous,'li2_chain_fetch','progress'),'li2_fetch_progress','validation_calls'),'actual closing authentication and continuation validations')
        query=self.f(closed,st,'query');self.eq(query,'li2_tf_continuation',pc=self.head+6)
        self.current_maps(self.f(query,'li2_tf_continuation','maps'));self.page(self.f(query,'li2_tf_continuation','page'));self.backing(self.f(query,'li2_tf_continuation','backing'))
        successor=last['slot'];new_step=last['step'];self.eq(successor,st,phase=3,origin=2,fallback=0,prepare_attempted=1,prepare_complete=1,decode_attempted=1,decode_complete=1,prepare_result=0,decode_result=0,classify_result=0,retry=0,event_id=last['event'])
        self.decoded(self.f(successor,st,'decoded'),6)
        request=self.f(new_step,'li2_step_owner','request');self.eq(request,'li2_step_request',page_count=1,original_flags=self.app['seed'][1])
        need(self.f(request,'li2_step_request','decoded')==self.f(successor,st,'decoded'),'new branch uses its genuine prepared descriptor')
        self.eq(new_step,'li2_step_owner',phase=3,in_handler=0,first_error=0,first_detail=0,trace_seen=0,revoke_sync_started=0,open_sync=0,revoke_sync=0)
        self.step_frame(self.f(new_step,'li2_step_owner','before'),self.samples[3]['before'],self.app['seed'][1])
        zero(self.f(new_step,'li2_step_owner','after'),'successor has not executed at prefix return')
        for key in ('open_started','opened'):need(integers(self.f(new_step,'li2_step_owner',key))==(1,0),'new branch actually opens original page')
        for key in ('revoke_started','revoked','open_result','revoke_result'):zero(self.f(new_step,'li2_step_owner',key),'no invented successor close/error')
        for key in ('release','first_release','first_fetch','first_decoded','query','unexpected'):zero(self.f(successor,st,key),'no unexecuted successor operation '+key)
        new_fetch=self.f(successor,st,'fetch');self.eq(new_fetch,'li2_chain_fetch',pc=self.head+6,length=15,page_count=1,pid=self.pid,tid=self.pid,identity_observed=1)
        need(self.f(new_fetch,'li2_chain_fetch','bytes')==self.source[6:21] and self.i(last['ref'],'li2_fetch_ref','sequence')>self.i(prior['ref'],'li2_fetch_ref','sequence'),'real released predecessor then fresh successor borrow')
        self.page(self.r.items(new_fetch,'li2_chain_fetch','pages','li2_fetch_page')[0]);self.backing(self.r.items(new_fetch,'li2_chain_fetch','backing','li2_fetch_backing')[0])
        self.eq(self.f(new_fetch,'li2_chain_fetch','progress'),'li2_fetch_progress',held=1,complete=1,first_error=0,first_detail=0,sequence=self.i(last['ref'],'li2_fetch_ref','sequence'))
        lease=self.f(chain,'li2_tf_chain','lease');lt='li2_tf_same_page'
        self.eq(lease,lt,phase=5,origin_active=0,slot=prior['active'],owner_generation=self.i(closed,st,'generation'),completed_event=self.point_rows[2][7]['event'])
        need(self.f(lease,lt,'transfer')==self.f(prior['raw'],'cto_snapshot','physical'if self.fallback else'current'),'actual cancelled stage remains in completed lease')
        self.step_frame(self.f(lease,lt,'opening_frame'),self.samples[0]['before']);self.step_frame(self.f(lease,lt,'previous_before'),self.samples[1]['before'])

    def finish(self,exit_status):
        h=self.ch;stale=bool(self.current_control);expected=self.old_result['terminal_expected']['outcome']
        need(h[:4]==(0x315446435449324c,1,len(self.cto),4) and h[4:8]==(self.image['current_elf']['head'],self.image['current_elf']['high_return'],self.current_control,1),'whole compiled current prefix identity')
        need(h[8:17]==((2,1,1,1,125,903,302,0,0)if stale else(4,4,0,1,exit_status,expected['failure_code'],expected['detail_abs']*(-1 if expected['detail_negative']else 1)&U64,1,self.h[20]))and h[17]==int(not stale) and not any(h[18:]),'actual complete/failed chronology and terminal first error')
        footer=q(self.r.data[-64:]);need(footer[:4]==(0x314654435449324c,1,len(self.cto),len(self.cto)) and 1<=footer[4]<=64 and 0<footer[5]<=len(self.cto) and footer[6:]==(exit_status,h[13]),'complete bounded appended write/footer')
        if footer[4]==1:need(footer[5]==len(self.cto),'one exact whole appendix write')
        a=self.registry(self.f(self.cto,'cto_wire','initial_registry'));b=self.registry(self.f(self.cto,'cto_wire','terminal_registry'))
        need(a[0]<=b[0] and a[1][:a[0]]==b[1][:a[0]] and a[2]==b[2],'actual protected table only appends, old strict ranges remain unchanged')
        main=self.image['objects'][self.image['main_object']]['data'];mh,loads=old.elf(main);need(mh[1]==2,'fixed actual ET_EXEC fixture')
        matches=[p for p in loads if p[1]==5 and p[3]<=self.head and self.head+PAGE<=p[3]+p[5]];need(len(matches)==1,'whole prefix within one actual RX source load');p=matches[0];offset=p[2]+self.head-p[3]
        need(self.i(self.cto,'cto_wire','source_offset')==offset and self.source==main[offset:offset+PAGE]==self.image['current_elf']['source'],'whole actual original ELF page/file-offset join')
        need(self.source==bytes.fromhex('669066906690ff2500000000')+struct.pack('<Q',self.exit)+b'\xcc'*(PAGE-20),'entire exact NOP/FF25 source/fill')
        high=[p for p in loads if p[1]==5 and p[3]<=self.exit and self.exit+16<=p[3]+p[5]];need(len(high)==1,'actual high return load');p=high[0];at=p[2]+self.exit-p[3]
        need(main[at:at+16]==bytes.fromhex('f390ff2500000000')+struct.pack('<Q',self.h[20]),'whole immutable high PAUSE/FF25 return')
        need(self.f(self.cto,'cto_wire','entry_source')==self.source,'actual whole entry source')
        self.frame_rows();self.chronology()
        terminal=self.f(self.cto,'cto_wire','terminal_chain');self.chain(terminal,stale)
        self.view(self.f(self.cto,'cto_wire','terminal_view'),self.fallback)
        if stale:
            for key in ('joined_chain','prefix_chain','joined_counts','joined_custody','joined_view','joined_source'):zero(self.f(self.cto,'cto_wire',key),'no invented successful joined hash '+key)
            active=self.i(terminal,'li2_tf_chain','active');slot=self.r.items(terminal,'li2_tf_chain','slots','li2_tf_chain_slot')[active]
            need(active==self.point_rows[1][3]['active'],'failed same original owner remains selected');step,progress=self.close_slot(slot,True)
            self.step_frame(self.f(step,'li2_step_owner','before'),self.samples[0]['before']);self.step_frame(self.f(step,'li2_step_owner','after'),self.samples[1]['before'])
            need(progress==self.f(self.b,'uho_wire','terminal_fetch'),'whole terminal occupied failed fetch equals actual closed owner prefix')
            self.eq(self.f(self.cto,'cto_wire','terminal_counts'),'li2_current_custody_stats',first_error=302,first_detail=0)
        else:
            self.prefix_closed()
            need(self.f(self.cto,'cto_wire','joined_source')==self.source,'actual unchanged whole page on hash ingress')
            joined=self.f(self.cto,'cto_wire','joined_chain');self.chain(joined)
            self.view(self.f(self.cto,'cto_wire','joined_view'),self.fallback)
            self.eq(joined,'li2_tf_chain',pending=0,in_handler=0)
            lease=self.f(joined,'li2_tf_chain','lease');self.eq(lease,'li2_tf_same_page',origin_active=0,phase=5)
            self.count(self.f(self.cto,'cto_wire','joined_counts'));self.count(self.f(self.cto,'cto_wire','terminal_counts'))
            latest=self.point_rows[3][7]
            need(self.v(self.f(self.cto,'cto_wire','joined_counts'),'li2_current_custody_stats',' '.join(COUNTERS))==self.v(self.f(latest['raw'],'cto_snapshot','counts'),'li2_current_custody_stats',' '.join(COUNTERS)),'no hidden current-custody stages between prefix and hash')
        result=dict(rows=self.samples,tls_origin=self.tls_origin,fallback=self.fallback,current_control=self.current_control,summary=dict(ingresses=h[8],completed_handlers=h[9],stale_injected=h[10],joined_hash=h[15],runtime_storage_objects=9,initial_protected_ranges=a[0],terminal_protected_ranges=b[0],current_stages=0 if self.fallback else 1,retained_stages=0 if self.fallback or stale else 2,physical_fallbacks=int(self.fallback),completed_prefix=int(not stale)),terminal_chain=terminal)
        result['terminal_chain_expected']=chain_report(self.r,terminal,expected)
        counts=self.f(self.cto,'cto_wire','terminal_counts');ct='li2_current_custody_stats'
        detail=self.i(counts,ct,'first_detail');negative=int(detail>>63)
        result['terminal_current_expected']=dict(version=1,status=h[12],failure_code=h[13],
            **{k:self.i(counts,ct,k)for k in COUNTERS},first_error=self.i(counts,ct,'first_error'),
            first_detail_abs=(-detail)&U64 if negative else detail,first_detail_negative=negative)
        return result


def read(data,layout,image,app,pid,cpu,exit_status,control=0,*,current_control=0,fallback=False):
    need(type(data)is bytes and type(layout)is dict and set(layout)=={'old','current'},'exact appended record and two actual layouts')
    need(type(current_control)is int and current_control in(0,1) and type(fallback)is bool and not(current_control and fallback),'distinct actual current control/fallback mode')
    need(type(pid)is int and pid>0 and type(cpu)is int and cpu>=0 and type(control)is int and 0<=control<=7 and type(exit_status)is int,'actual subject/control identity')
    need(not(current_control or fallback)or(control==0 and app['header'][4]==0),'two additive fixed mode0 cases never replace original25')
    need(type(image)is dict and type(image.get('uid'))is int and 0<=image['uid']<1<<32 and set(image['current_elf'])=={'head','high_return','source'},'actual launch and independent prefix ELF inventory')
    n=layout['old']['types']['uho_wire']['bytes']+64;need(n<len(data)<16<<20,'exact old slice followed by bounded actual appendix')
    original=data[:n];lr=old.Reader(original,layout['old'])
    if current_control:
        need(exit_status==125,'required actual stale-chain termination')
        spec=importlib.util.spec_from_file_location('current_custody_failed_chain',Path(__file__).with_name('stale.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        owner=module.Check(lr,image,app,pid,cpu,0).finish()
    else:owner=old.read(original,layout['old'],image,app,pid,cpu,exit_status,control)
    cr=wire.Reader(data[n:],layout['current'],lr)
    owner['current_custody']=Check(cr,lr,image,app,pid,cpu,control,current_control,fallback,owner).finish(exit_status)
    owner['original_sha256']=hashlib.sha256(data).hexdigest();owner['old_slice_sha256']=hashlib.sha256(original).hexdigest()
    return owner


def terminal(parsed,unrolled,owner):
    need(owner['current_custody']['current_control']==0,'old terminal join applies only to original outcomes or explicit physical fallback')
    result=old.terminal(parsed,unrolled,owner)
    need(parsed['chain']==owner['current_custody']['terminal_chain_expected'],'every terminal chain field equals actual protected snapshot')
    return result


def current_terminal(parsed,unrolled,owner):
    """Separate failed original TF chain, with successful old generated work idle."""
    c=owner['current_custody'];need(c['current_control']==1 and c['summary']['completed_prefix']==0 and c['summary']['joined_hash']==0,'actual uncompleted stale case')
    result=old.terminal(parsed,unrolled,owner)
    need(unrolled['first_error']==0 and unrolled['first_detail_abs']==0 and unrolled['active']==unrolled['busy']==0 and unrolled['entries']==unrolled['completed'] and unrolled['unexpected']==0,'old owner remains quiet; no fake unrolled failure')
    need(parsed['chain']==c['terminal_chain_expected'],'every failed terminal chain field equals actual protected snapshot')
    need(parsed['chain']['error']==903 and parsed['chain']['detail_abs']==302 and parsed['chain']['detail_negative']==0,'actual original chain first error, not a reclassified pass')
    result.update(required_stale_refusal=1,completed_prefix=0)
    return result


def chain_report(r,b,outcome):
    f,i=r.field,r.integer;t='li2_tf_chain'
    row=dict(version=1,scope='opt_in_same_page_tf_lease',**outcome)
    mapping={'active':'active','pending':'pending','error':'first_error','event':'event_id','sequence':'sequence','attempts':'attempts','steps':'steps','nx_entries':'nx_entries','trace_entries':'trace_entries','fallbacks':'fallbacks','preparations':'prepare_attempts','releases':'releases','unexpected':'unexpected_events'}
    row.update({k:i(b,t,v)for k,v in mapping.items()});row['proof_valid']=i(f(b,t,'entry'),'li2_tf_trace_entry','valid')
    for n,s in enumerate(r.items(b,t,'slots','li2_tf_chain_slot')):
        st='li2_tf_chain_slot';owner=f(s,st,'owner');step=f(owner,'li2_tf_owner','step');d=f(s,st,'decoded');fetch=f(s,st,'fetch');progress=f(fetch,'li2_chain_fetch','progress');query=f(s,st,'query');release=f(s,st,'release')
        values={k:i(s,st,v)for k,v in dict(phase='phase',origin='origin',fallback='fallback',generation='generation',event='event_id',prepare='prepare_attempted',prepared='prepare_complete',retry='retry',unexpected='unexpected_frame_observed').items()}
        values.update({k:i(d,'li2_decoded',k)for k in('pc','code','length')})
        values.update(owner_phase=i(step,'li2_step_owner','phase'),owner_error=i(step,'li2_step_owner','first_error'),trace=i(step,'li2_step_owner','trace_seen'),post_pc=i(owner,'li2_tf_owner','actual_post_pc'),borrow=i(f(fetch,'li2_chain_fetch','ref'),'li2_fetch_ref','sequence'),held=i(progress,'li2_fetch_progress','held'),fetch_error=i(progress,'li2_fetch_progress','first_error'),validations=i(progress,'li2_fetch_progress','validation_calls'),query=i(query,'li2_tf_continuation','attempted'),queried=i(query,'li2_tf_continuation','complete'),query_pc=i(query,'li2_tf_continuation','pc'),release=i(release,'li2_chain_release','started'),released=i(release,'li2_chain_release','complete'))
        for k,member in(('open','open_started'),('opened','opened'),('revoke','revoke_started'),('revoked','revoked')):
            a,z=integers(f(step,'li2_step_owner',member));need(a in(0,1)and z in(0,1),'actual permission bit pair');values[k]=a|(z<<1)
        row.update({'s'+str(n)+'_'+k:v for k,v in values.items()})
    lease=f(b,t,'lease');lt='li2_tf_same_page'
    for key,field in dict(phase='phase',active='origin_active',candidates='candidates',misses='misses',transfers='transfers',closed='closed_leases',event='completed_event').items():row['lease_'+key]=i(lease,lt,field)
    transfer=f(lease,lt,'transfer')
    for key,field in dict(phase='phase',before='before_sequence',after='after_sequence').items():row['lease_fetch_'+key]=i(transfer,'li2_fetch_rx_view',field)
    return row


# Sixteen original gated records (nine control0 plus controls1..7), then two
# distinct additions. The old472 mutations still run on the original old slices.
CURRENT_CONTROL_COUNTS={(k,0,False):60 for k in range(8)}
CURRENT_CONTROL_COUNTS.update({(0,1,False):52,(0,0,True):61})


def controls(data,layout,image,app,pid,cpu,exit_status,control=0,*,current_control=0,fallback=False):
    """Supplied-copy refusals only; the complete real record must pass first."""
    original=hashlib.sha256(data).hexdigest()
    accepted=read(data,layout,image,app,pid,cpu,exit_status,control,current_control=current_control,fallback=fallback)
    n=layout['old']['types']['uho_wire']['bytes']+64;legacy=data[:n];appendix=data[n:]
    lr=old.Reader(legacy,layout['old']);types=layout['current']['types']
    old_controls=old.controls(legacy,layout['old'],image,app,pid,cpu,exit_status,control)if not current_control else dict(refusals=[])
    def where(path):
        at=0;t='cto_wire'
        for key,index,child in path:
            field=types[t]['fields'][key];at+=field['offset']
            if index is not None:at+=index*(types[child]['bytes']if child else 8)
            if child:t=child
        return at
    tests=[]
    def add(name,path,byte=0):tests.append((name,[where(path)+byte],1))
    for k in (0,2,4,6,8,9,15,17):add('header_'+str(k),[('h',k,None)])
    for key in ('original_source','entry_source','joined_source'):add('whole_'+key,[(key,None,None)],PAGE-1)
    for k in range(9):add('actual_protected_object_'+str(k),[('initial_registry',None,'cto_registry'),('storage',k,'li2_cto_storage'),('address',None,None)])
    add('actual_bridge_program_header',[('initial_registry',None,'cto_registry'),('ph',0,'Elf64_Phdr'),('p_flags',None,None)])
    add('actual_strict_range',[('initial_registry',None,'cto_registry'),('ranges',0,'li2_fork_range'),('end',None,None)])
    add('actual_terminal_range_count',[('terminal_registry',None,'cto_registry'),('count',None,None)])
    # Both captured copies change coherently: append-only equality remains true,
    # so each refusal exercises the exact symbol/DWARF registration boundary.
    registry=layout['current']['registrations']['uho_wire']
    old_bias=q(lr.field(lr.data[:-64],'uho_wire','h'))[9]-layout['old']['symbols']['li2_raw6']
    registered_first=old_bias+registry['address'];registered_end=registered_first+registry['bytes']
    registered_indices=[]
    for field in ('initial_registry','terminal_registry'):
        r_at=where([(field,None,'cto_registry')]);r_type=types['cto_registry']['fields']
        count=int.from_bytes(appendix[r_at+r_type['count']['offset']:r_at+r_type['count']['offset']+4],'little')
        matches=[i for i in range(count)if struct.unpack_from('<QQ',appendix,r_at+r_type['ranges']['offset']+i*16)==(registered_first,registered_end)]
        need(len(matches)==1,'actual registered control witness');registered_indices.append((field,matches[0]))
    for member in ('first','end'):
        tests.append(('coherent_registered_'+member,[where([(field,None,'cto_registry'),('ranges',index,'li2_fork_range'),(member,None,None)])for field,index in registered_indices],1))

    add('initial_actual_memory',[('initial_memory',None,'li2_uho_memory'),('data',None,None)])
    add('initial_actual_tls',[('tls_origin',None,'uh_frame'),('fs',None,None)])
    tests.extend([('footer_status',[len(appendix)-16],1),('footer_extent',[len(appendix)-48],1)])
    for k in range(2 if current_control else 4):
        row=[('rows',k,'cto_row')];frame=row+[('before',None,'uh_frame')]
        tests.append(('row'+str(k)+'_coherent_AF',[where(frame+[('uc',None,None)])+40+17*8,where(frame+[('frame',None,'li2_step_frame'),('greg',None,None)])+17*8],16))
        add('row'+str(k)+'_full_FP',frame+[('frame',None,'li2_step_frame'),('fp',None,None)],160)
        add('row'+str(k)+'_stack',row+[('stack',None,None)],159)
        add('row'+str(k)+'_data',row+[('data',None,None)],8191)
    frame=[('rows',0,'cto_row'),('after',None,'uh_frame')]
    tests.append(('coherent_return_AF',[where(frame+[('uc',None,None)])+40+17*8,where(frame+[('frame',None,'li2_step_frame'),('greg',None,None)])+17*8],16))
    stage=[('rows',1,'cto_row'),('points',1,'cto_snapshot')];selected='physical'if fallback else'current';view=stage+[(selected,None,'li2_fetch_rx_view')]
    add('actual_custody_kind',view+[('custody',None,'li2_page_custody_receipt'),('kind',None,None)])
    add('actual_custody_epoch',view+[('custody',None,'li2_page_custody_receipt'),('epoch',None,None)])
    add('actual_staged_source',view+[('bytes',None,None)])
    add('separate_physical_origin',view+[('custody',None,'li2_page_custody_receipt'),('origin',None,'li2_fetch_map_progress'),('observation',None,'li2_maps_observation'),('io_performed',None,None)])
    query=view+[('maps',None,'li2_fetch_map_progress')]if fallback else stage+[('provenance',None,'li2_current_custody_provenance'),('origin',None,'li2_maps_current_view'),('query',None,'li2_fetch_map_progress')]
    add('actual_query_io',query+[('observation',None,'li2_maps_observation'),('io_performed',None,None)])
    add('actual_current_counter',stage+[('counts',None,'li2_current_custody_stats'),('current_stages',None,None)])
    add('actual_shared_phase',stage+[('custody',None,'li2_page_custody_stats'),('phase',None,None)])
    add('actual_owner_session',stage+[('session',None,'li2_step_session'),('application_mask',None,None)])
    if current_control:
        add('failed_held_fetch',[('terminal_chain',None,'li2_tf_chain'),('slots',accepted['current_custody']['terminal_chain_expected']['active'],'li2_tf_chain_slot'),('fetch',None,'li2_chain_fetch'),('progress',None,'li2_fetch_progress'),('held',None,None)])
        add('actual_discard_epoch',[('stale_after',None,'cto_snapshot'),('custody',None,'li2_page_custody_stats'),('epoch',None,None)])
        add('no_invented_prefix_completion',[('prefix_chain',None,'li2_tf_chain'),('initialized',None,None)])
    else:
        p=where([('rows',3,'cto_row'),('points',4,'cto_snapshot'),('active',None,None)]);active=int.from_bytes(appendix[p:p+4],'little')
        closed=[('prefix_chain',None,'li2_tf_chain'),('slots',active,'li2_tf_chain_slot')]
        add('actual_predecessor_revocation',closed+[('owner',None,'li2_tf_owner'),('step',None,'li2_step_owner'),('revoked',None,None)])
        add('actual_predecessor_release',closed+[('release',None,'li2_chain_release'),('complete',None,None)])
        add('actual_terminal_chain_error',[('terminal_chain',None,'li2_tf_chain'),('first_error',None,None)])
    add('actual_stack_retirement',stage+[('view_state',None,'li2_cto_view_state'),('stack_retired',None,None)])
    add('unused_api_point',[('rows',0,'cto_row'),('points',0,'cto_snapshot'),('present',None,None)])
    add('actual_source_offset',[('source_offset',None,None)])
    need(len(tests)+int(fallback)==CURRENT_CONTROL_COUNTS[control,current_control,fallback] and len({x[0]for x in tests})==len(tests),'exact fixed new supplied-control population')
    names=[]
    for name,offsets,bit in tests:
        changed=bytearray(appendix)
        for offset in offsets:
            need(0<=offset<len(changed),'bounded whole actual metadata mutation');changed[offset]^=bit
        rejected=False
        try:
            cr=wire.Reader(bytes(changed),layout['current'],lr)
            Check(cr,lr,image,app,pid,cpu,control,current_control,fallback,accepted).finish(exit_status)
        except ValueError as error:
            if name.endswith('_coherent_AF'):need(str(error)=='complete prefix signal-origin envelope','coherent UC/GREG mutation reaches exact full-flags predicate')
            if name=='coherent_return_AF':need(str(error)=='whole same-event frame exact except prescribed TF/RF','coherent returned flags reach exact same-event comparator')
            if name.startswith('coherent_registered_'):need(str(error)=='whole registered object equals actual symbol/DWARF extent','coherent range mutation reaches exact registration-boundary predicate')
            rejected=True
        need(rejected,'complete appended reader refuses supplied '+name);names.append(name)
    if fallback:
        cr=wire.Reader(appendix,layout['current'],lr)
        view=cr.field(cr.data[:-64],'cto_wire','terminal_view')
        changed_app=dict(app);changed_current=dict(app['current']);header=list(changed_current['header'])
        header[10]=cr.integer(view,'li2_cto_view_state','stack_end')
        changed_current['header']=tuple(header);changed_app['current']=changed_current
        rejected=False
        try:Check(cr,lr,image,changed_app,pid,cpu,control,current_control,fallback,accepted).finish(exit_status)
        except ValueError as error:
            need(str(error)=='actual fallback protection page lies wholly in the original stack interval','coherent page-aligned request mutation reaches exact fallback provenance join')
            rejected=True
        need(rejected,'complete appended reader refuses supplied fallback protection outside the original stack')
        names.append('actual_fallback_protection_interval')
    need(len(names)==CURRENT_CONTROL_COUNTS[control,current_control,fallback],'exact complete current supplied-control count')
    need(data[:n]==legacy and hashlib.sha256(data).hexdigest()==original,'all actual old/new bytes remain unchanged')
    return dict(refusals=[]if(current_control or fallback)else old_controls['refusals'],
        additional_legacy_refusals=old_controls['refusals']if fallback else[],current_refusals=names,
        native_operations=0,original_sha256=original,old_slice_sha256=hashlib.sha256(legacy).hexdigest())
