"""Independent v3 certificate evidence. No native operation or decoder replay."""
import hashlib
import struct

PAGE=4096
BYTES=65536
SLOTS=64
TOTAL=BYTES*SLOTS
U64=(1<<64)-1
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)

def need(ok,why):
    if not ok:raise ValueError(why)

def zero(b,why):need(not any(b),why)
def q(b):return struct.unpack('<'+'Q'*(len(b)//8),b)

def bridge(data):
    """Whole actual ELF and local storage extents, independently of DWARF."""
    need(type(data)is bytes and 64<=len(data)<=64<<20,'complete retained certificate bridge')
    def take(at,n):
        need(type(at)is int and 0<=at<=len(data) and 0<=n<=len(data)-at,'whole certificate ELF interval')
        return data[at:at+n]
    h=struct.unpack('<16sHHIQQQIHHHHHH',take(0,64))
    need(h[0][:7]==b'\x7fELF\x02\x01\x01' and h[1:4]==(3,62,1) and h[8:10]==(64,56) and 0<h[10]<=32 and h[11]==64 and 0<h[12]<=4096,'actual shared certificate ELF shape')
    ph=[struct.unpack('<IIQQQQQQ',take(h[5]+56*i,56)) for i in range(h[10])]
    for p in ph:
        if p[0]!=1:continue
        need(p[1] in (4,5,6) and p[5]<=p[6] and p[3]<=U64-p[6] and p[7]==PAGE and p[2]%PAGE==p[3]%PAGE,'actual complete non-WX certificate bridge load')
        take(p[2],p[5])
    sh=[struct.unpack('<IIQQQQIIQQ',take(h[6]+64*i,64)) for i in range(h[12])]
    tables=[s for s in sh if s[1]==2];need(len(tables)==1,'one actual certificate bridge symbol table')
    t=tables[0];need(t[9]==24 and t[5]%24==0 and t[5]//24<=1<<18 and t[6]<len(sh),'bounded whole certificate symbol table')
    strings=sh[t[6]];need(strings[1]==3,'actual certificate symbol names');names=take(strings[4],strings[5]);symbols={}
    for at in range(t[4],t[4]+t[5],24):
        n,info,other,section,address,size=struct.unpack('<IBBHQQ',take(at,24))
        need(n<len(names) and b'\0' in names[n:],'complete actual certificate symbol name')
        name=names[n:names.index(b'\0',n)].decode()
        if name not in ('srcg_store','sro_wire','protected'):continue
        need(name not in symbols and info==1 and other==0 and 0<section<len(sh) and 0<size<16<<20 and address<=U64-size,'unique complete local certificate storage')
        s=sh[section];need(s[1] in (1,8) and s[2]==3 and s[3]<=address<address+size<=s[3]+s[5]<=U64,'whole local certificate object in allocated RW section')
        owners=[i for i,p in enumerate(ph) if p[0]==1 and p[3]<address+size and address<p[3]+p[6]]
        need(len(owners)==1 and ph[owners[0]][1]==6 and ph[owners[0]][3]<=address and address+size<=ph[owners[0]][3]+ph[owners[0]][6],'whole certificate object in exactly one actual RW/NX load')
        symbols[name]=(address,size,owners[0])
    need(set(symbols)=={'srcg_store','sro_wire','protected'},'all actual certificate storage symbols')
    ordered=sorted((a,a+n)for a,n,_ in symbols.values());need(all(a[1]<=b[0]for a,b in zip(ordered,ordered[1:])),'disjoint whole certificate bridge objects')
    return h,ph,symbols


class Checks:
    def certificate_initialize(self):
        self.cert=self.f(self.b,'sro_wire','certificate');self.store=self.f(self.cert,'srco_wire','store')
        self.certificate_arena=self.i(self.store,'scalar_certificate_store','arena')
        self.certificates={};self.certificate_publications={};self.certificate_retirements={}
        binding=self.image.get('certificate_binding')
        need(type(binding)is dict and binding.get('version')==1,'actual certificate build binding')
        self.digests={}
        for name in ('archive','policy'):
            v=binding.get(name);need(type(v)is dict and set(v)=={'bytes','sha256'} and type(v['bytes'])is int and v['bytes']>0 and type(v['sha256'])is str and len(v['sha256'])==64,'whole actual certificate '+name+' identity')
            d=bytes.fromhex(v['sha256']);need(len(d)==32 and any(d),'nonzero actual certificate digest');self.digests[name]=d
        self.bridge_header,self.bridge_ph,self.bridge_symbols=bridge(self.image.get('certificate_bridge'))
        headers=self.image.get('certificate_headers');need(type(headers)is dict and headers,'actual compiler-M certificate header closure')
        storage=self.r.layout.get('certificate_storage')
        need(type(storage)is dict and set(storage)==set(self.bridge_symbols),'actual DWARF certificate storage inventory')
        for name,(address,n,_) in self.bridge_symbols.items():
            d=storage[name];need(type(d)is dict and set(d)=={'address','bytes','alignment','source'} and type(d['source'])is str and d['source'] and
                d['address']==address and d['bytes']==n and type(d['alignment'])is int and 0<d['alignment']<=PAGE and not d['alignment']&(d['alignment']-1) and address%d['alignment']==0,
                'whole actual certificate ELF/DWARF storage equality')
            need(self.r.layout['symbols'][name]==address,'actual certificate symbol address equality')
            need(d['source'] in headers and type(headers[d['source']])is dict and set(headers[d['source']])=={'bytes','sha256'},'actual DWARF storage origin is in complete compiler dependency closure')
        need(storage['srcg_store']['bytes']==self.r.types['scalar_certificate_store']['bytes'] and storage['sro_wire']['bytes']==self.r.types['sro_wire']['bytes'] and storage['protected']['bytes']==128*16,'complete actual certificate/storage type extents')

    def cert_address(self,index):
        need(type(index)is int and 0<=index<SLOTS,'bounded certificate logical slot')
        return self.certificate_arena+BYTES*index

    def cert_permission(self,b,address,prot,error=0,sync_error=0):
        t='sr_permission';self.eq(b,t,started=1,returned=1,sync_started=1,sync_returned=1,complete=int(not(error or sync_error)),prot=prot,result=error,sync_result=sync_error)
        self.query(self.f(b,t,'query'),address,prot,16,failed=bool(error))

    def certificate_registry(self,b):
        t='srco_registry';count=self.i(b,t,'count');need(0<count<=128,'actual bounded certificate protected registry')
        self.eq(b,t,complete=1,table=self.symbol('protected'))
        im=self.f(b,t,'bridge');h=self.bridge_header
        self.eq(im,'image',bias=self.bias,entry=self.bias+h[4],n=h[10],source=0,source_size=0,backing_fd=-1,kind=3)
        pointer=self.i(im,'image','ph');need(4096<=pointer<(1<<47)-56*h[10] and pointer%8==0,'actual runtime bridge PHDR storage');zero(self.f(im,'image','source_hash'),'runtime bridge has no invented original-source digest')
        ph=self.f(b,t,'ph');need(ph[:56*h[10]]==b''.join(struct.pack('<IIQQQQQQ',*p)for p in self.bridge_ph),'all actual runtime bridge program headers equal retained ELF')
        zero(ph[56*h[10]:],'unused runtime bridge program-header slots')
        ranges=self.r.items(b,t,'ranges','li2_fork_range');kinds=self.f(b,t,'initial_code')
        pairs=[]
        for i,row in enumerate(ranges):
            if i>=count:zero(row,'unused protected row');need(kinds[i]==0,'unused protection kind');continue
            a,z=self.v(row,'li2_fork_range','first end');need(0<a<z<1<<47 and kinds[i] in (0,1),'actual byte-exact protected interval and provenance kind');pairs.append((a,z,kinds[i]))
        addresses=q(self.f(b,t,'address'));sizes=q(self.f(b,t,'bytes'));alignments=q(self.f(b,t,'alignment'))
        want=(self.symbol('srcg_store'),self.symbol('sro_wire'),self.certificate_arena)
        need(addresses==want and sizes==(self.r.types['scalar_certificate_store']['bytes'],self.r.types['sro_wire']['bytes'],TOTAL),'three actual source-selected registration extents')
        need(alignments==(self.r.layout['certificate_storage']['srcg_store']['alignment'],self.r.layout['certificate_storage']['sro_wire']['alignment'],PAGE),'actual complete registration alignments')
        indices=struct.unpack('<3I',self.f(b,t,'range_index'));loads=struct.unpack('<2I',self.f(b,t,'load_index'))
        for i,(a,n) in enumerate(zip(addresses,sizes)):
            need(a%alignments[i]==0 and [j for j,row in enumerate(pairs)if row==(a,a+n,0)]==[indices[i]],'unique exact source-selected strict protection registration')
            if i<2:
                name=('srcg_store','sro_wire')[i];p=self.bridge_ph[self.bridge_symbols[name][2]]
                need(loads[i]==self.bridge_symbols[name][2] and self.bias+p[3]<=a<a+n<=self.bias+p[3]+p[6],'whole actual metadata in selected RW/NX bridge load')
                rounded=(self.bias+(p[3]&-PAGE),self.bias+((p[3]+p[6]+PAGE-1)&-PAGE),0)
                need(rounded in pairs,'actual strict protect_image registration contains complete metadata load')
        return pairs

    def certificate_header(self,b,index,generation,entry):
        t='li2_reuse_certificate_header'
        self.eq(b,t,version=1,bytes=BYTES,registry=self.symbol('srcg_store'),slot=index,generation=generation,generated=entry,rseq_proof=generation)
        plan=self.i(b,t,'plan_proof')
        need(plan==generation+max(generation-65,0),'exact cold plan-proof ordinal precedes this retirement reconstruction')
        for name,digest in self.digests.items():need(self.f(b,t,name)==digest,'certificate binds actual '+name+' digest')
        zero(self.f(b,t,'reserved'),'whole reserved certificate header')

    def certificate_payload(self,data,index,generation,publication):
        need(len(data)==BYTES and generation in self.history,'whole certificate payload and independently retained generation')
        s=self.history[generation];need(s['index']==index,'certificate logical slot matches retained generation')
        t='li2_reuse_certificate';n=self.r.types[t]['bytes'];raw=data[:n];self.r.walk(raw,t)
        header=self.f(raw,t,'header');self.certificate_header(header,index,generation,s['entry'])
        need(header==self.f(publication,'srcg_publication','header'),'whole actual certificate header equals protected publication mirror')
        need(self.f(raw,t,'key')==self.f(s['raw'],'sr_slot','key'),'whole certificate immutable source identity matches independent owner')
        plan=self.f(raw,t,'plan');expected=self.f(s['raw'],'sr_slot','plan')
        if self.control==11 and s['source']['pc']==self.h[20] and generation==self.i(self.f(self.owner,'scalar_owner','current'),'sr_record','publication_generation'):
            # Actual supplied corruption changes only the protected slot map;
            # immutable certificate retains the already-published exact plan.
            expected=bytearray(expected);offset=self.r.types['li2_region_plan']['fields']['map']['offset']+self.r.types['li2_region_pc']['fields']['original_pc']['offset']
            struct.pack_into('<Q',expected,offset,self.h[20]);expected=bytes(expected)
        need(plan==expected,'whole immutable certificate plan equals independently reconstructed publication')
        zero(data[n:],'every unused certificate payload byte')
        if generation in self.certificates:need(self.certificates[generation]==data,'all retained copies of one immutable certificate generation agree')
        else:self.certificates[generation]=data
        return raw

    def certificate_publication(self,b,index,generation):
        t='srcg_publication';self.eq(b,t,started=1,complete=1,zeroed=BYTES,copied=self.r.types['li2_reuse_certificate']['bytes'],verified=BYTES)
        self.certificate_header(self.f(b,t,'header'),index,generation,self.history[generation]['entry'])
        address=self.cert_address(index);self.query(self.f(b,t,'writable'),address,3,16);self.cert_permission(self.f(b,t,'sealed'),address,1)
        if generation in self.certificate_publications:need(self.certificate_publications[generation]==b,'whole repeated certificate publication snapshot')
        else:self.certificate_publications[generation]=b

    def certificate_retirement(self,b,old):
        t='srcg_retirement';index=old['index'];g=old['new_generation'];previous=old['old_generation'];address=self.cert_address(index)
        self.eq(b,t,started=1,consumed=1,old_verified=1,authority_revoked=1,writable_complete=1,slot=index,compared=BYTES,copied=BYTES,address=address,
                old_entry=old['slot']['entry'],new_entry=old['entry'],old_generation=previous,new_generation=g,completion=old['completion'])
        p=self.f(b,t,'old_publication');self.certificate_publication(p,index,previous)
        self.certificate_payload(self.f(b,t,'old_bytes'),index,previous,p)
        self.query(self.f(b,t,'old_idle'),address,1,16);self.cert_permission(self.f(b,t,'closed'),address,1);self.cert_permission(self.f(b,t,'writable'),address,3)
        if g in self.certificate_retirements:need(self.certificate_retirements[g]==b,'whole repeated consumed-generation certificate retirement')
        else:self.certificate_retirements[g]=b

    def certificate_match(self,b,generation,attempted=True,result=0):
        if not attempted:zero(b,'unattempted certificate proof is wholly zero');return
        self.eq(b,'li2_reuse_certificate_match',attempted=1,complete=int(not result),result=result,compared=0 if result else BYTES,generation=generation)

    def certificate_record(self,b,result,kind,c):
        t='sr_record';rows=self.r.items(b,t,'certificate','li2_reuse_certificate_observation');live=self.r.items(b,t,'certificate_live','li2_reuse_certificate_match');rseq=self.r.items(b,t,'live_rseq','li2_rseq_region_live')
        generation=result.get('publication_generation',0)
        focal_rows=self.r.items(self.b,'sro_wire','entries','sro_entry')
        origins=[i for i,e in enumerate(focal_rows)if self.i(e,'sro_entry','present') and self.f(e,'sro_entry','owner')==b]
        need(len(origins)<=1,'one actual focal origin for a captured record')
        source_state=None
        if origins:source_state=self.f(self.r.items(self.cert,'srco_wire','focal','srco_focal')[origins[0]],'srco_focal','source_rseq')
        first=bool(generation and c not in (5,15,17));last=kind=='complete' or c==3
        live_count=3 if last else 0 if c in (5,11,15,16,17) or not generation else 1 if c in (2,4) else 2
        for i,row in enumerate(rows):
            active=first if i==0 else last
            self.certificate_match(self.f(row,'li2_reuse_certificate_observation','match'),generation,active,2610 if c==11 and i==0 else 0)
            if active:self.query(self.f(row,'li2_reuse_certificate_observation','mapping'),self.cert_address(result['slot']),1,16)
            else:zero(self.f(row,'li2_reuse_certificate_observation','mapping'),'unattempted certificate mapping observation')
        for i,(m,obs) in enumerate(zip(live,rseq)):
            self.certificate_match(m,generation,i<live_count)
            if i>=live_count:zero(obs,'unattempted live-rseq observation');continue
            frame=result['after'] if i==2 else result['before'];ot='li2_rseq_region_live'
            self.eq(obs,ot,attempted=1,complete=1,result=0,session=self.symbol('selected_session'))
            reg,epoch=self.v(obs,ot,'registered epoch');need(reg in (0,1) and (not reg or epoch>0),'actual optional live-rseq registration epoch')
            registers=self.f(obs,ot,'registers')
            if source_state is not None:
                need((reg,epoch)==self.v(source_state,'li2_rseq_state','registered epoch') and
                    self.v(registers,'li2_write_registers','fs_base gs_base')==self.v(source_state,'li2_rseq_state','fs_base gs_base'),
                    'all focal live-rseq inputs bind actual source-hook state')
            if reg:self.eq(registers,'li2_write_registers',fs_base=frame['fs'],gs_base=frame['gs'])
            elif epoch==0:self.eq(registers,'li2_write_registers',fs_base=0,gs_base=0)
            if i:need(self.v(registers,'li2_write_registers','fs_base gs_base')==self.v(self.f(rseq[0],ot,'registers'),'li2_write_registers','fs_base gs_base'),'copied rseq bases retain their protected-state origin')
            need(q(self.f(registers,'li2_write_registers','gpr'))==tuple(frame['greg'][j]for j in GREG),'all actual live-rseq GPR inputs equal authentic current frame')
            if i:need(self.v(obs,ot,'registered epoch')==self.v(rseq[0],ot,'registered epoch'),'same actual live-rseq registration across entry')
        # Nested tgkill (control1) arrives while handling is set. The genuine
        # unexpected route captures it but cannot call sr_map_actual/srcg_terminal.
        terminal=kind=='fault' or c==7
        self.certificate_match(self.f(b,t,'certificate_terminal'),generation,terminal)

    def certificate_control_prefix(self,before,current,c):
        if c==3:
            for name,child,kept in (('certificate','li2_reuse_certificate_observation',1),('certificate_live','li2_reuse_certificate_match',1),('live_rseq','li2_rseq_region_live',1)):
                a=self.r.items(before,'sr_record',name,child);b=self.r.items(current,'sr_record',name,child)
                need(a[:kept]==b[:kept],'pre-filter certificate proof is retained exactly')
                for row in a[kept:]:zero(row,'filter installation precedes later certificate proofs')
        elif c in (11,16):
            for name in ('certificate','certificate_live','certificate_terminal','live_rseq'):zero(self.f(before,'sr_record',name),'slot mutation precedes all certificate checks')

    def certificate_control_fields(self,c):
        if c==7:return ('certificate_terminal',)
        if c==3:return ('certificate','certificate_live','live_rseq')
        if c in (11,16):return ('certificate',)
        return ()

    def certificate_rseq_transition(self,source,state,plan,build):
        # The typed live helper preserves historical footprint state. Cold
        # construction alone writes the original complete NONE proof.
        if build:
            last=plan['original'][-1];pc,nxt=struct.unpack_from('<QQ',last);code=struct.unpack_from('<I',last,24)[0];length=struct.unpack_from('<I',last,48)[0]
            footprint=struct.pack('<4Q4I',pc,nxt,0,0,1,1,code,length)
            self.r.change(source,state,'li2_rseq_state',values=dict(last_pc=pc,last_code=code,last_policy=1,last_first=0,last_end=0,last_footprint=footprint))
        else:need(source==state,'whole historical rseq state preserved by live certificate checks')

    def footprint(self,b,plan,index):
        rows=self.r.items(self.b,'sro_wire','entries','sro_entry');focal=self.r.items(self.cert,'srco_wire','focal','srco_focal')
        need(type(index)is int and 0<=index<2,'actual bounded caller focal index')
        e,f=rows[index],focal[index]
        need(self.i(e,'sro_entry','present')==1 and b in (self.f(e,'sro_entry','redirected_owners'),self.f(e,'sro_entry','completed_owners')),'exact actual caller-selected focal rseq snapshot origin')
        source=self.f(f,'srco_focal','source_rseq');state=self.f(b,'sro_owners','rseq')
        raw=self.f(e,'sro_entry','owner');build=self.i(raw,'sr_record','build_started')
        self.certificate_rseq_transition(source,state,plan,build)
        for obs in self.r.items(raw,'sr_record','live_rseq','li2_rseq_region_live'):
            if self.i(obs,'li2_rseq_region_live','complete'):
                need(self.v(obs,'li2_rseq_region_live','registered epoch')==self.v(state,'li2_rseq_state','registered epoch'),'actual live observation equals actual protected rseq snapshot')
                need(self.v(self.f(obs,'li2_rseq_region_live','registers'),'li2_write_registers','fs_base gs_base')==self.v(state,'li2_rseq_state','fs_base gs_base'),'copied live-check TLS bases bind the actual retained rseq state')

    def certificate_counters(self,publications,hits,c,failed):
        a=publications+hits
        adjust={1:-1,2:-1,3:0,4:-1,5:-2,6:0,7:-1,8:0,9:0,10:0,11:-2,12:0,13:0,14:0,15:-2,16:-1,17:-2}
        live={1:-1,2:-2,3:0,4:-2,5:-3,6:0,7:-1,8:0,9:0,10:0,11:-3,12:0,13:0,14:0,15:-3,16:-3,17:-3}
        self.eq(self.store,'scalar_certificate_store',publications=publications,retirements=self.i(self.reuse,'scalar_reuse','retirements'),
            checks=2*a+(adjust[c]if c else -int(failed)),live_checks=3*a+(live[c]if c else -int(failed)),terminal_matches=self.i(self.owner,'scalar_owner','unexpected')-int(c in (1,14)))

    def certificate_report(self,outcome):
        t='scalar_certificate_store';return dict(version=1,**outcome,initialized=self.i(self.store,t,'initialized'),publications=self.i(self.store,t,'publications'),
            retirements=self.i(self.store,t,'retirements'),certificate_checks=self.i(self.store,t,'checks'),live_rseq_checks=self.i(self.store,t,'live_checks'),
            terminal_matches=self.i(self.store,t,'terminal_matches'),pending=self.i(self.f(self.store,t,'current'),'srcg_current','pending'))

    def certificate_current(self,b,generation,index,build,pending=True,cleanup=False):
        t='srcg_current';s=self.history[generation];self.eq(b,t,pending=int(pending),constructing=int(build),committed=1,slot=index,address=self.cert_address(index),generated=s['entry'],generation=generation,
            old_generation=max(generation-64,0)if build else 0,plan_proof=generation+max(generation-65,0)if build else 0,rseq_proof=generation if build else 0)
        virgin=self.f(b,t,'virgin')
        if build and generation<=64:self.query(virgin,self.cert_address(index),3,16)
        else:zero(virgin,'no invented virgin certificate observation')
        if cleanup:self.cert_permission(self.f(b,t,'cleanup'),self.cert_address(index),1,sync_error=-13 if self.control==4 else 0)
        else:zero(self.f(b,t,'cleanup'),'no fabricated certificate cleanup')

    def certificate_finish(self,outputs,slots,failed):
        t='scalar_certificate_store';s=self.store;r=self.r;used=self.i(self.owner,'scalar_owner','used');a=self.certificate_arena
        self.eq(s,t,initialized=1,metadata_registered=1,allocated=1,arena_registered=1,allocation_result=a)
        need(0<a<(1<<47)-TOTAL and a%PAGE==0,'whole allocated certificate arena')
        for name in ('arena','low_arena'):
            lo=self.i(self.owner,'scalar_owner',name);need(a+TOTAL<=lo or lo+64*PAGE<=a,'certificate and executable arenas disjoint')
        h=q(self.f(self.cert,'srco_wire','h'));pending=self.i(self.f(s,t,'current'),'srcg_current','pending')
        need(h==(0x314347534c49324c,1,r.types['srco_wire']['bytes'],r.types[t]['bytes'],r.types['li2_reuse_certificate']['bytes'],BYTES,SLOTS,1,1,0,SLOTS,BYTES if pending else 0,self.symbol('srcg_store'),a,TOTAL,0),'whole complete actual certificate capture protocol')
        first=self.certificate_registry(self.f(self.cert,'srco_wire','initial_registry'));last=self.certificate_registry(self.f(self.cert,'srco_wire','terminal_registry'))
        need(last[:len(first)]==first,'actual protected registry is append-only')
        for i,b in enumerate(r.items(s,t,'initial','li2_private_code_query')):self.query(b,a+i*64*PAGE,3,64)
        ready=q(self.f(s,t,'ready_generation'));index=self.i(self.reuse,'scalar_reuse','slot')
        need(ready==tuple(0 if pending and i==index else g for i,g in enumerate(self.live)),'separate dispatch readiness is revoked for actual pending abort')
        pubs=r.items(s,t,'slot','srcg_publication');payload=self.f(self.cert,'srco_wire','payload');queries=r.items(self.cert,'srco_wire','terminal_mapping','li2_private_code_query')
        need(q(self.f(self.cert,'srco_wire','terminal_bytes'))==(BYTES,)*64,'all64 actual terminal extents captured exactly once')
        for i,(p,query) in enumerate(zip(pubs,queries)):
            data=payload[i*BYTES:(i+1)*BYTES]
            self.query(query,self.cert_address(i),1 if i<used else 3,16)
            if i>=used:zero(p,'unused certificate publication');zero(data,'whole unused RW/NX certificate extent');continue
            g=self.live[i];self.certificate_publication(p,i,g);self.certificate_payload(data,i,g,p)
        retired=self.f(s,t,'retirement');g=self.i(self.reuse,'scalar_reuse','generation')
        if g>64:self.certificate_retirement(retired,self.retired[g])
        else:zero(retired,'no invented certificate retirement before capacity')
        actual=r.items(self.b,'sro_wire','entries','sro_entry');focals=r.items(self.cert,'srco_wire','focal','srco_focal')
        for i,(e,f) in enumerate(zip(actual,focals)):
            if not self.i(e,'sro_entry','present'):zero(f,'whole unused certificate focal capture');continue
            ft='srco_focal';raw=self.f(e,'sro_entry','owner');present=self.i(e,'sro_entry','slot_observed');completed=self.i(raw,'sr_record','completed')
            self.eq(f,ft,source_present=1,slot_present=present,completed=completed)
            before=q(self.f(f,ft,'before_counts'));gb=q(self.f(e,'sro_entry','global_before'))
            need(before[:2]==(gb[0],max(gb[0]-64,0)) and before[2:]==(2*gb[2],3*gb[2],0),'actual focal source-hook counters precede this entry')
            if not present:
                for key in ('slot','copied','generation','ready_generation','address'):self.eq(f,ft,**{key:0})
                for key in ('slot_counts','after_counts','current','completed_current','publication','retirement','payload'):zero(self.f(f,ft,key),'unpublished certificate focal field '+key)
                need(self.f(f,ft,'source_rseq')==self.f(self.f(self.b,'sro_wire','terminal_owners'),'sro_owners','rseq'),'whole unpublished focal preserves actual rseq state')
                continue
            generation=self.i(e,'sro_entry','reuse_generation');index=self.i(raw,'sr_record','slot');build=self.i(raw,'sr_record','build_started')
            if failed and not self.i(raw,'sr_record','redirected'):
                terminal=self.f(self.f(self.b,'sro_wire','terminal_owners'),'sro_owners','rseq')
                self.certificate_rseq_transition(self.f(f,ft,'source_rseq'),terminal,self.history[generation]['plan'],build)
            self.eq(f,ft,slot=index,copied=BYTES,generation=generation,ready_generation=generation,address=self.cert_address(index))
            self.certificate_current(self.f(f,ft,'current'),generation,index,build)
            p=self.f(f,ft,'publication');self.certificate_publication(p,index,generation);self.certificate_payload(self.f(f,ft,'payload'),index,generation,p)
            if build and generation>64:self.certificate_retirement(self.f(f,ft,'retirement'),self.retired[generation])
            else:zero(self.f(f,ft,'retirement'),'hit/virgin publication has no certificate retirement')
            slot=q(self.f(f,ft,'slot_counts'));need(slot==(gb[0]+build,max(gb[0]+build-64,0),*before[2:]),'publication alone changes source-to-slot certificate counters')
            if completed:
                self.certificate_current(self.f(f,ft,'completed_current'),generation,index,build)
                need(self.f(f,ft,'completed_current')==self.f(f,ft,'current'),'whole unchanged stable certificate claim through completion hook')
                need(q(self.f(f,ft,'after_counts'))==(slot[0],slot[1],slot[2]+2,slot[3]+3,slot[4]),'actual two complete comparisons and three live guards at focal completion')
            else:zero(self.f(f,ft,'after_counts'),'failed focal has no completion counters');zero(self.f(f,ft,'completed_current'),'failed focal has no completion claim')
        current=self.f(self.owner,'scalar_owner','current');anchor=self.f(s,t,'current')
        if pending or self.i(current,'sr_record','completed'):
            index=self.i(self.reuse,'scalar_reuse','slot');generation=self.live[index]
            self.certificate_current(anchor,generation,index,self.i(current,'sr_record','build_started'),bool(pending),bool(pending))
        else:zero(anchor,'unclaimed clean/pre-publication attempt has no certificate authority')

    def mapping_idle_prefix(self):
        need(self.h[31:38]==(0,0,0,1,0,0,1),'actual mapping dispatcher has quiet generated owners and no pending route')


# Twenty common certificate controls, eight for every actual focal source row,
# and six for every actual focal slot. All original4102 are a separate table.
CONTROL_COUNTS={(m,0):(48 if m in (11,12) else 34)for m in range(13)}
CONTROL_COUNTS.update({(0,c):20 if c==6 else 28 if c in (8,9,10,12,13,14) else 34 for c in range(1,18)})
CONTROL_COUNTS[0,1]+=1 # Coherent forged association from inside the active handler.
MAPPING_CONTROL_COUNT=20


def mutations(data,layout,Reader):
    r=Reader(data,layout);types=r.types;tests=[]
    def at(path):
        offset=0;t='sro_wire'
        for key,index,child in path:
            f=types[t]['fields'][key];offset+=f['offset']
            if index is not None:offset+=index*(types[child]['bytes']if child else 8)
            if child:t=child
        return offset
    root=[('certificate',None,'srco_wire')];store=root+[('store',None,'scalar_certificate_store')]
    def add(name,path,byte=0):tests.append((name,[at(path)+byte]))
    add('wire_version',root+[('h',1,None)])
    for key in ('publications','checks','live_checks','terminal_matches','initialized','arena'):
        add('store_'+key,store+[(key,None,None)])
    add('ready_generation',store+[('ready_generation',0,None)])
    add('whole_terminal_tail',root+[('payload',None,None)],BYTES-1)
    add('whole_terminal_key',root+[('payload',None,None)],160)
    header=store+[('slot',0,'srcg_publication'),('header',None,'li2_reuse_certificate_header')]
    for key in ('archive','plan_proof'):
        field=types['li2_reuse_certificate_header']['fields'][key]['offset']
        tests.append(('coherent_header_'+key,[at(header+[(key,None,None)]),at(root+[('payload',None,None)])+field]))
    add('actual_terminal_permission',root+[('terminal_mapping',0,'li2_private_code_query'),('expected_prot',None,None)])
    add('whole_terminal_extent',root+[('terminal_bytes',0,None)])
    add('actual_publication_seal',store+[('slot',0,'srcg_publication'),('sealed',None,'sr_permission'),('complete',None,None)])
    for stage,key in (('initial_registry','first'),('terminal_registry','end')):
        reg=root+[(stage,None,'srco_registry')];index=struct.unpack_from('<I',data,at(reg+[('range_index',None,None)]))[0]
        need(index<128,'actual bounded selected registry index for control')
        add(stage+'_exact_extent',reg+[('ranges',index,'li2_fork_range'),(key,None,None)])
    add('actual_registry_kind',root+[('terminal_registry',None,'srco_registry'),('initial_code',None,None)],
        struct.unpack_from('<I',data,at(root+[('terminal_registry',None,'srco_registry'),('range_index',None,None)]))[0])
    add('actual_pending',store+[('current',None,'srcg_current'),('pending',None,None)])
    add('retired_whole_tail',store+[('retirement',None,'srcg_retirement'),('old_bytes',None,None)],BYTES-1)
    need(len(tests)==20,'twenty fixed common certificate refusals')
    body=data[:-64];rows=r.items(body,'sro_wire','entries','sro_entry')
    all_records=[([('owner',None,'scalar_owner'),(key,None,'sr_record')],r.field(r.field(body,'sro_wire','owner'),'scalar_owner',key))for key in ('current','last')]
    all_records += [([('entries',i,'sro_entry'),('owner',None,'sr_record')],r.field(e,'sro_entry','owner'))for i,e in enumerate(rows)]
    all_records += [([('control_before',None,'sr_record')],r.field(body,'sro_wire','control_before'))]
    for i,e in enumerate(rows):
        if not r.integer(e,'sro_entry','present'):continue
        base=root+[('focal',i,'srco_focal')]
        for name,path,byte in (
            ('source_pid',[('source_rseq',None,'li2_rseq_state'),('pid',None,None)],0),
            ('source_epoch',[('source_rseq',None,'li2_rseq_state'),('epoch',None,None)],0),
            ('before_counters',[('before_counts',0,None)],0),('slot_counters',[('slot_counts',2,None)],0),
            ('claim_generation',[('current',None,'srcg_current'),('generation',None,None)],0),
            ('whole_payload_tail',[('payload',None,None)],BYTES-1),
            ('source_presence',[('source_present',None,None)],0),('completed',[('completed',None,None)],0)):
            add('focal'+str(i)+'_'+name,base+path,byte)
        if not r.integer(e,'sro_entry','slot_observed'):continue
        add('focal'+str(i)+'_publication',base+[('publication',None,'srcg_publication'),('header',None,'li2_reuse_certificate_header'),('generation',None,None)])
        add('focal'+str(i)+'_ready',base+[('ready_generation',None,None)])
        record=r.field(e,'sro_entry','owner')
        for name,path in (
            ('match_bytes',[('certificate',0,'li2_reuse_certificate_observation'),('match',None,'li2_reuse_certificate_match'),('compared',None,None)]),
            ('live_registration',[('live_rseq',0,'li2_rseq_region_live'),('registered',None,None)]),
            ('terminal_match',[('certificate_terminal',None,'li2_reuse_certificate_match'),('compared',None,None)])):
            # Coherently change every identical captured alias. A whole-row
            # equality must not hide the semantic certificate refusal.
            offsets=[at(prefix+path)for prefix,raw in all_records if raw==record]
            need(offsets and len(set(offsets))==len(offsets),'all actual identical record aliases for supplied certificate control')
            tests.append(('focal'+str(i)+'_'+name,offsets))
        add('focal'+str(i)+'_retired_payload',base+[('retirement',None,'srcg_retirement'),('old_bytes',None,None)],BYTES-1)
    if q(r.field(body,'sro_wire','control'))[0]==1:
        add('nested_forged_terminal_association',store+[('terminal_matches',None,None)])
    return tests


def forge_nested_terminal(changed,data,layout,Reader):
    # This extra stimulus supplies a coherent valid-looking association in every
    # identical current/focal record and the actual global count. It must fail
    # the source-derived no-association counter, not an unrelated alias check.
    r=Reader(data,layout);types=r.types;body=data[:-64]
    wf=types['sro_wire']['fields'];ot=types['scalar_owner'];rt=types['sr_record']
    owner=r.field(body,'sro_wire','owner');current=r.field(owner,'scalar_owner','current')
    generation=r.integer(current,'sr_record','publication_generation')
    need(generation>0 and not any(r.field(current,'sr_record','certificate_terminal')),
         'actual nested terminal proof starts wholly zero with a published generation')
    rows=r.items(body,'sro_wire','entries','sro_entry');et=types['sro_entry']
    offsets=[wf['owner']['offset']+ot['fields'][key]['offset'] for key in ('current','last')
             if r.field(owner,'scalar_owner',key)==current]
    offsets += [wf['entries']['offset']+i*et['bytes']+et['fields']['owner']['offset']
                for i,e in enumerate(rows) if r.field(e,'sro_entry','owner')==current]
    if r.field(body,'sro_wire','control_before')==current:offsets.append(wf['control_before']['offset'])
    need(len(offsets)>=2 and len(set(offsets))==len(offsets),'all actual nested current/focal aliases')
    for offset in offsets:
        struct.pack_into('<IIi4xQQ',changed,offset+rt['fields']['certificate_terminal']['offset'],1,1,0,BYTES,generation)


def controls(data,layout,image,app,pid,cpu,exit_status,control,boundaries,read,Reader):
    tests=mutations(data,layout,Reader)
    need(len(tests)==CONTROL_COUNTS[(app['mode'],control)],'exact additive certificate supplied-control population')
    names=[];original=hashlib.sha256(data).digest()
    for name,offsets in tests:
        changed=bytearray(data)
        for offset in offsets:changed[offset]^=1
        if name=='nested_forged_terminal_association':forge_nested_terminal(changed,data,layout,Reader)
        rejected=False
        try:read(bytes(changed),layout,image,app,pid,cpu,exit_status,control,boundaries=boundaries)
        except ValueError as error:
            if name=='nested_forged_terminal_association':need(str(error)=='exact scalar_certificate_store.terminal_matches','nested forgery reaches exact no-association counter')
            if control==1 and name=='focal0_terminal_match':need(str(error)=='unattempted certificate proof is wholly zero','nested match mutation reaches whole zero proof')
            if name=='coherent_header_archive':need(str(error)=='certificate binds actual archive digest','coherent digest mutation reaches independent build binding')
            if name=='coherent_header_plan_proof':need(str(error)=='exact cold plan-proof ordinal precedes this retirement reconstruction','coherent proof mutation reaches actual proof chronology')
            rejected=True
        need(rejected,'strict certificate reader rejected supplied '+name);names.append(name)
    need(len(names)==len(set(names)) and hashlib.sha256(data).digest()==original,'unique supplied certificate controls preserve actual evidence')
    return names
