"""Distinct completed-generation owner reader. Old scalar readers stay exact.

All source/ELF/process closure and independent native full-state joins remain
mandatory. Resident slots and captured historical generations are never conflated.
"""
import hashlib
import importlib.util
from pathlib import Path
import struct

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

HERE=Path(__file__).resolve().parent
wire=load('scalar_reuse_certificate_wire',HERE/'wire.py')
certificate=load('scalar_reuse_certificate_checks',HERE/'certificate.py')
donor=load('scalar_reuse_donor',HERE.parent/'scalar_region_owner'/'read.py')
plan_reader=load('scalar_reuse_plan',HERE.parent/'scalar_region_owner'/'plan.py')
boundary_reader=load('scalar_reuse_certificate_boundaries',HERE.parent/'scalar_region_reuse_owner'/'boundaries.py')
old=wire.old
need,zero,q,canonical=old.need,old.zero,old.q,old.canonical
Reader,Fields=wire.Reader,old.Fields
U64,PAGE,FP,TF,RF,MASK=old.U64,old.PAGE,old.FP,old.TF,old.RF,old.MASK
P,L,R=old.P,old.L,old.R
DATA,STACK,STACK_FAULT,RSP,GREG=donor.DATA,donor.STACK,donor.STACK_FAULT,donor.RSP,donor.GREG
FAILURE=dict(donor.FAILURE,**{})
FAILURE.update({15:(2603,5),16:(2603,6),17:(2603,5)})

class Check(certificate.Checks,donor.Check):
    def __init__(self,reader,image,app,pid,cpu,control,boundaries):
        self.r,self.image,self.app,self.pid,self.cpu,self.control=reader,image,app,pid,cpu,control
        self.b=reader.data[:-64];self.h=q(self.f(self.b,'uho_wire','h'))
        self.control_words=q(self.f(self.b,'uho_wire','control'))
        self.owner=self.f(self.b,'uho_wire','owner');self.bias=self.h[9]-reader.layout['symbols']['li2_raw6']
        self.boundaries=boundary_reader.observe(boundary_reader.requests(reader),boundaries)
        self.reuse=self.f(self.b,'sro_wire','reuse');self.history={};self.retired={}
        self.mapping_code=None
        self.certificate_initialize()
        self.objects={};self.bases={};self.source_ids={};self.backings={};self.maps_seen={}
        for key,obj in image['objects'].items():
            need(type(key)is int and key>=0 and type(obj)is dict,'explicit lifecycle object inventory')
            h,loads=old.elf(obj['data']);self.objects[key]=(obj,h,loads)
        need(image['main_object'] in self.objects and image['interpreter_object'] in self.objects,'actual main/interpreter object assignment')

    def header(self,exit_status):
        h=self.h;r=self.r;c=self.control_words
        code,detail=(self.mapping_code,7 if self.mapping_code==136 else 0) if self.mapping_code is not None else (0,0) if exit_status==0 else FAILURE[self.control] if self.control else (2604,11)
        need(h[:9]==(0x31524f534c49324c,3,r.types['sro_wire']['bytes'],r.types['scalar_owner']['bytes'],r.types['sro_entry']['bytes'],r.types['sr_record']['bytes'],r.types['sr_frame']['bytes'],968,128),'whole actual scalar capture version/type extents')
        need(canonical(self.bias) and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(k) for k in ('li2_raw6','li2_gateway_start','li2_gateway_end')) and h[10]<=h[9]<h[11],'actual compiled bridge gateway relation')
        need(canonical(h[12],h[13]) and h[12]%PAGE==0 and h[13]==524288,'actual complete altstack')
        need(h[14:16]==(1,0) and h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,0),'actual private retained FD3 sink')
        need(h[20]==self.app['head'] and h[22]==self.image['main_object'] and h[23]==1 and h[26:30]==(1,exit_status,code,detail&U64),'actual focal original image and exact outcome')
        need(h[39]==0 and h[41:43]==(h[16],0) and h[45]<=h[44]<=h[43] and h[46]<=h[43] and h[47:50]==(0,0,0) and h[50:53]==(1,1,1) and
            h[53]==int(self.control==14) and not any(h[54:56]) and not any(h[58:]),'complete diagnostics, FD guards, alias cleanup and actual terminal capture')
        need(canonical(h[56],h[57]-h[56]) and h[56]%PAGE==h[57]%PAGE==0 and h[56]<h[57]<(1<<47),'actual protected runtime vDSO extent')
        need(c[0]==self.control and not any(c[4:6]) and not any(c[32:]),'actual fixed control and reserved words')
        a,b=(self.f(self.b,'sro_wire',k) for k in ('sink_initial','sink_terminal'))
        for value in (a,b):
            st=self.stat(value);need(st['mode']&0xffff==0x8180 and st['size']==0,'actual0600 regular empty pre-write sink');self.eq(value,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(a,b,'stat',observed=('st_atim','st_mtim','st_ctim'))
        footer=q(r.data[-64:]);need(footer[:4]==(0x314652534c49324c,3,len(self.b),len(self.b)) and 1<=footer[4]<=64 and 0<footer[5]<=len(self.b) and footer[6:]==(exit_status,code),'complete exact footer and bounded actual write progress')
        if footer[4]==1:need(footer[5]==len(self.b),'actual single complete write')
        self.image_header(self.f(self.b,'sro_wire','main'),self.image['main_object']);self.image_header(self.f(self.b,'sro_wire','interpreter'),self.image['interpreter_object'])
        obj,_,loads=self.objects[self.image['main_object']];page=h[20]&-PAGE
        matches=[p for p in loads if p[1]==5 and p[3]<=page and page+PAGE<=p[3]+p[5]]
        need(len(matches)==1 and h[21]==matches[0][2]+page-matches[0][3],'actual complete main source-page file offset')
        need(self.f(self.b,'sro_wire','original_source')==self.app['source_page']==obj['data'][h[21]:h[21]+PAGE],'whole independent actual application source page')
        hardware=self.f(self.b,'sro_wire','hardware');self.eq(hardware,'li2_selected_hardware',abi_version=1,reserved=0)
        for i,key in enumerate(('leaf0','leaf1','leaf7')):need(struct.unpack('<4I',self.f(hardware,'li2_selected_hardware',key))==tuple(self.app['hardware'][i][2:]),'actual bridge/application hardware equality')
        return dict(status=exit_status,failure_code=code,detail_abs=abs(detail),detail_negative=int(detail<0))

    def slot(self,b,index,generation):
        t='sr_slot';self.eq(b,t,installed=1,complete=1,filled=PAGE,verified=PAGE)
        source=self.key(self.f(b,t,'key'));entry=self.i(self.owner,'scalar_owner','low_arena' if source['pc']<1<<31 else 'arena')+index*PAGE
        focal=source['pc']==self.h[20];identity=generation
        need(0<generation<=self.i(self.reuse,'scalar_reuse','generation') and index<64,'bounded actual publication generation/slot')
        if self.control==5 and focal and generation==self.i(self.f(self.owner,'scalar_owner','current'),'sr_record','publication_generation'):identity^=1<<63
        self.eq(b,t,identity=identity)
        plan=plan_reader.check(self.f(b,t,'plan'),source['page'],source['bytes'],source['pc'],entry,self.boundaries,self.control==11 and focal and generation==self.i(self.f(self.owner,'scalar_owner','current'),'sr_record','publication_generation'))
        self.query(self.f(b,t,'writable'),entry,3);self.permission(self.f(b,t,'publication'),entry,1)
        need(entry+PAGE<=source['page'] or entry>=source['page']+PAGE,'actual source and generated disjoint pages')
        result=dict(source=source,entry=entry,page=plan['image'],plan=plan,raw=b,index=index,generation=generation)
        if generation in self.history:need(self.history[generation]['raw']==b and self.history[generation]['index']==index,'whole repeated generation snapshot agrees')
        else:self.history[generation]=result
        return result

    def record(self,b,slots,kind='complete',focal=False):
        t='sr_record';c=self.control if focal else 0
        source=self.source(self.f(b,t,'source'),c in (8,9,10));before=self.frame(self.f(b,t,'before'));self.nx(before,source['pc'])
        flags=self.i(b,t,'flags');need(flags&(TF|RF)==0 and before['greg'][17]==flags|RF,'actual logical flags at genuine NX ingress')
        no_slot=c in (8,9,10,12,13,14)
        result=dict(before=before,after=None,unexpected=None,source=source,entry=0,mapped=None,key=source['key'],raw_key=source['raw_key'],generation=source['generation'],slot=self.i(b,t,'slot'))
        build,returned=self.v(b,t,'build_started build_returned');need(build in (0,1) and returned==build-int(c==14),'actual complete build prefix or one interrupted call')
        self.eq(b,t,build_result=0)
        if no_slot:
            self.eq(b,t,publication_generation=0,slot_present=0,slot=0,redirected=0,exit_seen=0,completed=0,release_started=0,release_complete=0,release_result=0,
                cleanup_started=0,cleanup_complete=0,gpr_written=0,flags_written=0,exit_index=0,idle_bytes=0,live_bytes=0,closed_bytes=0,build_started=1)
            for key in ('original','idle','live','open','close','cleanup','after'):zero(self.f(b,t,key),'whole unexecuted pre-publication field '+key)
            self.eq(b,t,unexpected_seen=int(c==14),map_result=int(c==14))
            if c==14:
                f=self.frame(self.f(b,t,'unexpected'));self.nested(f,before);result['unexpected']=f
            else:zero(self.f(b,t,'unexpected'),'pre-publication refusal has no unexpected signal')
            error,detail={8:(302,100),9:(302,100),10:(306,4095),12:(119,0),13:(305,0),14:(0,0)}[c]
            # The alias/permission details are exact old fetch validation facts,
            # joined below to the captured first-error event, never an either/or.
            self.fetch(self.f(b,t,'final_fetch'),source,True,error,detail)
            self.certificate_record(b,result,kind,c)
            return result
        slot=self.i(b,t,'slot');generation=self.i(b,t,'publication_generation')
        need(self.i(b,t,'slot_present')==1 and slot<64,'actual bounded retained slot before generation lookup')
        if c==15:generation=q(self.f(self.reuse,'scalar_reuse','live'))[slot]
        need(generation in self.history,'actual retained publication generation')
        s=self.history[generation];need(s['index']==slot,'exact generation belongs to this logical slot')
        plan=s['plan'];entry=s['entry'];result.update(entry=entry,plan=plan,publication_generation=generation)
        need(source['key']==s['source']['key'],'current fresh ticket joins exact immutable slot key')
        if c in (5,11,15,17):
            self.eq(b,t,redirected=0,exit_seen=0,completed=0,release_started=0,release_complete=0,release_result=0,unexpected_seen=0,map_result=0,
                gpr_written=0,flags_written=0,exit_index=0,idle_bytes=0,live_bytes=0,closed_bytes=0)
            for key in ('original','idle','live','open','close','after','unexpected'):zero(self.f(b,t,key),'unexecuted supplied slot/plan refusal '+key)
        elif c==16:
            self.eq(b,t,gpr_written=plan['gpr_written'],flags_written=plan['flags_written'],redirected=0,
                exit_seen=0,completed=0,release_started=0,release_complete=0,release_result=0,unexpected_seen=0,
                map_result=0,exit_index=0,live_bytes=0,closed_bytes=0)
            self.query(self.f(b,t,'idle'),entry,1)
            retired=self.retired[generation]['slot']['page'];image=plan['image']
            differences=[i for i in range(PAGE) if retired[i]!=image[i]]
            need(differences,'actual retired image differs from current generation')
            self.eq(b,t,idle_bytes=differences[0])
            for key in ('original','live','open','close','after','unexpected'):zero(self.f(b,t,key),'no execution after stale full-image refusal '+key)
        else:
            self.eq(b,t,gpr_written=plan['gpr_written'],flags_written=plan['flags_written'])
            self.query(self.f(b,t,'idle'),entry,1);self.eq(b,t,idle_bytes=PAGE)
            self.permission(self.f(b,t,'open'),entry,5,error=-13 if c==2 else 0,sync_error=-13 if c==4 else 0)
            entered=c not in (2,4);self.eq(b,t,redirected=int(entered),live_bytes=PAGE if entered else 0)
            if entered:self.query(self.f(b,t,'live'),entry,5)
            else:zero(self.f(b,t,'live'),'failed open has no fabricated live query')
            if kind=='complete' or c==3:
                after=self.frame(self.f(b,t,'after'));self.nx(after,after['greg'][16]);need(after['greg'][16] in plan['exits'],'actual exact original same-page exit')
                self.conserved(before,after,plan);result['after']=after
                self.eq(b,t,exit_seen=1,exit_index=plan['exits'].index(after['greg'][16]),completed=int(kind=='complete'),release_started=int(kind=='complete'),release_complete=int(kind=='complete'),release_result=0,
                    unexpected_seen=0,map_result=0,closed_bytes=PAGE if kind=='complete' else 0)
                self.permission(self.f(b,t,'close'),entry,1,error=-13 if c==3 else 0)
                zero(self.f(b,t,'unexpected'),'completed/close-error event has no unexpected frame');zero(self.f(b,t,'original'),'successful exact exit has no fabricated fault association')
            else:
                self.eq(b,t,exit_seen=0,exit_index=0,completed=0,release_started=0,release_complete=0,release_result=0,closed_bytes=0)
                for key in ('after','close'):zero(self.f(b,t,key),'no fabricated endpoint '+key)
                unexpected=kind=='fault' or c in (1,7);self.eq(b,t,unexpected_seen=int(unexpected),map_result=0 if kind=='fault' else int(unexpected))
                if unexpected:
                    f=self.frame(self.f(b,t,'unexpected'));result['unexpected']=f
                    if kind=='fault':
                        m=self.mapped(self.f(b,t,'original'),plan,f['greg'][16]);result['mapped']=m
                        need(m['kind']==1,'actual generated fault at copied source instruction')
                        d=plan['original'][m['head_index']];need(struct.unpack_from('<I',d,260)[0]==1,'faulting copied instruction is an actual single read')
                        g=f['greg'];address=int.from_bytes(f['si'][16:24],'little')
                        need(f['sig']==11 and struct.unpack_from('<iii',f['si'])==(11,0,2) and g[19:21]==(4,14) and g[22]==address and g[17]&(TF|RF)==RF,
                            'actual generated read fault SI/CR2/error/trap, no completion')
                        disp,base,index,scale,width,abits,seg,access,res=struct.unpack_from('<Q8I',d,192)
                        first=(disp+(g[GREG[base]] if base!=16 else 0)+(g[GREG[index]]*scale if index!=16 else 0))&U64
                        need(access==1 and abits==64 and canonical(first,width) and first<=address<first+width,'actual fault lies inside decoded live-register read span')
                    elif c==7:
                        pc=f['greg'][16];need(pc in plan['exits'],'supplied exit mutation retains real NX exit');self.nx(f,pc,True)
                        zero(self.f(b,t,'original'),'original NX exit is outside generated instruction map')
                    else:
                        self.nested(f,before);zero(self.f(b,t,'original'),'runtime gateway is outside generated instruction map')
                else:
                    zero(self.f(b,t,'unexpected'),'unentered failure has no unexpected frame');zero(self.f(b,t,'original'),'unentered failure has no PC mapping')
        if kind=='complete':
            self.eq(b,t,cleanup_started=0,cleanup_complete=0);zero(self.f(b,t,'cleanup'),'successful owner has no cleanup attempt')
            self.fetch(self.f(b,t,'final_fetch'),source,False)
        else:
            good=c not in (3,4);self.eq(b,t,cleanup_started=1,cleanup_complete=int(good))
            self.permission(self.f(b,t,'cleanup'),entry,1,error=-13 if c==3 else 0,sync_error=-13 if c==4 else 0)
            self.fetch(self.f(b,t,'final_fetch'),source,True)
        self.certificate_record(b,result,kind,c)
        return result

    def controls(self,current,result):
        c=self.control_words;kind=self.control;t='sr_record'
        before=self.f(self.b,'sro_wire','control_before');supplied=self.f(self.b,'sro_wire','supplied_before')
        if kind not in (1,14):zero(self.f(self.b,'sro_wire','nested_fp'),'unused nested observation wholly zero')
        want=[0]*40;want[0]=kind
        if not kind:
            need(c==tuple(want),'no fabricated control progress');zero(before,'unused control owner');zero(supplied,'unused supplied signal');return
        stage={1:1,2:2,3:2,4:2,5:5,6:6,7:7,8:8,9:8,10:8,11:11,12:9,13:10,14:12,15:13,16:14,17:15}[kind]
        want[1:4]=[stage,1,int(kind not in (1,14))]
        slot=self.i(current,t,'slot');entry=result['entry'] if result else 0
        if kind in (1,14):
            want[6:9]=[self.pid,self.pid,5];want[12]=1;want[18:23]=c[18:23]
            self.nested_fp(result['before'],result['unexpected'])
        elif kind in (2,3,4):want[8:14]=[entry,PAGE,5 if kind==2 else 1,324 if kind==4 else 10,1,1];want[15:17]=[1,1]
        elif kind==5:
            generation=self.i(current,t,'publication_generation');want[6:8]=[generation,generation^(1<<63)]
        elif kind in (6,7):
            pc=self.h[20] if kind==6 else result['unexpected']['greg'][16];want[6:8]=[pc,pc+1]
        elif kind in (8,9,10):want[6:8]=c[6:8] # independently whole-source inverted in source()
        elif kind==11:want[6:8]=[self.h[20],self.h[20]+1]
        elif kind==12:
            address=c[25];need(canonical(address,PAGE) and address%PAGE==0,'actual private alias mmap result')
            source=result['source'];need(address!=source['page'] and all(not(a<=address<a+64*PAGE) for a in self.v(self.owner,'scalar_owner','arena low_arena')),'actual alias is distinct from source/generated allocations')
            want[23:29]=[1,1,address,1,1,0]
        elif kind==13:want[23:32]=[1,1,0,1,1,0,1,1,0]
        need(c==tuple(want),'exact actual/supplied control protocol, no invented return markers')
        if kind==6:
            zero(before,'entry mutation has zero owner before capture');actual=self.frame(supplied,False);self.nx(actual,self.h[20])
            desired=bytearray(supplied);f=self.r.types['sr_frame']['fields']
            struct.pack_into('<Q',desired,f['si']['offset']+16,self.h[20]+1);struct.pack_into('<Q',desired,f['uc']['offset']+320,self.h[20]+1)
            need(self.f(current,t,'before')==desired,'whole actual pre-source frame versus only supplied SI/UC mirror mutation')
            return
        if kind==7:
            actual=self.frame(supplied,False);pc=result['unexpected']['greg'][16];self.nx(actual,pc)
            desired=bytearray(supplied);f=self.r.types['sr_frame']['fields']
            struct.pack_into('<Q',desired,f['si']['offset']+16,pc+1);struct.pack_into('<Q',desired,f['uc']['offset']+320,pc+1)
            for key in ('fs','gs','fs_result','gs_result','tls_complete'):
                x=f[key];desired[x['offset']:x['offset']+x['bytes']]=self.f(result['unexpected']['raw'],'sr_frame',key)
            need(result['unexpected']['raw']==desired,'whole actual endpoint versus only supplied SI mirror and actual TLS getters')
        else:zero(supplied,'unused supplied signal remains wholly zero')
        later=('cleanup_started','cleanup_complete','cleanup','final_fetch')
        if kind in (1,7,14):later+=('unexpected_seen','unexpected','map_result','original')
        elif kind in (2,4):later+=('open',)
        elif kind==3:later+=('open','live','live_bytes','redirected','exit_seen','exit_index','after','close')
        elif kind in (8,9,10,12,13):later+=('build_started','build_returned','build_result')+ (('source',) if kind in (8,9,10) else ())
        if kind==15:later+=('publication_generation',)
        if kind==16:later+=('gpr_written','flags_written','idle','idle_bytes')
        self.certificate_control_prefix(before,current,kind)
        later+=self.certificate_control_fields(kind)
        self.r.change(before,current,t,observed=later)
        if kind>=15:self.reuse_control(current,before,result)

    def clean_miss(self,b,slots):
        t='sr_record';rawsource=self.f(b,t,'source');ready=self.i(rawsource,'li2_region_source','ready');need(ready in (0,1),'actual clean source-ready bit')
        before=self.frame(self.f(b,t,'before'),bool(ready));pc=before['greg'][16];self.nx(before,pc)
        flags=self.i(b,t,'flags');need(flags&(TF|RF)==0 and before['greg'][17]==flags|RF,'clean miss keeps exact original frame')
        build,returned,result=self.v(b,t,'build_started build_returned build_result')
        need(build in (0,1) and returned==build,'complete actual clean-miss build prefix')
        allowed=('before','flags','source','build_started','build_returned','build_result');expected=bytearray(len(b))
        for key in allowed:
            f=self.r.types[t]['fields'][key];expected[f['offset']:f['offset']+f['bytes']]=self.f(b,t,key)
        need(b==expected,'no published slot/redirect/endpoint fabricated on a clean miss')
        if not ready:
            zero(rawsource,'unsupported source output wholly zero');need(not build and not result and self.i(self.owner,'scalar_owner','source_misses')>0,'source miss has no decoder work')
        else:
            source=self.source(rawsource);need(source['pc']==pc and all(s['source']['key']!=source['key'] for s in slots),'clean miss is a new actual immutable key')
            if not build:
                permits=self.r.items(self.reuse,'scalar_reuse','permits','srr_permit')
                need(len(slots)==64 and not any(self.i(p,'srr_permit','valid')for p in permits) and result==0 and
                    self.i(self.owner,'scalar_owner','capacity_misses')>0,'actual bounded capacity without a completed generation permit')
            else:
                codes=(1,2402,2403,2404);need(result in codes and q(self.f(self.owner,'scalar_owner','refusals'))[codes.index(result)]>0,'actual typed planner refusal, never an omitted accepted execution')
                scratch=self.f(self.owner,'scalar_owner','scratch');self.eq(scratch,'li2_region_plan',version=1,ready=0,decoder_result=0,page=source['page'],entry=pc,
                    generated=self.i(self.owner,'scalar_owner','low_arena' if pc<1<<31 else 'arena')+self.candidate_slot()*PAGE)
                need(self.f(scratch,'li2_region_plan','source')==source['bytes'],'complete last refused-plan input retained')
        return before

    def report_rows(self,outcome):
        expected=self.physical_rows(outcome);own=Fields(self.r,self.owner,'scalar_owner');cur=own.child('current','sr_record')
        names='initialized first_error used candidates source_misses plan_misses capacity_misses publications hits entries completed unexpected events plan_checks rseq_checks'.split()
        scalar=dict(version=2,**outcome,**{k:own.integer(k) for k in names},active=self.h[31],busy=self.h[32],decoding=self.h[53],signals=list(q(own.field('signals'))),
            refusals=list(q(own.field('refusals'))),exit_indices=list(q(own.field('exit_counts'))))
        scalar['current']=(cur.values('slot_present slot redirected exit_seen completed exit_index')+
            cur.child('open','sr_permission').values('started returned complete')+cur.child('close','sr_permission').values('started returned complete')+
            cur.values('release_started release_complete cleanup_started cleanup_complete')+
            [cur.child('before','sr_frame').integer('complete'),cur.child('after','sr_frame').integer('complete'),cur.integer('unexpected_seen'),cur.child('unexpected','sr_frame').integer('complete')]+
            cur.child('original','li2_region_pc').values('ready kind head_index source_offset')+cur.values('idle_bytes live_bytes closed_bytes')+
            cur.child('final_fetch','li2_fetch_progress').values('held complete')+cur.values('build_started build_returned build_result gpr_written flags_written'))
        reuse=dict(version=1,**outcome)
        reuse.update({k:self.i(self.reuse,'scalar_reuse',k)for k in ('generation','retirement_attempts','retirements','claims','permits_issued','pending','retiring','cursor')})
        expected.update(scalar=scalar,reuse=reuse,certificate=self.certificate_report(outcome),vdso=(self.h[56],self.h[57]));return expected

    def finish(self,exit_status):
        outcome=self.header(exit_status);h=self.h;r=self.r;ot='scalar_owner';o=self.owner;c=self.control;failed=exit_status==125 and self.mapping_code is None;mode=self.app['mode']
        self.eq(o,ot,initialized=1,metadata_registered=1,arena_registered=1,allocated=1,low_arena_registered=1,low_allocated=1,first_error=0 if self.mapping_code is not None else outcome['failure_code'],first_detail=0 if self.mapping_code is not None else outcome['detail_abs'])
        arena,low,used=self.v(o,ot,'arena low_arena used')
        need(canonical(arena,64*PAGE) and arena%PAGE==0 and 0<low<=2**31-64*PAGE and low%PAGE==0 and
            (low+64*PAGE<=arena or arena+64*PAGE<=low) and used<=64,'both actual disjoint protected arenas and unchanged total64 capacity')
        self.eq(o,ot,allocation_result=arena,low_allocation_result=low)
        publications=self.i(o,ot,'publications');need(used==min(publications,64),'exact bounded residents for completed publications')
        self.query(self.f(o,ot,'initial'),arena,3,64);self.query(self.f(o,ot,'low_initial'),low,3,64)
        session=self.f(o,ot,'session');self.eq(session,'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        need(self.i(session,'li2_step_session','sync_query')<1<<63 and self.i(session,'li2_step_session','sync_query')&96==96,'actual core synchronization session')
        self.reuse_registry(0 if self.mapping_code is not None else exit_status)
        generated=self.f(self.b,'sro_wire','generated');slots=[]
        for i,b in enumerate(r.items(o,ot,'slots','sr_slot')):
            if i>=used:zero(b,'whole unused immutable slot');zero(generated[i*PAGE:(i+1)*PAGE],'whole unused generated page capture');continue
            s=self.slot(b,i,q(self.f(self.reuse,'scalar_reuse','live'))[i]);slots.append(s)
            need(s['entry']==q(self.f(self.reuse,'scalar_reuse','entry'))[i],'independent cleanup address equals actual resident publication address')
        self.history_rows()
        for i,s in enumerate(slots):
            image=self.retired[s['generation']]['slot']['page'] if c==16 and s['source']['pc']==h[20] else s['page']
            need(generated[i*PAGE:(i+1)*PAGE]==image,'every actual terminal generated byte including explicit stale-image control')
        need(h[40]==used,'all actual used slots captured')
        entries,completed,hits=self.v(o,ot,'entries completed hits');prepub=c in (8,9,10,12,13,14)
        self.eq(o,ot,candidates=sum(self.i(o,ot,k) for k in ('source_misses','plan_misses','capacity_misses','publications','hits'))+int(c==6 or prepub),
            entries=publications+hits-int(c in (2,4,5,11,15,16,17)),completed=entries-int(failed and c not in (2,4,5,6,8,9,10,11,12,13,14,15,16,17)),unexpected=int(failed and not c or c in (1,7,14)))
        need(sum(q(self.f(o,ot,'refusals')))==self.i(o,ot,'plan_misses') and sum(q(self.f(o,ot,'exit_counts')))==completed and
            sum(q(self.f(o,ot,'signals')))==self.i(o,ot,'events'),'complete distinct refusal/exit/signal partitions')
        self.eq(o,ot,plan_checks=publications+self.i(self.reuse,'scalar_reuse','retirement_attempts')+int(c in (8,9,10,12,13)),rseq_checks=publications)
        self.certificate_counters(publications,hits,c,failed)
        current=self.f(o,ot,'current');last=self.f(o,ot,'last');rows=r.items(self.b,'sro_wire','entries','sro_entry')
        count=0 if c==6 or self.mapping_code is not None else self.app['invocations'];need(count in (0,1,2) and h[24]==count and h[25]==(0 if failed else count),'all fixed focal attempts and genuine completions')
        outputs=[];bundles=[]
        for i,e in enumerate(rows):
            if i>=count:zero(e,'whole unused focal row capacity');continue
            et='sro_entry';self.eq(e,et,present=1,ordinal=i,committed=int(not failed),source_bytes=PAGE,terminal_source_bytes=PAGE,slot_observed=int(not prepub))
            raw=self.f(e,et,'owner');result=self.record(raw,slots,'complete' if not failed else 'fault' if not c else 'control',True)
            need(result['source']['pc']==h[20] and result['source']['object']==self.image['main_object'],'focal record is exact authenticated main head')
            result['source_page']=self.f(e,et,'source_page');result['terminal_source_page']=self.f(e,et,'terminal_source_page')
            need(result['source_page']==result['terminal_source_page']==self.app['source_page'],'whole actual main source throughout ownership')
            result['before_memory']=self.memory(self.f(e,et,'before_memory'),result['source'],0)
            stage=2 if failed and not c and self.app['base_mode'] in (6,8) else 1 if failed else 0
            if stage==2:need(result['mapped'] is not None and self.i(raw,'sr_record','cleanup_complete')==1,'actual mapped read fault and complete retire before readback')
            result['after_memory']=self.memory(self.f(e,et,'after_memory'),result['source'],stage,result['entry'] if stage==2 else 0)
            entered=self.i(raw,'sr_record','redirected')==1;self.eq(e,et,generated_bytes=PAGE if entered else 0)
            if entered:
                need(self.f(e,et,'generated_page')==self.history[result['publication_generation']]['page'],'whole actual generated RX image at redirect')
                self.redirected(self.f(e,et,'redirected'),result['before'],result['entry'])
                bundle=self.owners(self.f(e,et,'redirected_owners'),True);self.footprint(bundle,result['plan'],i);bundles.append(bundle)
            else:
                for key in ('generated_page','redirected','redirected_owners'):zero(self.f(e,et,key),'no invented redirect '+key)
            if not failed:
                bundle=self.owners(self.f(e,et,'completed_owners'));self.footprint(bundle,result['plan'],i)
                # The live exit check preserves the actual historical NONE
                # footprint and independently rechecks the current pin.
                need(self.i(self.f(bundle,'sro_owners','rseq'),'li2_rseq_state','epoch')==self.i(self.f(bundles[-1],'sro_owners','rseq'),'li2_rseq_state','epoch'),'same registration epoch throughout actual owner')
            else:zero(self.f(e,et,'completed_owners'),'failed entry has no completed owner snapshot')
            need((result['before']['fs'],result['before']['gs'])==tuple(self.app['machine'][1:3]),'focal actual TLS joins application prefix')
            gb,ga=(q(self.f(e,et,k)) for k in ('global_before','global_after'));need(gb[4]==min(gb[0],64) and gb[2]==gb[3] and gb[0]<=publications and gb[1]<=hits,'source hook observes quiet global counters and bounded residents')
            if not failed:
                build=self.i(raw,'sr_record','build_started');need(ga==(gb[0]+build,gb[1]+1-build,gb[2]+1,gb[3]+1,min(gb[0]+build,64)),'exact per-entry publication/hit/entry/completion deltas')
            else:need(ga==(0,)*5,'failed attempt has no fabricated global-after snapshot')
            terminal=self.i(e,et,'terminal');need(terminal in (0,1),'actual terminal row marker')
            if terminal:need(h[30]==i and raw==current,'whole final focal row equals actual current owner')
            outputs.append(result)
        focal=q(self.f(self.b,'sro_wire','focal'));focal_exits=q(self.f(self.b,'sro_wire','focal_exits'))
        need(focal==(sum(self.i(self.f(e,'sro_entry','owner'),'sr_record','build_started') for e in rows[:count] if self.i(e,'sro_entry','slot_observed')),
            sum(1-self.i(self.f(e,'sro_entry','owner'),'sr_record','build_started') for e in rows[:count] if self.i(e,'sro_entry','slot_observed')),
            sum(self.i(self.f(e,'sro_entry','owner'),'sr_record','redirected') for e in rows[:count]),h[25],count),'all actual focal source/slot/entry/completion counters')
        expected_exits=[0]*8
        for e in rows[:count]:
            raw=self.f(e,'sro_entry','owner')
            if self.i(raw,'sr_record','completed'):expected_exits[self.i(raw,'sr_record','exit_index')]+=1
        need(focal_exits==tuple(expected_exits) and all(focal_exits[i]<=q(self.f(o,ot,'exit_counts'))[i] for i in range(8)),'focal exact exit partition is a subset of global completions')
        if c==6:
            before=self.frame(self.f(current,'sr_record','before'),False);self.nx(before,h[20],True)
            expected=bytearray(len(current))
            for key in ('before','flags','final_fetch'):
                f=r.types['sr_record']['fields'][key];expected[f['offset']:f['offset']+f['bytes']]=self.f(current,'sr_record',key)
            need(current==expected and h[30]==2,'exact pre-source refusal owner prefix')
            # The fixed non-hash head passes prepare15 but control6 fails sr_nx
            # before region_source. No later fetch_validate has run.
            ft='li2_fetch_progress';f=self.f(current,'sr_record','final_fetch');self.eq(f,ft,held=1,complete=1,first_error=0,first_detail=0,identity_observed=1,pages_copied=1,bytes_copied=15,last_backing_page=0,last_backing_observed=0,validation_calls=0)
            need(self.i(f,ft,'sequence')>0,'real complete pre-source held fetch');self.maps(self.f(f,ft,'preparation'))
            zero(self.f(f,ft,'validation'),'pre-source refusal has no fetch validation observation')
        elif failed:need(h[30]==0 and self.i(rows[0],'sro_entry','terminal')==1,'actual failed focal terminal prefix')
        elif self.i(current,'sr_record','completed'):
            self.record(current,slots);need(current==last,'whole current completed owner equals retained last')
        else:self.clean_miss(current,slots)
        if completed:self.record(last,slots)
        else:zero(last,'no invented prior successful owner')
        if not failed:
            focal_current=self.i(self.f(self.f(current,'sr_record','source'),'li2_region_source','key'),'li2_region_source_key','entry')==h[20]
            need(h[30]==(count-1 if focal_current else 2),'actual current focal index or nonfocal sentinel')
            if self.mapping_code is None:need(h[31:38]==(0,0,0,1,0,0,1),'actual successful idle owner at final report')
            else:self.mapping_idle_prefix()
            self.eq(self.f(self.b,'sro_wire','terminal_fetch'),'li2_fetch_progress',held=0,first_error=0)
        else:
            entered=c not in (2,4,5,6,8,9,10,11,12,13,14,15,16,17);routed=c not in (6,8,9,10,12,13,14)
            need(h[31:34]==(int(entered),1,1) and h[34]==int(bool(c and c!=7)) and h[35:38]==(int(routed),8 if routed else 0,1) and
                h[38]==self.i(current,'sr_record','flags'),'actual interrupted owner active/handling/route/flags prefix')
            need(self.f(self.b,'sro_wire','terminal_fetch')==self.f(current,'sr_record','final_fetch'),'whole failed fetch capture equals unreleased current ticket')
        self.reuse_final(current,outputs,slots,0 if self.mapping_code is not None else exit_status)
        self.owners(self.f(self.b,'sro_wire','terminal_owners'));self.controls(current,outputs[0] if outputs else None);self.scratch(slots)
        self.certificate_finish(outputs,slots,failed)
        expected=self.report_rows(outcome)
        return dict(mode=mode,control=c,entries=outputs,focal=focal,terminal_expected=expected,
            supplied_before=self.frame(self.f(self.b,'sro_wire','supplied_before'),False) if c==6 else None,
            summary=dict(focal_entries=count,focal_completed=h[25],global_entries=entries,global_completed=completed,publications=publications,
                required_failed_operation=int(failed),supplied_control=int(bool(c)),held_fetch=self.i(self.f(self.b,'sro_wire','terminal_fetch'),'li2_fetch_progress','held'),
                cleanup_complete=self.i(current,'sr_record','cleanup_complete')))

    def permit(self,b,generation=None,valid=None):
        g,c,v=self.v(b,'srr_permit','generation completion valid')
        need(v in (0,1) and (g==c==0 or 0<g<=self.i(self.reuse,'scalar_reuse','generation') and
            g<=c<=self.i(self.owner,'scalar_owner','completed')),'actual bounded generation/completion permit')
        if generation is not None:need(g==generation,'permit belongs to exact publication generation')
        if valid is not None:need(v==valid,'exact permit consumption/availability state')
        return g,c,v

    def candidate_slot(self):
        used=self.i(self.owner,'scalar_owner','used')
        if used<64:return used
        cursor=self.i(self.reuse,'scalar_reuse','cursor')
        permits=self.r.items(self.reuse,'scalar_reuse','permits','srr_permit')
        eligible=[(cursor+n)%64 for n in range(64) if self.i(permits[(cursor+n)%64],'srr_permit','valid')]
        need(eligible,'a planned replacement has an actual completed-generation permit')
        return eligible[0]

    def reuse_registry(self,exit_status):
        b=self.reuse;t='scalar_reuse';o=self.owner;ot='scalar_owner';c=self.control
        publications,hits,entries,completed,used=self.v(o,ot,'publications hits entries completed used')
        self.eq(b,t,initialized=1,registered=1,generation=publications,
            retirement_attempts=max(publications-64,0),retirements=max(publications-64,0),
            claims=publications+hits,permits_issued=completed,cursor=max(publications-64,0)%64,retiring=0)
        pending=int(exit_status==125 and c not in (6,8,9,10,12,13,14))
        self.eq(b,t,pending=pending)
        live=q(self.f(b,t,'live'));predecessors=q(self.f(b,t,'predecessor'));addresses=q(self.f(b,t,'entry'))
        expected=tuple(0 if i>=used else i+1 if publications<=64+i else 65+i+64*((publications-65-i)//64) for i in range(64))
        need(live==expected and predecessors==tuple(max(g-64,0)for g in live),
            'every resident generation and predecessor follows bounded completed round-robin replacement')
        self.live=live;slot,target=self.v(b,t,'slot target')
        need(publications>0 and slot<used and target==addresses[slot],
            'stable protected last-claim slot and independent cleanup address')
        current=self.f(o,ot,'current')
        if pending:need(self.v(current,'sr_record','slot_present slot')==(1,slot),'pending cleanup belongs to actual current slot')
        for i,address in enumerate(addresses):
            if i>=used:need(address==0,'unused independent address stays zero')
            else:need(address in (self.i(o,ot,'arena')+i*PAGE,self.i(o,ot,'low_arena')+i*PAGE),'every independent address belongs to its allocated logical slot')
        claimed=self.f(b,t,'claimed');permit_rows=self.r.items(b,t,'permits','srr_permit');ordinals=[]
        for i,p in enumerate(permit_rows):
            if i>=used:zero(p,'whole unused permit');continue
            g,completion,v=self.permit(p)
            if completion:ordinals.append(completion)
            if pending and i==slot:
                expected_valid=int(c==17);self.permit(p,valid=expected_valid)
                cg,cc,cv=self.permit(claimed)
                need((g,completion)==(cg,cc) and (cv==1 or cg==cc==cv==0),'actual consumed permit retained without a fabricated new completion')
            else:self.permit(p,live[i],1)
        need(len(ordinals)==len(set(ordinals)),'distinct actual completion ordinals for resident permits')
        if pending or self.i(current,'sr_record','completed'):
            self.permit(claimed)
        else:zero(claimed,'new clean/unpublished attempt has no claimed predecessor permit')

    def retirement(self,b):
        t='srr_retirement';slot,oldgen,newgen,completion,ordinal,oldentry,newentry=self.v(b,t,
            'slot old_generation new_generation completion ordinal old_entry new_entry')
        self.eq(b,t,started=1,consumed=1,old_verified=1,target_ready=1,replaced=1,verified_bytes=PAGE)
        need(0<=slot<64 and 0<oldgen and newgen==oldgen+64 and newgen<=self.i(self.reuse,'scalar_reuse','generation') and
            ordinal==newgen-64 and slot==(ordinal-1)%64 and oldgen<=completion<=self.i(self.owner,'scalar_owner','completed'),
            'actual retired generation, completion and bounded replacement ordinal')
        previous=self.slot(self.f(b,t,'old_slot'),slot,oldgen)
        need(oldentry==previous['entry'] and newentry in (self.i(self.owner,'scalar_owner','arena')+slot*PAGE,
            self.i(self.owner,'scalar_owner','low_arena')+slot*PAGE),'actual prior and target arena entries')
        self.query(self.f(b,t,'old_idle'),oldentry,1)
        self.permission(self.f(b,t,'revoked'),oldentry,1)
        self.permission(self.f(b,t,'target_closed'),newentry,1)
        self.permission(self.f(b,t,'writable'),newentry,3)
        zero(self.f(b,t,'cleanup'),'completed retirement has no fabricated abort cleanup')
        result=dict(raw=b,slot=previous,index=slot,old_generation=oldgen,new_generation=newgen,
            completion=completion,entry=newentry)
        if newgen in self.retired:need(self.retired[newgen]['raw']==b,'whole repeated retirement snapshot agrees')
        else:self.retired[newgen]=result
        return result

    def history_rows(self):
        retired=self.f(self.reuse,'scalar_reuse','retirement');generation=self.i(self.reuse,'scalar_reuse','generation')
        if generation>64:
            row=self.retirement(retired);need(row['new_generation']==generation,'last global retirement belongs to latest publication')
        else:zero(retired,'no retirement before actual64 residents')
        for e in self.r.items(self.b,'sro_wire','entries','sro_entry'):
            slot_raw=self.f(e,'sro_entry','reuse_slot');t=self.f(e,'sro_entry','reuse_retirement')
            claim=self.f(e,'sro_entry','reuse_claim');g=self.i(e,'sro_entry','reuse_generation')
            if not self.i(e,'sro_entry','slot_observed'):
                need(g==0,'unpublished focal has no generation');zero(slot_raw,'no invented focal slot');zero(t,'no invented focal retirement');zero(claim,'no invented focal claim');continue
            raw=self.f(e,'sro_entry','owner');index=self.i(raw,'sr_record','slot');actual=self.slot(slot_raw,index,g)
            need(actual['source']['pc']==self.h[20],'by-value focal generation is exact actual application head')
            build=self.i(raw,'sr_record','build_started');before=q(self.f(e,'sro_entry','global_before'))
            need(g==before[0]+1 if build else g<=before[0],'focal generation is new publication or actual retained hit')
            if build and g>64:
                row=self.retirement(t);need(row['new_generation']==g and row['index']==index and row['entry']==actual['entry'],'focal retirement binds its exact new generation')
                self.permit(claim,row['old_generation'],1)
                need(row['completion']<=before[3],'replacement permit precedes the actual new focal entry')
                need(self.i(claim,'srr_permit','completion')==row['completion'],'actual focal consumed retirement permit')
            elif build:zero(t,'virgin publication has no retirement');zero(claim,'virgin publication claims no previous completion')
            else:
                zero(t,'hit performs no retirement');self.permit(claim,g,1)
                need(self.i(claim,'srr_permit','completion')<=before[3],'hit permit came from a genuine earlier completed entry')
        for newgen,row in self.retired.items():
            if newgen in self.history:
                need(row['entry']==self.history[newgen]['entry'] and row['index']==self.history[newgen]['index'],
                    'historical replacement and retained generation agree on physical slot')

    def reuse_control(self,current,before,result):
        c=self.control;t='sro_reuse_control';b=self.f(self.b,'sro_wire','reuse_control')
        need(c in (15,16,17),'only three explicit additional actual reuse controls')
        generation=result['publication_generation'];retired=self.retired[generation]
        self.eq(b,t,started=1,mutated=1,generation_before=generation,
            generation_after=retired['old_generation'] if c==15 else generation,copied=PAGE if c==16 else 0)
        self.eq(before,'sr_record',publication_generation=generation,build_started=1,build_returned=1,build_result=0)
        self.eq(current,'sr_record',publication_generation=retired['old_generation'] if c==15 else generation)
        p0=self.f(b,t,'permit_before');p1=self.f(b,t,'permit_after')
        self.eq(p0,'srr_permit',generation=retired['old_generation'],completion=retired['completion'],valid=0)
        self.eq(p1,'srr_permit',generation=retired['old_generation'],completion=retired['completion'],valid=int(c==17))
        index=result['slot'];actual=self.r.items(self.reuse,'scalar_reuse','permits','srr_permit')[index]
        need(p1==actual,'actual supplied stale permit remains in protected terminal state')
        if c==16:
            need(retired['slot']['page']!=self.history[generation]['page'],'stale-code control writes a genuinely different retired image')
            self.permission(self.f(b,t,'writable'),result['entry'],3);self.permission(self.f(b,t,'closed'),result['entry'],1)
        else:
            zero(self.f(b,t,'writable'),'no invented stale-code write transition');zero(self.f(b,t,'closed'),'no invented stale-code close transition')

    def reuse_final(self,current,outputs,slots,exit_status):
        c=self.control;b=self.reuse;t='scalar_reuse';slot,target=self.v(b,t,'slot target')
        pending=self.i(b,t,'pending');claimed=self.f(b,t,'claimed')
        record_generation=self.i(current,'sr_record','publication_generation')
        if pending or self.i(current,'sr_record','completed'):
            generation=self.live[slot];need(record_generation==(generation-64 if c==15 else generation),
                'actual current generation matches pending or completed resident except exact stale control')
            if self.i(current,'sr_record','build_started'):
                if generation<=64:zero(claimed,'actual virgin claim has no predecessor')
                else:
                    row=self.retired[generation];self.permit(claimed,row['old_generation'],1)
                    need(self.i(claimed,'srr_permit','completion')==row['completion'],'current replacement consumed exact recorded permit')
            else:self.permit(claimed,generation,1)
        if pending:
            self.eq(self.b,'sro_wire',reuse_pending_bytes=PAGE)
            image=self.retired[self.live[slot]]['slot']['page'] if c==16 else self.history[self.live[slot]]['page']
            need(self.f(self.b,'sro_wire','reuse_pending_page')==image,'whole actual pending page uses independent cleanup address')
        else:
            self.eq(self.b,'sro_wire',reuse_pending_bytes=0);zero(self.f(self.b,'sro_wire','reuse_pending_page'),'no invented pending page')
        if c<15:zero(self.f(self.b,'sro_wire','reuse_control'),'whole unused new reuse control')
        # Bind completion ordinals to independently captured endpoints where
        # history is available. A focal's own consumed pre-entry claim is not
        # its subsequent completion; only earlier observed endpoints apply.
        endpoints={}
        rows=self.r.items(self.b,'sro_wire','entries','sro_entry')
        for e in rows:
            if not self.i(e,'sro_entry','slot_observed'):continue
            claim=self.f(e,'sro_entry','reuse_claim');cg,cc,_=self.permit(claim)
            if cg in endpoints:need(cc>=endpoints[cg],'later focal claim follows independently observed completion')
            retired=self.f(e,'sro_entry','reuse_retirement')
            if self.i(retired,'srr_retirement','started'):
                rg,rc=self.v(retired,'srr_retirement','old_generation completion')
                if rg in endpoints:need(rc>=endpoints[rg],'focal retirement follows independently observed completion')
            if self.i(e,'sro_entry','committed'):
                endpoints[self.i(e,'sro_entry','reuse_generation')]=q(self.f(e,'sro_entry','global_after'))[3]
        last_generation=self.i(self.f(self.owner,'scalar_owner','last'),'sr_record','publication_generation')
        completed=self.i(self.owner,'scalar_owner','completed')
        for p in self.r.items(b,t,'permits','srr_permit'):
            g,completion,_=self.permit(p)
            if g in endpoints:need(completion>=endpoints[g],'terminal permit follows independently observed focal completion')
            if g and g==last_generation:need(completion==completed,'actual last completed generation has exact terminal completion ordinal')
        retired=self.f(b,t,'retirement')
        if self.i(retired,'srr_retirement','started'):
            g,completion=self.v(retired,'srr_retirement','old_generation completion')
            if g in endpoints:need(completion>=endpoints[g],'last retirement follows independently observed focal completion')
        for result in outputs:
            if result['entry']:
                generation=result['publication_generation']
                need(generation in self.history and self.history[generation]['index']==result['slot'],
                    'every focal frame retains exact by-value generation history')


def boundary_requests(data,layout):
    return boundary_reader.requests(Reader(data,layout))


def read(data,layout,image,app,pid,cpu,exit_status,control=0,*,boundaries):
    need(type(pid)is int and pid>0 and type(cpu)is int and cpu>=0 and type(control)is int and 0<=control<=17 and type(exit_status)is int,'actual reuse subject identity/control')
    need(type(image)is dict and type(image.get('uid'))is int and 0<=image['uid']<1<<32,'actual explicit launch UID')
    mode=app['mode'];need(type(mode)is int and 0<=mode<=12 and (not control or mode==0),'original13 real modes/14 controls plus three actual reuse controls')
    need(app['base_mode']==(4 if mode>=11 else mode) and app['invocations']==(2 if mode>=11 else 1),'exact repeat/generation invocation count')
    need(exit_status==(125 if control or 5<=mode<=10 else 0),'exact required failure or completed application exit')
    return Check(Reader(data,layout),image,app,pid,cpu,control,boundaries).finish(exit_status)


def terminal(parsed,scalar,unrolled,owner,reuse,certificate):
    result=donor.terminal(parsed,scalar,unrolled,owner)
    need(reuse==owner['terminal_expected']['reuse'],'every reuse report field equals actual protected registry')
    need(certificate==owner['terminal_expected']['certificate'],'every certificate report field equals actual protected store')
    return result


BASE_COUNTS={(0, 0): 86, (1, 0): 86, (2, 0): 86, (3, 0): 86, (4, 0): 86, (5, 0): 88, (6, 0): 88, (7, 0): 88, (8, 0): 88, (9, 0): 88, (10, 0): 88, (11, 0): 96, (12, 0): 96, (0, 1): 102, (0, 2): 82, (0, 3): 86, (0, 4): 82, (0, 5): 82, (0, 6): 49, (0, 7): 83, (0, 8): 68, (0, 9): 68, (0, 10): 68, (0, 11): 82, (0, 12): 68, (0, 13): 68, (0, 14): 81, (0, 15): 82, (0, 16): 82, (0, 17): 82}
CONTROL_COUNTS={(0, 0): 140, (1, 0): 140, (2, 0): 140, (3, 0): 140, (4, 0): 140, (5, 0): 142, (6, 0): 142, (7, 0): 142, (8, 0): 142, (9, 0): 142, (10, 0): 142, (11, 0): 157, (12, 0): 157, (0, 1): 156, (0, 2): 136, (0, 3): 140, (0, 4): 136, (0, 5): 136, (0, 6): 106, (0, 7): 137, (0, 8): 122, (0, 9): 122, (0, 10): 122, (0, 11): 136, (0, 12): 122, (0, 13): 122, (0, 14): 135, (0, 15): 136, (0, 16): 136, (0, 17): 136}

def controls(data,layout,image,app,pid,cpu,exit_status,control=0,*,boundaries):
    """Finite supplied-copy refusals. No native operation or acceptance credit."""
    original=hashlib.sha256(data).hexdigest();read(data,layout,image,app,pid,cpu,exit_status,control,boundaries=boundaries)
    types=layout['types']
    def where(path):
        at=0;t='sro_wire'
        for key,index,child in path:
            field=types[t]['fields'][key];at+=field['offset']
            if index is not None:
                at+=index*(types[child]['bytes'] if child else 8)
            if child:t=child
        return at
    tests=[]
    def add(name,path,byte=0):tests.append((name,where(path)+byte))
    for index in (0,2,27,28,39,40,48,50,51,52):add('header_'+str(index),[('h',index,None)])
    add('nested_uid_authority',[('sink_initial',None,'stat'),('st_uid',None,None)])
    add('owner_publications',[('owner',None,'scalar_owner'),('publications',None,None)])
    add('owner_first_error',[('owner',None,'scalar_owner'),('first_error',None,None)])
    add('actual_native_closed',[('terminal_native_counts',None,'li2_native_counts'),('closed',None,None)])
    add('actual_global_close',[('terminal_global_close',None,'li2_native_close'),('complete',None,None)])
    add('terminal_rseq_epoch',[('terminal_owners',None,'sro_owners'),('rseq',None,'li2_rseq_state'),('epoch',None,None)])
    add('terminal_pair_live',[('terminal_owners',None,'sro_owners'),('pair',None,P),('live',None,None)])
    count=0 if control==6 else app['invocations']
    if count:
        base=[('entries',0,'sro_entry')]
        for name,tail in (
            ('source_page',[('source_page',None,None)]),('terminal_source',[('terminal_source_page',None,None)]),
            ('data_memory',[('before_memory',None,'li2_sro_memory'),('data',None,None)]),
            ('after_stack',[('after_memory',None,'li2_sro_memory'),('stack',None,None)]),
            ('source_generation',[('owner',None,'sr_record'),('source',None,'li2_region_source'),('key',None,'li2_region_source_key'),('page',None,'li2_fetch_page'),('generation',None,None)]),
            ('cleanup_prefix',[('owner',None,'sr_record'),('cleanup_complete',None,None)]),
            ('maps_io',[('after_memory',None,'li2_sro_memory'),('initial',None,'li2_sro_maps'),('maps',None,'li2_fetch_map_progress'),('observation',None,'li2_maps_observation'),('io_performed',None,None)])):
            add(name,base+tail)
        add('before_fp_metadata',base+[('owner',None,'sr_record'),('before',None,'sr_frame'),('frame',None,'li2_step_frame'),('fp',None,None)],464)
        if control not in (2,4,5,8,9,10,11,12,13,14,15,16,17):add('whole_actual_generated_page',base+[('generated_page',None,None)],1796)
    else:add('actual_unmutated_entry',[('supplied_before',None,'sr_frame'),('si',None,None)],16)
    tests.extend([('footer_status',len(data)-16),('footer_extent',len(data)-48)])
    tests=[(name,[offset]) for name,offset in tests]
    if control in (1,14):
        inners=[
            [('entries',0,'sro_entry'),('owner',None,'sr_record'),('unexpected',None,'sr_frame')],
            [('owner',None,'scalar_owner'),('current',None,'sr_record'),('unexpected',None,'sr_frame')]]
        masks=[];oldmasks=[]
        for inner in inners:
            copied=inner+[('frame',None,'li2_step_frame')]
            masks.extend([where(inner+[('uc',None,None)])+296,where(copied+[('mask',None,None)])])
            oldmasks.extend([where(inner+[('uc',None,None)])+40+21*8,where(copied+[('greg',None,None)])+21*8])
        tests.extend([
            ('nested_coherent_mask',masks),('nested_coherent_oldmask',oldmasks),
            ('nested_actual_fs',[where(inner+[('fs',None,None)]) for inner in inners]),
            ('nested_actual_gs',[where(inner+[('gs',None,None)]) for inner in inners])])
    nested=[('nested_fp',None,'uho_nested_fp')]
    semantic=set()
    if control in (1,14):
        for name,index in (('nested_snapshot_complete',2),('nested_snapshot_request',11),
                           ('nested_snapshot_rsp',5),('nested_snapshot_copied',6)):
            tests.append((name,[where(nested+[('h',index,None)])]))
        tests.extend([
            ('nested_snapshot_one_xmm',[where(nested+[('zero',None,None)])+160]),
            ('nested_snapshot_coherent_xmm',[where(nested+[(key,None,None)])+160 for key in ('zero','ones')]),
            ('nested_snapshot_bv',[where(nested+[(key,None,None)])+512 for key in ('zero','ones')]),
            ('nested_snapshot_compacted',[where(nested+[(key,None,None)])+520 for key in ('zero','ones')]),
            ('nested_snapshot_zero_tail',[where(nested+[('zero',None,None)])+FP-1]),
            ('nested_snapshot_ones_tail',[where(nested+[('ones',None,None)])+FP-1])])
        sp=int.from_bytes(data[where(nested+[('h',6,None)]):where(nested+[('h',6,None)])+8],'little')
        lo=int.from_bytes(data[where(nested+[('h',3,None)]):where(nested+[('h',3,None)])+8],'little')
        address=where(inners[0]+[('frame',None,'li2_step_frame'),('fp_address',None,None)])
        fp=int.from_bytes(data[address:address+8],'little')
        tests.extend([
            ('nested_destination_reserved',[where(nested+[('stack',None,None)])+fp-lo+416]),
            ('nested_actual_reserved',[where(inner+[('frame',None,'li2_step_frame'),('fp',None,None)])+416 for inner in inners]),
            ('nested_actual_xmm',[where(inner+[('frame',None,'li2_step_frame'),('fp',None,None)])+160 for inner in inners]),
            ('nested_actual_bv',[where(inner+[('frame',None,'li2_step_frame'),('fp',None,None)])+512 for inner in inners]),
            ('nested_uncopied_capacity',[where(nested+[('stack',None,None)])+sp]),
            ('nested_coherent_fp_pointer',[where(inner+[('uc',None,None)])+224 for inner in inners]+
                [where(inner+[('frame',None,'li2_step_frame'),('fp_address',None,None)]) for inner in inners])])
        semantic={'nested_snapshot_coherent_xmm','nested_snapshot_bv','nested_destination_reserved',
                  'nested_actual_reserved','nested_actual_xmm','nested_actual_bv'}
    else:tests.append(('unused_nested_observation',[where(nested+[('h',0,None)])]))
    need(len(tests)==(29,48,28,29,28,28,21,29,28,28,28,28,28,28,47,28,28,28)[control],
        'every original owner corruption retained under exact scalar field paths')
    # Additional general-graph/custody observations, all on supplied copies.
    for name in ('candidates','source_misses','plan_misses','capacity_misses','hits','entries','completed','unexpected','events','plan_checks','rseq_checks'):
        tests.append(('scalar_'+name,[where([('owner',None,'scalar_owner'),(name,None,None)])]))
    for name in ('signals','refusals','exit_counts'):
        tests.append(('scalar_partition_'+name,[where([('owner',None,'scalar_owner'),(name,0,None)])]))
    for i in (26,29,41,53,54,55,24,25):tests.append(('scalar_header_'+str(i),[where([('h',i,None)])]))
    for name in ('focal','focal_exits'):tests.append(('scalar_'+name,[where([(name,0,None)])]))
    if count:
        base=[('entries',0,'sro_entry')]
        for name,path,byte in (
            ('before_stage',[('before_memory',None,'li2_sro_memory'),('stage',None,None)],0),
            ('after_stage',[('after_memory',None,'li2_sro_memory'),('stage',None,None)],0),
            ('stack_observed',[('before_memory',None,'li2_sro_memory'),('stack_observed',None,None)],0),
            ('stack_missing',[('before_memory',None,'li2_sro_memory'),('stack_missing',None,None)],0),
            ('whole_after_data',[('after_memory',None,'li2_sro_memory'),('data',None,None)],8191),
            ('physical_snapshot',[('before_memory',None,'li2_sro_memory'),('initial',None,'li2_sro_maps'),('after',None,'li2_maps_stats'),('acquisitions',None,None)],0)):
            tests.append((name,[where(base+path)+byte]))
    if control not in (6,8,9,10,12,13,14):
        address=where([('entries',0,'sro_entry'),('owner',None,'sr_record'),('slot',None,None)])
        slot=int.from_bytes(data[address:address+4],'little')
        plan=where([('entries',0,'sro_entry'),('reuse_slot',None,'sr_slot'),('plan',None,'li2_region_plan')])
        for name,offset in (('heads',8),('blocks',12),('exits',16),('maps',20),('longest',24),('decoder_calls',40),
                ('source',80),('image',4176),('image_tail',8271),('original_effect',8272+284),('emitted_effect',28032+284),
                ('head_successor',47792+20),('exit_pc',49840),('pc_map',49904+32)):
            tests.append(('whole_plan_'+name,[plan+offset]))
    if not control and app['mode'] not in range(5,11) or control==3:
        after=[('entries',0,'sro_entry'),('owner',None,'sr_record'),('after',None,'sr_frame')]
        frame=after+[('frame',None,'li2_step_frame')]
        tests.extend([
            ('actual_conserved_rsp',[where(frame+[('greg',None,None)])+15*8,where(after+[('uc',None,None)])+40+15*8]),
            ('actual_conserved_flags',[where(frame+[('greg',None,None)])+17*8+2,where(after+[('uc',None,None)])+40+17*8+2]),
            ('actual_conserved_full_fp',[where(frame+[('fp',None,None)])+160])])
    if not control and 5<=app['mode']<=10:
        owner=[('entries',0,'sro_entry'),('owner',None,'sr_record')];f=owner+[('unexpected',None,'sr_frame')]
        for name,field in (('actual_fault_original','original_pc'),('actual_fault_offset','source_offset'),('actual_fault_kind','kind')):
            tests.append((name,[where(owner+[('original',None,'li2_region_pc'),(field,None,None)])]))
        tests.append(('actual_fault_direction',[where(f+[('frame',None,'li2_step_frame'),('greg',None,None)])+19*8,where(f+[('uc',None,None)])+40+19*8]))
        tests.append(('actual_fault_span',[where(f+[('frame',None,'li2_step_frame'),('greg',None,None)])+22*8+1,
            where(f+[('uc',None,None)])+40+22*8+1,where(f+[('si',None,None)])+17,where(f+[('uc',None,None)])+321]))
    if count==2:
        base=[('entries',1,'sro_entry')]
        for name,path,byte in (
            ('ordinal',[('ordinal',None,None)],0),('source',[('source_page',None,None)],0),
            ('before_fp',[('owner',None,'sr_record'),('before',None,'sr_frame'),('frame',None,'li2_step_frame'),('fp',None,None)],464),
            ('after_fp',[('owner',None,'sr_record'),('after',None,'sr_frame'),('frame',None,'li2_step_frame'),('fp',None,None)],464),
            ('generation',[('owner',None,'sr_record'),('source',None,'li2_region_source'),('key',None,'li2_region_source_key'),('page',None,'li2_fetch_page'),('generation',None,None)],0),
            ('slot',[('owner',None,'sr_record'),('slot',None,None)],0),('terminal_source',[('terminal_source_page',None,None)],0),
            ('memory',[('after_memory',None,'li2_sro_memory'),('data',None,None)],0),
            ('rseq',[('redirected_owners',None,'sro_owners'),('word',None,None)],0),('generated',[('generated_page',None,None)],0)):
            tests.append(('second_invocation_'+name,[where(base+path)+byte]))
    metadata=[('boundary_header',8),('boundary_initial_phase',36),('boundary_after_allocations',112),('boundary_row_extent',24)]
    if control not in (6,14):
        need(struct.unpack_from('<Q',boundaries,16)[0]>0,'actual focal unsupported boundary observation is mandatory')
        metadata.extend((name,128+offset) for name,offset in (
            ('boundary_api',32),('boundary_code',40+24),('boundary_length',40+48),('boundary_source',40+56),
            ('boundary_refusal',40+240),('boundary_reserved',40+300)))
    need(len(tests)+len(metadata)==BASE_COUNTS[(app['mode'],control)],'all original scalar supplied-control population retained before additive reuse controls')
    # Additional actual generation/permit/retirement fields. These do not replace
    # any old whole-state or graph corruption above.
    reuse=[('reuse',None,'scalar_reuse')]
    for key in ('initialized','registered','generation','retirement_attempts','retirements','claims',
                'permits_issued','pending','retiring','cursor','slot','target'):
        tests.append(('reuse_'+key,[where(reuse+[(key,None,None)])]))
    for key in ('live','predecessor','entry'):
        tests.append(('reuse_'+key,[where(reuse+[(key,0,None)])]))
    for key in ('generation','completion','valid'):
        tests.append(('resident_permit_'+key,[where(reuse+[('permits',0,'srr_permit'),(key,None,None)])+(7 if key=='completion' else 0)]))
        tests.append(('claimed_permit_'+key,[where(reuse+[('claimed',None,'srr_permit'),(key,None,None)])+(7 if key in ('generation','completion') else 0)]))
    retired=reuse+[('retirement',None,'srr_retirement')]
    for key in ('old_generation','new_generation','ordinal','slot','old_entry','new_entry','verified_bytes',
                'started','consumed','old_verified','target_ready','replaced','completion'):
        tests.append(('retirement_'+key,[where(retired+[(key,None,None)])+(7 if key=='completion' else 0)]))
    for name,path in (
        ('old_image',[('old_slot',None,'sr_slot'),('plan',None,'li2_region_plan'),('image',None,None)]),
        ('old_source',[('old_slot',None,'sr_slot'),('key',None,'li2_region_source_key'),('bytes',None,None)]),
        ('revoked',[('revoked',None,'sr_permission'),('complete',None,None)]),
        ('target_closed',[('target_closed',None,'sr_permission'),('complete',None,None)]),
        ('writable',[('writable',None,'sr_permission'),('complete',None,None)]),
        ('old_idle',[('old_idle',None,'li2_private_code_query'),('complete',None,None)]),
        ('cleanup',[('cleanup',None,'sr_permission'),('started',None,None)])):
        tests.append(('retirement_'+name,[where(retired+path)]))
    for key in ('reuse_pending_page','reuse_pending_bytes'):
        tests.append((key,[where([(key,None,None)])]))
    tests.append(('reuse_control_started',[where([('reuse_control',None,'sro_reuse_control'),('started',None,None)])]))
    for index in (56,57):tests.append(('actual_vdso_'+str(index),[where([('h',index,None)])]))
    for index in range(2 if count==2 else 1):
        focal=[('entries',index,'sro_entry')]
        for name,path,byte in (
            ('generation',[('reuse_generation',None,None)],0),
            ('identity',[('reuse_slot',None,'sr_slot'),('identity',None,None)],0),
            ('source',[('reuse_slot',None,'sr_slot'),('key',None,'li2_region_source_key'),('bytes',None,None)],4095),
            ('image',[('reuse_slot',None,'sr_slot'),('plan',None,'li2_region_plan'),('image',None,None)],0),
            ('claim_valid',[('reuse_claim',None,'srr_permit'),('valid',None,None)],0),
            ('claim_completion',[('reuse_claim',None,'srr_permit'),('completion',None,None)],7),
            ('retired_generation',[('reuse_retirement',None,'srr_retirement'),('new_generation',None,None)],0)):
            tests.append(('focal_reuse_'+str(index)+'_'+name,[where(focal+path)+byte]))
    # Rewrite every retained completion alias for one actual resident generation.
    # Cross-copy equality remains true; the source-causal generation lower bound
    # must reject this independently of global completed upper bounds.
    permit_paths=[reuse+[('permits',i,'srr_permit')]for i in range(64)]+[reuse+[('claimed',None,'srr_permit')]]
    permit_paths += [[('entries',i,'sro_entry'),('reuse_claim',None,'srr_permit')]for i in range(2)]
    permit_paths += [[('reuse_control',None,'sro_reuse_control'),(k,None,'srr_permit')]for k in ('permit_before','permit_after')]
    retire_paths=[retired]+[[('entries',i,'sro_entry'),('reuse_retirement',None,'srr_retirement')]for i in range(2)]
    def number(path):return struct.unpack_from('<Q',data,where(path))[0]
    generations=[number(p+[('generation',None,None)])for p in permit_paths[:64]]
    generation=next((g for g in generations if g>1),0)
    need(generation>1,'actual resident generation admits a coherent causal predecessor control')
    causal=[where(p+[('completion',None,None)])for p in permit_paths if number(p+[('generation',None,None)])==generation]
    causal += [where(p+[('completion',None,None)])for p in retire_paths if number(p+[('old_generation',None,None)])==generation]
    tests.append(('permit_completion_before_generation',sorted(set(causal))))
    if control==6:
        # Preserve both actual captured copies so whole-copy equality cannot
        # reject before the exact pre-source chronology predicates.
        fetches=[[('owner',None,'scalar_owner'),('current',None,'sr_record'),('final_fetch',None,'li2_fetch_progress')],
                 [('terminal_fetch',None,'li2_fetch_progress')]]
        for name,tail in (
            ('pre_source_validation_calls',[('validation_calls',None,None)]),
            ('pre_source_backing_observed',[('last_backing_observed',None,None)]),
            ('pre_source_validation_observation',[('validation',None,'li2_fetch_map_progress'),('observation',None,'li2_maps_observation'),('io_performed',None,None)])):
            tests.append((name,[where(path+tail)for path in fetches]))
    need(len(tests)+len(metadata)==CONTROL_COUNTS[(app['mode'],control)],'exact additive reuse supplied-control population')
    need(len({name for name,_ in tests})==len(tests),'unique fixed supplied record controls')
    names=[]
    for name,offsets in tests:
        changed=bytearray(data);rejected=False
        for offset in offsets:
            if name=='permit_completion_before_generation':struct.pack_into('<Q',changed,offset,generation-1)
            else:changed[offset]^=4 if name=='nested_snapshot_bv' else 64 if name=='nested_coherent_fp_pointer' else 32 if name=='actual_conserved_flags' else 1
        try:read(bytes(changed),layout,image,app,pid,cpu,exit_status,control,boundaries=boundaries)
        except ValueError as error:
            if name=='permit_completion_before_generation':
                need(str(error)=='actual bounded generation/completion permit','coherent aliases reach exact causal permit refusal')
            if name in ('nested_coherent_mask','nested_coherent_oldmask','nested_actual_fs','nested_actual_gs'):
                need(str(error)=='nested SA_NODEFER mask/OLD_MASK and actual unchanged handler TLS',
                    'coherent nested control reaches its exact semantic refusal')
            if name=='nested_coherent_fp_pointer':
                need(str(error)=='exact nested redzone/alignment destination inside independent lower-altstack preimage',
                    'coherent FP pointer control reaches exact kernel placement')
            if name in semantic:
                need(str(error)=='entire nested FP equals independent live state, destination preimage and exact kernel writes',
                    'coherent nested state control reaches the whole-buffer comparator')
            expected_error={
                'pre_source_validation_calls':'exact li2_fetch_progress.validation_calls',
                'pre_source_backing_observed':'exact li2_fetch_progress.last_backing_observed',
                'pre_source_validation_observation':'pre-source refusal has no fetch validation observation',
                'actual_conserved_rsp':'every actual GPR outside complete typed write union',
                'actual_conserved_flags':'all actual flags outside typed union; undefined AF is not predicted',
                'actual_conserved_full_fp':'entire actual FP/mask/TLS unchanged',
                'actual_fault_span':'actual fault lies inside decoded live-register read span'}
            if name in expected_error:
                need(str(error)==expected_error[name],'coherent scalar control reaches its exact semantic refusal')
            rejected=True
        need(rejected,'whole owner reader refuses supplied '+name);names.append(name)
    for name,offset in metadata:
        changed=bytearray(boundaries);changed[offset]^=1;rejected=False
        try:read(data,layout,image,app,pid,cpu,exit_status,control,boundaries=bytes(changed))
        except ValueError:rejected=True
        need(rejected,'whole scalar reader refuses supplied '+name);names.append(name)
    need(len(names)==CONTROL_COUNTS[(app['mode'],control)] and len(set(names))==len(names),'all fixed scalar refusal controls executed once')
    need(hashlib.sha256(data).hexdigest()==original,'original actual record unchanged')
    additional=certificate.controls(data,layout,image,app,pid,cpu,exit_status,control,boundaries,read,Reader)
    return dict(refusals=names,certificate_refusals=additional,native_operations=0,original_sha256=original)


CERTIFICATE_CONTROL_COUNTS=certificate.CONTROL_COUNTS
CERTIFICATE_MAPPING_CONTROL_COUNT=certificate.MAPPING_CONTROL_COUNT

def mapping(data,layout,image,app,pid,cpu,exit_status,code,*,boundaries):
    need(type(pid)is int and pid>0 and type(cpu)is int and cpu>=0 and exit_status==125 and type(code)is int and code in (136,144,155,158), 'exact actual mapping refusal identity')
    need(type(image)is dict and type(image.get('uid'))is int and 0<=image['uid']<1<<32, 'actual mapping launch UID')
    check=Check(Reader(data,layout),image,app,pid,cpu,0,boundaries)
    check.mapping_code=code
    return check.finish(exit_status)


def mapping_controls(data,layout,image,app,pid,cpu,exit_status,code,*,boundaries):
    mapping(data,layout,image,app,pid,cpu,exit_status,code,boundaries=boundaries)
    tests=certificate.mutations(data,layout,Reader);need(len(tests)==certificate.MAPPING_CONTROL_COUNT,'exact mapping certificate control population')
    names=[]
    for name,offsets in tests:
        changed=bytearray(data)
        for offset in offsets:changed[offset]^=1
        rejected=False
        try:mapping(bytes(changed),layout,image,app,pid,cpu,exit_status,code,boundaries=boundaries)
        except ValueError:rejected=True
        need(rejected,'actual mapping certificate reader rejected supplied '+name);names.append(name)
    return dict(certificate_refusals=names,original_sha256=hashlib.sha256(data).hexdigest(),native_operations=0)
