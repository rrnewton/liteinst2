"""Strict actual scalar-owner capture reader; no subject or decoder replay.

Source/process/ELF closure and the independent native full-state comparator
remain mandatory caller obligations. Supplied mutations get zero native credit.
"""
import hashlib
import importlib.util
from pathlib import Path
import struct


def _load(name,leaf):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(leaf))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

wire=_load('scalar_owner_wire','wire.py');plan_reader=_load('scalar_owner_plan','plan.py')
boundary_reader=_load('scalar_owner_boundaries','boundaries.py')
old=wire.old
need,zero,q,canonical=old.need,old.zero,old.q,old.canonical
Reader,Fields=wire.Reader,old.Fields
U64,PAGE,FP,TF,RF,MASK=old.U64,old.PAGE,old.FP,old.TF,old.RF,old.MASK
P,L,R=old.P,old.L,old.R
DATA,STACK=old.DATA,old.STACK
STACK_FAULT=STACK+2*PAGE
RSP=STACK+PAGE+131072-504
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
# Literal runtime first-error call sites; none are accepted alternative results.
FAILURE={1:(2604,5),2:(2603,7),3:(2603,9),4:(2603,7),5:(2603,5),6:(2604,11),7:(2604,11),
         8:(2602,1),9:(2602,1),10:(2602,1),11:(2603,5),12:(2602,1),13:(2602,1),14:(2604,5)}


class Check(old.Check):
    def __init__(self,reader,image,app,pid,cpu,control,boundaries):
        self.r,self.image,self.app,self.pid,self.cpu,self.control=reader,image,app,pid,cpu,control
        self.b=reader.data[:-64];self.h=q(self.f(self.b,'uho_wire','h'))
        self.control_words=q(self.f(self.b,'uho_wire','control'))
        self.owner=self.f(self.b,'uho_wire','owner');self.bias=self.h[9]-reader.layout['symbols']['li2_raw6']
        self.boundaries=boundary_reader.observe(boundary_reader.requests(reader),boundaries)
        self.objects={};self.bases={};self.source_ids={};self.backings={};self.maps_seen={}
        for key,obj in image['objects'].items():
            need(type(key)is int and key>=0 and type(obj)is dict,'explicit lifecycle object inventory')
            h,loads=old.elf(obj['data']);self.objects[key]=(obj,h,loads)
        need(image['main_object'] in self.objects and image['interpreter_object'] in self.objects,'actual main/interpreter object assignment')


    def f(self,b,t,k):return self.r.field(b,t,k)


    def i(self,b,t,k):return self.r.integer(b,t,k)


    def v(self,b,t,k):return self.r.values(b,t,k)


    def eq(self,b,t,**v):self.r.equal(b,t,**v)


    def z(self,b,label):zero(b,label)


    def symbol(self,n):return self.bias+self.r.layout['symbols'][n]


    def stat(self,b):
        t='stat';self.eq(b,t,__pad0=0);zero(self.f(b,t,'__glibc_reserved'),'kernel stat reserved words')
        for k in ('st_atim','st_mtim','st_ctim'):
            need(self.i(self.f(b,t,k),'timespec','tv_nsec')<1000000000,'actual stat nanoseconds')
        return dict(zip(('dev','ino','mode','size'),self.v(b,t,'st_dev st_ino st_mode st_size')))


    def maps(self,b,kind=None):
        t='li2_fetch_map_progress';self.eq(b,t,last_read=0,close_result=0,opened=1,close_started=1,closed=1)
        fd,n,rows=self.v(b,t,'fd bytes rows');need(fd<1<<31 and 0<n<=256<<10 and 0<rows<=2048,'complete real maps read bounds')
        o=self.f(b,t,'observation');a,h,e,k,io=self.v(o,'li2_maps_observation','acquisition_id handler_id mutation_epoch kind io_performed')
        need(a>0 and e>0 and k in (0,1,4) and io==int(k!=4) and (h==0 if k==0 else h>0),'exact maintained acquisition class and physical I/O')
        if kind is not None:need(k==kind,'exact maps call-site kind')
        identity=self.v(b,t,'fd last_read close_result bytes opened close_started closed')
        if a in self.maps_seen:need(self.maps_seen[a]==identity,'same retained physical acquisition bytes/descriptor')
        else:self.maps_seen[a]=identity
        # The maintained updater changes canonical row_count after mprotect,
        # while retaining the physical read's fd/byte receipt. Its mutation
        # epoch, not acquisition_id alone, identifies this exact row view.
        if (a,e) in self.maps_seen:need(self.maps_seen[a,e]==rows,'same exact canonical view within its mutation epoch')
        else:self.maps_seen[a,e]=rows
        return a,h,e,k


    def query(self,b,entry,prot,pages=1,failed=False):
        t='li2_private_code_query';self.eq(b,t,first=entry,end=entry+pages*PAGE,attempted=1,expected_prot=prot)
        self.maps(self.f(b,t,'maps'))
        if failed:
            self.eq(b,t,complete=0,pages_checked=0,first_vma=0,last_vma_end=0,actual_prot=0,result=305,detail=0)
        else:
            self.eq(b,t,complete=1,pages_checked=pages,actual_prot=prot,result=0,detail=0)
            a,z=self.v(b,t,'first_vma last_vma_end')
            need(a%PAGE==z%PAGE==0 and 0<a<=entry and entry+pages*PAGE<=z<(1<<47),'complete actual private VMA envelope')


    def permission(self,b,entry,prot,error=0,sync_error=0):
        t='uh_permission';ok=not(error or sync_error)
        self.eq(b,t,started=1,returned=1,sync_started=1,sync_returned=1,complete=int(ok),prot=prot,result=error,sync_result=sync_error)
        self.query(self.f(b,t,'query'),entry,prot,failed=bool(error))


    def image_header(self,b,objid):
        t='image';obj,h,loads=self.objects[objid];bias,source=self.v(b,t,'bias source')
        need(canonical(source,len(obj['data'])) and bias%PAGE==0,'real protected original snapshot and image bias')
        need(self.i(b,t,'backing_fd')<1<<31,'actual original sealed descriptor')
        self.eq(b,t,entry=bias+h[4],ph=source+h[5],n=h[10],source_size=len(obj['data']),kind=obj['kind'])
        need(self.f(b,t,'source_hash')==hashlib.sha256(obj['data']).digest(),'whole original image digest')
        self.bases[objid]=bias


    def frame(self,b,tls=True):
        t='uh_frame';self.eq(b,t,started=1,si_saved=1,uc_saved=1,complete=1)
        si,uc,s=(self.f(b,t,k) for k in ('si','uc','frame'))
        greg=q(self.f(s,'li2_step_frame','greg'));mask,fpaddr,n,initialized=self.v(s,'li2_step_frame','mask fp_address fp_bytes initialized')
        fp=self.f(s,'li2_step_frame','fp');lo,cap=self.h[12:14]
        need(cap==524288 and lo%PAGE==0 and fpaddr%16==0 and lo<=fpaddr and 580<=n<=FP and fpaddr+n<=lo+cap and initialized==n,'actual signal FP extent on configured altstack')
        need(q(uc[40:224])==greg and int.from_bytes(uc[224:232],'little')==fpaddr and int.from_bytes(uc[296:304],'little')==mask,'all copied signal GREG/mask/FP pointers')
        need(uc[304:424]==si[:120],'glibc mask tail is the exact following kernel siginfo, not additional signal-mask bits')
        need(struct.unpack_from('<II',fp,464)==(0x46505853,n) and struct.unpack_from('<I',fp,480)[0]==n-4 and struct.unpack_from('<I',fp,n-4)[0]==0x46505845 and q(fp[520:528])==(0,),'full standard kernel FP metadata')
        zero(fp[n:],'every unused FP byte')
        need(int.from_bytes(uc[16:24],'little')==lo and int.from_bytes(uc[24:28],'little')==0 and int.from_bytes(uc[32:40],'little')==cap,'actual installed altstack, no invented SS_ONSTACK')
        fs,gs=self.v(b,t,'fs gs')
        if tls:self.eq(b,t,tls_complete=1,fs_result=0,gs_result=0)
        else:self.eq(b,t,tls_complete=0,fs_result=0,gs_result=0,fs=0,gs=0)
        sig=self.i(b,t,'sig');need(struct.unpack_from('<i',si)[0]==sig,'actual signal number in complete SI')
        return dict(greg=greg,fp=fp,fp_bytes=n,mask=mask,fs=fs,gs=gs,si=si,uc=uc,raw=b,sig=sig)


    def nx(self,f,pc,mutated=False):
        g=f['greg'];si=f['si'];need(f['sig']==11 and struct.unpack_from('<iii',si)==(11,0,2) and g[16]==pc and g[19:21]==(21,14) and g[22]==pc and int.from_bytes(si[16:24],'little')==pc+int(mutated),'exact first-byte genuine NX or explicit supplied SI+1')
        need(g[17]&(TF|RF)==RF and g[18]==0x2b000000000033 and g[21]==MASK and f['mask']==MASK and g[15]<(1<<47),'actual saved NX execution envelope')


    def pin(self,b,pid):
        t='li2_rseq_data';self.eq(b,t,pid=pid,tid=pid,attempted=1,complete=1,error=0,detail=0)
        a,p,alloc,gen,offset=self.v(b,t,'address page allocation generation offset')
        need(canonical(a,32) and a%32==0 and p==a&-PAGE and alloc>0 and gen>0 and offset%PAGE==0,'actual registered page geometry/identity')
        self.maps(self.f(b,t,'maps'));return a,p,alloc,gen,offset


    def owners(self,b,redirected=False,pc=None):
        need(pc is None,'scalar callers use typed-plan footprint join')
        t='uho_owners';self.eq(b,t,captured=1,word=0)
        state=self.f(b,t,'rseq');st='li2_rseq_state'
        self.eq(state,st,initialized=1,first_error=0,first_detail=0,pid=self.pid,tid=self.pid)
        reg=self.i(state,st,'registered');need(reg in (0,1),'actual optional registration')
        self.eq(b,t,word_observed=int(redirected and reg))
        need(self.i(state,st,'calls')==sum(self.i(state,st,k) for k in ('registrations','unregistrations','kernel_errors')),'all actual registration calls accounted')
        need(self.i(state,st,'registrations')-self.i(state,st,'unregistrations')==reg,'actual current registration lifetime')
        self.eq(state,st,epoch=self.i(state,st,'registrations'))
        if reg:
            self.eq(state,st,held=1,phase=3,length=32,tls_attempted=1,tls_complete=1,fs_result=0,gs_result=0)
            need(self.i(state,st,'epoch')>0,'actual registered epoch')
            data=self.f(state,st,'data');identity=self.pin(data,self.pid)
            need(self.v(state,st,'address page')==identity[:2],'current exact retained pin')
        else:self.eq(state,st,held=0,phase=0)
        if pc is not None:
            self.eq(state,st,last_pc=pc+22,last_code=176,last_policy=1,last_first=0,last_end=0)
            self.eq(self.f(state,st,'last_footprint'),'li2_write_footprint',pc=pc+22,next_pc=pc+24,first=0,end=0,abi_version=1,policy=1,code=176,length=2)
        # This build routes all physical native epochs through native_pair;
        # the old registered one-page owner is never initialized or entered.
        zero(self.f(b,t,'rseq_native'),'complete unused old one-page rseq owner')
        p,l,r=(self.f(b,t,k) for k in ('pair','lifecycle','rseq_pair'))
        self.eq(p,P,initialized=1,phase=2,in_handler=0,first_error=0,first_detail=0,live=0,entry_pending=0,pid=self.pid,tid=self.pid,session=self.symbol('selected_session'))
        self.eq(l,L,initialized=1,busy=0,live=0,first_error=0,first_detail=0,opening=0,pid=self.pid,tid=self.pid)
        self.eq(r,R,initialized=1,active=0,checking=0,entry_checked=0,first_error=0,first_detail=0,unsafe_terminal=0)
        need(self.i(l,L,'owner')==self.i(r,R,'owner') and canonical(self.i(l,L,'owner')),'same private pair owner')
        need(self.i(l,L,'published')==self.i(l,L,'closed_pages')==self.i(r,R,'published'),'all actual pair pages closed')
        need(self.i(p,P,'seeds')==self.i(p,P,'epochs_closed')==self.i(r,R,'attempts')==self.i(r,R,'closed'),'all actual pair epochs closed')
        need(self.i(r,R,'preentries')==self.i(r,R,'entries') and self.i(p,P,'refaults')==self.i(p,P,'refault_completed'),'every prior native boundary/refault completed')
        need(self.i(p,P,'epochs_closed')==self.i(p,P,'one_page_closes')+self.i(p,P,'two_page_closes') and self.i(l,L,'published')==self.i(p,P,'seeds')+self.i(p,P,'extensions'),'pair page/epoch conservation')
        if self.i(r,R,'attempts'):
            self.eq(r,R,pid=self.pid,tid=self.pid,word_before=0,word_entry=0,word_after=0)
            if self.i(r,R,'registered'):
                x=self.pin(self.f(r,R,'before'),self.pid);y=self.pin(self.f(r,R,'after'),self.pid)
                need(x==y and self.v(r,R,'address page')==x[:2],'closed pair pin retains full allocation/generation')
            else:
                for k in ('before','after'):zero(self.f(r,R,k),'unregistered pair has no invented pin')
        return b


    def redirected(self,raw,before,entry):
        frame=self.frame(raw,False);want=bytearray(before['raw']);t='uh_frame'
        f=self.r.types[t]['fields'];st=self.r.types['li2_step_frame']['fields']
        struct.pack_into('<Q',want,f['uc']['offset']+40+16*8,entry)
        struct.pack_into('<Q',want,f['frame']['offset']+st['greg']['offset']+16*8,entry)
        for key in ('fs','gs','fs_result','gs_result','tls_complete'):
            x=f[key];want[x['offset']:x['offset']+x['bytes']]=bytes(x['bytes'])
        need(raw==bytes(want),'entire saved SI/UC/GREG/FP frame changes only RIP at actual redirect')
        return frame


    def nested_fp(self,outer,inner):
        saved=outer['fp'];n=outer['fp_bytes'];c=self.control_words;hw=self.app['hardware']
        need(c[22]==1 and c[21]==self.app['xcr0'] and c[23]==0,'actual guarded handler XGETBV equals same-process initial XCR0')
        features=0xe7|(0x200 if c[21]&0x200 else 0)
        need(c[21]==features and struct.unpack_from('<IIQI',saved,464)==(0x46505853,n,features,n-4) and q(saved[512:520])==(features,),'closed supported nondynamic signal user-feature set')
        ends=[576]
        for feature in (2,5,6,7,9):
            if features>>feature&1:
                row=hw[3+feature];need(row[:2]==(13,feature) or row[:2]==[13,feature],'actual CPUID subleaf identity')
                size,offset=row[2:4];need(size>0 and offset>=576 and offset+size<=65532,'bounded standard component')
                ends.append(offset+size)
        need(n==max(ends)+4 and inner['fp_bytes']==n,'exact independently observed nested FP extent')
        zero(saved[484:512],'full kernel FP software reserved bytes');zero(saved[520:576],'full standard header reserved bytes')
        raw=self.f(self.b,'uho_wire','nested_fp');t='uho_nested_fp';h=q(self.f(raw,t,'h'))
        lo,cap=self.h[12:14];sp=inner['greg'][15]
        need(lo<sp and sp+16<=lo+cap and h==(1,1,1,lo,cap,sp,sp-lo,features,self.pid,self.pid,5,features,1,1,0,0),
            'actual final assembly stack/RAW7 identity and completed independent XSAVE pair')
        pre=self.f(raw,t,'stack');zero(pre[h[6]:],'uncopied upper-altstack capacity stays zero')
        at=int.from_bytes(inner['uc'][224:232],'little')-lo
        need(at>=0 and lo+at==((sp-128-n)&~63) and at+n<=h[6],
            'exact nested redzone/alignment destination inside independent lower-altstack preimage')
        z,o=(self.f(raw,t,k) for k in ('zero','ones'))
        need(z[512:576]==o[512:576] and int.from_bytes(z[512:520],'little')&~features==0,
            'two standard XSAVE headers have identical actual in-use bits')
        zero(z[520:576],'independent XSAVE has no compaction or reserved header data')
        zero(z[n-4:],'whole independent zero-initialized save tail')
        need(o[n-4:]==b'\xff'*(FP-(n-4)),'whole independent ones-initialized save tail')
        need(z[416:512]==bytes(96) and o[416:512]==b'\xff'*96,
            'actual XSAVE leaves full legacy reserved/software region untouched')
        mask=struct.unpack_from('<I',saved,28)[0]
        need(mask&0x1f80==0x1f80 and struct.unpack_from('<I',z,28)[0]==mask,
            'same-CPU independently observed MXCSR capability')
        expected=bytearray(FP);expected[:n]=pre[at:at+n]
        # Plain XSAVE64, never XSAVEOPT/XSAVEC: equal observations are actual
        # writes; complementary seeds prove an untouched destination byte.
        # Both headers were zero before the saves; no partial BV bits are inferred.
        for i,(a,b) in enumerate(zip(z[:n-4],o[:n-4])):
            if a==b:expected[i]=a
            else:need((a,b)==(0,255),'independent XSAVE pair has only actual writes or untouched complementary seeds')
        struct.pack_into('<IIQI',expected,464,0x46505853,n,features,n-4)
        expected[484:512]=bytes(28)
        struct.pack_into('<Q',expected,512,int.from_bytes(z[512:520],'little')|3|(features&0x200))
        expected[520:576]=bytes(56)
        if features&0x200:
            need(c[18]<(1<<32) and c[19:21]==(0,1) and hw[2][4]&24==24 and hw[12][2]==8,'actual permitted RDPKRU/CPUID D9 geometry')
            offset=hw[12][3]
            need(z[offset:offset+4]==o[offset:offset+4]==struct.pack('<I',c[18]),
                'independent standard saves equal actual pre-signal PKRU')
            struct.pack_into('<I',expected,offset,c[18])
        else:need(c[18:21]==(0,0,0),'no unsupported PKRU instruction or invented result')
        struct.pack_into('<I',expected,n-4,0x46505845)
        need(inner['fp']==expected,'entire nested FP equals independent live state, destination preimage and exact kernel writes')


    def key(self,b):
        t='li2_region_source_key';pc=self.i(b,t,'entry');p=self.f(b,t,'page');pt='li2_fetch_page';page=pc&-PAGE
        need(canonical(pc,15) and pc%PAGE<=PAGE-15,'actual same-page source ingress15')
        self.eq(p,pt,address=page,backing=1,logical=5,closed_prot=1)
        allocation,generation,offset,objid=self.v(p,pt,'allocation generation offset object')
        need(allocation>0 and generation>0 and offset%PAGE==0 and objid in self.objects,'known source allocation/generation/object')
        obj,h,loads=self.objects[objid]
        extent=max((p[3]+p[6]+PAGE-1)&-PAGE for p in loads)
        need(self.i(p,pt,'initial_extent') in ((0,extent) if offset==0 and objid not in (self.image['main_object'],self.image['interpreter_object']) else (0,)),
            'source-exact initial loader extent annotation')
        owners=[p for p in loads if p[1]==5 and (p[2]&-PAGE)<=offset and offset+pc%PAGE+15<=p[2]+p[5]]
        need(len(owners)==1,'one authenticated executable original ingress range')
        seg=owners[0];bias=page-((seg[3]&-PAGE)+offset-(seg[2]&-PAGE))
        need(bias>=0 and bias%PAGE==0,'actual object bias from exact source file offset')
        if objid in self.bases:need(self.bases[objid]==bias,'one actual object bias')
        else:self.bases[objid]=bias
        need(offset<len(obj['data']) and offset+PAGE<=(len(obj['data'])+PAGE-1)&-PAGE,'whole source within actual file or its authenticated rounded EOF page')
        want=obj['data'][offset:offset+PAGE];want+=bytes(PAGE-len(want))
        need(self.f(b,t,'bytes')==want,'every live source byte equals original ELF and exact rounded EOF zeros')
        backing=self.f(b,t,'backing');bt='li2_fetch_backing';self.eq(backing,bt,seals_observed=1,stat_observed=1,stat_result=0)
        st=self.stat(self.f(backing,bt,'stat'));fd,seals=self.v(backing,bt,'retained_fd seals')
        need(200<=fd<1<<31 and seals==15 and st['size']==obj['carrier_bytes'] and st['mode']&0xf000==0x8000,
            'actual original duplicate, four seals and complete carrier extent')
        if objid not in (self.image['main_object'],self.image['interpreter_object']):
            expected=obj['backing'];need(all(st[k]==expected[k] for k in ('dev','ino','size')) and seals==expected['seals'],'actual dependency retained backing')
        elif objid==self.image['main_object']:need(st==self.stat(self.f(self.b,'sro_wire','main_backing')),'actual main retained backing')
        stable=(fd,seals,st['dev'],st['ino'],st['mode'],st['size'])
        if objid in self.backings:need(stable==self.backings[objid],'same retained backing for each actual object')
        else:self.backings[objid]=stable
        first,end,major,minor,inode,vmaoff=self.v(p,pt,'vma_first vma_end vma_major vma_minor vma_inode vma_offset')
        dev=st['dev'];maj=((dev>>8)&0xfff)|((dev>>32)&0xfffff000);minr=(dev&255)|((dev>>12)&0xffffff00)
        need(first%PAGE==end%PAGE==vmaoff%PAGE==0 and first<=page and page+PAGE<=end and vmaoff+page-first==offset and
            (major,minor,inode)==(maj,minr,st['ino']),'whole actual source VMA identity')
        identity=(pc,p,stable,want)
        return dict(pc=pc,page=page,object=objid,bytes=want,raw_key=b,key=identity,generation=generation,page_row=p)

    def source(self,b,mutated=False):
        t='li2_region_source';self.eq(b,t,ready=1);ref=self.f(b,t,'borrow')
        need(canonical(self.i(ref,'li2_fetch_ref','owner')) and self.i(ref,'li2_fetch_ref','sequence')>0,'actual fresh occupied borrow')
        actual=b
        if mutated:
            need(self.control in (8,9,10),'only explicit source controls may alter a supplied copy')
            original=self.f(self.f(self.b,'sro_wire','control_before'),'sr_record','source')
            expected=bytearray(original);c=self.control_words
            if self.control==8:
                at=self.r.types[t]['fields']['borrow']['offset']+self.r.types['li2_fetch_ref']['fields']['sequence']['offset'];oldvalue=int.from_bytes(original[at:at+8],'little');size=8;value=oldvalue^(1<<63)
            elif self.control==9:
                at=self.r.types[t]['fields']['key']['offset']+self.r.types['li2_region_source_key']['fields']['page']['offset']+self.r.types['li2_fetch_page']['fields']['generation']['offset'];oldvalue=int.from_bytes(original[at:at+8],'little');size=8;value=oldvalue^(1<<63)
            else:
                at=self.r.types[t]['fields']['key']['offset']+self.r.types['li2_region_source_key']['fields']['bytes']['offset']+PAGE-1;oldvalue=original[at];size=1;value=oldvalue^1
            expected[at:at+size]=value.to_bytes(size,'little')
            need(bytes(expected)==b and c[6:8]==(oldvalue,value),'whole explicit supplied source mutation and actual predecessor')
            b=original;ref=self.f(b,t,'borrow')
        result=self.key(self.f(b,t,'key'));result.update(raw=b,actual_raw=actual,borrow=self.i(ref,'li2_fetch_ref','sequence'),borrow_owner=self.i(ref,'li2_fetch_ref','owner'))
        return result

    def slot(self,b,index):
        t='sr_slot';self.eq(b,t,installed=1,complete=1,filled=PAGE,verified=PAGE)
        source=self.key(self.f(b,t,'key'));entry=self.i(self.owner,'scalar_owner','low_arena' if source['pc']<1<<31 else 'arena')+index*PAGE
        focal=source['pc']==self.h[20];identity=index+1
        if self.control==5 and focal:identity^=1<<63
        self.eq(b,t,identity=identity)
        plan=plan_reader.check(self.f(b,t,'plan'),source['page'],source['bytes'],source['pc'],entry,self.boundaries,self.control==11 and focal)
        self.query(self.f(b,t,'writable'),entry,3);self.permission(self.f(b,t,'publication'),entry,1)
        need(entry+PAGE<=source['page'] or entry>=source['page']+PAGE,'actual source and generated disjoint pages')
        return dict(source=source,entry=entry,page=plan['image'],plan=plan,raw=b)

    def maps_bundle(self,b,source,stage,stack_kind,restored=False,generated=0):
        t='li2_sro_maps';self.eq(b,t,rows_checked=8,source_checked=1,generated_checked=int(stage==2))
        m=self.maps(self.f(b,t,'maps'),0 if stage else 1)
        before,after=(self.f(b,t,k) for k in ('before','after'));st='li2_maps_stats'
        for v in (before,after):self.eq(v,st,active=int(stage==0),poisoned=0,reserved=0)
        self.eq(after,st,valid=1,fresh_calls=self.i(before,st,'fresh_calls')+1,acquisitions=self.i(before,st,'acquisitions')+1,handler_id=self.i(before,st,'handler_id'))
        need(m[0]==self.i(after,st,'acquisitions') and m[1]==(0 if stage else self.i(before,st,'handler_id')) and m[2]==self.i(after,st,'mutation_epoch'),'actual physical snapshot/stat identity')
        need(self.i(after,st,'mutation_epoch')>=self.i(before,st,'mutation_epoch') and self.i(after,st,'invalidations')>=self.i(before,st,'invalidations') and self.i(after,st,'reuses')==self.i(before,st,'reuses'),'physical fresh parser preserves exact counter meanings')
        points=(DATA,DATA+8191,DATA+8192,STACK,STACK+PAGE,STACK_FAULT,STACK_FAULT+PAGE,STACK+PAGE+131072)
        for i,row in enumerate(self.r.items(b,t,'rows','li2_sro_map_row')):
            rt='li2_sro_map_row';self.eq(row,rt,offset=0,major=0,minor=0,inode=0,private=1)
            a,z,prot=self.v(row,rt,'first end prot');need(a%PAGE==z%PAGE==0 and a<=points[i]<z,'actual fixed memory VMA')
            if i<2:want=(DATA,DATA+8192,3)
            elif 4<=i<=6:
                want=(STACK+PAGE,STACK+PAGE+131072,3)
                if stack_kind:want=((STACK+PAGE,STACK_FAULT,3),(STACK_FAULT,STACK_FAULT+PAGE,1 if restored else 0),(STACK_FAULT+PAGE,STACK+PAGE+131072,3))[i-4]
            else:
                need(prot==0 and z-points[i]>=PAGE,'actual inaccessible guard');continue
            need((a,z,prot)==want,'complete exact fixed memory permission extent')
        row=self.f(b,t,'source');p=source['page_row']
        self.eq(row,'li2_sro_map_row',first=self.i(p,'li2_fetch_page','vma_first'),end=self.i(p,'li2_fetch_page','vma_end'),
            offset=self.i(p,'li2_fetch_page','vma_offset'),major=self.i(p,'li2_fetch_page','vma_major'),minor=self.i(p,'li2_fetch_page','vma_minor'),inode=self.i(p,'li2_fetch_page','vma_inode'),prot=1,private=1)
        row=self.f(b,t,'generated')
        if stage==2:
            self.eq(row,'li2_sro_map_row',offset=0,major=0,minor=0,inode=0,private=1,prot=1)
            a,z=self.v(row,'li2_sro_map_row','first end');need(a%PAGE==z%PAGE==0 and a<=generated and generated+PAGE<=z,'actual retired generated R/NX extent')
        else:zero(row,'no invented generated memory-observation query')

    def memory(self,b,source,stage,generated=0):
        t='li2_sro_memory';rsp=self.app['rsp'];kind=0 if rsp==RSP else 1 if rsp==STACK_FAULT-0x58 else 2 if rsp==STACK_FAULT+PAGE-0x58 else -1
        need(kind>=0 and stage in (0,1,2) and (stage!=2 or kind>0),'exact fixed stack geometry and typed readback stage')
        observed=bytes(0 if stage!=2 and kind and STACK_FAULT<=rsp-128+i<STACK_FAULT+PAGE else 1 for i in range(224));copied=sum(observed)
        self.eq(b,t,attempted=1,complete=1,stage=stage,stack_kind=kind,data_copied=8192,stack_copied=copied,stack_missing=224-copied,stack_full=int(copied==224),
            restore_started=int(stage==2),restore_returned=int(stage==2),restore_verified=int(stage==2),result=0,detail=0,restore_result=0,rsp=rsp,data_first=DATA,stack_first=rsp-128,generated=generated if stage==2 else 0)
        self.maps_bundle(self.f(b,t,'initial'),source,stage,kind,generated=generated)
        if stage==2:self.maps_bundle(self.f(b,t,'restored'),source,stage,kind,True,generated)
        else:zero(self.f(b,t,'restored'),'no unperformed permission/readback snapshot')
        result={k:self.f(b,t,k) for k in ('data','stack','stack_observed')}
        need(result['data']==self.app['data'] and result['stack_observed']==observed and
            result['stack']==bytes(self.app['stack'][i] if observed[i] else 0 for i in range(224)),
            'every actual observed data/stack byte, exact explicit absent bytes and bitmap')
        return result

    def fetch(self,b,source,held,error=0,detail=0):
        t='li2_fetch_progress';self.eq(b,t,held=int(held),complete=1,first_error=error,identity_observed=1,first_detail=detail,
            pages_copied=1,bytes_copied=15,sequence=source['borrow'])
        need(self.i(b,t,'validation_calls')>=1,'actual retained source validation calls')
        # Fetch's backing page index is zero in this genuine one-page lease.
        self.eq(b,t,last_backing_page=0,last_backing_observed=1)
        self.maps(self.f(b,t,'preparation'));self.maps(self.f(b,t,'validation'))

    def footprint(self,b,plan):
        state=self.f(b,'sro_owners','rseq');last=plan['original'][-1]
        pc,nxt=struct.unpack_from('<QQ',last);code=struct.unpack_from('<I',last,24)[0];length=struct.unpack_from('<I',last,48)[0]
        self.eq(state,'li2_rseq_state',last_pc=pc,last_code=code,last_policy=1,last_first=0,last_end=0)
        self.eq(self.f(state,'li2_rseq_state','last_footprint'),'li2_write_footprint',pc=pc,next_pc=nxt,first=0,end=0,abi_version=1,policy=1,code=code,length=length)

    def mapped(self,b,plan,pc):
        rows=[m for m in plan['maps'] if m['generated_pc']==pc]
        need(len(rows)==1,'actual PC is exactly one generated instruction head')
        self.eq(b,'li2_region_pc',**rows[0]);return rows[0]

    def conserved(self,before,after,plan):
        a,g=before['greg'],after['greg'];wm=plan['gpr_written'];fm=plan['flags_written']
        need(all(a[GREG[i]]==g[GREG[i]] for i in range(16) if not (wm>>i&1)),'every actual GPR outside complete typed write union')
        need(all(a[i]==g[i] for i in range(23) if i not in GREG+(16,17,22)),'all unchanged non-GPR signal registers')
        need(g[17]&(TF|RF)==RF and g[17]&~(fm|RF)==a[17]&~(fm|RF),'all actual flags outside typed union; undefined AF is not predicted')
        need(before['fp']==after['fp'] and before['fp_bytes']==after['fp_bytes'] and before['mask']==after['mask'] and
            (before['fs'],before['gs'])==(after['fs'],after['gs']),'entire actual FP/mask/TLS unchanged')
        need(before['uc'][:40]==after['uc'][:40] and before['uc'][296:304]==after['uc'][296:304],'entire actual UC stack/flags/link/Linux mask')
    def nested(self,f,before):
        need(f['sig']==5 and struct.unpack_from('<iii',f['si'])==(5,0,-6) and struct.unpack_from('<II',f['si'],16)==(self.pid,self.image['uid']),
            'real nested SI_TKILL sender and actual launch UID')
        need(f['greg'][16]==f['greg'][14]==self.h[9]+25 and f['greg'][13]==0 and
            (f['greg'][8],f['greg'][9],f['greg'][12],f['greg'][2],f['greg'][0],f['greg'][1])==(self.pid,self.pid,5,0,0,0) and
            self.h[12]<=f['greg'][15]<self.h[12]+self.h[13] and f['greg'][17]&0x10500==0,
            'actual nested tgkill gateway/arguments/runtime stack and control flags')
        need(f['mask']==MASK and f['greg'][21]==MASK and (f['fs'],f['gs'])==(before['fs'],before['gs']),
            'nested SA_NODEFER mask/OLD_MASK and actual unchanged handler TLS')

    def record(self,b,slots,kind='complete',focal=False):
        t='sr_record';c=self.control if focal else 0
        source=self.source(self.f(b,t,'source'),c in (8,9,10));before=self.frame(self.f(b,t,'before'));self.nx(before,source['pc'])
        flags=self.i(b,t,'flags');need(flags&(TF|RF)==0 and before['greg'][17]==flags|RF,'actual logical flags at genuine NX ingress')
        no_slot=c in (8,9,10,12,13,14)
        result=dict(before=before,after=None,unexpected=None,source=source,entry=0,mapped=None,key=source['key'],raw_key=source['raw_key'],generation=source['generation'],slot=self.i(b,t,'slot'))
        build,returned=self.v(b,t,'build_started build_returned');need(build in (0,1) and returned==build-int(c==14),'actual complete build prefix or one interrupted call')
        self.eq(b,t,build_result=0)
        if no_slot:
            self.eq(b,t,slot_present=0,slot=0,redirected=0,exit_seen=0,completed=0,release_started=0,release_complete=0,release_result=0,
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
            return result
        slot=self.i(b,t,'slot');need(self.i(b,t,'slot_present')==1 and slot<len(slots),'actual installed immutable slot')
        s=slots[slot];plan=s['plan'];entry=s['entry'];result.update(entry=entry,plan=plan)
        need(source['key']==s['source']['key'],'current fresh ticket joins exact immutable slot key')
        if c in (5,11):
            self.eq(b,t,redirected=0,exit_seen=0,completed=0,release_started=0,release_complete=0,release_result=0,unexpected_seen=0,map_result=0,
                gpr_written=0,flags_written=0,exit_index=0,idle_bytes=0,live_bytes=0,closed_bytes=0)
            for key in ('original','idle','live','open','close','after','unexpected'):zero(self.f(b,t,key),'unexecuted supplied slot/plan refusal '+key)
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
        return result

    def header(self,exit_status):
        h=self.h;r=self.r;c=self.control_words
        code,detail=(0,0) if exit_status==0 else FAILURE[self.control] if self.control else (2604,11)
        need(h[:9]==(0x31524f534c49324c,1,r.types['sro_wire']['bytes'],r.types['scalar_owner']['bytes'],r.types['sro_entry']['bytes'],r.types['sr_record']['bytes'],r.types['sr_frame']['bytes'],968,128),'whole actual scalar capture version/type extents')
        need(canonical(self.bias) and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(k) for k in ('li2_raw6','li2_gateway_start','li2_gateway_end')) and h[10]<=h[9]<h[11],'actual compiled bridge gateway relation')
        need(canonical(h[12],h[13]) and h[12]%PAGE==0 and h[13]==524288,'actual complete altstack')
        need(h[14:16]==(1,0) and h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,0),'actual private retained FD3 sink')
        need(h[20]==self.app['head'] and h[22]==self.image['main_object'] and h[23]==1 and h[26:30]==(1,exit_status,code,detail&U64),'actual focal original image and exact outcome')
        need(h[39]==0 and h[41:43]==(h[16],0) and h[45]<=h[44]<=h[43] and h[46]<=h[43] and h[47:50]==(0,0,0) and h[50:53]==(1,1,1) and
            h[53]==int(self.control==14) and not any(h[54:]),'complete diagnostics, FD guards, alias cleanup and actual terminal capture')
        need(c[0]==self.control and not any(c[4:6]) and not any(c[32:]),'actual fixed control and reserved words')
        a,b=(self.f(self.b,'sro_wire',k) for k in ('sink_initial','sink_terminal'))
        for value in (a,b):
            st=self.stat(value);need(st['mode']&0xffff==0x8180 and st['size']==0,'actual0600 regular empty pre-write sink');self.eq(value,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(a,b,'stat',observed=('st_atim','st_mtim','st_ctim'))
        footer=q(r.data[-64:]);need(footer[:4]==(0x314652534c49324c,1,len(self.b),len(self.b)) and 1<=footer[4]<=64 and 0<footer[5]<=len(self.b) and footer[6:]==(exit_status,code),'complete exact footer and bounded actual write progress')
        if footer[4]==1:need(footer[5]==len(self.b),'actual single complete write')
        self.image_header(self.f(self.b,'sro_wire','main'),self.image['main_object']);self.image_header(self.f(self.b,'sro_wire','interpreter'),self.image['interpreter_object'])
        obj,_,loads=self.objects[self.image['main_object']];page=h[20]&-PAGE
        matches=[p for p in loads if p[1]==5 and p[3]<=page and page+PAGE<=p[3]+p[5]]
        need(len(matches)==1 and h[21]==matches[0][2]+page-matches[0][3],'actual complete main source-page file offset')
        need(self.f(self.b,'sro_wire','original_source')==self.app['source_page']==obj['data'][h[21]:h[21]+PAGE],'whole independent actual application source page')
        hardware=self.f(self.b,'sro_wire','hardware');self.eq(hardware,'li2_selected_hardware',abi_version=1,reserved=0)
        for i,key in enumerate(('leaf0','leaf1','leaf7')):need(struct.unpack('<4I',self.f(hardware,'li2_selected_hardware',key))==tuple(self.app['hardware'][i][2:]),'actual bridge/application hardware equality')
        return dict(status=exit_status,failure_code=code,detail_abs=abs(detail),detail_negative=int(detail<0))
    def controls(self,current,result):
        c=self.control_words;kind=self.control;t='sr_record'
        before=self.f(self.b,'sro_wire','control_before');supplied=self.f(self.b,'sro_wire','supplied_before')
        if kind not in (1,14):zero(self.f(self.b,'sro_wire','nested_fp'),'unused nested observation wholly zero')
        want=[0]*40;want[0]=kind
        if not kind:
            need(c==tuple(want),'no fabricated control progress');zero(before,'unused control owner');zero(supplied,'unused supplied signal');return
        stage={1:1,2:2,3:2,4:2,5:5,6:6,7:7,8:8,9:8,10:8,11:11,12:9,13:10,14:12}[kind]
        want[1:4]=[stage,1,int(kind not in (1,14))]
        slot=self.i(current,t,'slot');entry=result['entry'] if result else 0
        if kind in (1,14):
            want[6:9]=[self.pid,self.pid,5];want[12]=1;want[18:23]=c[18:23]
            self.nested_fp(result['before'],result['unexpected'])
        elif kind in (2,3,4):want[8:14]=[entry,PAGE,5 if kind==2 else 1,324 if kind==4 else 10,1,1];want[15:17]=[1,1]
        elif kind==5:want[6:8]=[slot+1,(slot+1)^(1<<63)]
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
        self.r.change(before,current,t,observed=later)

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
            if not build:need(len(slots)==64 and result==0 and self.i(self.owner,'scalar_owner','capacity_misses')>0,'actual full unchanged slot capacity')
            else:
                codes=(1,2402,2403,2404);need(result in codes and q(self.f(self.owner,'scalar_owner','refusals'))[codes.index(result)]>0,'actual typed planner refusal, never an omitted accepted execution')
                scratch=self.f(self.owner,'scalar_owner','scratch');self.eq(scratch,'li2_region_plan',version=1,ready=0,decoder_result=0,page=source['page'],entry=pc,
                    generated=self.i(self.owner,'scalar_owner','low_arena' if pc<1<<31 else 'arena')+len(slots)*PAGE)
                need(self.f(scratch,'li2_region_plan','source')==source['bytes'],'complete last refused-plan input retained')
        return before

    def physical_rows(self,outcome):
        wire0=Fields(self.r,self.b,'sro_wire');bundle=wire0.child('terminal_owners','sro_owners')
        pair=bundle.child('pair',P);life=bundle.child('lifecycle',L);rp=bundle.child('rseq_pair',R)
        state=bundle.child('rseq','li2_rseq_state');close=wire0.child('terminal_global_close','li2_native_close');native=wire0.child('terminal_native_counts','li2_native_counts')
        cb=close.data;ct=close.name;pages=close.integer('pages')
        self.eq(cb,ct,busy=0,complete=1,first_error=0,first_detail=0,first_error_address=0,pid=self.pid,tid=self.pid,last_result=0,sync_result=0,
            attempted=pages,returned=pages,closed=pages,verified=pages,sync_started=int(pages>0),sync_returned=int(pages>0),cleanup_started=0,cleanup_complete=0,
            cleanup_attempted=0,cleanup_returned=0,cleanup_first_result=0,cleanup_sync_result=0)
        need(close.integer('sequence')>0 and pages<=2 and close.integer('sequence')>=life.integer('close_calls'),'actual distinct global native close sequence')
        if pages:need(canonical(close.integer('last_address')) and close.integer('last_address')%PAGE==0,'actual last native closed page')
        else:self.eq(cb,ct,last_address=0)
        for key in ('before','after'):self.maps(close.field(key))
        need(native.integer('admissions')==native.integer('closed')==life.integer('published') and native.integer('attempts')==life.integer('attempts') and
            native.integer('attempts')>=sum(native.integer(k) for k in ('admissions','blocked','low_address_refusals')),'physical native pair counts independent of generated entries')
        revisit=native.integer('revisit_count');need(0<=revisit<=16 and revisit<=max(native.integer('admissions')-1,0),'actual native revisit bound')
        values=list(q(native.field('revisit_ns')));need(all(v>0 for v in values[:revisit]) and not any(values[revisit:]),'whole native timing prefix/zero tail')
        need(native.integer('first_source_offset')%PAGE==0 and (native.integer('first_admission_ns')>0 if native.integer('admissions') else native.integer('first_admission_ns')==0),'actual first native timing/offset')
        physical={k:native.integer(k) for k in ('attempts','admissions','closed','blocked','low_address_refusals','first_admission_ns','first_source_offset','revisit_count')}
        physical.update(status=outcome['status'],failure_code=outcome['failure_code'],revisit_ns=values[:revisit],close_error=0,close_complete=1,close_busy=0,epoch_exits=0,refaults=0,epoch_error=0)
        return dict(outcome=outcome,native_pair=old.pair_row(pair,life,rp,close,outcome),rseq=old.rseq_row(state,outcome),native=physical,
            route=self.h[36],pending=self.h[35],dependencies=self.h[22])

    def report_rows(self,outcome):
        expected=self.physical_rows(outcome);own=Fields(self.r,self.owner,'scalar_owner');cur=own.child('current','sr_record')
        names='initialized first_error used candidates source_misses plan_misses capacity_misses publications hits entries completed unexpected events plan_checks rseq_checks'.split()
        scalar=dict(version=1,**outcome,**{k:own.integer(k) for k in names},active=self.h[31],busy=self.h[32],decoding=self.h[53],signals=list(q(own.field('signals'))),
            refusals=list(q(own.field('refusals'))),exit_indices=list(q(own.field('exit_counts'))))
        scalar['current']=(cur.values('slot_present slot redirected exit_seen completed exit_index')+
            cur.child('open','sr_permission').values('started returned complete')+cur.child('close','sr_permission').values('started returned complete')+
            cur.values('release_started release_complete cleanup_started cleanup_complete')+
            [cur.child('before','sr_frame').integer('complete'),cur.child('after','sr_frame').integer('complete'),cur.integer('unexpected_seen'),cur.child('unexpected','sr_frame').integer('complete')]+
            cur.child('original','li2_region_pc').values('ready kind head_index source_offset')+cur.values('idle_bytes live_bytes closed_bytes')+
            cur.child('final_fetch','li2_fetch_progress').values('held complete')+cur.values('build_started build_returned build_result gpr_written flags_written'))
        expected['scalar']=scalar;return expected
    def scratch(self,slots):
        """Retained unpublished workspace never becomes execution authority."""
        b=self.f(self.owner,'scalar_owner','scratch');t='li2_region_plan'
        if not any(b):
            need(self.i(self.owner,'scalar_owner','publications')==0 and self.i(self.owner,'scalar_owner','plan_misses')==0,'zero workspace only before any returned plan');return
        self.eq(b,t,version=1,decoder_result=0);ready=self.i(b,t,'ready');need(ready in (0,1),'workspace ready bit')
        page,entry,generated=self.v(b,t,'page entry generated');source=self.f(b,t,'source')
        need(canonical(page,PAGE) and canonical(generated,PAGE) and page%PAGE==generated%PAGE==0 and page!=generated and page<=entry<page+PAGE,'bounded retained workspace addresses')
        origins=[]
        for objid,bias in self.bases.items():
            obj,_,loads=self.objects[objid]
            for p in loads:
                if p[1]==5 and (bias+p[3])&-PAGE<=page and entry+15<=bias+p[3]+p[5]:
                    offset=(p[2]&-PAGE)+page-((bias+p[3])&-PAGE)
                    if 0<=offset<len(obj['data']) and offset+PAGE<=(len(obj['data'])+PAGE-1)&-PAGE:
                        original=obj['data'][offset:offset+PAGE];origins.append(original+bytes(PAGE-len(original)))
        if self.control==10 and entry==self.h[20]:
            altered=bytearray(self.app['source_page']);altered[-1]^=1;need(source==altered,'exact control-only corrupted scratch input')
        else:need(origins and all(x==source for x in origins),'whole retained workspace joins authenticated original object bytes')
        if ready:
            plan_reader.check(b,page,source,entry,generated,self.boundaries);return
        status=plan_reader.failed(b,page,source,entry,generated,self.boundaries)
        need(q(self.f(self.owner,'scalar_owner','refusals'))[(1,2402,2403,2404).index(status)]>0,
            'retained failed workspace belongs to an actually counted exact refusal class')
        current=self.f(self.owner,'scalar_owner','current')
        if self.i(current,'sr_record','build_returned') and self.i(current,'sr_record','build_result'):
            need(self.i(current,'sr_record','build_result')==status,'actual current planner result equals whole first-failure reconstruction')

    def finish(self,exit_status):
        outcome=self.header(exit_status);h=self.h;r=self.r;ot='scalar_owner';o=self.owner;c=self.control;failed=exit_status==125;mode=self.app['mode']
        self.eq(o,ot,initialized=1,metadata_registered=1,arena_registered=1,allocated=1,low_arena_registered=1,low_allocated=1,first_error=outcome['failure_code'],first_detail=outcome['detail_abs'])
        arena,low,used=self.v(o,ot,'arena low_arena used')
        need(canonical(arena,64*PAGE) and arena%PAGE==0 and 0<low<=2**31-64*PAGE and low%PAGE==0 and
            (low+64*PAGE<=arena or arena+64*PAGE<=low) and used<=64,'both actual disjoint protected arenas and unchanged total64 capacity')
        self.eq(o,ot,allocation_result=arena,low_allocation_result=low,publications=used)
        self.query(self.f(o,ot,'initial'),arena,3,64);self.query(self.f(o,ot,'low_initial'),low,3,64)
        session=self.f(o,ot,'session');self.eq(session,'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        need(self.i(session,'li2_step_session','sync_query')<1<<63 and self.i(session,'li2_step_session','sync_query')&96==96,'actual core synchronization session')
        generated=self.f(self.b,'sro_wire','generated');slots=[]
        for i,b in enumerate(r.items(o,ot,'slots','sr_slot')):
            if i>=used:zero(b,'whole unused immutable slot');zero(generated[i*PAGE:(i+1)*PAGE],'whole unused generated page capture');continue
            s=self.slot(b,i);need(generated[i*PAGE:(i+1)*PAGE]==s['page'],'every actual terminal generated byte including CC tail');slots.append(s)
        need(h[40]==used,'all actual used slots captured')
        entries,completed,hits=self.v(o,ot,'entries completed hits');prepub=c in (8,9,10,12,13,14)
        self.eq(o,ot,candidates=sum(self.i(o,ot,k) for k in ('source_misses','plan_misses','capacity_misses','publications','hits'))+int(c==6 or prepub),
            entries=used+hits-int(c in (2,4,5,11)),completed=entries-int(failed and c not in (2,4,5,6,8,9,10,11,12,13,14)),unexpected=int(failed and not c or c in (1,7,14)))
        need(sum(q(self.f(o,ot,'refusals')))==self.i(o,ot,'plan_misses') and sum(q(self.f(o,ot,'exit_counts')))==completed and
            sum(q(self.f(o,ot,'signals')))==self.i(o,ot,'events'),'complete distinct refusal/exit/signal partitions')
        plan_adjust={1:-1,2:-1,3:0,4:-1,5:-2,6:0,7:-1,8:1,9:1,10:1,11:-1,12:1,13:1,14:0}
        rseq_adjust={1:-1,2:-2,3:0,4:-2,5:-3,6:0,7:-1,8:0,9:0,10:0,11:-3,12:0,13:0,14:0}
        self.eq(o,ot,plan_checks=3*used+2*hits+(plan_adjust[c] if c else -int(failed)),rseq_checks=4*used+3*hits+(rseq_adjust[c] if c else -int(failed)))
        current=self.f(o,ot,'current');last=self.f(o,ot,'last');rows=r.items(self.b,'sro_wire','entries','sro_entry')
        count=0 if c==6 else self.app['invocations'];need(count in (0,1,2) and h[24]==count and h[25]==(0 if failed else count),'all fixed focal attempts and genuine completions')
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
                need(self.f(e,et,'generated_page')==slots[result['slot']]['page'],'whole actual generated RX image at redirect')
                self.redirected(self.f(e,et,'redirected'),result['before'],result['entry'])
                bundle=self.owners(self.f(e,et,'redirected_owners'),True);self.footprint(bundle,result['plan']);bundles.append(bundle)
            else:
                for key in ('generated_page','redirected','redirected_owners'):zero(self.f(e,et,key),'no invented redirect '+key)
            if not failed:
                bundle=self.owners(self.f(e,et,'completed_owners'));self.footprint(bundle,result['plan'])
                # Exit rechecks every original descriptor and current pin. Those
                # observations are actual new work; they are not forced equal.
                need(self.i(self.f(bundle,'sro_owners','rseq'),'li2_rseq_state','epoch')==self.i(self.f(bundles[-1],'sro_owners','rseq'),'li2_rseq_state','epoch'),'same registration epoch throughout actual owner')
            else:zero(self.f(e,et,'completed_owners'),'failed entry has no completed owner snapshot')
            need((result['before']['fs'],result['before']['gs'])==tuple(self.app['machine'][1:3]),'focal actual TLS joins application prefix')
            gb,ga=(q(self.f(e,et,k)) for k in ('global_before','global_after'));need(gb[0]==gb[4] and gb[2]==gb[3] and gb[0]<=used and gb[1]<=hits,'source hook observes quiet global counters')
            if not failed:
                build=self.i(raw,'sr_record','build_started');need(ga==tuple(gb[j]+(build if j in (0,4) else 1-build if j==1 else 1) for j in range(5)),'exact per-entry publication/hit/entry/completion deltas')
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
            ft='li2_fetch_progress';f=self.f(current,'sr_record','final_fetch');self.eq(f,ft,held=1,complete=1,first_error=0,first_detail=0,identity_observed=1,pages_copied=1,bytes_copied=15,last_backing_page=0,last_backing_observed=1)
            need(self.i(f,ft,'sequence')>0 and self.i(f,ft,'validation_calls')>0,'real pre-source held fetch after old routes');self.maps(self.f(f,ft,'preparation'));self.maps(self.f(f,ft,'validation'))
        elif failed:need(h[30]==0 and self.i(rows[0],'sro_entry','terminal')==1,'actual failed focal terminal prefix')
        elif self.i(current,'sr_record','completed'):
            self.record(current,slots);need(current==last,'whole current completed owner equals retained last')
        else:self.clean_miss(current,slots)
        if completed:self.record(last,slots)
        else:zero(last,'no invented prior successful owner')
        if not failed:
            focal_current=self.i(self.f(self.f(current,'sr_record','source'),'li2_region_source','key'),'li2_region_source_key','entry')==h[20]
            need(h[30]==(count-1 if focal_current else 2),'actual current focal index or nonfocal sentinel')
            need(h[31:38]==(0,0,0,1,0,0,1),'actual successful idle owner at final report')
            self.eq(self.f(self.b,'sro_wire','terminal_fetch'),'li2_fetch_progress',held=0,first_error=0)
        else:
            entered=c not in (2,4,5,6,8,9,10,11,12,13,14);routed=c not in (6,8,9,10,12,13,14)
            need(h[31:34]==(int(entered),1,1) and h[34]==int(bool(c and c!=7)) and h[35:38]==(int(routed),8 if routed else 0,1) and
                h[38]==self.i(current,'sr_record','flags'),'actual interrupted owner active/handling/route/flags prefix')
            need(self.f(self.b,'sro_wire','terminal_fetch')==self.f(current,'sr_record','final_fetch'),'whole failed fetch capture equals unreleased current ticket')
        self.owners(self.f(self.b,'sro_wire','terminal_owners'));self.controls(current,outputs[0] if outputs else None);self.scratch(slots)
        expected=self.report_rows(outcome)
        return dict(mode=mode,control=c,entries=outputs,focal=focal,terminal_expected=expected,
            supplied_before=self.frame(self.f(self.b,'sro_wire','supplied_before'),False) if c==6 else None,
            summary=dict(focal_entries=count,focal_completed=h[25],global_entries=entries,global_completed=completed,publications=used,
                required_failed_operation=int(failed),supplied_control=int(bool(c)),held_fetch=self.i(self.f(self.b,'sro_wire','terminal_fetch'),'li2_fetch_progress','held'),
                cleanup_complete=self.i(current,'sr_record','cleanup_complete')))


def boundary_requests(data,layout):
    return boundary_reader.requests(Reader(data,layout))


def read(data,layout,image,app,pid,cpu,exit_status,control=0,*,boundaries):
    need(type(pid)is int and pid>0 and type(cpu)is int and cpu>=0 and type(control)is int and 0<=control<=14 and type(exit_status)is int,'actual scalar subject identity/control')
    need(type(image)is dict and type(image.get('uid'))is int and 0<=image['uid']<1<<32,'actual explicit launch UID')
    mode=app['mode'];need(type(mode)is int and 0<=mode<=12 and (not control or mode==0),'fixed13 real modes and14 separate mode0 controls')
    need(app['base_mode']==(4 if mode>=11 else mode) and app['invocations']==(2 if mode>=11 else 1),'exact repeat/generation invocation count')
    need(exit_status==(125 if control or 5<=mode<=10 else 0),'exact required failure or completed application exit')
    return Check(Reader(data,layout),image,app,pid,cpu,control,boundaries).finish(exit_status)


def terminal(parsed,scalar,unrolled,owner):
    expected=owner['terminal_expected'];outcome=expected['outcome']
    need(scalar==expected['scalar'],'every scalar report field equals actual captured owner')
    for key in ('native_pair','rseq'):need(parsed[key]==expected[key],'entire actual '+key+' report/capture join')
    for key,value in expected['native'].items():need(parsed['native'][key]==value,'physical native report/capture '+key)
    for name in ('loader','native_pair','rseq','run','chain','trace_run','reuse','repeat_lease'):
        need(all(parsed[name][key]==value for key,value in outcome.items()),'unchanged shared terminal outcome '+name)
    if parsed['repeat'] is not None:need(all(parsed['repeat'][key]==value for key,value in outcome.items()),'unchanged optional REP outcome')
    need(parsed['loader']['admissions']==expected['native']['admissions'] and parsed['loader']['dependency_objects']==expected['dependencies'] and
        parsed['loader']['step_route']==parsed['run']['route']==expected['route'] and parsed['run']['pending']==expected['pending'],'actual route/dependency/physical count joins')
    for key,scope in (('rseq_native','registered_native_epochs'),('rseq_boundary','registered_current_pc_refault')):
        for name,value in parsed[key].items():
            want=1 if name=='version' else scope if name=='scope' else outcome[name] if name in outcome else [0]*len(value) if type(value)is list else 0
            need(value==want,'whole unchanged unused old owner '+key+'.'+name)
    # The old unrolled report is not a raw member of this wire. Its complete
    # original reader/control gate remains mandatory; these are additional
    # source-backed cross-owner quietness and real handler-count joins.
    need(all(unrolled[k]==v for k,v in outcome.items()) and unrolled['initialized']==1 and unrolled['first_error']==0 and
        unrolled['active']==unrolled['busy']==0 and unrolled['entries']==unrolled['completed'] and unrolled['publications']==unrolled['used']<=64,
        'unchanged original unrolled stream is genuinely quiet, not relabeled as scalar')
    extra=int(owner['control'] in (1,7,14) or 5<=owner['mode']<=10)
    need(scalar['events']==unrolled['events']+extra,'scalar earliest preentry counts the terminal unexpected signal before old preentry')
    delta=[0]*5
    if extra:delta[1 if owner['control'] in (1,14) else 0]=1
    need(scalar['signals']==[unrolled['signals'][i]+delta[i] for i in range(5)],'exact actual cross-owner signal partition')
    return dict(reports_present=1,status=outcome['status'],failure_code=outcome['failure_code'],captured_global_native_closed=expected['native']['closed'],
        captured_fetch_held=owner['summary']['held_fetch'],captured_cleanup_complete=owner['summary']['cleanup_complete'])


# Fixed source-derived refusal inventory; no count is inferred from observations.
CONTROL_COUNTS={(0,0):86,(1,0):86,(2,0):86,(3,0):86,(4,0):86,
    (5,0):88,(6,0):88,(7,0):88,(8,0):88,(9,0):88,(10,0):88,(11,0):96,(12,0):96,
    (0,1):102,(0,2):82,(0,3):86,(0,4):82,(0,5):82,(0,6):49,(0,7):83,
    (0,8):68,(0,9):68,(0,10):68,(0,11):82,(0,12):68,(0,13):68,(0,14):81}


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
    add('terminal_rseq_epoch',[('terminal_owners',None,'uho_owners'),('rseq',None,'li2_rseq_state'),('epoch',None,None)])
    add('terminal_pair_live',[('terminal_owners',None,'uho_owners'),('pair',None,P),('live',None,None)])
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
        if control not in (2,4,5,8,9,10,11,12,13,14):add('whole_actual_generated_page',base+[('generated_page',None,None)],1796)
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
    need(len(tests)==(29,48,28,29,28,28,21,29,28,28,28,28,28,28,47)[control],
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
        plan=where([('owner',None,'scalar_owner'),('slots',slot,'sr_slot'),('plan',None,'li2_region_plan')])
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
    need(len(tests)+len(metadata)==CONTROL_COUNTS[(app['mode'],control)],'exact fixed scalar supplied-control population')
    need(len({name for name,_ in tests})==len(tests),'unique fixed supplied record controls')
    names=[]
    for name,offsets in tests:
        changed=bytearray(data);rejected=False
        for offset in offsets:changed[offset]^=4 if name=='nested_snapshot_bv' else 64 if name=='nested_coherent_fp_pointer' else 32 if name=='actual_conserved_flags' else 1
        try:read(bytes(changed),layout,image,app,pid,cpu,exit_status,control,boundaries=boundaries)
        except ValueError as error:
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
    return dict(refusals=names,native_operations=0,original_sha256=original)
