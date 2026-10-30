"""Finite genuine-TRACE experiment, not whole-program or cache-history qualification.

The caller binds fresh source/build/ELF/headers/process closure and separately
compares these complete actual frames with the native fixture. No decoder runs.
"""
import hashlib
import struct
from pathlib import Path
import importlib.util
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
HERE=Path(__file__).resolve().parent
wire=load('span_trace_wire',HERE/'wire.py');plan=load('span_trace_plan',HERE/'plan.py')
old=wire.old
need,zero,q,canonical=old.need,old.zero,old.q,old.canonical
U64,PAGE,FP,TF,RF,MASK=old.U64,old.PAGE,old.FP,old.TF,old.RF,old.MASK
DATA,STACK,RSP=old.DATA,old.STACK,old.RSP
P,L,R=old.P,old.L,old.R


def elf_symbols(data):
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
            if name in wire.REGISTERED or name in ('li2_raw6','li2_gateway_start','li2_gateway_end','span_transfer','selected_chain','protected'):
                need(name not in symbols,'unique actual bridge symbol');symbols[name]=(address,size)
    need(set(symbols)==set(wire.REGISTERED)|{'li2_raw6','li2_gateway_start','li2_gateway_end','span_transfer','selected_chain','protected'},'whole required compiled object inventory')
    ph=[struct.unpack_from('<IIQQQQQQ',data,h[5]+56*i)for i in range(h[10])]
    return h,ph,symbols


class Check(old.Check):
    def __init__(self,reader,image,app,pid,cpu,control):
        self.r,self.image,self.app,self.pid,self.cpu,self.control=reader,image,app,pid,cpu,control
        self.b=reader.data[:-64];self.h=q(self.f(self.b,'spto_wire','h'));self.control_words=q(self.f(self.b,'spto_wire','control'))
        self.entry=self.f(self.b,'spto_wire','entry');self.record=self.f(self.entry,'spto_entry','owner')
        self.bias=self.h[9]-reader.layout['symbols']['li2_raw6'];self.head=app['head'];self.page=self.head&-PAGE
        self.objects={};self.bases={};self.backings={};self.maps_seen={};self.source_ids={}
        for key,obj in image['objects'].items():
            need(type(key)is int and key>=0 and type(obj)is dict,'actual explicit object inventory')
            h,loads=old.elf(obj['data']);self.objects[key]=(obj,h,loads)
        need(image['main_object'] in self.objects and image['interpreter_object']in self.objects,'actual original object identities')
        self.eh,self.ph,self.symbols=elf_symbols(image['bridge'])
        need(set(reader.layout['symbols'])==set(self.symbols)|{'span_progress'} and all(reader.layout['symbols'][k]==v[0]for k,v in self.symbols.items()),'actual same fresh ELF and DWARF symbols')

    def header(self,status):
        h=self.h;r=self.r;t='spto_wire';code=3104 if status else 0;detail=5 if self.control else 11 if status else 0
        need(h[:9]==(0x314f54535049324c,2,r.types[t]['bytes'],r.types['spto_entry']['bytes'],r.types['sp_record']['bytes'],r.types['sp_slot']['bytes'],r.types['sp_frame']['bytes'],968,128),'whole actual TRACE capture version and extent')
        need(canonical(self.bias) and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(k)for k in ('li2_raw6','li2_gateway_start','li2_gateway_end'))and h[10]<=h[9]<h[11],'actual bridge bias and gateway')
        need(canonical(h[12],h[13])and h[12]%PAGE==0 and h[13]==524288,'whole actual altstack')
        need(h[14:16]==(1,0)and h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,0),'actual exclusive FD3 sink')
        need(h[20]==self.head and h[22]==self.image['main_object']and h[23:26]==(1,self.app['mode'],0)and h[26:30]==(1,status,code,detail),'exact focal source, fixed mode and actual outcome')
        need(h[39:43]==(0,0,h[16],0)and h[45]<=h[44]<=h[43]and h[46]<=h[43]and h[47:50]==(0,0,0)and h[50:52]==(1,1)and h[57]==1 and h[63]==0,'all sink/diagnostic and terminal markers')
        need(h[52:57]==tuple(self.symbol(k)for k in ('selected_scalar_span','span_progress','spr','selected_chain','spto_wire')),'actual protected owner/capability/collector addresses')
        need(type(self.control)is int and self.control in(0,1)and(not self.control or self.app['mode']==0)and self.control_words[0]==self.control,'exact requested nested case')
        if not self.control:
            zero(self.f(self.b,t,'nested_fp'),'no invented nested observation');need(not any(self.control_words[1:]),'no unexecuted nested control')
        else:
            c=self.control_words;need(c[1:3]==(1,1)and not any(c[3:6])and c[6:9]==(self.pid,self.pid,5)and not any(c[9:12])and c[12]==1 and not any(c[13:18]),'actual single nonreturning pointer-free tgkill')
        for key in ('sink_initial','sink_terminal'):
            a=self.f(self.b,t,key);st=self.stat(a);need(st['mode']&0xffff==0x8180 and st['size']==0,'actual empty0600 sink');self.eq(a,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(self.f(self.b,t,'sink_initial'),self.f(self.b,t,'sink_terminal'),'stat',observed=('st_atim','st_mtim','st_ctim'))
        footer=q(r.data[-64:]);need(footer[:4]==(0x314654535049324c,2,len(self.b),len(self.b))and 1<=footer[4]<=64 and 0<footer[5]<=len(self.b)and footer[6:]==(status,code),'whole actual wire/footer/write completion')
        if footer[4]==1:need(footer[5]==len(self.b),'single complete actual write')
        for key,objid in (('main',self.image['main_object']),('interpreter',self.image['interpreter_object'])):self.image_header(self.f(self.b,t,key),objid)
        obj,_,loads=self.objects[self.image['main_object']];bias=self.bases[self.image['main_object']]
        spans=[p for p in loads if p[1]==5 and bias+p[3]<=self.page and self.page+PAGE<=bias+p[3]+p[5]]
        need(len(spans)==1 and h[21]==spans[0][2]+self.page-bias-spans[0][3]and obj['data'][h[21]:h[21]+PAGE]==self.app['source']==self.f(self.b,t,'original_source'),'whole actual retained main source')
        hardware=self.f(self.b,t,'hardware');self.eq(hardware,'li2_selected_hardware',abi_version=1,reserved=0)
        for i,key in enumerate(('leaf0','leaf1','leaf7')):need(struct.unpack('<4I',self.f(hardware,'li2_selected_hardware',key))==tuple(self.app['hardware'][i][2:]),'all actual initial CPUID facts')
        return dict(status=status,failure_code=code,detail_abs=detail,detail_negative=0)

    def registry(self,b):
        t='spto_registry';self.eq(b,t,complete=1,table=self.symbol('protected'));count=self.i(b,t,'count');need(0<count<=128,'bounded actual registration table')
        rows=self.r.items(b,t,'ranges','li2_fork_range');ranges=[self.v(x,'li2_fork_range','first end')for x in rows[:count]]
        for row in rows[count:]:zero(row,'whole unused protected range')
        need(all(canonical(a,z-a)for a,z in ranges),'whole actual protected byte intervals')
        kinds=self.f(b,t,'initial_code');need(not any(kinds[count:])and all(x in(0,1)for x in kinds),'literal initial-code classification')
        im=self.f(b,t,'bridge');self.eq(im,'image',bias=self.bias,entry=self.bias+self.eh[4],n=len(self.ph),source=0,source_size=0,backing_fd=(1<<32)-1,kind=3)
        zero(self.f(im,'image','source_hash'),'no invented original bridge hash');need(canonical(self.i(im,'image','ph'),56*len(self.ph)),'actual program header pointer')
        need(self.f(b,t,'ph')==b''.join(struct.pack('<IIQQQQQQ',*p)for p in self.ph)+bytes((32-len(self.ph))*56),'all actual bridge program headers')
        objects=[];decl=self.r.layout['registrations'];need(set(decl)==set(wire.REGISTERED),'all exact byte-registration source witnesses')
        for name,(source,tag)in wire.REGISTERED.items():
            d=decl[name];at,n=self.symbols[name];a,z=self.bias+at,self.bias+at+n
            need(set(d)=={'address','bytes','alignment','tag','source'}and(d['address'],d['bytes'],d['tag'])==(at,n,tag)and type(d['alignment'])is int and 0<d['alignment']<=PAGE and not d['alignment']&(d['alignment']-1)and a%d['alignment']==0 and d['source'].endswith('/tools/page-entry/selected/'+source),'actual symbol/DWARF/source-selected registration '+name)
            need(ranges.count((a,z))==1 and kinds[ranges.index((a,z))]==0,'whole strict registered object extent')
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

    def page_row(self,b):
        t='li2_fetch_page';self.eq(b,t,address=self.page,backing=1,object=self.image['main_object'],logical=5,closed_prot=1,offset=self.h[21],initial_extent=0)
        need(self.i(b,t,'allocation')>0 and self.i(b,t,'generation')>0,'actual positive allocation/generation and exact main extent')
        a,z,major,minor,inode,off=self.v(b,t,'vma_first vma_end vma_major vma_minor vma_inode vma_offset');st=self.stat(self.f(self.b,'spto_wire','main_backing'));dev=st['dev']
        need(a%PAGE==z%PAGE==off%PAGE==0 and a<=self.page<self.page+PAGE<=z and off+self.page-a==self.h[21]and(major,minor,inode)==(((dev>>8)&0xfff)|((dev>>32)&0xfffff000),(dev&255)|((dev>>12)&0xffffff00),st['ino']),'whole actual page/VMA/backing identity')
        return b

    def backing(self,b):
        self.eq(b,'li2_fetch_backing',seals_observed=1,stat_observed=1,seals=15,stat_result=0)
        need(200<=self.i(b,'li2_fetch_backing','retained_fd')<1<<31 and self.stat(self.f(b,'li2_fetch_backing','stat'))==self.stat(self.f(self.b,'spto_wire','main_backing')),'actual sealed retained duplicate/stat')

    def source(self,b):
        self.eq(b,'li2_span_source',ready=1);key=self.f(b,'li2_span_source','key');self.eq(key,'li2_span_source_key',entry=self.head)
        self.page_row(self.f(key,'li2_span_source_key','page'));self.backing(self.f(key,'li2_span_source_key','backing'))
        need(self.f(key,'li2_span_source_key','bytes')==self.app['source'],'whole4096 source ticket bytes')
        ref=self.f(b,'li2_span_source','borrow');a,n=self.v(ref,'li2_fetch_ref','owner sequence');need(canonical(a)and n>0,'actual fresh occupied fetch identity')
        return dict(key=key,ref=ref,borrow=n,owner=a,page=self.page,pc=self.head,bytes=self.app['source'])

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
        want=bytearray(a['raw']);fields=self.r.types['sp_frame']['fields'];step=self.r.types['li2_step_frame']['fields']
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
        self.eq(pages[0],'li2_step_page',address=self.page,object=self.i(sourcepage,'li2_fetch_page','allocation'),generation=self.i(sourcepage,'li2_fetch_page','generation'),offset=self.h[21],closed_prot=1,open_prot=5);zero(pages[1],'whole unused permission page')
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

    def transfer(self,b,source,closed_slot,index,resumed):
        t='li2_span_transfer_progress';self.eq(b,t,phase=5 if resumed else 3,issued=1,consume_attempted=int(not resumed),consumed=int(not resumed),resume_attempted=int(resumed),resumed=int(resumed),previous=index,successor_installed=int(resumed),first_error=0,first_detail=0,pc=self.head,flags=self.app['seed'][1],previous_generation=self.i(closed_slot,'li2_tf_chain_slot','generation'),previous_borrow=self.i(self.f(self.f(closed_slot,'li2_tf_chain_slot','fetch'),'li2_chain_fetch','ref'),'li2_fetch_ref','sequence'),fresh_borrow=source['borrow'])
        need(self.i(b,t,'serial')>0 and self.i(b,t,'event')==self.i(self.f(self.entry,'spto_entry','closed_chain'),'li2_tf_chain','event_id'),'actual one-use event identity')
        a,n=self.observation(self.f(b,t,'released'),self.head-2,False,self.f(self.f(closed_slot,'li2_tf_chain_slot','fetch'),'li2_chain_fetch','ref'))
        x,m=self.observation(self.f(b,t,'fresh'),self.head,not resumed,source['ref']);need(a==x and m>n,'actual newer singleton sequence, no caller-asserted release')
        need(self.f(self.f(b,t,'fresh'),'li2_span_fetch_observation','pages')[:self.r.types['li2_fetch_page']['bytes']]==self.f(self.f(closed_slot,'li2_tf_chain_slot','query'),'li2_tf_continuation','page'),'fresh source exactly equals completed continuation query')
        self.eq(b,t,next=index^1 if resumed else 0)

    def focal(self,status):
        e=self.entry;et='spto_entry';r=self.record;t='sp_record';mode=self.app['mode'];resumed=mode==2;failed=bool(status)
        self.eq(e,et,present=1,closed=1,source_ready=1,terminal=1,redirected=int(not resumed),resumed=int(resumed),completed=int(not failed and not resumed),source_bytes=PAGE,generated_bytes=0 if resumed else PAGE,terminal_source_bytes=PAGE,resumed_closed=int(resumed))
        need(self.f(e,et,'source_page')==self.f(e,et,'terminal_source_page')==self.app['source'],'every actual source byte before/after')
        self.eq(r,t,close_started=1,close_complete=1,prepare_started=1,prepare_complete=1,prepare_result=0,build_started=1,build_returned=1,build_result=int(resumed),resume_started=int(resumed),resume_complete=int(resumed),resume_result=0,resumed_route=int(resumed),miss_release_started=int(resumed),miss_release_complete=int(resumed),miss_release_result=0,flags=self.app['seed'][1])
        source=self.source(self.f(r,t,'source'));before=self.frame(self.f(r,t,'before'));ingress=self.normalized(self.f(r,t,'ingress'),before)
        self.trace(ingress,self.head,self.app['seed'][1]|TF);self.trace(before,self.head,self.app['seed'][1]);self.same_event(ingress,before,self.app['seed'][1])
        need((before['fs'],before['gs'])==tuple(self.app['machine'][1:3]),'actual unchanged per-lane TLS origin')
        p,c=(self.f(e,et,k)for k in('predecessor','closed_chain'));index,closed,oldref,pbefore=self.closed_transition(p,c,self.head-2,ingress)
        self.eq(self.f(r,t,'transfer'),'li2_span_transfer_progress',event=self.i(c,'li2_tf_chain','event_id'))
        self.transfer(self.f(r,t,'transfer'),source,closed,index,resumed)
        self.owners(self.f(e,et,'source_owners'))
        before_memory=self.memory(self.f(e,et,'before_memory'),False);after_memory=self.memory(self.f(e,et,'after_memory'),failed)
        result=dict(ingress=ingress,before=before,predecessor_before=pbefore,source=self.app['source'],terminal_source=self.app['source'],before_memory=before_memory,after_memory=after_memory,redirected=int(not resumed),generated_entry=0,completed=not failed and not resumed,resumed_route=int(resumed),mapped=None)
        if resumed:
            self.eq(r,t,slot_present=0,slot=0,redirected=0,exit_seen=0,completed=0,release_started=0,release_complete=0,cleanup_started=0,cleanup_complete=0,unexpected_seen=0,release_result=0,map_result=0,gpr_written=0,flags_written=0,exit_index=0,idle_bytes=0,live_bytes=0,closed_bytes=0,publication_generation=0)
            for key in('slot','generated_page','redirected_owners','completed_owners'):zero(self.f(e,et,key),'no generated owner on descriptive miss '+key)
            for key in('after','unexpected','original','idle','live','open','close','cleanup','final_fetch'):zero(self.f(r,t,key),'no fabricated generated path '+key)
            self.progress(self.f(r,t,'miss_fetch'),source['borrow'],False)
            need(self.f(r,t,'miss_fetch')==self.f(self.f(self.f(r,t,'transfer'),'li2_span_transfer_progress','fresh'),'li2_span_fetch_observation','progress'),'actual released miss singleton retained by capability')
            frame=self.frame(self.f(e,et,'resumed_frame'));self.trace(frame,self.head,self.app['seed'][1]|TF);self.same_event(before,frame,self.app['seed'][1]|TF)
            successor=self.f(e,et,'resumed_chain');next_index=index^1
            s,ref,_=self.chain_slot(successor,next_index,self.head,False);need(self.i(ref,'li2_fetch_ref','owner')==source['owner']and self.i(ref,'li2_fetch_ref','sequence')>source['borrow'],'actual newly prepared ordinary successor, never restored predecessor')
            self.eq(s,'li2_tf_chain_slot',origin=2,generation=self.i(self.r.items(c,'li2_tf_chain','slots','li2_tf_chain_slot')[next_index],'li2_tf_chain_slot','generation')+1,event_id=self.i(c,'li2_tf_chain','event_id'))
            need(self.r.items(successor,'li2_tf_chain','slots','li2_tf_chain_slot')[index]==closed,'closed predecessor survives successor install')
            step=self.f(self.f(s,'li2_tf_chain_slot','owner'),'li2_tf_owner','step');self.step_frame(self.f(step,'li2_step_owner','before'),before)
            self.r.change(c,successor,'li2_tf_chain',observed=('active','pending','sequence','attempts','trace_entries','prepare_attempts','entry','slots'))
            for key in('sequence','attempts','trace_entries','prepare_attempts'):self.eq(successor,'li2_tf_chain',**{key:self.i(c,'li2_tf_chain',key)+1})
            exit_frame=self.normalized(self.f(e,et,'resumed_exit'),frame);self.trace(exit_frame,self.head+2,self.app['seed'][1]|TF)
            closure=self.f(e,et,'resumed_closed_chain');closed_index,_,closed_ref,_=self.closed_transition(successor,closure,self.head,exit_frame,True)
            # A new event boundary increments event_id and invalidates the old
            # same-handler trace proof before the actual successor closes.
            need(closed_index==next_index and closed_ref==ref,'actual resumed successor fully closed and released')
            result.update(disposition='resumed',resumed=frame,resumed_exit=exit_frame)
            return result
        self.eq(r,t,slot_present=1,redirected=1,publication_generation=self.i(self.f(e,et,'slot'),'sp_slot','identity'),gpr_written=0x305,flags_written=0x8d5,idle_bytes=PAGE,live_bytes=PAGE,map_result=1 if self.control else 0)
        zero(self.f(r,t,'miss_fetch'),'generated path never released a descriptive miss')
        for key in('resumed_frame','resumed_exit','resumed_chain','resumed_closed_chain'):zero(self.f(e,et,key),'no fabricated ordinary successor '+key)
        slot=self.f(e,et,'slot');self.eq(slot,'sp_slot',installed=1,complete=1,filled=PAGE,verified=PAGE)
        need(self.f(slot,'sp_slot','key')==source['key']and 0<self.i(slot,'sp_slot','identity') and self.i(r,t,'slot')<64,'actual complete generation/source identity')
        raw_plan=self.f(slot,'sp_slot','plan');generated=self.i(raw_plan,'li2_span_plan','generated')
        expected,image=plan.plan(self.app['source'],self.page,self.head,generated)
        need(raw_plan==expected and self.f(e,et,'generated_page')==image,'whole57184 plan and every actual generated page byte')
        self.query(self.f(slot,'sp_slot','writable'),generated,3);self.permission(self.f(slot,'sp_slot','publication'),generated,1)
        self.query(self.f(r,t,'idle'),generated,1);self.permission(self.f(r,t,'open'),generated,5);self.query(self.f(r,t,'live'),generated,5)
        self.owners(self.f(e,et,'redirected_owners'),True)
        first=self.f(self.f(e,et,'source_owners'),'spto_owners','rseq');last=self.f(self.f(e,et,'redirected_owners'),'spto_owners','rseq');rt='li2_rseq_state'
        self.r.change(first,last,rt,observed=('last_first','last_end','last_pc','last_code','last_policy','last_footprint'));self.eq(last,rt,last_first=0,last_end=0,last_pc=self.head+29,last_code=701,last_policy=1)
        self.eq(self.f(last,rt,'last_footprint'),'li2_write_footprint',pc=self.head+29,next_pc=self.head+31,first=0,end=0,abi_version=1,policy=1,code=701,length=2)
        result['generated_entry']=generated
        if not failed:
            self.eq(r,t,exit_seen=1,completed=1,release_started=1,release_complete=1,release_result=0,cleanup_started=0,cleanup_complete=0,unexpected_seen=0,closed_bytes=PAGE,exit_index=1 if mode==0 else 0)
            after=self.frame(self.f(r,t,'after'));self.nx(after,self.page+(0x250 if mode==0 else 0x270))
            need(before['fp']==after['fp'] and before['mask']==after['mask']and before['fp_bytes']==after['fp_bytes']and(before['fs'],before['gs'])==(after['fs'],after['gs'])and before['uc'][:40]==after['uc'][:40]and before['uc'][296:304]==after['uc'][296:304],'whole unaffected FP/mask/TLS/UC state')
            self.permission(self.f(r,t,'close'),generated,1);self.progress(self.f(r,t,'final_fetch'),source['borrow'],False)
            for key in('unexpected','original','cleanup'):zero(self.f(r,t,key),'no invented failed-path field '+key)
            self.owners(self.f(e,et,'completed_owners'));need(self.f(self.f(e,et,'completed_owners'),'spto_owners','rseq')==last,'actual final full NONE recheck retains identical rseq state')
            result.update(disposition='completed',after=after)
        else:
            self.eq(e,et,terminal=1);self.eq(r,t,exit_seen=0,completed=0,release_started=0,release_complete=0,release_result=0,cleanup_started=1,cleanup_complete=1,unexpected_seen=1,closed_bytes=0,exit_index=0)
            for key in('after','close'):zero(self.f(r,t,key),'no invented application endpoint')
            zero(self.f(e,et,'completed_owners'),'no successful completion bundle');self.permission(self.f(r,t,'cleanup'),generated,1);self.progress(self.f(r,t,'final_fetch'),source['borrow'],True)
            need(self.f(r,t,'final_fetch')==self.f(self.b,'spto_wire','terminal_fetch'),'actual failed held fetch prefix remains terminal')
            f=self.frame(self.f(r,t,'unexpected'));result['unexpected']=f
            if self.control:
                need(f['sig']==5 and struct.unpack_from('<iii',f['si'])==(5,0,-6)and struct.unpack_from('<II',f['si'],16)==(self.pid,self.image['uid']),'real nested SI_TKILL identity')
                g=f['greg'];need(g[16]==g[14]==self.h[9]+25 and g[13]==0 and(g[8],g[9],g[12],g[2],g[0],g[1])==(self.pid,self.pid,5,0,0,0)and self.h[12]<=g[15]<self.h[12]+self.h[13]and g[17]&0x10500==0 and g[21]==MASK and f['mask']==MASK and(f['fs'],f['gs'])==(before['fs'],before['gs']),'actual nested gateway/frame/mask/TLS, no generated-PC association')
                self.nested_fp(before,f);zero(self.f(r,t,'original'),'actual nested runtime PC map miss');result['disposition']='nested'
            else:
                map_bytes=expected[54064+3*48:54064+4*48];need(self.f(r,t,'original')==map_bytes,'exact previously complete generated head association')
                g=f['greg'];need(f['sig']==11 and struct.unpack_from('<iii',f['si'])==(11,0,2)and g[16]==generated+13 and g[19:22]==(4,14,MASK)and g[22]==DATA+8192 and int.from_bytes(f['si'][16:24],'little')==DATA+8192 and g[17]&(TF|RF)==RF and f['mask']==MASK,'actual generated read fault, never completion')
                need(f['fp']==before['fp']and(f['fs'],f['gs'])==(before['fs'],before['gs']),'whole fault FP/TLS retained')
                result.update(disposition='fault',mapped=dict(original_pc=self.head+13,generated_pc=generated+13,head_index=3))
        return result

    def memory(self,b,after_abort=False):
            t='li2_uho_memory';self.eq(b,t,attempted=1,complete=1,after_abort=int(after_abort),rows_checked=6,data_copied=8192,stack_copied=224,result=0,detail=0,rsp=RSP,data_first=DATA,stack_first=RSP-128)
            m=self.maps(self.f(b,t,'maps'),0 if after_abort else 1)
            before,after=(self.f(b,t,k) for k in ('before','after'));st='li2_maps_stats'
            for v in (before,after):self.eq(v,st,active=int(not after_abort),poisoned=0,reserved=0)
            self.eq(after,st,valid=1,fresh_calls=self.i(before,st,'fresh_calls')+1,acquisitions=self.i(before,st,'acquisitions')+1,handler_id=self.i(before,st,'handler_id'))
            need(m[0]==self.i(after,st,'acquisitions') and m[1]==(0 if after_abort else self.i(before,st,'handler_id')) and m[2]==self.i(after,st,'mutation_epoch'),'memory acquisition actual stats join')
            # Fresh parser RAW advances mutation/invalidation counters according to
            # the fixed gateway; they are retained, never called extra acquisitions.
            need(self.i(after,st,'mutation_epoch')>=self.i(before,st,'mutation_epoch') and self.i(after,st,'invalidations')>=self.i(before,st,'invalidations') and self.i(after,st,'reuses')==self.i(before,st,'reuses'),'source-bound fresh parser counters')
            points=(DATA,DATA+8191,DATA+8192,STACK,RSP-128,STACK+4096+131072)
            for i,row in enumerate(self.r.items(b,t,'rows','li2_uho_map_row')):
                self.eq(row,'li2_uho_map_row',offset=0,major=0,minor=0,inode=0,private=1)
                a,z,prot=self.v(row,'li2_uho_map_row','first end prot');need(a%PAGE==z%PAGE==0 and a<=points[i]<z,'actual private fixed-memory VMA')
                if i<2:need((a,z,prot)==(DATA,DATA+8192,3),'whole data VMA')
                elif i==4:need((a,z,prot)==(STACK+4096,STACK+4096+131072,3),'whole alternate application stack VMA')
                else:need(prot==0 and z-points[i]>=PAGE,'actual unreadable guard VMA')
            result={k:self.f(b,t,k) for k in ('data','stack')}
            need(result['data']==self.app['data'] and result['stack']==self.app['stack'],'every immutable application data/stack byte')
            return result

    def finish(self,status):
        outcome=self.header(status);failed=bool(status)
        session=self.f(self.b,'spto_wire','session');self.eq(session,'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        n=self.i(session,'li2_step_session','sync_query');need(n<1<<63 and n&96==96,'actual registered sync-core session')
        initial,terminal=(self.registry(self.f(self.b,'spto_wire',key))for key in('initial_registry','terminal_registry'))
        need(terminal[0][:len(initial[0])]==initial[0]and terminal[1][:len(initial[1])]==initial[1],'actual append-only registration with all original strict rows intact')
        entry=self.focal(status);self.owners(self.f(self.b,'spto_wire','terminal_owners'));self.physical_rows(outcome)
        counts=q(self.f(self.b,'spto_wire','counts'));events=q(self.f(self.b,'spto_wire','events'))
        names='initialized used offers closed resumed hash_misses candidates source_misses plan_misses capacity_misses publications hits entries completed unexpected plan_checks rseq_checks generation retirement_attempts retirements claims permits_issued pending retiring cursor first_error first_detail decoding closing resuming reserved0 reserved1'.split()
        c=dict(zip(names,counts,strict=True))
        need(c['initialized']==1 and int(self.app['mode']!=2)<=c['used']<=64 and c['offers']==c['closed']==c['candidates']==c['entries']+c['resumed'],'actual complete offer/close and entry/resume partition')
        need(c['resumed']==sum(c[k]for k in('hash_misses','source_misses','plan_misses','capacity_misses'))and c['entries']==c['publications']+c['hits']==c['claims'],'exact descriptive misses and generation entries')
        need(c['generation']==c['publications']==c['used']+c['retirements']and c['retirement_attempts']==c['retirements']and c['cursor']<64,'actual completed publication/retirement accounting')
        need(c['completed']==c['permits_issued']==c['entries']-int(failed)and c['unexpected']==int(failed)and c['pending']==int(failed)and c['retiring']==0,'real completion permits and retained failed owner')
        need(c['plan_checks']==2*c['entries']+c['completed']+c['retirement_attempts']and c['rseq_checks']==3*c['entries']+c['completed'],'all exact static/NONE proof calls, no skipped cached proof')
        need(c['first_error']==outcome['failure_code']and c['first_detail']==outcome['detail_abs']and not any(counts[27:])and events[0]==sum(events[1:6])and sum(events[6:10])==c['plan_misses']and sum(events[10:])==c['completed'],'whole error/event/refusal/exit accounting')
        if failed:
            need(self.h[30:38]==(1,1,1,1,int(self.control==1),1,9,1),'actual nonreturning failed span route and owner flags')
            need(self.f(self.b,'spto_wire','terminal_record')==self.record,'whole current failure is the retained focal record')
            need(self.h[38]==self.app['seed'][1],'actual outer logical flags retain failed entry')
        else:
            need(self.h[31:37]==(0,0,0,1,0,0)and self.h[37]==1,'all new and old routes quiet at successful termination')
            fetch=self.f(self.b,'spto_wire','terminal_fetch');self.eq(fetch,'li2_fetch_progress',held=0,complete=1,first_error=0,first_detail=0)
        chain=self.f(self.b,'spto_wire','terminal_chain');self.eq(chain,'li2_tf_chain',initialized=1,first_error=0,first_detail=0,pending=0,in_handler=0)
        for slot in self.r.items(chain,'li2_tf_chain','slots','li2_tf_chain_slot'):
            # This finite boundary has two CLOSED owners, not the old terminal
            # unexecuted FALLBACK. Keep the complete close/query/release proof.
            self.eq(slot,'li2_tf_chain_slot',phase=5,fallback=0,unexpected_frame_observed=0)
            owner=self.f(slot,'li2_tf_chain_slot','owner');step=self.f(owner,'li2_tf_owner','step')
            self.eq(step,'li2_step_owner',phase=5,first_error=0,first_detail=0,in_handler=0,
                trace_seen=1,revoke_sync_started=1,open_sync=0,revoke_sync=0)
            self.eq(owner,'li2_tf_owner',continuation_started=1,continuation_complete=1,continuation_result=0,unexpected_frame_observed=0)
            request=self.f(step,'li2_step_owner','request');pages=self.i(request,'li2_step_request','page_count')
            need(pages in(1,2),'actual bounded terminal source bundle')
            for key in ('open_started','opened','revoke_started','revoked'):
                need(struct.unpack('<2I',self.f(step,'li2_step_owner',key))==tuple(int(i<pages)for i in range(2)),
                     'entire terminal source permission mask closed')
            for key in ('open_result','revoke_result'):zero(self.f(step,'li2_step_owner',key),'all actual terminal permission results')
            query=self.f(slot,'li2_tf_chain_slot','query')
            self.eq(query,'li2_tf_continuation',attempted=1,page_observed=1,complete=1,result=0,pc=self.i(owner,'li2_tf_owner','actual_post_pc'))
            self.eq(self.f(slot,'li2_tf_chain_slot','release'),'li2_chain_release',started=1,complete=1,result=0)
            fetch=self.f(slot,'li2_tf_chain_slot','fetch');ref=self.f(fetch,'li2_chain_fetch','ref')
            seq=self.i(ref,'li2_fetch_ref','sequence');need(seq>0,'actual retained released borrow')
            self.eq(self.f(fetch,'li2_chain_fetch','progress'),'li2_fetch_progress',held=0,complete=1,first_error=0,first_detail=0,sequence=seq)
        need(self.i(self.f(chain,'li2_tf_chain','entry'),'li2_tf_trace_entry','valid')==0,'no terminal one-use ordinary capability')
        need(not self.i(self.f(chain,'li2_tf_chain','lease'),'li2_tf_same_page','origin_active'),'no terminal same-page permission lease')
        return dict(control=self.control,entry=entry,outcome=outcome,summary=c,events=events,original_sha256=hashlib.sha256(self.r.data).hexdigest(),_check=self)

    def physical_rows(self,outcome):
            """Exact raw snapshots projected in the unchanged report field order."""
            wire=old.Fields(self.r,self.b,'uho_wire');bundle=wire.child('terminal_owners','uho_owners')
            pair=bundle.child('pair',P);life=bundle.child('lifecycle',L);rp=bundle.child('rseq_pair',R)
            state=bundle.child('rseq','li2_rseq_state');close=wire.child('terminal_global_close','li2_native_close')
            native=wire.child('terminal_native_counts','li2_native_counts')
            cb=close.data;ct=close.name;pages=close.integer('pages')
            self.eq(cb,ct,busy=0,complete=1,first_error=0,first_detail=0,first_error_address=0,
                pid=self.pid,tid=self.pid,last_result=0,sync_result=0,
                attempted=pages,returned=pages,closed=pages,verified=pages,
                sync_started=int(pages>0),sync_returned=int(pages>0),cleanup_started=0,cleanup_complete=0,
                cleanup_attempted=0,cleanup_returned=0,cleanup_first_result=0,cleanup_sync_result=0)
            need(close.integer('sequence')>0 and pages<=2 and
                close.integer('sequence')>=life.integer('close_calls'),'distinct global successful native-close sequence')
            if pages:need(canonical(close.integer('last_address')) and close.integer('last_address')%PAGE==0,'actual last closed native page')
            else:self.eq(cb,ct,last_address=0)
            for key in ('before','after'):self.maps(close.field(key))
            need(native.integer('admissions')==native.integer('closed')==life.integer('published') and
                native.integer('attempts')==life.integer('attempts') and
                native.integer('attempts')>=sum(native.integer(k) for k in ('admissions','blocked','low_address_refusals')),
                'physical pair admissions and closed pages, independent of generated entries')
            revisit=native.integer('revisit_count');need(0<=revisit<=16 and revisit<=max(native.integer('admissions')-1,0),'actual bounded native revisit population')
            values=list(q(native.field('revisit_ns')));need(all(v>0 for v in values[:revisit]) and not any(values[revisit:]),'actual positive revisit prefix and entire zero tail')
            need(native.integer('first_source_offset')%PAGE==0 and (native.integer('first_admission_ns')>0 if native.integer('admissions') else native.integer('first_admission_ns')==0),'actual first native timing/offset observation')
            physical={k:native.integer(k) for k in ('attempts','admissions','closed','blocked','low_address_refusals','first_admission_ns','first_source_offset','revisit_count')}
            need(self.h[58]<=native.integer('admissions') and not any(self.h[59:63]),
                'actual main admissions subset and entire unused native epoch state')
            physical.update(version=1,status=outcome['status'],failure_code=outcome['failure_code'],revisit_ns=values[:revisit],
                main_admissions=self.h[58],main_refaults=self.h[59],
                close_error=close.integer('first_error'),close_complete=close.integer('complete'),close_busy=close.integer('busy'),
                epoch_exits=self.h[60],refaults=self.h[61],epoch_error=self.h[62])
            return dict(native_pair=old.pair_row(pair,life,rp,close,outcome),rseq=old.rseq_row(state,outcome),native=physical)


def read(data,layout,image,app,pid,cpu,exit_status,control=0):
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0 and type(exit_status)is int and exit_status==(125 if app['mode']==3 or control else 0),'exact actual process/CPU/required outcome')
    return Check(wire.Reader(data,layout),image,app,pid,cpu,control).finish(exit_status)


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
            a,z=struct.unpack('<2I',f(step,'li2_step_owner',member));need(a in(0,1)and z in(0,1),'actual permission bit pair');values[k]=a|(z<<1)
        row.update({'s'+str(n)+'_'+k:v for k,v in values.items()})
    lease=f(b,t,'lease');lt='li2_tf_same_page'
    for key,field in dict(phase='phase',active='origin_active',candidates='candidates',misses='misses',transfers='transfers',closed='closed_leases',event='completed_event').items():row['lease_'+key]=i(lease,lt,field)
    transfer=f(lease,lt,'transfer')
    for key,field in dict(phase='phase',before='before_sequence',after='after_sequence').items():row['lease_fetch_'+key]=i(transfer,'li2_fetch_rx_view',field)
    return row


def terminal(parsed,owner):
    """Bind exact newly reported rows and old physical/rseq rows to raw capture.

    The collector also runs every unchanged old report safety comparator; this
    projection cannot replace those gates or grant full cache-history credit.
    """
    need(type(parsed)is dict,'typed complete terminal parser output')
    c=owner['summary'];check=owner['_check'];h=check.h;outcome=owner['outcome'];events=owner['events']
    fields='initialized first_error used offers closed resumed hash_misses candidates source_misses plan_misses capacity_misses publications hits entries completed unexpected plan_checks rseq_checks'.split()
    span=dict(version=1,**outcome,**{k:c[k]for k in fields},events=events[0],active=h[31],busy=h[32],decoding=c['decoding'],closing=c['closing'],resuming=c['resuming'])
    f=old.Fields(check.r,check.f(check.b,'spto_wire','terminal_transfer'),'li2_span_transfer_progress')
    span['transfer']=f.values('phase serial event previous next successor_installed previous_generation previous_borrow fresh_borrow pc flags issued consume_attempted consumed resume_attempted resumed first_error')+[abs(f.signed('first_detail')),int(f.signed('first_detail')<0)]
    span['signals']=list(events[1:6]);span['refusals']=list(events[6:10]);span['exit_indices']=list(events[10:18])
    r=old.Fields(check.r,check.f(check.b,'spto_wire','terminal_record'),'sp_record')
    span['current']=r.values('slot_present slot redirected exit_seen completed exit_index')+r.child('open','sp_permission').values('started returned complete')+r.child('close','sp_permission').values('started returned complete')+r.values('release_started release_complete cleanup_started cleanup_complete')+[r.child('before','sp_frame').integer('complete'),r.child('after','sp_frame').integer('complete'),r.integer('unexpected_seen'),r.child('unexpected','sp_frame').integer('complete')]+r.child('original','li2_region_pc').values('ready kind head_index source_offset')+r.values('idle_bytes live_bytes closed_bytes')+r.child('final_fetch','li2_fetch_progress').values('held complete')+r.values('build_started build_returned build_result gpr_written flags_written')
    reuse=dict(version=1,**outcome,**{k:c[k]for k in 'generation retirement_attempts retirements claims permits_issued pending retiring cursor'.split()})
    f=old.Fields(check.r,check.f(check.b,'spto_wire','terminal_current'),'li2_current_custody_stats')
    current=dict(version=1,status=outcome['status'],failure_code=outcome['failure_code'],
        **{k:f.integer(k)for k in 'attempts current_stages current_seeds physical_fallbacks retained_stages retained_checks commits cancels first_error'.split()},
        first_detail_abs=abs(f.signed('first_detail')),first_detail_negative=int(f.signed('first_detail')<0))
    chain=chain_report(check.r,check.f(check.b,'spto_wire','terminal_chain'),outcome)
    lease={k:v for k,v in chain.items()if k.startswith('lease_')}
    expected=dict(scalar_span=span,scalar_span_reuse=reuse,current_tf=current,chain=chain,lease=lease,**check.physical_rows(outcome))
    for key,value in expected.items():need(key in parsed and parsed[key]==value,'entire actual protected terminal row '+key)
    return dict(actual_terminal_rows=len(expected),whole_focal_transfer=1,whole_program_qualification=0)


CONTROL_COUNTS={(0,0):32,(1,0):32,(2,0):32,(3,0):33,(0,1):35}

def controls(data,layout,image,app,pid,cpu,exit_status,control=0):
    """Finite supplied corruptions after the actual full record has passed.

    These refuse evidence changes; they are not native failure injections and
    cannot replace the remaining genuine transfer/retirement qualification.
    """
    accepted=read(data,layout,image,app,pid,cpu,exit_status,control)
    types=layout['types'];edges=layout['edges'];trials=[]
    def extent(*path):
        at=0;t='spto_wire';size=types[t]['bytes']
        for part in path:
            key,index=part if type(part)is tuple else(part,0)
            f=types[t]['fields'][key];at+=f['offset'];size=f['bytes']
            child=edges[t].get(key)
            if child:
                need(type(index)is int and index>=0 and (index+1)*types[child]['bytes']<=size,'bounded typed supplied child')
                at+=index*types[child]['bytes'];size=types[child]['bytes'];t=child
            else:
                need(index==0,'opaque supplied member uses an explicit byte offset');t=None
        return at,size
    def changed(name,path,offset=0,mask=1):
        at,n=extent(*path);need(0<=offset<n,'bounded supplied mutation');b=bytearray(data);b[at+offset]^=mask;trials.append((name,bytes(b)))
    def coherent(name,paths,offset=0,mask=1):
        b=bytearray(data)
        for path in paths:
            at,n=extent(*path);need(0<=offset<n,'bounded coherent supplied mutation');b[at+offset]^=mask
        trials.append((name,bytes(b)))
    e=('entry',);r=e+('owner',);source=r+('source',);transfer=r+('transfer',)
    changed('wire_version',('h',),8)
    changed('header_focal_pc',('h',),20*8)
    trials.append(('missing_footer',data[:-1]));trials.append(('appended_record',data+b'\0'))
    changed('original_source_tail',('original_source',),PAGE-1)
    changed('whole_before_source',e+('source_page',),PAGE-1)
    changed('whole_terminal_source',e+('terminal_source_page',),PAGE-1)
    changed('whole_source_key',source+('key','bytes'),PAGE-1)
    changed('main_initial_extent',source+('key','page','initial_extent'))
    changed('sealed_backing_stat',source+('key','backing','stat','st_ino'))
    changed('current_borrow',source+('borrow','sequence'))
    changed('previous_borrow',transfer+('previous_borrow',))
    changed('capability_phase',transfer+('phase',))
    changed('capability_event',transfer+('event',))
    changed('whole_before_FP',r+('before','frame','fp'),FP-1)
    changed('whole_stack',e+('after_memory','stack'),223)
    changed('whole_data',e+('after_memory','data'),8191)
    changed('session_mask',('session','application_mask'))
    changed('no_completion_credit',e+('completed',))
    changed('actual_global_entries',('counts',),12*8)
    changed('actual_rseq_registration',e+('source_owners','rseq','epoch'))
    # Forge the same non-page interval in both real registry aliases. The
    # precise symbol+DWARF+registration extent must reject this coherent lie.
    c=accepted['_check'];address=c.symbol('spto_wire');indices=[]
    for key in('initial_registry','terminal_registry'):
        raw=c.f(c.b,'spto_wire',key);rows=c.r.items(raw,'spto_registry','ranges','li2_fork_range')
        found=[i for i,x in enumerate(rows[:c.i(raw,'spto_registry','count')])if c.i(x,'li2_fork_range','first')==address]
        need(len(found)==1,'actual unique supplied registry origin');indices.append(found[0])
    coherent('coherent_registered_extent',[(key,('ranges',index),'end')for key,index in zip(('initial_registry','terminal_registry'),indices,strict=True)])
    index=c.i(c.f(c.entry,'spto_entry','closed_chain'),'li2_tf_chain','active')
    changed('old_release_complete',e+('closed_chain',('slots',index),'release','complete'))
    changed('old_query_complete',e+('closed_chain',('slots',index),'query','complete'))
    if app['mode']==2:
        changed('resume_consumed_twice',transfer+('consumed',))
        changed('resume_successor_installed',transfer+('successor_installed',))
        changed('resume_fresh_release',r+('miss_fetch','held'))
        changed('resume_real_trace',e+('resumed_exit','frame','greg'),16*8)
        changed('resume_closed_marker',e+('resumed_closed',))
        changed('resume_release_complete',e+('resumed_closed_chain',('slots',index^1),'release','complete'))
        changed('resume_new_generation',e+('resumed_chain',('slots',index^1),'generation'))
        changed('resume_no_generated_owner',e+('slot','installed'))
    else:
        changed('whole_generated_tail',e+('generated_page',),PAGE-1)
        changed('whole_plan_unused_head',e+('slot','plan'),8272+63*336)
        changed('typed_relocated_target',e+('slot','plan'),30112+4*336+248)
        changed('whole_publication',e+('slot','publication','complete'))
        changed('actual_open',r+('open','complete'))
        changed('actual_generation',r+('publication_generation',))
        changed('actual_source_rseq',e+('redirected_owners','rseq','last_code'))
        changed('actual_close_or_cleanup',r+(('cleanup'if exit_status else 'close'),'complete'))
        if app['mode']==3:changed('exact_failed_pc_association',r+('original','original_pc'))
        if control:
            changed('nested_independent_FP_snapshot',('nested_fp','zero'),160)
            nh=q(c.f(c.f(c.b,'spto_wire','nested_fp'),'uho_nested_fp','h'))
            fp_at=int.from_bytes(accepted['entry']['unexpected']['uc'][224:232],'little')
            changed('nested_actual_stack_preimage',('nested_fp','stack'),fp_at-nh[3]+416)
            # Mutate both whole retained aliases; a raw/current equality alone
            # cannot reject this coherent false exact-PC association.
            coherent('nested_forged_mapping',[r+('original','ready'),('terminal_record','original','ready')])
    need(len(trials)==CONTROL_COUNTS[app['mode'],control]and len({n for n,_ in trials})==len(trials),'literal complete finite record-control table')
    names=[]
    for name,changed_data in trials:
        refused=False
        try:read(changed_data,layout,image,app,pid,cpu,exit_status,control)
        except ValueError:refused=True
        need(refused,'actual protected TRACE reader accepted supplied '+name);names.append(name)
    return dict(refusals=names,native_operations=0,original_sha256=hashlib.sha256(data).hexdigest())
