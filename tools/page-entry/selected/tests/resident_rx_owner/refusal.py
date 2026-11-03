"""Literal causal RX refusals, with one independently checked completed prefix.

There is no application stdout in these failed subjects. The small ``app``
mapping below contains only source-derived fixture constants and captured
coordinates for the shared lower-level owner checks. It is not an application
record, and no application/native equivalence is inferred from it.
"""
import copy,hashlib,importlib.util,struct
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('resident_rx_refusal_base',HERE/'read.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
wire=base.wire;generation=base.base;plan=generation.plan;old=generation.old
need,zero,q,canonical=base.need,base.zero,base.q,base.canonical
PAGE,TF,RF,MASK=base.PAGE,base.TF,base.RF,base.MASK
T,STATE,CERT=base.T,base.STATE,base.CERT
# Unprefixed 8e d0 in 64-bit mode uses the default 32-bit operand size:
# iced-x86 1.21.0 Code::Mov_Sreg_r32m16 (294). The real rseq write-footprint
# guard rejects this unsupported SS destination before execution.
STOPS={1:(101,305),2:(1205,180),3:(300,228),4:(142,0),5:(4902,15),6:(1207,294),7:(4900,11)}


def app_symbols(data):
    """Independent complete ELF coordinates for the actual causal operands."""
    h,_=old.elf(data)
    need(h[1]==2 and h[11]==64 and 0<h[12]<=256 and h[6]+64*h[12]<=len(data),
         'bounded original ET_EXEC sections')
    sections=[struct.unpack_from('<IIQQQQIIQQ',data,h[6]+64*i)for i in range(h[12])]
    tables=[s for s in sections if s[1]==2];need(len(tables)==1,'one actual symbol table')
    t=tables[0];need(t[9]==24 and t[5]%24==0 and t[6]<len(sections)and
        t[4]+t[5]<=len(data),'complete actual symbols')
    st=sections[t[6]];need(st[1]==3 and st[4]+st[5]<=len(data),'complete actual names')
    names=data[st[4]:st[4]+st[5]];found={}
    wanted={'rrx_case_id','rrx_mailbox','rrx_attack','rrx_after_attack',
        'region_app_capture_high','region_app_capture_pointer'}
    for at in range(t[4],t[4]+t[5],24):
        n,info,other,section,address,size=struct.unpack_from('<IBBHQQ',data,at)
        need(n<len(names)and b'\0'in names[n:],'whole symbol name')
        name=names[n:names.index(b'\0',n)].decode('ascii')
        if name in wanted:
            need(name not in found and not other and 0<section<len(sections),
                 'unique actual causal/capture symbol')
            found[name]=(info,address,size,section)
    ph=[struct.unpack_from('<IIQQQQQQ',data,h[5]+56*i)for i in range(h[10])]
    return found,sections,ph


class Prefix(base.Check):
    """Reuse the actual owner theorem, without its positive-app constructor."""
    def __init__(self,r,image,pid,cpu,case):
        self.r,self.image,self.pid,self.cpu,self.case=r,image,pid,cpu,case
        self.ordinal=0;self.serial=1;self.b=r.data;self.h=q(self.f(self.b,T,'h'))
        self.maps_seen={};self.source_ids={};self.backings={};self.bases={};self.objects={}
        self.eh,self.ph,self.symbols=generation.elf_symbols(image['bridge'],wire.REGISTERED)
        need(set(r.layout['symbols'])==set(self.symbols)|{'r3_owner','span_progress','pg_domain_source'}and
            all(r.layout['symbols'][k]==v[0]for k,v in self.symbols.items()),
            'same whole actual ELF/DWARF symbol inventory')
        need(r.layout['symbols']['r3_owner']==r.layout['symbols']['r3_memory'],
             'actual aligned owner starts at its complete symbol')
        self.bias=self.h[9]-r.layout['symbols']['r3_owner']
        need(canonical(self.bias)and self.bias%PAGE==0,'actual bridge bias')
        for key,obj in image['objects'].items():
            need(type(key)is int and type(obj)is dict,'actual original objects')
            h,loads=old.elf(obj['data']);self.objects[key]=(obj,h,loads)
        need(image['main_object']in self.objects and image['interpreter_object']in self.objects and
            image['main_object']!=image['interpreter_object'],'distinct real main/interpreter')
        for key,objid in(('main',image['main_object']),('interpreter',image['interpreter_object'])):
            self.image_header(self.f(self.b,T,key),objid)
        need(self.bases[image['main_object']]==0,'fixed original executable')
        self.page=0x410000;self.head=0x410200;self.binding=image['persistent_binding']
        self.binding_identity()
        need(image['maps_mode']in('maintained','differential'),'actual maps mode')
        self.differential=image['maps_mode']=='differential'
        self.certificates=r.items(self.b,T,'certificate',CERT)
        key=self.f(self.f(self.certificates[0],CERT,'payload'),'r3_payload','source')
        row=r.items(key,'li2_pg_source_key','page','li2_pg_source_page')[0]
        self.main_backing=self.f(row,'li2_pg_source_page','backing')
        self.source_offset=self.i(self.f(row,'li2_pg_source_page','identity'),'li2_fetch_page','offset')
        self.before=self.frame(self.f(self.b,T,'before'));self.after=self.frame(self.f(self.b,T,'after'))
        self.next=self.frame(self.f(self.b,T,'next'))
        self.entered=self.f(self.b,T,'entered');self.terminal=self.f(self.b,T,'terminal')
        self.closed=self.f(self.b,T,'closed');self.handoff=self.f(self.b,T,'handoff')
        self.source_count=self.i(self.entered,STATE,'source_pages')
        need(0<self.source_count<=64,'actual bounded source union')
        self.source_before=self.f(self.b,T,'h')[328:384]
        self.source_rows=r.items(self.b,T,'source','li2_pg_source_page')
        self.layouts=[q(self.f(self.f(self.f(c,CERT,'payload'),'r3_payload','header'),
            'r3_header','layout'))for c in self.certificates]
        self.resident_before=self.f(self.b,T,'resident_before')
        self.generation_before=self.f(self.b,T,'generation_before')
        self.content=self.f(self.entered,STATE,'content')
        self.publication_epoch=self.i(self.content,'li2_rsl_content_ref','publication_epoch')
        self.application_geometry()

    def binding_identity(self):
        b=self.binding
        need(b['version']==1 and b['profile']=='resident-rx-two-flags-capture-v1'and
            b['mode']=='release'and all(b[k]is True for k in('native_probe','parse_memo',
            'unregistered','subentry','cross_pair','direct_frontier','resident_three',
            'sealed_storage','source_lease','flag_stack','helper_tf','stable_generation',
            'resident_rx','rx_capture','tf_nx_page_boundary'))and b['activations']==2 and
            b['causal']['case']==self.case,'distinct literal causal RX binding')

    def application_geometry(self):
        obj=self.objects[self.image['main_object']][0];data=obj['data']
        found,sections,loads=app_symbols(data);self.causal=self.binding['causal']
        def body(name,prot,n,info):
            actual,address,size,section=found[name]
            need(actual==info and size==n,'whole actual instruction/object '+name)
            rows=[p for p in loads if p[0]==1 and p[1]==prot and p[3]<=address<address+n<=p[3]+p[5]]
            need(len(rows)==1,'one complete original LOAD '+name)
            p=rows[0];at=p[2]+address-p[3];need(at+n<=len(data),'whole file extent')
            return data[at:at+n]
        need(int.from_bytes(body('rrx_case_id',4,8,17),'little')==self.case,
             'actual compiled subject selector')
        expected={'rrx_case_id','rrx_mailbox','region_app_capture_high','region_app_capture_pointer'}
        if self.case not in(5,7):expected.add('rrx_attack')
        if self.case==4:expected.add('rrx_after_attack')
        need(set(found)==expected,'complete causal symbol roster')
        c=self.causal;info,address,n,section=found['rrx_mailbox'];s=sections[section]
        need(info==17 and n==80 and s[1]==8 and s[2]&7==3 and
            0x200030000<=address<address+n<=0x200032000 and
            any(p[0]==1 and p[1]==6 and p[3]+p[5]<=address<address+n<=p[3]+p[6]for p in loads)and
            (c['mailbox'],c['mailbox_bytes'])==(address,80),
            'whole originally zero guest mailbox in actual RW/NX LOAD')
        if self.case not in(5,7):
            code={1:b'\xff\xe7',2:b'\xc6\x07\x5a',3:b'\x0f\x05',4:b'\x0f\x05',6:b'\x8e\xd0'}[self.case]
            need(body('rrx_attack',5,len(code),18)==code and c['attack']==found['rrx_attack'][1],
                 'literal original attack instruction and bound coordinate')
        else:need(c['attack']==0,'no synthetic stale-generation instruction')
        need(c['after_attack']==(c['attack']+2 if self.case==4 else 0),
             'exact post-syscall coordinate only for the attempted mapping')
        if self.case==4:
            need(found['rrx_after_attack'][1:3]==(c['after_attack'],0),'actual after-attack symbol')
        need(c['symbols']=={k:list(v)for k,v in found.items()if k.startswith('rrx_')},
             'whole bound causal symbol facts')
        source=plan.source_image();rows=[p for p in loads if p[0]==1 and p[1]==5 and
            p[3]<=self.page<self.page+len(source)<=p[3]+p[5]]
        need(len(rows)==1,'whole six-page original source LOAD')
        p=rows[0];at=p[2]+self.page-p[3]
        need(data[at:at+len(source)]==source and c['source_offset']==at and at%PAGE==0,
             'every actual original source byte and aligned backing offset')
        capture,pointer=found['region_app_capture_high'],found['region_app_capture_pointer']
        need(capture[0]==18 and 0<capture[2]<PAGE and 0x200021000<=capture[1]<capture[1]+capture[2]<=0x200022000 and
            pointer[0]==16 and pointer[2]==0 and 0x200010000<=pointer[1]<=0x200011000-8,
            'actual finite capture code and readonly pointer symbols')
        need(sum(p[0]==1 and p[1]==5 and p[3]<=capture[1]<capture[1]+capture[2]<=p[3]+p[5]
                 for p in loads)==1,'whole actual high capture function in one RX LOAD')
        rows=[p for p in loads if p[0]==1 and p[1]==4 and p[3]<=pointer[1]<pointer[1]+8<=p[3]+p[5]]
        need(len(rows)==1,'whole capture pointer LOAD');p=rows[0]
        need(data[p[2]+pointer[1]-p[3]:p[2]+pointer[1]-p[3]+8]==struct.pack('<Q',capture[1]),
             'literal source-bound capture destination')
        geometry=self.binding['geometry']
        need(geometry['root']==self.head and geometry['roots']==[self.head,0x412200,0x414200]and
            geometry['source']==dict(bytes=len(source),sha256=hashlib.sha256(source).hexdigest())and
            geometry['capture_symbols']=={k:list(found[k][1:3])for k in
                ('region_app_capture_high','region_app_capture_pointer')},'exact complete source binding')
        seed=[0x3141592600000000+i*0x102030405 for i in range(16)]
        seed[0]=1;seed[1]=4;seed[3]=self.head;seed[4]=self.h[22];seed[11]=pointer[1]
        self.app=dict(source=source,seed=tuple(seed),rsp=self.h[22],capture_pc=capture[1],
            capture_pointer=pointer[1],stack=bytes((i*29+7)&255 for i in range(520)),
            machine=(MASK,self.before['fs'],self.before['gs']))

    def first_completion(self,code,detail):
        h=self.h;r=self.r;self.record_identity()
        retained=r.layout['retained_storage']
        need(set(retained)=={'retained','selected_slot','selection','previous_selection','domain'}and
            retained['retained']['bytes']==2*r.types['li2_ptr_slot']['bytes']and
            retained['selected_slot']['bytes']==4 and retained['selection']['bytes']==retained['previous_selection']['bytes']==24 and
            retained['selected_slot']['offset']==retained['retained']['offset']+retained['retained']['bytes'],
            'old two-slot storage stays separate')
        need(h[12]%PAGE==0 and canonical(h[12],524288)and h[13:16]==(524288,1,0)and
            h[16]&(3|0x400|0x800)==1 and h[17:19]==(0,1),'real owned sink and altstack')
        need(h[19:22]==(self.head,0x41420e,self.app['capture_pc'])and h[22]%16==8 and
            h[23]==self.app['capture_pointer']and h[24:28]==(1,1,1,1)and
            h[28]>0 and h[29]==h[28]+1 and h[30]==h[29]+1 and h[31]in(0,1)and h[32]>0,
            'actual first entry, terminal and ordinary next TRACE')
        need(h[33:41]==(1,125,code,detail,1,h[16],0,1),'first record retains actual later failure')
        ingress=q(self.f(self.b,T,'ingress'))
        need(sum(ingress[1:])==ingress[0]==h[30]and ingress[1]>=1 and ingress[2]>=2 and
            ingress[3:]==(1,0,0),'complete first focal signal partition')
        need(q(self.f(self.b,T,'bootstrap'))==(self.pid,)*5+(0,0,24,1),'real process bootstrap')
        self.eq(self.f(self.b,T,'session'),'li2_step_session',pid=self.pid,tid=self.pid,
            sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        need(self.i(self.f(self.b,T,'session'),'li2_step_session','sync_query')&96==96,
             'actual synchronization capability')
        for key in('sink_initial','sink_terminal'):
            st=self.f(self.b,T,key);value=self.stat(st)
            need(value['mode']&0xffff==0x8180 and value['size']==0,'whole original empty regular sink')
            self.eq(st,'stat',st_nlink=1,st_uid=self.image['uid'])
        r.change(self.f(self.b,T,'sink_initial'),self.f(self.b,T,'sink_terminal'),'stat',
            observed=('st_atim','st_mtim','st_ctim'))
        self.eq(self.f(self.b,T,'hardware'),'li2_selected_hardware',abi_version=1,reserved=0)
        self.source_union();self.registry();self.source_bind();self.prebind_content()
        models=[self.certificate(i)for i in range(3)]
        ids=[self.f(c,CERT,'identity')for c in self.certificates]
        need(len({self.i(x,'li2_sealed_identity','fd')for x in ids})==3 and
            len({self.v(x,'li2_sealed_identity','device inode')for x in ids})==3,
            'three actual distinct sealed backings')
        directory=self.i(self.entered,STATE,'directory')
        need(directory==self.layouts[0][5]and self.f(self.b,T,'directory')==plan.directory(self.layouts),
             'whole independently rebuilt dispatch directory')
        for row in r.items(self.b,T,'directory_query','li2_private_code_query'):self.query(row,directory,1,3)
        self.scan(self.f(self.b,T,'directory_scan'),12288)
        for key in('entered','terminal'):self.state(self.f(self.b,T,key),key)
        for key in('closed','handoff'):
            if self.case==7:replacement_handoff(self,self.f(self.b,T,key))
            else:self.state(self.f(self.b,T,key),key)
        self.consumed_transfer();self.frames()
        for site,row in enumerate(r.items(self.b,T,'memory','li2_r3o_memory')):self.memory(row,site)
        return [dict(heads=x['heads'],exits=x['exits'])for x in models]


def second_record(c,r,code,detail):
    """Whole initialized-but-unentered member, including exact zero payload."""
    second=r.items(r.data,'rrx_bundle','record',T)[1];h=q(c.f(second,T,'h'))
    expected=list(c.h);expected[10]+=wire.RECORD_BYTES;expected[22]=0
    expected[24:33]=[0]*9;expected[41:48]=list(h[41:48])if c.case==5 else[0]*7
    need(h==tuple(expected),'whole second header never invents an entry or completion')
    copied=('bootstrap','sink_initial','sink_terminal','main','interpreter','hardware','session')
    prebind=('ingress','resident_before','generation_before','rx_before')if c.case==5 else()
    for key in r.types[T]['fields']:
        if key=='h':continue
        value=c.f(second,T,key)
        if key in copied:need(value==c.f(c.b,T,key),'same initialized second member '+key)
        elif key not in prebind:zero(value,'whole unreached second member '+key)
    if c.case==5:
        p=c.f(second,T,'resident_before');pt='li2_rsl_resident_progress'
        c.eq(p,pt,last_serial=1,bindings=1,snapshots=1)
        for key in('bound','seed','epoch'):zero(c.f(p,pt,key),'unbound second execution lease '+key)
        for key in('plans','validations','authentications','fresh_maps_passes','source_bytes',
                    'plan_source_bytes','guard_pages','observation_seals'):
            need(c.f(p,pt,key)==c.f(c.f(c.handoff,STATE,'resident_progress'),pt,key),
                 'no new semantic construction before second actual bind '+key)
        g=c.f(second,T,'generation_before');gt='li2_rsl_generation_progress'
        c.eq(g,gt,generation=1,publication_epoch=c.publication_epoch,state=1,preserved=9,
            invalidations=0,source_mutations=1,pending=0,pending_epoch=0,number=0,result=0)
        zero(c.f(g,gt,'args'),'no invented preservation arguments')
        need(c.i(g,gt,'effects')==c.i(c.generation_before,gt,'effects')+9,
             'nine original actual getters precede stale injection')
        calls,counts=c.counters(c.f(second,T,'rx_before'))
        need([calls[k]for k in base.OPERATIONS[:6]]==[(x,x)for x in(3,3,6,3,3,1)]and
            counts==dict(retained_entries=0,execution_releases=1,suspensions=9,resumptions=9,
                retirements=0,terminal_attempted=0,terminal_closed=0),'actual pre-injection RX counts')
        p=c.f(second,T,'h')[328:384];c.eq(p,'li2_rsl_progress',initialized=1,pages=c.source_count,reserved=0)
        need(c.i(p,'li2_rsl_progress','epoch')==c.i(p,'li2_rsl_progress','invalidations')+1 and
            c.i(p,'li2_rsl_progress','bindings')>0 and c.i(p,'li2_rsl_progress','valid')in(0,1),
            'actual bounded pre-bind source state')
        ingress=q(c.f(second,T,'ingress'))
        need(sum(ingress[1:])==ingress[0]>c.h[30]and ingress[3:]==(1,0,0),
             'actual later root signal before any second frame')
    return second


def original_code(c,pc,length):
    """Whole bytes from the authenticated application's one original RX LOAD."""
    obj,header,loads=c.objects[c.image['main_object']]
    need(type(pc)is int and type(length)is int and 0<length<=PAGE and canonical(pc,length),
         'bounded original instruction extent')
    rows=[p for p in loads if p[0]==1 and p[1]==5 and p[3]<=pc<pc+length<=p[3]+p[5]]
    need(len(rows)==1,'one actual original RX predecessor extent')
    p=rows[0];at=p[2]+pc-p[3];data=obj['data']
    need(at+length<=len(data),'whole original predecessor file bytes')
    return data[at:at+length]


def attack_ingress(c,greg,si,uc,count,reports):
    """Typed first ingress plus the exact existing terminal route witness.

    NX is an execute fault, never a metadata-write fault. TRACE CR2 is stale
    kernel state; its complete value remains in both identical frame copies.
    A later NX is proved by the real fallback/report path, not a forged frame.
    """
    pc=c.layouts[0][0]+1 if c.case==1 else c.causal['attack']
    need(greg[16]==pc and uc[40:224]==struct.pack('<23Q',*greg)and uc[304:432]==si,
         'whole actual first-ingress GREG/UC/siginfo joins')
    signal,error,code=struct.unpack_from('<iii',si)
    need(error==0 and code==2 and int.from_bytes(si[16:24],'little')==pc,
         'exact kernel signal code/address at the actual attack coordinate')
    zero(si[12:16],'actual signal alignment');zero(si[24:],'whole unused first-ingress siginfo')
    loader=reports['LI2_LOADER'];group=reports['LI2_PERSISTENT_UNREGISTERED'];sub=reports['LI2_PERSISTENT_SUBENTRY']
    chain=reports['LI2_CHAIN']
    need(type(count)is int and all(type(row)is dict for row in(loader,group,sub,chain))and
         all(type(chain[k])is int for k in chain if k not in('scope',)),
         'actual typed ingress count and independent terminal witnesses')
    if signal==11:
        need(c.case in(2,3,4)and count==1 and greg[19:21]==(21,14)and
             greg[22]==pc and greg[17]&(TF|RF)==RF,
             'one original execute-NX ingress with exact CR2/error/trap/RF')
        need(group['phase']==13 and group['recovery_complete']==1 and
             group['entries']==group['completed']and not group['first_error']and
             group['opened_pages']==group['closed_pages']==17*group['domain_members']and
             sub['complete']==1 and sub['serial']==group['serial']and
             sub['generation']==group['generation']and sub['slot']==group['selected_slot']and
             sub['root']==sub['pc']and sub['head']==0 and 0<pc-sub['pc']<=PAGE,
             'actual completed ordinary original-source predecessor before NX frontier')
        original_code(c,sub['pc'],pc-sub['pc'])
        if c.case==2:
            prefix=b'\x48\xa1'+struct.pack('<Q',c.causal['mailbox']+32)+b'\x48\x89\xc7'
            need(original_code(c,pc-13,16)==prefix+b'\xc6\x07\x5a'and
                 sub['pc']==pc-3 and group['domain_members']==1 and greg[13]==greg[8],
                 'literal MOVABS/MOV/store frontier and real unchanged metadata operand')
            need(all(type(loader[k])is int for k in('tf_pc','tf_length','tf_code','tf_bytes_lo',
                 'tf_bytes_hi','tf_actual_flags'))and loader['tf_pc']==pc-13 and
                 loader['tf_length']==10 and loader['tf_code']==326 and
                 struct.pack('<QQ',loader['tf_bytes_lo'],loader['tf_bytes_hi'])==prefix[:10]+bytes(6)and
                 loader['tf_phase']==5 and loader['tf_trace']==1 and loader['tf_error']==0 and
                 loader['tf_release_complete']==loader['tf_query_complete']==1 and
                 loader['tf_actual_flags']&(TF|RF)==TF and
                 greg[17]==((loader['tf_actual_flags']&~TF)|RF),
                 'actual completed TF MOVABS plus flag-preserving generated MOV')
        return dict(pc=pc,signal=11,si_code=2,route='completed_ordinary_to_execute_nx',ingresses=1,
                    ordinary_root=sub['pc'],ordinary_serial=sub['serial'])
    need(signal==5 and c.case in(1,3,4,6)and greg[17]&TF and not greg[17]&RF and
         greg[19:21]==(0,1),'whole actual pre-execution TRACE flags/error/trap')
    if c.case==1:
        need(count==1 and greg[22]==c.causal['attack']and
             original_code(c,c.causal['attack'],2)==b'\xff\xe7',
             'one actual TF indirect branch from its original execute-fault coordinate')
        return dict(pc=pc,signal=5,si_code=2,route='executed_indirect_to_private',ingresses=1)
    need(count==2 and chain['active']in(0,1)and chain['pending']==chain['error']==
         chain['unexpected']==chain['proof_valid']==0,
         'exact first TRACE then one NX refault, no pending/failed chain')
    active=chain['active'];a='s'+str(active)+'_';p='s'+str(active^1)+'_'
    reason,decoded=(5,294)if c.case==6 else(3,870)
    wanted=dict(phase=6,origin=2,fallback=reason,pc=pc,code=decoded,length=2,
        prepare=1,prepared=1,retry=0,owner_phase=0,owner_error=0,open=0,opened=0,
        revoke=0,revoked=0,trace=0,post_pc=0,held=0,fetch_error=0,query=0,
        queried=0,query_pc=0,release=1,released=1,unexpected=0)
    need(all(chain[a+k]==v for k,v in wanted.items())and chain[a+'borrow']>0 and
         chain[a+'generation']>0 and chain[a+'event']>chain[p+'event']>0,
         'actual exact selected/not-plain successor declined and released before refault')
    need(chain[p+'phase']==5 and chain[p+'origin']in(1,2)and chain[p+'fallback']==0 and chain[p+'owner_phase']==5 and
         chain[p+'owner_error']==chain[p+'held']==chain[p+'fetch_error']==chain[p+'unexpected']==0 and
         chain[p+'open']==chain[p+'opened']==chain[p+'revoke']==chain[p+'revoked']==
         chain[p+'trace']==chain[p+'query']==chain[p+'queried']==chain[p+'release']==chain[p+'released']==1 and
         chain[p+'post_pc']==chain[p+'query_pc']==pc and 0<chain[p+'length']<=15 and
         chain[p+'pc']+chain[p+'length']==pc,
         'literal actual closed sequential predecessor and source release at attack')
    predecessor=original_code(c,chain[p+'pc'],chain[p+'length'])
    if c.case==6:
        need(predecessor==b'\x66\x8c\xd0'and chain[p+'code']==287 and greg[13]&0xffff==0x2b,
             'actual TF-only selector read precedes unsupported MOV SS')
    else:
        need(original_code(c,pc,2)==b'\x0f\x05'and chain[p+'code']>0,
             'actual source-bound predecessor reaches the selected SYSCALL')
    # The failure reporter deliberately describes the active unexecuted slot,
    # not the closed predecessor. Its owner must remain wholly unstarted.
    need(all(loader[k]==0 for k in('tf_phase','tf_error','tf_pc','tf_length','tf_bytes_lo','tf_bytes_hi',
         'tf_code','tf_flow','tf_family','tf_trace','tf_actual_flags','tf_open_started','tf_opened',
         'tf_revoke_started','tf_revoked','tf_sync_started','tf_sync_abs','tf_sync_negative',
         'tf_continuation_started','tf_continuation_complete','tf_continuation_result_abs',
         'tf_continuation_result_negative','tf_query_attempted','tf_query_complete','tf_unexpected_frame'))and
         loader['tf_release_started']==loader['tf_release_complete']==1 and
         loader['tf_release_result_abs']==loader['tf_release_result_negative']==0,
         'failed report retains actual empty successor owner and real release')
    return dict(pc=pc,signal=5,si_code=2,route='closed_trace_to_exact_nx_fallback',ingresses=2,
                fallback=reason,predecessor_pc=chain[p+'pc'],predecessor_bytes=predecessor.hex(),
                terminal_nx_frame_captured=False)


def attack(c,r,reports):
    control=q(r.field(r.data,'rrx_bundle','control'));before=q(r.field(r.data,'rrx_bundle','mailbox_before'))
    after=q(r.field(r.data,'rrx_bundle','mailbox_after'));causal=c.causal
    initial=[0x315852524d32494c,c.case]+[0]*8
    if c.case==4:
        need(0<before[6]<=0x7fffffff,'actual opened image descriptor');initial[6]=before[6]
    need(before==tuple(initial),'whole initial untouched guest mailbox')
    expected=list(initial);expected[2:6]=[1,c.layouts[0][0]+1,c.layouts[0][0]+19*PAGE,causal['source_offset']]
    need(after==tuple(expected),'whole armed mailbox; refused guest instruction never returns')
    at=causal['mailbox'];pages=(((at+80+PAGE-1)&-PAGE)-(at&-PAGE))//PAGE
    c.query(r.field(r.data,'rrx_bundle','mailbox_query'),at&-PAGE,3,pages)
    need(all(not(at<end and first<at+80)for first,end in c.ranges),
         'mailbox remains outside every protected owner range')
    need(r.field(r.data,'rrx_bundle','metadata_before')==c.f(c.certificates[0],CERT,'payload')[:16],
         'actual first sealed header bytes, before the attack')
    ingress=None if c.case in(5,7)else attack_ingress(c,
        q(r.field(r.data,'rrx_bundle','attack_greg')),bytes(r.field(r.data,'rrx_bundle','attack_si')),
        bytes(r.field(r.data,'rrx_bundle','attack_uc')),control[3],reports)
    ingress_count=0 if ingress is None else ingress['ingresses']
    expected=[1,c.case,1,ingress_count,int(c.case==5),1 if c.case==5 else 0,
        2 if c.case==5 else 0,0,1,1,0,0,0,0,125,0]
    need(control==tuple(expected),'literal injection/attack/metadata/return chronology')
    greg=q(r.field(r.data,'rrx_bundle','attack_greg'));si=bytes(r.field(r.data,'rrx_bundle','attack_si'))
    uc=bytes(r.field(r.data,'rrx_bundle','attack_uc'))
    if c.case in(5,7):
        for key in('attack_greg','attack_si','attack_uc'):zero(r.field(r.data,'rrx_bundle',key),'no synthetic stale attack frame')
        return None
    need(int.from_bytes(uc[16:24],'little')==c.h[12]and int.from_bytes(uc[32:40],'little')==c.h[13]and
        int.from_bytes(uc[296:304],'little')==MASK and canonical(greg[15])and
        canonical(int.from_bytes(uc[224:232],'little')),'actual handler stack, mask and FP coordinate')
    if c.case in(1,2):need(greg[8]==after[3 if c.case==1 else 4],'actual guest target operand')
    elif c.case==3:need(greg[13]==228 and greg[8:10]==(1,after[4]),'actual clock output targets sealed metadata')
    elif c.case==4:
        need((greg[13],greg[8],greg[9],greg[12],greg[2],greg[0],greg[1])==
            (9,0x410000,24576,5,0x12,before[6]-1,causal['source_offset']),
            'literal actual guest MAP_FIXED arguments before RAW refusal')
    else:need(greg[13]&0xffff==0x2b,'actual MOV SS source selector remains unexecuted')
    c.attack_greg=greg
    return ingress


def replacement_handoff(c,state):
    """Case7's real revocation happened after terminal, before ordinary JMP."""
    r=c.r.whole;o=r.field(r.data,'rrx_bundle','replacement');t=STATE;rt='rrx_replace_control'
    changed={'fetch','source_progress','resident_progress','generation_progress','maps',
        'rx_lifetime','rx_progress','closed'}
    for key in r.types[t]['fields']:
        if key not in changed:
            need(c.f(state,t,key)==c.f(c.terminal,t,key),'whole retired handoff field '+key)
    c.eq(state,t,rx_lifetime=4)
    need(struct.unpack('<3I',c.f(state,t,'closed'))==(1,1,1),'all three code owners were actually retired')
    for key,kind,saved in(('rx_progress','li2_r3_rx_progress','rx'),
            ('source_progress','li2_rsl_progress','source'),
            ('generation_progress','li2_rsl_generation_progress','generation')):
        need(c.f(state,t,key)==r.items(o,rt,saved,kind)[2],
             'actual post-replacement state persists to ordinary handoff '+key)
    p=c.f(state,t,'resident_progress');pt='li2_rsl_resident_progress'
    for key in r.types[pt]['fields']:
        if key in('bound','seed','epoch'):zero(c.f(p,pt,key),'real invalidated resident execution lease '+key)
        else:need(c.f(p,pt,key)==c.f(c.f(c.terminal,t,'resident_progress'),pt,key),
                  'no new resident authorization at retired handoff '+key)
    fetch=c.f(state,t,'fetch');ft='li2_fetch_progress'
    sequence=c.i(fetch,ft,'sequence');c.progress(fetch,sequence,False)
    releases=r.items(o,rt,'release',ft)
    need(sequence>c.i(releases[-1],ft,'sequence'),'ordinary JMP borrows after all actual replacement checks')
    stats=c.f(state,t,'maps');c.eq(stats,'li2_maps_stats',poisoned=0,reserved=0)
    for key in('fresh_calls','acquisitions','reuses','invalidations','handler_id','mutation_epoch'):
        need(c.i(stats,'li2_maps_stats',key)>=c.i(c.f(c.terminal,t,'maps'),'li2_maps_stats',key),
             'actual post-replacement maps chronology '+key)


def replacement(c,r):
    o=r.field(r.data,'rrx_bundle','replacement');t='rrx_replace_control'
    if c.case!=7:
        zero(o,'no invented trusted replacement in an ordinary guest control');return None
    c.eq(o,t,started=1,quiet=1,invalidated=1,raw_started=1,raw_returned=1,complete=1,
        number=9,effect_result=0,result=0x410000,sync_result=0,seals=15,stat_result=0)
    main=c.f(c.b,T,'main');fd=c.i(main,'image','backing_fd')
    need(q(c.f(o,t,'args'))==(0x410000,24576,1,0x12,fd,c.causal['source_offset']),
         'actual trusted sealed-fd MAP_FIXED restores identical physical R permissions')
    backing=c.f(o,t,'backing');st=c.stat(backing)
    saved=[p for cert in c.certificates for p in r.items(c.f(c.f(cert,CERT,'payload'),
        'r3_payload','source'),'li2_pg_source_key','page','li2_pg_source_page')]
    need(len(saved)==6 and st['mode']&0xf000==0x8000 and st['size']>=c.causal['source_offset']+24576,
         'real complete sealed original-file extent')
    pages=r.items(o,t,'page','li2_fetch_page')
    backings=r.items(o,t,'page_backing','li2_fetch_backing')
    releases=r.items(o,t,'release','li2_fetch_progress')
    sequence=c.i(c.f(c.terminal,STATE,'fetch'),'li2_fetch_progress','sequence')
    for at,(page,b,release)in enumerate(zip(pages,backings,releases,strict=True)):
        source=saved[at%6];identity=c.f(source,'li2_pg_source_page','identity')
        prior=c.f(source,'li2_pg_source_page','backing')
        need(page==identity,'whole before/after physical source identity, including actual VMA bounds')
        c.file_page(page,b)
        need(c.backing_identity(b)==c.backing_identity(prior),
             'whole actual carrier identity on both sides of MAP_FIXED')
        # Fetches use the lifecycle-owned duplicate, not the image's mmap FD.
        c.eq(b,'li2_fetch_backing',retained_fd=c.i(prior,'li2_fetch_backing','retained_fd'),
             seals_observed=1,seals=15,stat_observed=1,stat_result=0)
        actual=c.f(b,'li2_fetch_backing','stat')
        for key in('st_dev','st_ino','st_mode','st_size'):
            need(c.f(actual,'stat',key)==c.f(backing,'stat',key),'actual mmap descriptor/backing join '+key)
        current=c.i(release,'li2_fetch_progress','sequence')
        need(current>sequence,'strictly ordered actual source borrows');sequence=current
        c.progress(release,current,False);c.eq(release,'li2_fetch_progress',validation_calls=2)
    for key in('bytes_before','bytes_after'):c.scan(c.f(o,t,key),24576)
    need(c.f(o,t,'source_after')==c.app['source'],'every actual post-replacement source byte')
    rx=r.items(o,t,'rx','li2_r3_rx_progress');source=r.items(o,t,'source','li2_rsl_progress')
    generation=r.items(o,t,'generation','li2_rsl_generation_progress')
    need(rx[0]==c.f(c.terminal,STATE,'rx_progress')and source[0]==c.f(c.terminal,STATE,'source_progress')and
        generation[0]==c.f(c.terminal,STATE,'generation_progress'),
        'actual replacement starts after the pristine completed terminal')
    need(rx[1]==rx[2]and source[1]==source[2]and generation[1]==generation[2],
         'actual mapping and validation do not renew authority')
    before,bc=c.counters(rx[0]);after,ac=c.counters(rx[1])
    deltas=(0,0,0,0,3,1,2,2)
    need(all(after[k]==tuple(v+d for v in before[k])for k,d in zip(base.OPERATIONS,deltas,strict=True))and
        ac==dict(bc,retirements=1),'only actual revoke/sync/metadata calls at invalidation')
    for key in r.types['li2_rsl_progress']['fields']:
        a,b=c.f(source[0],'li2_rsl_progress',key),c.f(source[1],'li2_rsl_progress',key)
        if key in('epoch','invalidations'):
            need(int.from_bytes(b,'little')==int.from_bytes(a,'little')+1,'real source invalidation '+key)
        elif key in('bound','valid'):zero(b,'source authorization removed before replacement '+key)
        else:need(a==b,'source field unchanged by invalidation '+key)
    gt='li2_rsl_generation_progress';g=generation[1]
    c.eq(g,gt,generation=2,publication_epoch=c.publication_epoch,state=3,preserved=0,
        invalidations=1,source_mutations=1,pending=0,pending_epoch=0,number=0,result=0)
    zero(c.f(g,gt,'args'),'no synthetic preserved mapping arguments')
    need(c.i(g,gt,'effects')==c.i(generation[0],gt,'effects')+1,
         'the one real before-effect transition precedes the raw replacement')
    need(struct.unpack('<3I',c.f(o,t,'lifetime'))==(1,4,4)and
        struct.unpack('<9I',c.f(o,t,'references'))==(0,)*9 and
        struct.unpack('<9I',c.f(o,t,'closed'))==(0,0,0,1,1,1,1,1,1),
        'actual drained claims and persistent retirement before and after RAW')
    need(struct.unpack('<3i',c.f(o,t,'code_result'))==(0,0,0),'all actual pre-RAW code queries succeeded')
    queries=r.items(o,t,'code_revoked','li2_sealed_code_query')
    for index,cert in enumerate(c.certificates):
        identity=c.f(cert,CERT,'identity')
        for member in range(3):c.sealed_query(queries[3*index+member],identity,
            c.layouts[index][member],1,8 if member<2 else 1)
    return dict(scope='trusted_capture_only_equal_mapping',guest_admission=False,
        bytes_compared_before=24576,bytes_compared_after=24576,source_borrows=12,
        validation_calls=24,result=0x410000,pre_raw_code_R_pages=51)


def source_binding(c,p,resident,reports):
    """Join the shared source lease to the actual typed old-owner terminal.

    Ordinary bind, resident bind and before_effect are distinct transitions.
    The caller has already applied the unchanged whole failed-prefix parser.
    These observations do not grant an entry/claim or replace a live predicate.
    """
    names=('LI2_LOADER','LI2_PERSISTENT_UNREGISTERED','LI2_PERSISTENT_SUBENTRY')
    need(type(reports)is dict and all(type(reports.get(n))is dict for n in names),
         'actual typed terminal rows accompany the failed source observation')
    loader,group,sub=(reports[n]for n in names);code,detail=STOPS[c.case]
    for row in(loader,group,sub):
        need(all(type(row.get(k))is int and row[k]==v for k,v in
             dict(version=1,status=125,failure_code=code).items()),'same literal failed terminal outcome')
    for row in(loader,group):
        need(type(row.get('detail_abs'))is int and row['detail_abs']==detail and
             type(row.get('detail_negative'))is int and row['detail_negative']==0,
             'same literal failed terminal detail')
    keys=('phase','serial','offers','entries','completed','cancelled','cold_attempts','publications','hits',
          'unexpected','guest_data_fault','first_error','active','busy','selected_slot','permit',
          'slot0_permit','slot1_permit','slot0_completed_serial','slot1_completed_serial',
          'opened_pages','closed_pages','anchor_released','registration_rechecked','recovery_complete',
          'domain_members','generation')
    need(all(type(group.get(k))is int and 0<=group[k]<1<<64 for k in keys)and
         all(type(v)is int and 0<=v<1<<64 for v in sub.values()),'exact integer old-owner source witness')
    need(group['offers']==group['serial']==group['entries']+group['cancelled']>0 and
         group['entries']==group['completed']==group['publications']+group['hits']and
         group['cold_attempts']==group['publications']+group['cancelled']and
         group['unexpected']==group['guest_data_fault']==group['active']==0,
         'every old offered source lifetime completed or cancelled before this refusal')
    abort=c.case in(5,7)
    need(group['busy']==int(abort)and group['first_error']==(code if abort else 0)and
         group['selected_slot']in(0,1)and group['permit']==group['slot'+str(group['selected_slot'])+'_permit']and
         group['slot0_permit']in(0,1)and group['slot1_permit']in(0,1)and
         group['anchor_released']==group['registration_rechecked']==1,
         'exact abort/quiet state and actual selected claim observation')
    # Reset clears the complete old entry and extent fields before every offer.
    # Drain fills them; cancellation leaves them zero; R3 abort changes neither.
    if group['recovery_complete']==1:
        need(group['phase']==(15 if abort else 13)and group['domain_members']in(1,2)and
             group['opened_pages']==group['closed_pages']==17*group['domain_members']and
             group['permit']==1 and group['slot'+str(group['selected_slot'])+'_completed_serial']==group['serial']and
             sub['complete']==1 and sub['serial']==group['serial']and
             sub['generation']==group['generation']and sub['slot']==group['selected_slot'],
             'whole completed old epoch, actual selected receipt and subentry serial')
    else:
        need(group['recovery_complete']==0 and group['phase']==(15 if abort else 14)and
             group['opened_pages']==group['closed_pages']==group['domain_members']==0 and
             all(sub[k]==0 for k in('serial','generation','root','pc','head','slot','bank','complete')),
             'whole cancelled old epoch has no entry, execution extent or subentry identity')
    pt='li2_rsl_progress';rt='li2_rsl_resident_progress'
    need(c.i(p,pt,'bindings')==group['serial']+c.i(resident,rt,'bindings'),
         'exact ordinary plus resident successful source-binding partition')
    if c.case in(3,4):
        c.eq(p,pt,valid=0);zero(c.f(p,pt,'bound'),'before-effect clears the whole ordinary source token')
    elif c.case==5:
        c.eq(p,pt,valid=1);zero(c.f(p,pt,'bound'),'fresh resident bind clears the whole ordinary source token')
    else:
        c.eq(p,pt,valid=1)
        c.eq(c.f(p,pt,'bound'),'li2_pg_token',owner=c.symbol('pe'),serial=group['serial'])
    return dict(ordinary_serial=group['serial'],ordinary_phase=group['phase'],
        ordinary_aborted=abort,resident_bindings=c.i(resident,rt,'bindings'),
        source_bindings=c.i(p,pt,'bindings'),source_valid=c.i(p,pt,'valid'))


def final_state(c,r,second,reports):
    final=r.field(r.data,'rrx_bundle','final');t=STATE;stale=c.case==5;replaced=c.case==7
    c.eq(final,t,phase=12 if stale or replaced else 10,busy=int(stale),active=0,consumed=int(not stale),
        released=int(not stale),exit_seen=int(not stale),first_error=4902 if stale else 4900 if replaced else 0,
        first_detail=15 if stale else 11 if replaced else 0,registry_bound=1,serial=2 if stale else 1,
        publications=3,entries=1,completed=1,cancelled=0,unexpected=0,ingresses=1,
        count=3,planned=3,exit_member=2,exit_index=1,root=c.head,flags=0xad7,gpr_written=3,flags_written=0x8d5)
    for key in('arena','directory','registry_count','source_pages','generation','installed','rx_release'):
        need(c.f(final,t,key)==c.f(c.terminal,t,key),'whole retained final owner field '+key)
    need(struct.unpack('<3I',c.f(final,t,'references'))==(0,0,0)and
        struct.unpack('<3I',c.f(final,t,'closed'))==((1,1,1)if c.case in(3,4,7)else(0,0,0)),
        'terminal-only physical cleanup does not invent successful ownership closure')
    c.eq(c.f(final,t,'token'),'li2_r3_token',owner=c.h[9],serial=2 if stale else 1)
    c.eq(c.f(final,t,'content'),'li2_rsl_content_ref',owner=c.symbol('rsl'),
        generation=2 if stale else 1,publication_epoch=c.publication_epoch)
    c.eq(final,t,rx_lifetime=4 if c.case in(3,4,7)else 1)
    calls,counts=c.counters(c.f(final,t,'rx_progress'))
    need([calls[k]for k in base.OPERATIONS[:6]]==[(v,v)for v in(3,3,6,3,6,2)]and
        counts==dict(retained_entries=0,execution_releases=1,
            suspensions=9 if stale else 0 if replaced else 4,
            resumptions=9 if stale else 0 if replaced else 4,retirements=int(c.case in(3,4,7)),terminal_attempted=1,
            terminal_closed=int(not stale)),
        'actual call/release/suspend/revoke counts, never a manufactured normal completion')
    gt='li2_rsl_generation_progress';g=c.f(final,t,'generation_progress')
    c.eq(g,gt,generation=2 if c.case in(3,4,7)else 1,publication_epoch=c.publication_epoch,
        state=3 if c.case in(3,4,7)else 1,preserved=9 if stale else 0 if replaced else 4,
        invalidations=int(c.case in(3,4,7)),source_mutations=1,pending=0,number=0,result=0)
    need(c.i(g,gt,'effects')==c.i(c.generation_before,gt,'effects')+(9 if stale else 10 if replaced else 5 if c.case in(3,4)else 4),
         'actual fixed fixture effect chronology')
    # clock_gettime is outside the exact generation-preserving getter set.
    # Its real before-effect path retires all code before the output guard
    # refuses the protected timespec. No native result or pending renewal exists.
    zero(c.f(g,gt,'args'),'no pending effect arguments');c.eq(g,gt,pending_epoch=0,number=0)
    if c.case==3:
        loader=reports['LI2_LOADER']
        need(loader['last_syscall']==228 and loader['failure_code']==300 and
             loader['detail_abs']==228 and loader['detail_negative']==0 and
             loader['syscalls']==loader['source_syscalls']==loader['forwarded']+1,
             'actual clock source dispatch refused before native forwarding after retirement')
    if stale:
        need(g==c.f(second,T,'generation_before'),'source owner stays live while only saved owner generation was corrupted')
        rr=c.f(final,t,'rseq');rt='li2_r3_rseq_progress'
        c.eq(rr,rt,session=c.symbol('selected_session'),active=1,checking=0,registered=0,
            seed_complete=1,entry_complete=0,close_complete=0,epoch=0,calls=0,address=0,page=0,
            length=0,signature=0,pid=c.pid,tid=c.pid,fs_selector=0,gs_selector=0,tls_complete=1,
            word_observed=0,word_before=0,word_entry=0,word_after=0,fs=c.before['fs'],gs=c.before['gs'])
        c.eq(c.f(rr,rt,'token'),'li2_r3_token',owner=c.h[9],serial=2)
        for key in('cold','before','observed','after'):zero(c.f(rr,rt,key),'no invented second decode/rseq observations '+key)
        need(c.i(rr,rt,'raw_checks')>0,'actual failed second lifetime still checks trusted RAW calls')
    else:need(c.f(final,t,'rseq')==c.f(c.terminal,t,'rseq'),'no new resident rseq claim after first completion')
    p=c.f(final,t,'source_progress');pt='li2_rsl_progress'
    c.eq(p,pt,initialized=1,pages=c.source_count,reserved=0)
    need(c.i(p,pt,'epoch')==c.i(p,pt,'invalidations')+1 and c.i(p,pt,'bindings')>0 and
        c.i(p,pt,'valid')in(0,1),'actual final source-state accounting')
    resident=c.f(final,t,'resident_progress');rt='li2_rsl_resident_progress'
    source_binding(c,p,resident,reports)
    origin=c.f(second,T,'resident_before')if stale else c.f(c.terminal,t,'resident_progress')
    if stale:
        prior=c.f(second,T,'h')[328:384];auth=2+c.i(prior,pt,'valid')
        c.eq(p,pt,epoch=c.i(prior,pt,'epoch'),invalidations=c.i(prior,pt,'invalidations'),
            bindings=c.i(prior,pt,'bindings')+1,valid=1)
        c.eq(c.f(final,t,'source'),'li2_rsl_ref',owner=c.symbol('rsl'),epoch=c.i(p,pt,'epoch'))
        c.eq(resident,rt,last_serial=2,bindings=2,snapshots=2,epoch=c.i(p,pt,'epoch'),
            plans=c.i(origin,rt,'plans'),validations=c.i(origin,rt,'validations')+1,
            authentications=c.i(origin,rt,'authentications')+auth,
            fresh_maps_passes=c.i(origin,rt,'fresh_maps_passes')+auth,
            source_bytes=c.i(origin,rt,'source_bytes')+auth*c.source_count*PAGE,
            plan_source_bytes=c.i(origin,rt,'plan_source_bytes'),guard_pages=c.i(origin,rt,'guard_pages'),
            observation_seals=c.i(origin,rt,'observation_seals')+2)
        need(c.f(resident,rt,'bound')==c.f(final,t,'token'),'actual fresh source bind before saved-generation refusal')
        seed=c.f(resident,rt,'seed');c.eq(seed,'li2_r3_seed',complete=1,reserved=0,serial=2,
            session=c.symbol('selected_session'),pid=c.pid,tid=c.pid,root=c.head)
        oldref=c.f(c.f(c.b,T,'held'),'li2_span_fetch_observation','ref')
        ref=c.f(seed,'li2_r3_seed','held');fetch=c.f(final,t,'fetch')
        c.eq(ref,'li2_fetch_ref',owner=c.i(oldref,'li2_fetch_ref','owner'),
            sequence=c.i(fetch,'li2_fetch_progress','sequence'))
        c.eq(fetch,'li2_fetch_progress',held=1,complete=1,first_error=0,first_detail=0,
            identity_observed=1,pages_copied=1,bytes_copied=15)
        need(c.i(fetch,'li2_fetch_progress','sequence')>c.i(oldref,'li2_fetch_ref','sequence'),
             'new genuinely held borrow is not a released first-activation pin')
    else:
        need(c.f(final,t,'source')==c.f(c.terminal,t,'source'),'saved source reference is not silently renewed')
        for key in r.types[rt]['fields']:
            if key in('bound','seed','epoch'):zero(c.f(resident,rt,key),'actual invalidated resident lease '+key)
            else:need(c.f(resident,rt,key)==c.f(origin,rt,key),'no later resident source reconstruction '+key)
    stats=c.f(final,t,'maps');c.eq(stats,'li2_maps_stats',poisoned=0,reserved=0)
    for key in('fresh_calls','acquisitions','reuses','invalidations','handler_id','mutation_epoch'):
        need(c.i(stats,'li2_maps_stats',key)>=c.i(c.f(c.handoff,t,'maps'),'li2_maps_stats',key),
             'actual final maps chronology '+key)
    need(struct.unpack('<3i',r.field(r.data,'rrx_bundle','final_code_result'))==(0,0,0),
         'all separate final physical R/NX queries actually succeeded')
    rows=r.items(r.data,'rrx_bundle','final_code','li2_sealed_code_query')
    for index,cert in enumerate(c.certificates):
        identity=c.f(cert,CERT,'identity')
        for member in range(3):c.sealed_query(rows[3*index+member],identity,
            c.layouts[index][member],1,8 if member<2 else 1)
    return calls,counts


def refusal(data,layout,image,pid,cpu,exit_status,case,reports):
    need(type(case)is int and case in STOPS and type(exit_status)is int and exit_status==125 and
        type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,
        'literal separate causal process and expected failure')
    code,detail=STOPS[case]
    need(type(data)is bytes and len(data)==wire.RAW_BYTES+64 and len(data)<4<<20,
         'whole actual failed wire inside original capture bound')
    footer=q(data[-64:])
    need(footer[:4]==(0x314658525732494c,1,wire.RAW_BYTES,wire.RAW_BYTES)and
        1<=footer[4]<=64 and 0<footer[5]<=wire.RAW_BYTES and footer[6:]==(125,code),
        'literal complete failed transport footer')
    r=wire.Reader(memoryview(data)[:-64],layout);h=q(r.field(r.data,'rrx_bundle','h'))
    need(h==(0x314258525732494c,1,wire.RAW_BYTES,wire.RECORD_BYTES,int(case==5),1,1,2,
        125,code,detail,1,1,0,1,wire.OWNER_BYTES),'actual first completion and unentered second activation')
    c=Prefix(wire.RecordView(r,0),image,pid,cpu,case);models=c.first_completion(code,detail)
    second=second_record(c,r,code,detail);fault=attack(c,r,reports);mapped=replacement(c,r)
    calls,counts=final_state(c,r,second,reports)
    ingress=q(r.field(r.data,'rrx_bundle','ingress'))
    need(sum(ingress[1:])==ingress[0]>c.h[30]and ingress[3:]==(1,0,0),
         'whole final actual signal partition without invented interior entry')
    return dict(status='failed_prefix',case=case,exit=125,code=code,detail=detail,
        first_completion=dict(entries=1,completed=1,publications=3,owner_frames=3,models=models),
        second_entry=False,attack=fault,replacement=mapped,final_code_R_pages=51,final_api_calls=calls,
        final_lifetime_counts=counts,signal_counts=ingress,application_stdout=False,
        checked_metadata_target_bytes=16,final_state_scope='literal_refusal_and_physical_queries',
        application_or_native_frames_compared=0,
        equivalence_credit=False,qualification_credit=False,performance_credit=False)


def controls(data,layout,image,pid,cpu,exit_status,case,reports):
    """Whole supplied observations are corrupted; no guest or result is forged."""
    refusal(data,layout,image,pid,cpu,exit_status,case,reports);types=layout['types'];refused=[]
    bundle=types['rrx_bundle']['fields'];record=bundle['record']['offset'];fields=types[T]['fields']
    final=bundle['final']['offset'];state=types[STATE]['fields']
    tests=[('footer_status',len(data)-16),('footer_code',len(data)-8),
        ('bundle_completed',bundle['h']['offset']+5*8),('first_completed',record+fields['h']['offset']+25*8),
        ('first_source',record+fields['source']['offset']),('first_certificate',record+fields['certificate']['offset']),
        ('first_frame',record+fields['before']['offset']),('invented_second_frame',record+wire.RECORD_BYTES+fields['before']['offset']),
        ('mailbox_target',bundle['mailbox_after']['offset']+4*8),('metadata_mutation',bundle['control']['offset']+10*8),
        ('final_query',bundle['final_code_result']['offset']),('final_publications',final+state['publications']['offset']),
        ('final_entries',final+state['entries']['offset']),('final_lifetime',final+state['rx_lifetime']['offset']),
        ('final_content',final+state['content']['offset']),('final_claim',final+state['references']['offset'])]
    if case==5:tests.append(('stale_injection',bundle['control']['offset']+6*8))
    else:tests.append(('actual_attack_pc',bundle['attack_greg']['offset']+16*8))
    if case==7:
        at=bundle['replacement']['offset'];f=types['rrx_replace_control']['fields']
        for name,key,offset in(('invalidation_before_raw','invalidated',0),
                ('actual_raw_result','result',0),('actual_physical_permissions','args',16),
                ('same_complete_page_identity','page',6*types['li2_fetch_page']['bytes']),
                ('every_actual_source_byte','source_after',8191),
                ('pre_raw_code_R','code_result',0),('retired_before_raw','lifetime',4),
                ('dirty_before_raw','generation',types['li2_rsl_generation_progress']['bytes'])):
            tests.append((name,at+f[key]['offset']+offset))
    for name,offset in tests:
        changed=bytearray(data);changed[offset]^=1
        try:refusal(bytes(changed),layout,image,pid,cpu,exit_status,case,reports)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted causal prefix mutation '+name)
    count=25 if case==7 else 17
    need(len(refused)==len(set(refused))==count,'all additive exact failed-prefix mutations')
    # Keep the original127 whole-record mutations above. These separate causal
    # joins mutate the actual token/progress or its independently parsed rows.
    observed=wire.Reader(memoryview(data)[:-64],layout)
    c=Prefix(wire.RecordView(observed,0),image,pid,cpu,case)
    last=observed.field(observed.data,'rrx_bundle','final')
    progress=c.f(last,STATE,'source_progress');resident=c.f(last,STATE,'resident_progress')
    source_binding(c,progress,resident,reports);joined=[]
    def reject_join(name,p=progress,r=resident,terminal=reports):
        try:source_binding(c,p,r,terminal)
        except ValueError:joined.append(name)
        else:raise ValueError('accepted altered source/terminal join '+name)
    for name,ty,field,inside in(('old_owner','li2_rsl_progress','bound',0),
            ('old_serial','li2_rsl_progress','bound',8),('source_valid','li2_rsl_progress','valid',0),
            ('source_bindings','li2_rsl_progress','bindings',0),
            ('resident_bindings','li2_rsl_resident_progress','bindings',0)):
        original=resident if ty=='li2_rsl_resident_progress'else progress
        changed=bytearray(original);changed[types[ty]['fields'][field]['offset']+inside]^=1
        reject_join(name,r=bytes(changed))if ty=='li2_rsl_resident_progress'else reject_join(name,p=bytes(changed))
    for label,row,key in(('group_serial','LI2_PERSISTENT_UNREGISTERED','serial'),
            ('group_offers','LI2_PERSISTENT_UNREGISTERED','offers'),
            ('group_phase','LI2_PERSISTENT_UNREGISTERED','phase'),
            ('group_first_error','LI2_PERSISTENT_UNREGISTERED','first_error'),
            ('group_busy','LI2_PERSISTENT_UNREGISTERED','busy'),
            ('group_opened','LI2_PERSISTENT_UNREGISTERED','opened_pages'),
            ('group_closed','LI2_PERSISTENT_UNREGISTERED','closed_pages'),
            ('group_anchor','LI2_PERSISTENT_UNREGISTERED','anchor_released'),
            ('group_registration','LI2_PERSISTENT_UNREGISTERED','registration_rechecked'),
            ('group_recovery','LI2_PERSISTENT_UNREGISTERED','recovery_complete'),
            ('group_permit','LI2_PERSISTENT_UNREGISTERED','permit'),
            ('subentry_serial','LI2_PERSISTENT_SUBENTRY','serial'),
            ('subentry_complete','LI2_PERSISTENT_SUBENTRY','complete'),
            ('loader_code','LI2_LOADER','failure_code'),
            ('group_detail','LI2_PERSISTENT_UNREGISTERED','detail_abs')):
        changed=copy.deepcopy(reports);changed[row][key]^=1;reject_join(label,terminal=changed)
    need(len(joined)==len(set(joined))==20,'all20 separate actual source/report join refusals')
    ingress=[]
    if case not in(5,7):
        g=list(q(observed.field(observed.data,'rrx_bundle','attack_greg')))
        si=bytes(observed.field(observed.data,'rrx_bundle','attack_si'))
        uc=bytes(observed.field(observed.data,'rrx_bundle','attack_uc'))
        events=q(observed.field(observed.data,'rrx_bundle','control'))[3]
        proof=attack_ingress(c,tuple(g),si,uc,events,reports)
        def reject_ingress(name,gg=g,ss=si,uu=uc,nn=events,rr=reports):
            try:attack_ingress(c,tuple(gg),ss,uu,nn,rr)
            except ValueError:ingress.append(name)
            else:raise ValueError('accepted altered actual attack ingress '+name)
        for name,offset in(('signal_kind',0),('signal_errno',4),('signal_code',8),('signal_address',16)):
            ss=bytearray(si);ss[offset]^=1;uu=bytearray(uc);uu[304:432]=ss
            reject_ingress(name,ss=bytes(ss),uu=bytes(uu))
        for name,index,mask in(('rip',16,1),('trap_error',19,1),('trap_number',20,1),
                              ('trace_flag',17,TF),('resume_flag',17,RF)):
            gg=g.copy();gg[index]^=mask;uu=bytearray(uc);uu[40:224]=struct.pack('<23Q',*gg)
            reject_ingress(name,gg=gg,uu=bytes(uu))
        uu=bytearray(uc);uu[40]^=1;reject_ingress('whole_greg_copy',uu=bytes(uu))
        uu=bytearray(uc);uu[304]^=1;reject_ingress('whole_siginfo_copy',uu=bytes(uu))
        reject_ingress('exact_ingress_count',nn=events+1)
        if proof['signal']==11:
            gg=g.copy();gg[22]^=1;uu=bytearray(uc);uu[40:224]=struct.pack('<23Q',*gg)
            reject_ingress('nx_cr2',gg=gg,uu=bytes(uu))
            key='pc';row='LI2_PERSISTENT_SUBENTRY'
        elif case==1:
            gg=g.copy();gg[22]^=1;uu=bytearray(uc);uu[40:224]=struct.pack('<23Q',*gg)
            reject_ingress('original_branch_cr2',gg=gg,uu=bytes(uu))
            # Construct a self-consistent NX frame: case1's actual RX target
            # must still refuse this different ingress mechanism.
            gg=g.copy();gg[17]=(gg[17]&~TF)|RF;gg[19:21]=[21,14];gg[22]=gg[16]
            ss=bytearray(si);ss[:4]=struct.pack('<i',11);uu=bytearray(uc)
            uu[40:224]=struct.pack('<23Q',*gg);uu[304:432]=ss
            reject_ingress('indirect_must_be_trace',gg=gg,ss=bytes(ss),uu=bytes(uu))
            key=None
        else:
            key='s'+str(reports['LI2_CHAIN']['active'])+'_fallback';row='LI2_CHAIN'
            changed=copy.deepcopy(reports);changed['LI2_CHAIN']['s'+str(reports['LI2_CHAIN']['active']^1)+'_post_pc']^=1
            reject_ingress('closed_predecessor_target',rr=changed)
        if key is not None:
            changed=copy.deepcopy(reports);changed[row][key]^=1;reject_ingress('exact_route_witness',rr=changed)
        need(len(ingress)==len(set(ingress))==14,'all14 separate typed ingress refusals')
    retirement=[]
    if case==3:
        # Separate additive controls: retain every original record, source and
        # ingress mutation above, then corrupt the actual retired clock state.
        rx=final+state['rx_progress']['offset'];gen=final+state['generation_progress']['offset']
        rxf=types['li2_r3_rx_progress']['fields'];gf=types['li2_rsl_generation_progress']['fields']
        offsets=[('retired_certificate_closed',final+state['closed']['offset'])]
        offsets += [(name,rx+rxf[key]['offset'])for name,key in
            (('actual_retirement','retirements'),('actual_suspensions','suspensions'),
             ('actual_resumptions','resumptions'))]
        offsets += [(name,gen+gf[key]['offset'])for name,key in
            (('dirty_generation','generation'),('dirty_state','state'),('real_invalidation','invalidations'),
             ('no_pending_renewal','pending'),('no_pending_arguments','args'),('actual_effect_count','effects'))]
        for name,offset in offsets:
            changed=bytearray(data);changed[offset]^=1
            try:refusal(bytes(changed),layout,image,pid,cpu,exit_status,case,reports)
            except ValueError:retirement.append(name)
            else:raise ValueError('accepted altered clock retirement '+name)
        for key in('last_syscall','forwarded'):
            changed=copy.deepcopy(reports);changed['LI2_LOADER'][key]^=1
            try:refusal(data,layout,image,pid,cpu,exit_status,case,changed)
            except ValueError:retirement.append('clock_'+key)
            else:raise ValueError('accepted altered clock forwarding '+key)
        need(len(retirement)==len(set(retirement))==12,'all12 exact retired-clock refusals')
    descriptors=[]
    if case==7:
        # The mapping descriptor and retained source descriptor are separate
        # actual authorities. Keep every old control above and corrupt each
        # of the twelve observed and six saved descriptor fields separately.
        replacement_at=bundle['replacement']['offset'];rf=types['rrx_replace_control']['fields']
        backing_bytes=types['li2_fetch_backing']['bytes']
        retained=types['li2_fetch_backing']['fields']['retained_fd']
        observed_at=replacement_at+rf['page_backing']['offset']
        certificate_at=record+fields['certificate']['offset']
        certificate_bytes=types[CERT]['bytes']
        source_at=types[CERT]['fields']['payload']['offset']+types['r3_payload']['fields']['source']['offset']
        page_at=types['li2_pg_source_key']['fields']['page']['offset']
        page_bytes=types['li2_pg_source_page']['bytes']
        backing_at=types['li2_pg_source_page']['fields']['backing']['offset']
        saved_at=[certificate_at+i*certificate_bytes+source_at+page_at+j*page_bytes+backing_at
                  for i in range(3)for j in range(2)]
        image_fd=record+fields['main']['offset']+types['image']['fields']['backing_fd']['offset']
        mapping_fd=replacement_at+rf['args']['offset']+4*8
        offsets=[('observed_retained_fd_'+str(i),observed_at+i*backing_bytes+retained['offset'])
                 for i in range(12)]
        offsets += [('saved_retained_fd_'+str(i),at+retained['offset'])for i,at in enumerate(saved_at)]
        offsets += [('mapping_fd',mapping_fd),('image_mapping_fd',image_fd)]
        def reject_descriptor(name,changed):
            try:refusal(bytes(changed),layout,image,pid,cpu,exit_status,case,reports)
            except ValueError:descriptors.append(name)
            else:raise ValueError('accepted altered exact descriptor authority '+name)
        for name,offset in offsets:
            changed=bytearray(data);changed[offset]^=1;reject_descriptor(name,changed)
        mapping_value=int.from_bytes(data[image_fd:image_fd+4],'little',signed=True)
        retained_value=int.from_bytes(data[saved_at[0]+retained['offset']:saved_at[0]+retained['offset']+4],
                                      'little',signed=True)
        need(mapping_value!=retained_value,'actual original and duplicated descriptor identities are distinct')
        changed=bytearray(data);at=observed_at+retained['offset']
        changed[at:at+4]=mapping_value.to_bytes(4,'little',signed=True)
        reject_descriptor('mapping_fd_cannot_authorize_fetch',changed)
        changed=bytearray(data);changed[mapping_fd:mapping_fd+8]=retained_value.to_bytes(8,'little',signed=True)
        reject_descriptor('retained_fd_cannot_replace_recorded_mmap_fd',changed)
        need(len(descriptors)==len(set(descriptors))==22,'all22 exact mapping/source descriptor refusals')
    return dict(count=count,refusals=refused,source_join_count=20,source_join_refusals=joined,
        descriptor_count=len(descriptors),descriptor_refusals=descriptors,
        retirement_count=len(retirement),retirement_refusals=retirement,
        ingress_count=len(ingress),ingress_refusals=ingress,
        source_sha256=hashlib.sha256(data).hexdigest(),native_operations=0)
