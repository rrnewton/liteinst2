"""Whole policy14 owner envelope and state, separate from actual event pairs."""
import struct
from pathlib import Path
import importlib.util

def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
HERE=Path(__file__).resolve().parent
base=load('loop_owner_base',HERE/'base.py')
direct=load('loop_history_direct_model',HERE/'direct_model.py')
need,zero,q,canonical=base.need,base.zero,base.q,base.canonical
PAGE,TF,RF,MASK,U64,GREG=base.PAGE,base.TF,base.RF,base.MASK,base.U64,base.GREG
plan,history,chooser,wire=base.plan,base.history,base.chooser,base.wire
LOOP_COUNTS=base.LOOP_COUNTS

class Check(base.Check):
    def work(self,w,rows,count,serial,terminal=False):
        t='pda_work';v=self.f(w,t,'view');vt='li2_pgd_view';self.eq(w,t,bound=1,completion=int(terminal),aborting=0,recovery_member=2)
        self.eq(v,vt,count=count,reserved=0,directory=self.h[40]);self.eq(self.f(v,vt,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
        members=self.r.items(v,vt,'member','li2_pgd_member');refs=[];pairs=[]
        for i,m in enumerate(members):
            if i>=count:zero(m,'whole unused active-domain member');continue
            mt='li2_pgd_member';ref=self.f(m,mt,'identity');slot,bank=self.v(ref,'li2_pgd_ref','slot bank');need(slot in(0,1)and bank in(0,1),'actual member slot/bank')
            s=rows[slot];g=self.f(s,'pdo_slot','generation');root=self.ref(ref,g,slot,bank);refs.append(ref)
            proof=self.i(s,'pdo_slot','proof');self.eq(m,mt,plan=proof+self.r.types['pe_payload']['fields']['plan']['offset'],key=proof+self.r.types['pe_payload']['fields']['source']['offset'])
            ci=next((j for j,c in enumerate(self.certificates)if self.i(c,'pdo_certificate','slot')==slot and self.i(c,'pdo_certificate','generation')==self.i(g,'li2_pg_generation','generation')),None)
            need(ci is not None and root==self.i(self.certificates[ci],'pdo_certificate','entry'),'actual active member joins its complete literal certificate')
            pairs.append((slot,self.i(g,'li2_pg_generation','generation'),self.i(g,'li2_pg_generation','build_serial')))
        need(len({x[0]for x in pairs})==count and len({x[1]for x in pairs})==count,'distinct actual domain generations')
        self.eq(w,t,primary=pairs[0][0],primary_bank=self.i(refs[0],'li2_pgd_ref','bank'),peer=2 if count==1 else pairs[1][0],exit_member=0 if terminal else 2)
        receipt=self.i(w,t,'receipt');need(receipt<3,'bounded selected immutable completion cell')
        self.permission(self.f(w,t,'directory_write'),self.h[40],3,3);self.permission(self.f(w,t,'directory_seal'),self.h[40],1,3)
        if terminal:self.query(self.f(w,t,'directory_closed'),self.h[40],1,pages=3)
        else:zero(self.f(w,t,'directory_closed'),'no premature directory terminal query')
        d=self.f(w,t,'directory');dt='li2_jd_domain_directory';total=28;need(count==1 and self.i(refs[0],'li2_pgd_ref','root')==self.head,'one independently reconstructed focal member')
        self.eq(d,dt,version=1,count=total,serial=serial,reserved=0);expected=[]
        for r in refs:
            base=self.layout(self.f(r,'li2_pgd_ref','layout'))[0]
            for j,off in enumerate(self.graph['offsets']):expected.append(struct.pack('<3Q2I',self.page+off,base+512*j,self.i(r,'li2_pgd_ref','generation'),self.i(r,'li2_pgd_ref','slot'),j))
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
    def delta(self,a,b,**increments):
        # Original counters keep the complete exact transition relation. The
        # new historical counter records repeated read-only receipt validators:
        # its actual value is retained, monotone, and joined to each snapshot.
        # It never supplies a publication, execution or cancellation residual.
        x,y=self.counts(a),self.counts(b)
        for k in x:
            if k=='misses':need(y[k]==tuple(v+(1 if i==increments.get('miss_reason',-1)else 0)for i,v in enumerate(x[k])),'exact classified miss bucket delta')
            elif k=='loop_historical_reconstructions':need(y[k]>=x[k],'actual historical reconstruction counter never regresses')
            else:need(y[k]==x[k]+increments.get(k,0),'exact focal dynamic counter delta '+k)

    def witness(self,raw):
        if not any(raw):return None
        t='li2_le_witness';pages=q(self.f(raw,t,'page'));source=self.f(raw,t,'source');entry=self.i(raw,t,'entry')
        rebuilt=chooser.choose(pages,source,entry)
        need(raw==rebuilt['raw'],'every source-owned chooser byte independently reconstructed, including refusals and zero tails')
        return rebuilt

    def loop_state(self,raw,counts,*,focal=False):
        t='plr_state';self.eq(raw,t,scope=0)
        route,complete=self.v(raw,t,'route choice_complete')
        need(route in(0,11,12)and complete in(0,1),'explicit completed or not-attempted policy route')
        actual=self.loop_counts(self.f(raw,t,'counts'))
        need(self.f(raw,t,'counts')==self.f(counts,'pdo_counts','loop'),'all nine duplicated literal state counters')
        rebuilt={k:self.witness(self.f(raw,t,k))for k in('choice','check','historical')}
        chosen=rebuilt['choice']
        if route==0:need(not complete and chosen is None,'idle route grants no chooser result')
        elif complete:
            need(chosen is not None and chosen['result']==(0 if route==12 else 1),
                 'policy12 winner or complete policy11 NO_ENVELOPE, never an incomplete-budget fallback')
        else:
            need(chosen is None,'warm route has no new cold chooser witness after the exact reset')
        if focal:
            need((route,complete)==(12,1)and chosen is not None and
                 chosen['pages']==(self.page,self.page+PAGE)and chosen['entry']==self.head and
                 chosen['source']==self.app['source']and chosen['selected']['choice']['heads']==28,
                 'focal policy12 cold choice joins whole actual source and genuine root')
        pages=q(self.f(raw,t,'pages'));source=self.f(raw,t,'source')
        if any(pages)or any(source):
            need(any(w is not None and pages==w['pages']and source==w['source']for w in rebuilt.values()),
                 'actual serialized source scratch belongs to a fully reconstructed witness')
        else:need(not any(pages)and not any(source),'whole not-yet-used source scratch')
        return dict(route=route,choice_complete=complete,counts=actual,witnesses=rebuilt,
                    direct=self.f(raw,t,'direct'))

    def loop_direct(self,states,domains):
        # Actual saved certificate/domain reconstruction remains in
        # domain_state/completion/history.direct_history. The private emitter
        # temporary is cleared after its last read, before serialized leave.
        for state in states:
            zero(state['direct'],'whole dead DIRECT scratch is zero outside the serialized decoder scope')

    def envelope(self,status):
        h=self.h;t='pdo_wire';r=self.r;mode=self.app['mode'];failed=mode>=5
        need(type(status)is int and status==(125 if failed else 0)and self.app['lane']==1 and 0<=mode<7,
             'actual maintained lane and distinct successful versus copied-read fault outcome')
        need(h[:9]==(0x414f504c5049324c,14,4864896,4248704,362664,364544,69632,968,128),
             'exact policy14 capture schema and independently derived whole extents')
        need(canonical(self.bias)and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(n)for n in('li2_raw6','li2_gateway_start','li2_gateway_end'))and h[10]<=h[9]<h[11],
             'actual compiled bridge gateway')
        need(h[12]%PAGE==0 and h[13]==524288 and h[14:16]==(1,0)and h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,mode),
             'actual signal stack, empty write-only FD3 and explicit case')
        need(h[20:26]==tuple(self.symbol(n)for n in('pe','pdo_wire','pg_source','pg_rseq','selected_chain','span_progress')),
             'all actual registered lifecycle addresses')
        storage=r.layout['retained_storage'];prefix=storage['retained']['offset'];size=r.types['li2_ptr_slot']['bytes']
        need(h[26:31]==(self.symbol('pe')+prefix,self.symbol('pe')+prefix+size,2,size,24)and
             h[31:35]==(self.head,0,self.symbol('pe')+storage['domain']['offset'],self.symbol('pg_domain_source')),
             'actual two-slot identity and domain offsets joined to complete DWARF')
        need(h[35]==1 and h[38]==0 and canonical(h[40],12288)and h[40]%PAGE==0 and
             h[41:47]==(225880,71384,11312,12288,3,int(failed))and
             h[47:53]==(1,status,3304 if failed else 0,11 if failed else 0,h[16],0)and
             h[53:57]==(self.symbol('pdo_encoded'),4<<20,1,1)and not any(h[57:]),
             'one actual complete focal lifetime with original failed outcome retained')
        need(h[39]==(0 if failed else self.base+(-124 if mode==1 else 88)),
             'actual successful selected cut or absent failed cut')
        selection=self.f(self.b,t,'selection')
        self.eq(selection,'plo_selection',version=1,protocol=2,case_id=mode,placement=self.app['placement'],lane=1,
            source_page=self.page,base=self.base,predecessor=self.app['predecessor'],entry=self.head,high=self.app['endpoint'],
            source_bytes=8192,template_bytes=144,source_checked=2,source_compared=16384,predecessor_checked=1,
            expected_policy=12,expected_epochs=1)
        need(q(self.f(selection,'plo_selection','cut'))==(self.base-124,self.base+88),
             'exact paired observation cuts, never source admission authority')
        raw=q(self.f(self.b,t,'raw_ingress'));need(sum(raw[1:])==raw[0]>0,'whole actual signal population')
        for key in('sink_initial','sink_terminal'):
            value=self.f(self.b,t,key);fact=self.stat(value)
            need(fact['mode']&0xffff==0x8180 and fact['size']==0,'actual empty regular0600 capture sink')
            self.eq(value,'stat',st_nlink=1,st_uid=self.image['uid'])
        r.change(self.f(self.b,t,'sink_initial'),self.f(self.b,t,'sink_terminal'),'stat',observed=('st_atim','st_mtim','st_ctim'))
        need(r.transport['status']==status and r.transport['code']==(3304 if failed else 0),'actual encoded-body terminal outcome')
        hardware=self.f(self.b,t,'hardware');self.eq(hardware,'li2_selected_hardware',abi_version=1,reserved=0)
        for i,k in enumerate(('leaf0','leaf1','leaf7')):
            need(struct.unpack('<4I',self.f(hardware,'li2_selected_hardware',k))==tuple(self.app['hardware'][i][2:]),'actual bridge/application CPUID equality')
        for key,obj in(('main',self.image['main_object']),('interpreter',self.image['interpreter_object'])):
            self.image_header(self.f(self.b,t,key),obj)
        session=self.f(self.b,t,'session')
        self.eq(session,'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        need(self.i(session,'li2_step_session','sync_query')&96==96,'actual registered membarrier support')
        zero(self.f(self.b,t,'cancellation'),'one focal record grants no companion HELD cancellation')
        if failed:zero(self.f(self.b,t,'next'),'failed read grants no later original TRACE')
        epochs=r.items(self.b,t,'epochs','pdo_epoch');need(len(epochs)==1,'literal one-epoch focal capacity');self.epochs=epochs
        initial_slots=r.items(self.f(epochs[0],'pdo_epoch','prior'),'pdo_slots','slots','pdo_slot')
        self.h_alloc=self.i(r.items(initial_slots[1],'pdo_slot','banks','ped_bank')[1],'ped_bank','generated')
        self.h_proof_alloc=self.i(initial_slots[1],'pdo_slot','proof')
        return epochs[0],self.f(self.b,t,'initial_domain'),raw

    def loop_terminal(self,actual,status,code):
        names=('version','status','failure_code','route','scope','choice_complete')+LOOP_COUNTS
        row=dict(zip(names,q(self.f(self.b,'pdo_wire','loop_row')),strict=True))
        expected=dict(version=1,status=status,failure_code=code,route=actual['route'],scope=0,
                      choice_complete=actual['choice_complete'],**actual['counts'])
        need(row==expected,'whole15-cell terminal row equals actual protected policy and all nine counters')
        return row
