"""Two real activations of retained RX code; old source/frame checks are shared.

Captured addresses never authorize execution. The caller authenticates the
actual process, image, compiler closure, native app and complete wire first.
"""
import importlib.util,struct
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
HERE=Path(__file__).resolve().parent
base=load('resident_rx_generation_checks',HERE.parent/'resident_generation_owner/read.py')
wire=load('resident_rx_wire',HERE/'wire.py')
need,zero,q,canonical=base.need,base.zero,base.q,base.canonical
PAGE,TF,RF,MASK=base.PAGE,base.TF,base.RF,base.MASK
T,STATE,CERT=base.T,base.STATE,base.CERT
OPERATIONS=('plan_api','compact_build_api','compact_validate_api','publication_api',
            'generated_code_mprotect','publication_sync','owner_metadata_mprotect',
            'source_metadata_mprotect')


class Check(base.Check):
    wire=wire
    closed_pages=0
    certificate_version=3

    def binding_identity(self):
        b=self.binding
        need(b['version']==1 and b['profile']=='resident-rx-two-flags-capture-v1'and
            b['mode']=='release'and all(b[k]is True for k in('native_probe','parse_memo',
            'unregistered','subentry','cross_pair','direct_frontier','resident_three',
            'sealed_storage','source_lease','flag_stack','helper_tf','stable_generation',
            'resident_rx','rx_capture','tf_nx_page_boundary'))and b['activations']==2 and
            b['causal']['case']==0,'distinct complete positive RX binding')

    def registry_storage(self):
        need(self.symbol('r3_memory')==self.h[9]and self.symbols['r3_memory'][1]==1249280 and
            self.h[3]==wire.OWNER_BYTES and self.symbols['r3_work'][1]==2329448 and
            self.symbols['rsl'][1]==70*PAGE and self.symbols['rsl_initialization'][1]==72,
            'complete RX owner/work/source storage and separate protected counter cells')

    def record_identity(self):
        h=self.h
        need(h[:9]==(0x315758525732494c,1,wire.RECORD_BYTES,wire.OWNER_BYTES,
            362568,364544,69632,968,128),'whole distinct RX record and actual owner sizes')
        at=self.r.types['rrx_bundle']['fields']['record']['offset']+self.ordinal*wire.RECORD_BYTES
        need(h[9:12]==(self.symbol('r3_owner'),self.symbol('rrx_bundle')+at,
            self.symbol('selected_chain'))and self.symbols['rrx_bundle'][1]==wire.RAW_BYTES,
            'whole real RX bundle/member/owner symbol identities')

    def certificate_permissions(self,b,identity,layout,proof):
        for field,prot in(('published',1),('opened',5),('released',5)):
            for i,row in enumerate(self.r.items(b,CERT,field,'li2_sealed_code_query')):
                self.sealed_query(row,identity,layout[i],prot,8 if i<2 else 1)
        for row,offset,pages in zip(self.r.items(b,CERT,'proof','li2_sealed_code_query'),
                (0,64*PAGE),(64,25),strict=True):self.sealed_query(row,identity,proof+offset,1,pages)
        for field,address,prot in(('slot_query',layout[3],1),('spill_query',layout[4],3)):
            for row in self.r.items(b,CERT,field,'li2_private_code_query'):self.query(row,address,prot)
        for field,size in(('proof_scan',364544),('code_scan',69632),('slot_scan',4096)):
            self.scan(self.f(b,CERT,field),size)

    def storage_state(self,b,active):
        t=STATE
        need(struct.unpack('<3I',self.f(b,t,'references'))==(int(active),)*3 and
            struct.unpack('<3I',self.f(b,t,'closed'))==(0,0,0)and
            struct.unpack('<3I',self.f(b,t,'installed'))==(1,1,1)and
            q(self.f(b,t,'generation'))==(1,2,3),
            'execution references drain while all three original sealed code extents remain RX')
        self.eq(b,t,rx_lifetime=1)

    def counters(self,p):
        t='li2_r3_rx_progress'
        rows=self.r.items(p,t,'call','li2_r3_rx_call')
        calls=[self.v(row,'li2_r3_rx_call','attempted succeeded')for row in rows]
        need(all(a==b for a,b in calls),'every successful-profile observed API attempt completed')
        return dict(zip(OPERATIONS,calls)),{k:self.i(p,t,k)for k in
            ('retained_entries','execution_releases','suspensions','resumptions','retirements',
             'terminal_attempted','terminal_closed')}

    def state(self,b,which):
        # All original source/table/rseq/frame/fetch/cost equations still run.
        super().state(b,which)
        active=which=='entered';p=self.f(b,STATE,'rx_progress');calls,counts=self.counters(p)
        need([calls[k]for k in OPERATIONS[:6]]==[(v,v)for v in(3,3,6,3,3,1)],
             'exact cold external API calls; no warm planner/build/validate/publish/code permission/sync')
        need(counts==dict(retained_entries=self.ordinal,
            execution_releases=self.ordinal+int(not active),suspensions=9*self.ordinal,
            resumptions=9*self.ordinal,retirements=0,terminal_attempted=0,terminal_closed=0),
            'actual independent activation and preserved-getter chronology')
        release=self.f(b,STATE,'rx_release')
        if active and not self.ordinal:zero(release,'no invented earlier execution release')
        elif not active:
            need(release==self.f(self.terminal,STATE,'fetch'),
                 'whole saved release is the actual focal terminal fetch, not later ordinary TF')
        else:
            self.eq(release,'li2_fetch_progress',held=0,complete=1,first_error=0,
                first_detail=0,identity_observed=1,last_backing_observed=1,validation_calls=1)


def read(data,layout,image,app,pid,cpu,exit_status):
    need(type(data)is bytes and type(pid)is int and 0<pid<1<<31 and type(cpu)is int and
        cpu>=0 and type(exit_status)is int and exit_status==0,'whole real successful RX process')
    need(len(data)==wire.RAW_BYTES+64 and len(data)<4<<20,'exact distinct bounded RX wire')
    footer=q(data[-64:]);need(footer[:4]==(0x314658525732494c,1,wire.RAW_BYTES,wire.RAW_BYTES)and
        1<=footer[4]<=64 and 0<footer[5]<=wire.RAW_BYTES and footer[6:]==(0,0),
        'whole actual successful transport footer')
    r=wire.Reader(memoryview(data)[:-64],layout);h=q(r.field(r.data,'rrx_bundle','h'))
    need(h==(0x314258525732494c,1,wire.RAW_BYTES,wire.RECORD_BYTES,1,2,2,2,
        0,0,0,1,0,0,1,wire.OWNER_BYTES),'two actual complete RX activations')
    need(type(app)is dict and app['version']==1 and app['complete']is True and
        app['records']==2 and app['owner_credit']is False and len(app['applications'])==2,
        'unchanged complete two-activation application reader')
    checks=[Check(wire.RecordView(r,i),image,app['applications'][i],pid,cpu)for i in range(2)]
    values=[c.finish(exit_status)for c in checks]
    first,last,a,b=base.activation_relation(r,checks,values)
    before=first.f(first.terminal,STATE,'rx_progress')
    after=last.f(last.terminal,STATE,'rx_progress')
    initial_calls,_=first.counters(before);last_calls,_=last.counters(after)
    stable={k:tuple(y-x for x,y in zip(initial_calls[k],last_calls[k],strict=True))for k in OPERATIONS}
    need(all(stable[k]==(0,0)for k in OPERATIONS[:6]),
         'stable second distinct activation has zero actual first-six API work')
    need(all(stable[k][0]==stable[k][1]>0 for k in OPERATIONS[6:]),
         'metadata permissions remain real and are reported separately')
    pre=last.f(last.b,T,'rx_before');_,precounts=last.counters(pre)
    need(precounts==dict(retained_entries=0,execution_releases=1,suspensions=9,
        resumptions=9,retirements=0,terminal_attempted=0,terminal_closed=0),
        'nine actual successful getters before the second real held source bind')
    need(last.f(last.entered,STATE,'rx_release')==first.f(first.terminal,STATE,'fetch'),
         'whole previous execution release persists until the next real completion')
    final=bytes(r.field(r.data,'rrx_bundle','final'));t=STATE
    for key in r.types[t]['fields']:
        if key not in('fetch','source_progress','resident_progress','generation_progress',
                     'maps','rx_lifetime','rx_progress','closed'):
            need(last.f(final,t,key)==last.f(last.handoff,t,key),
                 'whole final owner identity outside explicit retirement '+key)
    last.eq(final,t,rx_lifetime=4)
    need(struct.unpack('<3I',last.f(final,t,'closed'))==(1,1,1),
         'final nonpreservable output retired all three code extents')
    base.final_source_state(r,last,final,b)
    finalcalls,finalcounts=last.counters(last.f(final,t,'rx_progress'))
    need([finalcalls[k]for k in OPERATIONS[:6]]==[(v,v)for v in(3,3,6,3,6,2)]and
        finalcounts==dict(retained_entries=1,execution_releases=2,suspensions=13,resumptions=13,
            retirements=1,terminal_attempted=1,terminal_closed=1),
        'exact final real revoke, successful physical closure and no republishing')
    need(struct.unpack('<3i',r.field(r.data,'rrx_bundle','final_code_result'))==(0,0,0),
         'all final actual physical permission queries completed')
    rows=r.items(r.data,'rrx_bundle','final_code','li2_sealed_code_query')
    for i,c in enumerate(last.certificates):
        identity=last.f(c,CERT,'identity')
        for j in range(3):last.sealed_query(rows[3*i+j],identity,last.layouts[i][j],1,8 if j<2 else 1)
    need(q(r.field(r.data,'rrx_bundle','control'))==(1,)+(0,)*15,
         'positive observation has no causal injection')
    for key in('mailbox_before','mailbox_after','mailbox_query','attack_greg','attack_si',
               'attack_uc','metadata_before','replacement'):zero(r.field(r.data,'rrx_bundle',key),'unused positive causal field '+key)
    ingress=q(r.field(r.data,'rrx_bundle','ingress'))
    need(sum(ingress[1:])==ingress[0]>=last.h[30]and ingress[1]>=2 and ingress[2]>=4 and
        ingress[3:]==(1,0,0),'complete actual final signal partition')
    return dict(version=1,scope='two_distinct_retained_rx_activations',activations=values,
        publications=3,entries=2,completed=2,interior_signals=0,preserved_boundary_effects=9,
        stable_api_deltas=stable,final_api_calls=finalcalls,final_lifetime_counts=finalcounts,
        final_closed_pages=51,signal_counts=ingress,transport=dict(raw_bytes=wire.RAW_BYTES,
        body_calls=footer[4],last_body_result=footer[5],status=0,code=0),
        qualification_credit=False,performance_credit=False)


def pair_activation(native,gated,owner):
    base.base.pair_state(native,gated,owner)
    need(owner['cold_publications']==owner['resident_certificates']==3 and
        owner['entries']==owner['completed']==owner['anchor_released']==1 and
        owner['closed_pages']==0 and owner['interior_signals']==0 and
        owner['terminal_ingresses']==1 and owner['old_active_domain_limit']==2,
        'actual released execution claims and retained RX, separate from old NX owner')
    need(owner['models']==[dict(heads=2,exits=1),dict(heads=2,exits=1),dict(heads=3,exits=2)]and
        owner['native_instructions']==30 and owner['generated_guest_instructions']==28,
        'unchanged four-cycle native and generated graph populations')
    return dict(native_full_frames=5,protected_full_frames=3,native_instructions=30,
        generated_guest_instructions=28,fp_bytes=65536,uc_bytes=968,stack_bytes=520)


def pair(native,gated,owner):
    need(native['records']==gated['records']==2 and native['complete']is gated['complete']is True and
        len(owner['activations'])==2,'both unchanged real application records')
    out=[]
    for i in range(2):
        o=owner['activations'][i]
        need(o['ordinal']==i and o['actual_serial']==o['cumulative_entries']==o['cumulative_completed']==i+1,
             'literal independent activation chronology')
        out.append(pair_activation(native['applications'][i],gated['applications'][i],o))
    need(owner['publications']==3 and owner['entries']==owner['completed']==2 and
        owner['final_closed_pages']==51 and owner['preserved_boundary_effects']==9 and
        owner['interior_signals']==0 and all(owner['stable_api_deltas'][k]==(0,0)for k in OPERATIONS[:6]),
        'whole RX lifecycle after both full native-state comparisons')
    return dict(activations=out,native_full_frames=10,protected_full_frames=6,
        stable_api_deltas=owner['stable_api_deltas'],qualification_credit=False,performance_credit=False)


def pair_controls(native,gated,owner):
    pair(native,gated,owner)
    controls=[base.base.pair_controls_checked(native['applications'][i],gated['applications'][i],
        owner['activations'][i],pair_activation)for i in range(2)]
    need(all(x['count']==44 for x in controls),'all original44 supplied full-state mutations in each RX activation')
    return dict(count=88,activations=controls,native_operations=0)


def record_controls(data,layout,image,app,pid,cpu,exit_status,ordinal):
    return base.record_controls_checked(data,layout,image,app,pid,cpu,exit_status,ordinal,
        read,wire,'rrx_bundle','released')


def record_prepared_controls(data,layout,image,app,pid,cpu,exit_status,ordinal):
    return base.record_prepared_controls_checked(data,layout,image,app,pid,cpu,exit_status,ordinal,
        read,wire,'rrx_bundle','released')


def generation_controls(data,layout,image,app,pid,cpu,exit_status):
    return base.generation_controls_checked(data,layout,image,app,pid,cpu,exit_status,
        read,wire,'rrx_bundle','released')


def rx_controls(data,layout,image,app,pid,cpu,exit_status):
    """Actual RX field mutations; all original owner/frame controls stay shared."""
    read(data,layout,image,app,pid,cpu,exit_status);refused=[];types=layout['types']
    def at(path):
        t='rrx_bundle';offset=0
        for item in path:
            key,index=(item,0)if type(item)is str else item
            f=types[t]['fields'][key];offset+=f['offset'];child=layout['edges'][t].get(key)
            if child:
                need((index+1)*types[child]['bytes']<=f['bytes'],'whole RX stimulus member')
                offset+=index*types[child]['bytes'];t=child
            else:
                need(index<f['bytes'],'whole RX stimulus scalar');offset+=index
        return offset
    tests=[]
    for ordinal in (0,1):
        for state in ('entered','terminal'):
            prefix=(('record',ordinal),state)
            tests.append((str(prefix)+'/lifetime',prefix+('rx_lifetime',)))
            for operation in range(8):
                for key in ('attempted','succeeded'):
                    tests.append((str(prefix)+'/'+str(operation)+'/'+key,
                        prefix+('rx_progress',('call',operation),key)))
            for key in ('retained_entries','execution_releases','suspensions','resumptions','retirements'):
                tests.append((str(prefix)+'/'+key,prefix+('rx_progress',key)))
    for key in ('rx_lifetime','closed'):
        tests.append(('final/'+key,('final',key)))
    for key in ('terminal_attempted','terminal_closed'):
        tests.append(('final/'+key,('final','rx_progress',key)))
    for index in range(9):
        tests.append(('actual_final_R/'+str(index),(('final_code',index),'actual_prot')))
    for name,path in tests:
        changed=bytearray(data);changed[at(path)]^=1
        try:read(bytes(changed),layout,image,app,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted actual RX field corruption '+name)
    need(len(refused)==len(set(refused))==101,'all101 additive RX mutations reject')
    return dict(count=101,refusals=refused,native_operations=0)
