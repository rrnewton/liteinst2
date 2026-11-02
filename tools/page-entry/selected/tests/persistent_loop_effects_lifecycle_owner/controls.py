"""Independent supplied schema17 corruptions; no observations are invented.

Each control first requires the whole actual positive record, mutates one
identified field, and requires refusal. All fields use authenticated actual
DWARF, never hard-coded policy14 offsets. No subject or decoder is executed.
"""
import hashlib,struct,copy,importlib.util
from pathlib import Path
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
HERE=Path(__file__).resolve().parent
prior=load('lifecycle_controls_pf',HERE.parent/'persistent_fused_owner/read.py')
need=prior.need
LOOP_COUNTS=('chooser_attempts','chooser_selected','chooser_no_envelope','publications12',
 'hits12','entries_with12','completed_with12','historical_reconstructions','actual_entries12')

def controls(reader,data,layout,image,app,native,pid,cpu,exit_status):
    reader(data,layout,image,app,native,pid,cpu,exit_status)
    raw,_=prior.codec.decode(data,raw_bytes=16744832,schema_version=17)
    types=layout['types'];tests=[];loops=[]
    def at(t,k,base=0,index=0,child=None):
        return base+types[t]['fields'][k]['offset']+index*(types[child]['bytes']if child else 1)
    def add(name,t,k,base=0):tests.append((name,at(t,k,base)))
    for i in(0,1,2,3,4,28,29,31,32,35,38,39,41,42,43,44,45,46,47,48,49,50,54,55,56):
        tests.append(('header'+str(i),8*i))
    add('raw_ingress','pdo_wire','raw_ingress')
    selection=at('pdo_wire','selection')
    for k in('version','protocol','case_id','placement','lane','source_page','root','entry',
             'predecessor','cancel','stub','high','expected_offers','expected_completed',
             'source_checked','source_compared','predecessor_checked'):
        add('selection_'+k,'plc_selection',k,selection)
    for i in range(3):
        c=at('pdo_wire','certificates',index=i,child='pdo_certificate');p=at('pdo_certificate','payload',c)
        for k in('complete','index','slot','generation','entry','tail','code'):
            add('certificate'+str(i)+'_'+k,'pdo_certificate',k,c)
        for k in('version','plan_policy','archive','policy','serial','generation','reserved'):
            add('publication'+str(i)+'_'+k,'pe_header',k,at('pe_payload','header',p))
        for k in('version','heads','exits','stores','source_mask','source','layout','image','head',
                 'original','frontier','instruction','guard','exit_pc','table','links'):
            add('plan'+str(i)+'_'+k,'li2_pg_compact',k,at('pe_payload','plan',p))
    for i in range(5):
        e=at('pdo_wire','epochs',index=i,child='pdo_epoch');label='epoch'+str(i)
        for k in('h','prior','prior_domain','predecessor'):
            add(label+'_'+k,'pdo_epoch',k,e)
        loops.append((label+'_prior',at('pdo_epoch','prior_loop',e)))
        if i==3:
            # These cells must stay entirely zero: a refusal is not an entry.
            for k in('returned','after','entered','terminal','info','before_memory','after_memory','terminal_domain'):
                add('cancel_forbidden_'+k,'pdo_epoch',k,e)
            continue
        for name in('ingress','before','returned','after'):
            f=at('pdo_epoch',name,e)
            for k in('greg','fp'):add(label+'_'+name+'_'+k,'li2_step_frame',k,at('le_frame','frame',f))
            for k in('uc','si'):add(label+'_'+name+'_'+k,'le_frame',k,f)
        for name in('before_memory','after_memory'):
            for k in('data','stack'):add(label+'_'+name+'_'+k,'li2_pdo_memory',k,at('pdo_epoch',name,e))
        for name in('entered','terminal'):
            s=at('pdo_epoch',name,e)
            for t,k,parent in(('li2_pg_progress','phase','progress'),('li2_pg_progress','completion_permit','progress'),
                ('li2_pg_source_progress','release_complete','source'),('li2_pg_rseq_progress','active','rseq'),
                ('li2_fetch_progress','held','fetch'),('li2_span_transfer_progress','consumed','transfer')):
                add(label+'_'+name+'_'+parent+'_'+k,t,k,at('pdo_stage',parent,s))
            for k in('entry','domain_source','domain'):add(label+'_'+name+'_'+k,'pdo_stage',k,s)
            loops.append((label+'_'+name,at('pdo_stage','loop',s)))
        for k in('initial_slots','terminal_slots','initial_spill','terminal_spill','initial_directory','terminal_directory'):
            add(label+'_'+k,'pdo_epoch',k,e)
        domain=at('pdo_epoch','terminal_domain',e);work=at('pda_state','work',domain)
        cell=struct.unpack_from('<I',raw,at('pda_work','receipt',work))[0]
        need(cell<3,'actual bounded completed cell for independent supplied corruption')
        completion=at('pda_state','completion',domain,cell,'pda_completion')
        for k in('id','serial','count','complete','member','direct_exit'):
            add(label+'_completion_'+k,'pda_completion',k,completion)
        for k in('claimed','next_id','dual_completed'):add(label+'_domain_'+k,'pda_state',k,domain)
        n=at('pdo_wire','next',index=i,child='pdo_next')
        for k in('expected_ordinal','raw_ordinal','closed_complete','frame','closed'):
            add(label+'_next_'+k,'pdo_next',k,n)
    c=at('pdo_wire','cancellation')
    for k in('h','closed_slot','resumed_slot','initial_registry','terminal_registry'):
        add('cancel_'+k,'pbo_cancel',k,c)
    for name in('before','returned','next'):
        f=at('pbo_cancel',name,c)
        for k in('greg','fp'):add('cancel_'+name+'_'+k,'li2_step_frame',k,at('le_frame','frame',f))
        for k in('uc','si'):add('cancel_'+name+'_'+k,'le_frame',k,f)
    for name in('held','resumed'):
        s=at('pbo_cancel',name,c)
        for k in('progress','counts','slots','transfer','source','domain','entry','domain_source'):
            add('cancel_'+name+'_'+k,'pdo_stage',k,s)
        loops.append(('cancel_'+name,at('pdo_stage','loop',s)))
    for k in('version','status','reason','site','pc','detail'):
        add('cancel_miss_'+k,'li2_pg_miss',k,at('pbo_cancel','miss',c))
    for k in('ready','result','heads','exits','stores','entry','source','table','scan_started','scan_complete','scanned','nonzero'):
        add('cancel_plan_'+k,'pbo_miss_plan',k,at('pbo_cancel','plan',c))
    loops.append(('final',at('pdo_wire','final_loop')))
    need(len(loops)==16,'all16 actual protected loop snapshots')
    for name,p in loops:
        for k in('scope','route','choice_complete'):add(name+'_loop_'+k,'plr_state',k,p)
        for k in LOOP_COUNTS:add(name+'_loop_'+k,'plr_counts',k,at('plr_state','counts',p))
        for k in('choice','check','historical'):
            add(name+'_loop_'+k,'li2_le_witness','entry',at('plr_state',k,p))
        for k in('source','direct'):add(name+'_loop_'+k,'plr_state',k,p)
    for k in('final_counts','final_progress','loop_row','final_row','final_subentry','next_target'):
        add(k,'pdo_wire',k)
    tests.append(('cancel_forbidden_next',at('pdo_wire','next',index=3,child='pdo_next')))
    names=[n for n,_ in tests]
    need(len(names)==len(set(names))==723 and all(type(p)is int and 0<=p<len(raw)for _,p in tests),
         'literal distinct bounded lifecycle control roster')
    refused=[]
    for name,offset in tests:
        changed=bytearray(raw);changed[offset]^=1
        need(changed!=raw,'actual nonidentity lifecycle control '+name)
        encoded=prior.codec.encode_for_control(bytes(changed),schema_version=17)
        try:reader(encoded,layout,image,app,native,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted supplied lifecycle owner corruption '+name)
    need(refused==names,'every named lifecycle state/control corruption refused')
    return dict(refusals=refused,count=len(names),original_sha256=hashlib.sha256(data).hexdigest(),
                native_operations=0,qualification_credit=False)

def pf_controls(reader,data,layout,image,app,native,pid,cpu,exit_status):
    reader(data,layout,image,app,native,pid,cpu,exit_status)
    raw,_=prior.codec.decode(data,raw_bytes=16744832,schema_version=17)
    types=layout['types'];stages=[]
    def at(t,k,base=0):return base+types[t]['fields'][k]['offset']
    for i in range(5):
        e=at('pdo_wire','epochs')+i*types['pdo_epoch']['bytes']
        stages.append(('epoch'+str(i)+'_prior',at('pdo_epoch','prior_counts',e)))
        if i!=3:
            for name in('entered','terminal'):
                stages.append(('epoch'+str(i)+'_'+name,at('pdo_stage','counts',at('pdo_epoch',name,e))))
    c=at('pdo_wire','cancellation')
    for name in('held','resumed'):stages.append(('cancel_'+name,at('pdo_stage','counts',at('pbo_cancel',name,c))))
    stages.append(('final',at('pdo_wire','final_counts')))
    need(len(stages)==16,'all actual companion snapshots, excluding nonexistent cancelled entry/exit')
    refused=[]
    for name,p in stages:
        for key in('pf_backward_refused','pf_backward_cancelled'):
            changed=bytearray(raw);changed[at('pdo_counts',key,p)]^=1
            need(changed!=raw,'nonidentity actual protected PF counter control')
            try:reader(prior.codec.encode_for_control(bytes(changed),schema_version=17),layout,image,app,native,pid,cpu,exit_status)
            except ValueError:refused.append(name+'_'+key)
            else:raise ValueError('accepted protected lifecycle PF counter '+name+'_'+key)
    for name in('previous_last','refused_offset','cancelled_width','owner_extent'):
        changed=copy.deepcopy(layout);pf=changed['pf_refusals']
        if name=='previous_last':pf['previous_last']['bytes']+=8
        elif name=='refused_offset':pf['fields']['pf_backward_refused']['offset']+=8
        elif name=='cancelled_width':pf['fields']['pf_backward_cancelled']['bytes']=4
        else:changed['registrations']['pe']['bytes']+=64
        need(changed!=layout,'nonidentity protected field witness control')
        try:reader(data,changed,image,app,native,pid,cpu,exit_status)
        except ValueError:refused.append('layout_'+name)
        else:raise ValueError('accepted protected lifecycle field witness '+name)
    need(len(refused)==len(set(refused))==36,'all32 protected snapshot cells plus4 actual field witnesses')
    return dict(refusals=refused,count=36,original_sha256=hashlib.sha256(data).hexdigest(),native_operations=0)


EFFECTS_COUNT=319

def effects_controls(reader,data,layout,image,app,native,pid,cpu,exit_status):
    """Additive whole-state transport controls, after the complete positive.

    The old723 owner,36 PF and1069 pair rosters remain separate and mandatory.
    Reindexing a value-preserving pool is rejected: order is actual chronology.
    """
    reader(data,layout,image,app,native,pid,cpu,exit_status)
    raw,_=prior.codec.decode(data,raw_bytes=16744832,schema_version=17)
    types=layout['types'];tests=[]
    def at(t,k,base=0,index=0,child=None):
        return base+types[t]['fields'][k]['offset']+index*(types[child]['bytes']if child else 1)
    def set_value(name,offset,fmt,value):
        tests.append((name,[(offset,struct.pack(fmt,value))]))
    observation=at('pdo_wire','effects');t='ple_lifecycle_observation';st='ple_lifecycle_snapshot'
    count=struct.unpack_from('<Q',raw,at(t,'pool_count',observation))[0]
    order=tuple(range(10))+(15,16,12,13,14,17)
    for k,v in(('version',2),('bytes',3004881),('copied_mask',0),('pool_count',37)):
        set_value('effects_header_'+k,at(t,k,observation),'<Q',v)
    reference_offsets=[]
    for index in order:
        p=at(t,'snapshot',observation,index,st);prefix=at(st,'prefix',p)
        label='effects_stage'+str(index)
        set_value(label+'_completion',prefix,'<I',2)
        set_value(label+'_padding',prefix+4,'<I',1)
        for j,key in enumerate(LOOP_COUNTS):
            set_value(label+'_counter_'+key.replace('12','13'),prefix+8+8*j,'<Q',(1<<64)-1)
        for j in range(3):
            a=at(st,'reference',p)+4*j;reference_offsets.append(a)
            set_value(label+'_reference'+str(j),a,'<I',37)
        set_value(label+'_reserved',at(st,'reserved',p),'<I',1)
        for j in range(3):
            a=at(st,'scan',p,j,'pdo_scan')
            set_value(label+'_full_scan'+str(j),at('pdo_scan','compared',a),'<Q',0)
    for index in(10,11):
        set_value('effects_uncaptured'+str(index),at(t,'snapshot',observation,index,st),'<I',1)
    terminal=at(t,'terminal_row',observation)
    for j in range(18):
        value=struct.unpack_from('<Q',raw,terminal+8*j)[0]
        set_value('effects_terminal'+str(j),terminal+8*j,'<Q',value^1)
    set_value('effects_final_padding',len(raw)-1,'<B',1)
    pool=at(t,'witness',observation);size=types['li2_le_witness']['bytes']
    # B's complete NO_ENVELOPE and the later m16 refusal have distinct roots;
    # the whole positive already proved both. At most32 nonzero values can be
    # used by16 snapshots each satisfying the exact two-value relation.
    need(2<=count<=32 and size==83320,'actual distinct lifecycle refusal witnesses and two-value bound')
    for name,key in(('source','source'),('entry','entry')):
        offset=pool+types['li2_le_witness']['fields'][key]['offset']
        set_value('effects_pool_'+name,offset,'<B',raw[offset]^1)
    set_value('effects_unused_pool',pool+35*size,'<B',1)
    swap=[(pool,bytes(raw[pool+size:pool+2*size])),
          (pool+size,bytes(raw[pool:pool+size]))]
    for a in reference_offsets:
        ref=struct.unpack_from('<I',raw,a)[0]
        if ref in(1,2):swap.append((a,struct.pack('<I',3-ref)))
    tests.append(('effects_value_preserving_pool_reorder',swap))
    first=next(a for a in reference_offsets if struct.unpack_from('<I',raw,a)[0]==1)
    tests.append(('effects_duplicate_pool_value',[
        (at(t,'pool_count',observation),struct.pack('<Q',count+1)),
        (pool+count*size,bytes(raw[pool:pool+size])),(first,struct.pack('<I',count+1))]))
    empty=next(a for a in reference_offsets if struct.unpack_from('<I',raw,a)[0]==0)
    tests.append(('effects_zero_reference_is_not_pool_entry',[
        (at(t,'pool_count',observation),struct.pack('<Q',count+1)),
        (empty,struct.pack('<I',count+1))]))
    names=[name for name,_ in tests]
    need(len(names)==len(set(names))==EFFECTS_COUNT==319,'literal additive whole-state transport control roster')
    refused=[]
    for name,spans in tests:
        changed=bytearray(raw)
        for offset,value in spans:
            need(type(offset)is int and 0<=offset<=len(raw)-len(value),'bounded actual effects corruption')
            changed[offset:offset+len(value)]=value
        need(changed!=raw,'nonidentity supplied effects lifecycle corruption '+name)
        encoded=prior.codec.encode_for_control(bytes(changed),schema_version=17)
        try:reader(encoded,layout,image,app,native,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted effects lifecycle corruption '+name)
    need(refused==names,'every additive whole-state effects control refused')
    return dict(refusals=refused,count=EFFECTS_COUNT,original_sha256=hashlib.sha256(data).hexdigest(),
                native_operations=0,qualification_credit=False)
