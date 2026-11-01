"""Source-owned supplied policy14 corruptions; baseline must first pass.

These mutate retained bytes in memory only. They launch no child and create no
new observation. Old native41/PB/PF and the separate companion gates remain
mandatory; these new focal controls do not replace their populations.
"""
import hashlib,struct,importlib.util,copy
from pathlib import Path

def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
HERE=Path(__file__).resolve().parent
old=load('loop_control_codec',HERE.parent/'persistent_fused_owner/fault_read.py')
need=old.need
LOOP_COUNTS=('chooser_attempts','chooser_selected','chooser_no_envelope','publications12',
 'hits12','entries_with12','completed_with12','historical_reconstructions','actual_entries12')


def controls(reader,data,layout,image,app,pid,cpu,exit_status):
    original=reader(data,layout,image,app,pid,cpu,exit_status)
    failed=app['mode']>=5;decode=old.decode_failure if failed else old.base.codec.decode
    raw,_=decode(data,raw_bytes=4864896,schema_version=14);types=layout['types'];tests=[]
    def at(t,k,base=0,index=0,child=None):
        return base+types[t]['fields'][k]['offset']+index*(types[child]['bytes']if child else 1)
    def add(name,t,k,base=0,index=0,child=None):tests.append((name,at(t,k,base,index,child)))
    for i in(0,1,2,3,4,31,35,39,41,42,46,48,49,50):tests.append(('header'+str(i),8*i))
    add('raw_ingress','pdo_wire','raw_ingress')
    for k in('version','protocol','case_id','placement','lane','source_page','base','predecessor','entry','cut','high',
              'source_checked','source_compared','predecessor_checked','expected_policy','expected_epochs'):
        add('selection_'+k,'plo_selection',k,at('pdo_wire','selection'))
    certificate=at('pdo_wire','certificates');payload=at('pdo_certificate','payload',certificate);cp=at('pe_payload','plan',payload)
    for k in('complete','generation','entry','tail','code'):add('certificate_'+k,'pdo_certificate',k,certificate)
    for k in('version','plan_policy','archive','policy','serial','generation'):add('header_'+k,'pe_header',k,at('pe_payload','header',payload))
    for k in('version','heads','exits','stores','source_mask','source','layout','image','head','original','frontier','instruction','guard','exit_pc','table','links'):
        add('plan_'+k,'li2_pg_compact',k,cp)
    add('unused_certificate','pdo_wire','certificates',index=1,child='pdo_certificate')
    e=at('pdo_wire','epochs');entered=at('pdo_epoch','entered',e);terminal=at('pdo_epoch','terminal',e)
    for prefix,stage in(('entered',entered),('terminal',terminal)):
        for t,k,parent in(('li2_pg_progress','phase','progress'),('li2_pg_progress','completion_permit','progress'),
            ('li2_pg_source_progress','release_complete','source'),('li2_pg_source_progress','opened_pages','source'),
            ('li2_pg_rseq_progress','active','rseq'),('li2_pg_rseq_progress','close_complete','rseq'),
            ('li2_fetch_progress','held','fetch'),('li2_span_transfer_progress','consumed','transfer')):
            add(prefix+'_'+parent+'_'+k,t,k,at('pdo_stage',parent,stage))
        for k in('entry','domain_source','domain'):add(prefix+'_'+k,'pdo_stage',k,stage)
    for name in('ingress','before','returned','after'):
        f=at('pdo_epoch',name,e)
        for k in('greg','fp'):add(name+'_'+k,'li2_step_frame',k,at('le_frame','frame',f))
        for k in('uc','si'):add(name+'_'+k,'le_frame',k,f)
    for name in('before_memory','after_memory'):
        for k in('data','stack'):add(name+'_'+k,'li2_pdo_memory',k,at('pdo_epoch',name,e))
    for k in('initial_slots','terminal_slots','initial_spill','terminal_spill','initial_directory','terminal_directory','predecessor'):
        add(k,'pdo_epoch',k,e)
    loops=(('prior',at('pdo_epoch','prior_loop',e)),('entered',at('pdo_stage','loop',entered)),
           ('terminal',at('pdo_stage','loop',terminal)),('final',at('pdo_wire','final_loop')))
    for prefix,p in loops:
        for k in('scope','route','choice_complete'):add(prefix+'_loop_'+k,'plr_state',k,p)
        for k in LOOP_COUNTS:add(prefix+'_loop_'+k,'plr_counts',k,at('plr_state','counts',p))
        for k in('choice','check','historical'):add(prefix+'_loop_'+k,'li2_le_witness','entry',at('plr_state',k,p))
        for k in('source','direct'):add(prefix+'_loop_'+k,'plr_state',k,p)
    # Internal branch arms have their own interval-derived tokens. Neither a
    # captured mask nor a correct aggregate count can authorize a changed arm.
    choice=at('plr_state','choice',at('pdo_stage','loop',entered));shape=at('li2_le_witness','selected',choice)
    for i in range(28):add('chooser_head'+str(i)+'_token','li2_le_head','token',at('li2_le_shape','head',shape,i,'li2_le_head'))
    add('historical_policy','pe_header','plan_policy',at('pe_payload','header',payload))
    for k in('final_counts','final_progress','loop_row','final_row','final_subentry','cancellation'):add(k,'pdo_wire',k)
    if failed:
        info=at('pdo_epoch','info',e);rec=at('pdo_epoch_info','recovered',info)
        for k in('original_pc','flags','member','head','link','kind','phase','complete','gpr'):add('recovered_'+k,'li2_pg_recovered',k,rec)
        for k in('guest_data_fault','recovery_complete','recovery_scratch','final_fetch'):add('failed_'+k,'pdo_epoch_info',k,info)
        add('forbidden_next','pdo_wire','next')
    else:
        n=at('pdo_wire','next')
        for k in('expected_ordinal','raw_ordinal','closed_complete','frame','closed'):add('next_'+k,'pdo_next',k,n)
        domain=at('pdo_epoch','terminal_domain',e);work=at('pda_state','work',domain)
        cell=struct.unpack_from('<I',raw,at('pda_work','receipt',work))[0];need(cell<3,'actual bounded completed cell for supplied corruption')
        completion=at('pda_state','completion',domain,cell,'pda_completion');direct=at('pda_completion','direct_exit',completion)
        for k in('complete','member','heads','head','exits','index','arm','row','original','direct'):add('direct_'+k,'pda_direct_exit',k,direct)
    names=[n for n,_ in tests];need(len(names)==len(set(names))and all(0<=at<len(raw)for _,at in tests),'bounded named nonempty supplied control roster')
    refused=[]
    for name,offset in tests:
        altered=bytearray(raw);altered[offset]^=1;need(altered!=raw,'actual nonidentity corruption')
        encoded=old.encode_failed_control(bytes(altered),schema_version=14)if failed else old.base.codec.encode_for_control(bytes(altered),schema_version=14)
        try:reader(encoded,layout,image,app,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted supplied policy14 owner corruption '+name)
    need(refused==names,'every exact named supplied owner corruption refused')
    return dict(refusals=refused,count=len(names),original_sha256=hashlib.sha256(data).hexdigest(),
                native_operations=0,qualification_credit=False)
