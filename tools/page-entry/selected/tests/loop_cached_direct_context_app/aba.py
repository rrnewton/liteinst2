"""One real live-proof ABA, distinct from the unchanged positive experiment."""
import hashlib
import struct
from functools import partial
from types import SimpleNamespace

MAGIC,FOOTER=0x314142414132494c,0x314642414132494c
NAMES=('version','record','counts','query','page','before','query_bytes','frame_bytes',
       'page_bytes','header_words','stages','counter_words')

def need(ok,why):
    if not ok:raise ValueError(why)

def q(data,at=0,count=1):return struct.unpack_from('<'+'Q'*count,data,at)

def _framing(data,control,layout,aba_layout):
    a=aba_layout;v=layout
    need(type(data)is bytes and type(control)is int and control==1 and
         type(a)is dict and set(a)==set(NAMES)|{'symbol','owner','inferior_started'} and
         a['inferior_started']is False and all(type(a[n])is int and a[n]>0 for n in NAMES),
         'one distinct actual ABA control and complete compiler layout')
    need((a['version'],a['query_bytes'],a['frame_bytes'],a['page_bytes'],a['header_words'],a['stages'],a['counter_words'])==
         (1,296,67008,4096,40,3,64) and a['counts']==320 and a['query']==1856 and a['page']==2744 and
         a['before']>=a['page']+12288 and a['before']-a['page']-12288<64 and
         a['record']==a['before']+a['frame_bytes'] and len(data)==v['wire']+64+a['record']+64 and
         len(data)<4<<20,'whole original wire plus separate bounded causal appendix')
    h=q(data,0,32);at=v['wire']+64;r=data[at:at+a['record']];x=q(r,0,40)
    need(h[:9]==(0x314f58434132494c,1,v['wire'],v['epoch'],4,8,8,9,12) and
         h[16:28]==(1,2,0,0,0,0,125,3303,3303,3,0,1),
         'one actual completed epoch and one bound-only epoch, original3303/detail3 refusal')
    need(x[:5]==(MAGIC,1,a['record'],1,1) and x[6]==1 and x[8:12]==(4096,0,1,0) and
         x[28:36]==(125,3303,3303,3,0,1,15,0) and x[38]>0 and x[39]==0,
         'separate complete ABA record and actual stopped owner without observer failure')
    for offset,magic,size in ((v['wire'],0x314658434132494c,v['wire']),
                              (at+a['record'],FOOTER,a['record'])):
        f=q(data,offset,8)
        need(f[:4]==(magic,1,size,size) and 1<=f[4]<=64 and 0<f[5]<=size and f[6:]==(125,3303),
             'both whole bounded actual FD3 writes preserve the failed child outcome')
    return h,r,x

def terminal_observation(data,control,*,layout,aba_layout):
    _,r,_=_framing(data,control,layout,aba_layout)
    return 125,3303,q(r,aba_layout['counts']+2*512,32)

def read(data,app,native,image,pid,uid,control,exit_status,gated=None,*,backing_size,layout,
         aba_layout,differential,binding,dependencies):
    prior,common,descriptor=dependencies;v=layout;a=aba_layout
    h,r,x=_framing(data,control,v,a);owners,intervals=prior._layout(v,h)
    need(type(differential)is bool and binding['mode']==('differential'if differential else'release') and
         binding['cached_direct_aba']==dict(version=1,control=1,checkpoint='second-bound-before-entry',
             page_bytes=4096,layout_words=12,expected_exit=125,failure_code=3303,failure_detail=3,
             observation_authority=False,qualification_credit=False,performance_credit=False) and
         type(pid)is int and pid>0 and type(uid)is int and uid>=0 and exit_status==125 and gated is None and
         h[11]==h[13]==h[29]==0 and h[12]&0o6003==1 and h[28]==h[12] and
         h[14]>0 and h[14]%4096==0 and h[15]==524288 and h[30:]==(pid,pid),
         'actual causal process, compiled identity and original alternate stack; no completed application')
    initial,terminal=data[256:400],data[400:544]
    need(initial[:40]==terminal[:40] and q(initial,16)[0]==1 and
         prior.u(initial,24,2)==(0o100600,uid) and q(initial,48)[0]==q(terminal,48)[0]==0,
         'same actual fresh regular private sink before either write')
    prior.zero(data[544:v['wire_epoch']],'whole original wire alignment padding')
    owner=a['owner'];symbol=a['symbol']
    need(all(type(z)is dict and set(z)=={'address','bytes'} and
         all(type(n)is int and n>0 for n in z.values())for z in(owner,symbol)) and
         owner['bytes']==a['record'] and symbol['bytes']==96 and
         x[38]==h[9]-v['owners']['pe']['address']+owner['address'],'whole actual causal owner and readonly layout symbols')
    for old in v['owners'].values():
        need(owner['address']+owner['bytes']<=old['address'] or
             old['address']+old['bytes']<=owner['address'],'causal evidence disjoint from production authority')
    need(native['header'][5]==1 and len(native['observations'][0]['frames'])==12,
         'complete independent146-step native reference')
    model=app.trace_model(native)
    raw=data[v['wire_epoch']:v['wire_epoch']+v['epoch']]
    first=prior.complete_epoch(raw,0,v,h,owners,intervals,app,native,model,image,backing_size,pid,binding,common,descriptor)
    at=v['wire_epoch']+v['epoch'];raw=data[at:at+v['epoch']];e=q(raw,0,32)
    need(e[:5]==(1,0,0,0,0x412200) and e[5]==x[5]>first['header'][5] and e[6:8]==(2,0) and
         e[8]<8 and e[9]<2 and e[10]<9 and e[11]>0 and e[11]%4096==0 and e[12]>0 and e[13]>0 and
         e[14]==0x412200 and e[16:19]==(0,1,0) and not any(e[19:]),
         'actual second B/A bound snapshot has no entered, event or completion state')
    cursor=256
    for offset,size in intervals:
        prior.zero(raw[cursor:offset],'whole bound-only epoch padding');cursor=offset+size
    prior.zero(raw[cursor:],'whole bound-only trailing padding')
    members=[]
    for i in range(8):
        value=raw[v['epoch_member']+i*v['member']:v['epoch_member']+(i+1)*v['member']]
        if i<2:members.append(prior._member(value,prior.MEMBERS[1][i],e,v,image,backing_size,common))
        else:prior.zero(value,'whole unused bound-only member capacity')
    need(all(len({m[k]for m in members})==2 for k in('generation','binding','node','slot')) and
         e[8:10]==(members[0]['slot'],members[0]['bank']) and e[12]==members[0]['generation'] and
         e[15]==members[0]['layout'][0] and members[1]['raw']==first['members'][0]['raw'] and
         members[1]['key']==first['members'][0]['key'],'whole fresh B identity and retained A identity')
    proof=raw[v['epoch_bundle']:v['epoch_bundle']+v['bundle']]
    bundle=prior._bundle(proof,v,e,members,pid,app,binding)
    need(bundle['token']==h[9] and x[7]==owners['lcx_live'],'actual issued LCX bundle and exposed immutable live page')
    bound=prior._phase(raw[v['epoch_phase']:v['epoch_phase']+v['phase']],v,e,0,1,bundle,owners,descriptor)
    prior.zero(raw[v['epoch_phase']+v['phase']:v['epoch_phase']+4*v['phase']],
               'no entered, signal or completed phase after the ABA')
    for name in('entry','event','completion','side'):
        prior.zero(raw[v['epoch_'+name]:v['epoch_'+name]+v[name if name in('completion','side')else'frame']],
                   'no invented '+name+' in the ordinary bound-only wire')
    prior.zero(data[v['wire_epoch']+2*v['epoch']:v['wire']],'whole unused original epoch capacity')
    counts=[q(r,a['counts']+i*512,64)for i in range(3)]
    need(all(c[0]==sum(c[1:6]) and not any(c[49:])for c in counts) and
         all(all(left<=right for left,right in zip(before,after))for before,after in
             ((first['counts'][3],bound),(bound,counts[0]),(counts[0],counts[1]),(counts[1],counts[2]))),
         'all actual observation work retained in monotonic event and owner counters')
    need(x[12]==x[13]==counts[0][10]==counts[1][10]==counts[2][10] and
         x[14]==x[15]==counts[0][11]==counts[1][11]==counts[2][11] and
         counts[0][:6]==counts[1][:6]==counts[2][:6] and
         counts[0][43:48]==counts[1][43:48]==counts[2][43:48] and
         counts[0][41]==counts[1][41]==0 and counts[2][41]==1,
         'no second entry, completion, signal, AUX open/close/recovery/retirement; actual abort poison retained')
    need(0<x[16]==q(raw,v['epoch_phase']+11*8)[0]==x[19]==x[20]==x[37] and x[17]==x[16]+1 and x[18]==x[16]+2==x[36] and
         x[21]+2==x[22] and x[23:28]==(0,0,1,0,0) and
         counts[0][48]==x[21] and counts[1][48]==x[22] and counts[2][48]==x[22]+1,
         'two actual RAW transitions retire the issued proof; unchanged abort adds its actual code-R transition')
    queries=[r[a['query']+i*296:a['query']+(i+1)*296]for i in range(3)]
    for query,prot in zip(queries,(1,3,1),strict=True):descriptor._query(query,x[7],4096,prot)
    acquisition,handler,epoch=q(queries[0],128,3)
    need(all(q(query,128,3)==(acquisition,handler,epoch+i) and prior.u(query,152,2)==(4,0)
             for i,query in enumerate(queries)),
         'same actual handler/acquisition, with each real mprotect advancing the maintained maps epoch')
    pages=[r[a['page']+i*4096:a['page']+(i+1)*4096]for i in range(3)]
    need(pages[0]==proof[:4096] and pages[2]==pages[0] and pages[1][0]==pages[0][0]^1 and
         pages[1][1:]==pages[0][1:] and pages[0][0]==x[10] and pages[1][0]==x[11],
         'whole actual before, changed and restored page bytes; restoration grants no proof authority')
    prior.zero(r[a['page']+12288:a['before']],'whole causal frame alignment padding')
    frame=prior._frame(r[a['before']:],v,e,app,native,model,5,False,0x410207,common)
    return dict(epochs=1,bound_only_epochs=1,preentry_native_state_equal=True,preentry_pc=frame['pc'],
        native_pair=None,actual_refusals=1,actual_restorations=1,raw_controls=1,
        whole_record_sha256=hashlib.sha256(data).hexdigest(),qualification_credit=False,
        performance_credit=False,completed_application=False,scope='one real live-proof ABA refusal only')

def control_sites(v,a):
    base=v['wire']+64;epoch=v['wire_epoch']+v['epoch']
    return [('owner_failure',24*8),('failure_detail',25*8),('completed_epochs',16*8),
        ('sink_inode',264),('record_version',base+8),('record_complete',base+32),
        ('raw_target',base+7*8),('raw_result',base+23*8),('issued_epoch',base+20*8),
        ('restored_epoch',base+18*8),('entries',base+13*8),('completions',base+15*8),
        ('predicate_refusal',base+26*8),('before_bytes',base+a['page']),
        ('changed_bytes',base+a['page']+4096),('restored_bytes',base+a['page']+8192),
        ('query_before',base+a['query']),('query_writable',base+a['query']+296),
        ('query_restored',base+a['query']+592),('preentry_gpr',base+a['before']+v['frame_step']),
        ('preentry_fp',base+a['before']+v['frame_step']+v['step_fp']+160),
        ('first_event_fp',v['wire_epoch']+v['epoch_event']+v['frame_step']+v['step_fp']+160),
        ('bound_claim',epoch+8),('absent_completion',epoch+v['epoch_completion']),
        ('bound_source',epoch+v['epoch_member']+96),('bound_route',epoch+v['epoch_bundle']+v['bundle_route']),
        ('bound_directory',epoch+v['epoch_bundle']+v['bundle_directory']),
        ('footer',base+a['record']+48)]

CONTROL_COUNT=28
PHASE_CONTROL_COUNT=3
BACKING_CONTROL_COUNT=8

def controls(data,*args,**kw):
    original=read(data,*args,**kw);v=kw['layout'];a=kw['aba_layout'];refused=[];phase=[];backing=[]
    def reject(name,changed,target,**overrides):
        need(bytes(changed)!=data or overrides,'distinct supplied causal corruption')
        try:read(bytes(changed),*args,**dict(kw,**overrides))
        except ValueError:target.append(name)
        else:raise ValueError('accepted actual ABA corruption '+name)
    sites=control_sites(v,a);need(len(sites)==CONTROL_COUNT and len({offset for _,offset in sites})==CONTROL_COUNT,
                                'literal distinct ABA control roster')
    for name,offset in sites:
        changed=bytearray(data);changed[offset]^=1;reject(name,changed,refused)
    for stage in range(3):
        changed=bytearray(data);at=v['wire']+64+a['counts']+stage*512
        for word in(0,2):struct.pack_into('<Q',changed,at+word*8,q(changed,at+word*8)[0]+1)
        reject('extra_signal_stage'+str(stage),changed,phase)
    for i,number in enumerate((1,2)):
        for member in range(number):
            for page in range(2):
                at=v['wire_epoch']+i*v['epoch']+v['epoch_member']+member*v['member']+96+8+page*4376+104+72
                changed=bytearray(data);struct.pack_into('<Q',changed,at,q(data,at)[0]+1)
                reject(f'epoch{i}_member{member}_page{page}',changed,backing)
    image=args[2]
    need(image['bytes']!=kw['backing_size'],'original ELF differs from sealed actual carrier')
    for name,size in(('original_ELF',image['bytes']),('wrong_carrier',kw['backing_size']+1)):
        reject(name,data,backing,backing_size=size)
    need(len(phase)==PHASE_CONTROL_COUNT and len(backing)==BACKING_CONTROL_COUNT,'all separate causal phase/backing controls')
    return dict(original_sha256=original['whole_record_sha256'],refusals=refused,phase_refusals=phase,
                backing_refusals=backing,native_operations=0)

def configured(prior,common,descriptor):
    deps=(prior,common,descriptor)
    return SimpleNamespace(q=q,read=partial(read,dependencies=deps),controls=partial(controls,dependencies=deps),
        terminal_observation=terminal_observation,CONTROL_COUNT=CONTROL_COUNT,
        PHASE_CONTROL_COUNT=PHASE_CONTROL_COUNT,BACKING_CONTROL_COUNT=BACKING_CONTROL_COUNT)
