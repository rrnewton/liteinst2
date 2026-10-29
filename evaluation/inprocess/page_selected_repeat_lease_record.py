"""Strict actual REP lease records. Full frames use unchanged native comparators.

No frame base is inferred from a selector/ucontext. FS/GS are actual no-borrow
outer observations; the per-TRACE snapshots make no base observation syscall.
"""
import struct
from page_selected import need
from page_selected_maps_record import unpack as original_unpack
from page_selected_chain_record import REGS,TF,RF,u,frame,equal_state,live,startup,query
from page_selected_trace_run_record import snapshot,uc_edit,zero,release

MASK=(1<<64)-1
ERRORS=[7,7,8,7,8,8,220,221,221,221,222,222,222,224,12,13,204,220]
REGISTRATION=('initialized','registered','held','phase','pid','tid','address','page','length','signature',
              'epoch','fs_base','gs_base','fs_result','gs_result','tls_attempted','tls_complete','data')


def retained_layout(node):
    """Retain all union bytes; preserve independent actual DWARF members in layout.

    No union interpretation supplies acceptance. Complete actual owner siginfo
    bytes join the separately captured genuine signal object below.
    """
    kind=node['kind']
    if kind=='union':
        need(set(node)=={'kind','bytes','fields'}and 0<node['bytes']<=65536 and node['fields'],
             'whole nonempty actual union extent and typed member catalogue')
        names=[]
        for member in node['fields']:
            need(set(member)=={'name','offset','type'}and member['offset']==0 and
                 0<member['type']['bytes']<=node['bytes'],'actual union member offset/complete extent')
            names.append(member['name']);retained_layout(member['type'])
        need(len(names)==len(set(names)),'unique actual union member names')
        return dict(kind='array',bytes=node['bytes'],count=node['bytes'],element=dict(kind='scalar',bytes=1,signed=False))
    if kind=='struct':return dict(node,fields=[dict(x,type=retained_layout(x['type']))for x in node['fields']])
    if kind=='array':return dict(node,element=retained_layout(node['element']))
    return node


def unpack(data,node,offset=0):return original_unpack(data,retained_layout(node),offset)


def position(layout,path):
    node=layout['rl'];at=0
    for key in path:
        if isinstance(key,str):
            found=[x for x in node['fields']if x['name']==key]
            need(len(found)==1,'unique actual DWARF field');at+=found[0]['offset'];node=found[0]['type']
        else:
            need(node['kind']=='array'and 0<=key<node['count'],'actual array member')
            at+=key*node['element']['bytes'];node=node['element']
    return at,node['bytes']


def raw(data,layout,path):
    at,n=position(layout,path);need(0<=at<=len(data)-n,'complete actual raw extent');return data[at:at+n]


def snap(s,layout):
    snapshot(s,layout)
    need(len(s['extra'])==12288 and len(s['selectors'])==6 and
         s['selectors'][0]==u(s['state']['frame']['greg'][18])&0xffff and
         s['selectors'][1]==u(s['state']['frame']['greg'][18])>>48 and
         s['state']['fs']==s['state']['gs']==0,'whole additional memory/selectors; no invented frame base facts')


def same(a,b):
    equal_state(a['state'],b['state'])
    need(a['extra']==b['extra'] and a['selectors']==b['selectors'],'all four data pages and all selectors')


def unchanged(a,b,layout,flags):
    snap(a,layout);snap(b,layout);uc_edit(a,b,layout,17,flags)
    need(a['extra']==b['extra'] and a['selectors']==b['selectors'],'complete post-helper additional state')


def event(s,kind,pc,flags,layout,cr2):
    snap(s,layout);g=s['state']['frame']['greg']
    need(s['error']==0 and u(g[16])==pc and u(g[17])==flags and u(g[22])==cr2,
         'exact original PC, whole flags and actual CR2')
    if kind=='nx':need((s['signal'],s['code'],s['address'])==(11,2,pc) and g[19:21]==[21,14],
                        'genuine NX original-PC event')
    elif kind=='trace':need((s['signal'],s['code'],s['address'])==(5,2,pc) and g[19:21]==[0,1],
                           'genuine CPU TRACE, not caller-supplied trap')
    else:need(kind=='int3' and (s['signal'],s['code'],s['address'])==(5,128,0) and g[19:21]==[0,3],
              'literal source-bound native INT3 endpoint')


def model(c,s,b,progress):
    need(type(progress)is int and 0<=progress<=c['count'],'bounded actual architectural progress')
    want=list(c['seed']);want[1]-=progress
    want[7]=u(want[7]+(-1 if c['direction'] else 1)*c['width']*progress)
    need([u(s['state']['frame']['greg'][x])for x in REGS]==want,
         'independent literal STOS effect on all sixteen registers')
    memory=bytearray(b['state']['data']+b['extra']);base=c['data_address'];width=c['width']
    for j in range(progress):
        at=c['seed'][7]+(-1 if c['direction'] else 1)*width*j-base
        need(0<=at<=len(memory)-width,'literal expected store within complete retained data')
        memory[at:at+width]=(c['seed'][0]&((1<<(width*8))-1)).to_bytes(width,'little')
    need(s['state']['data']+s['extra']==memory and s['state']['stack']==b['state']['stack'],
         'whole untouched target stack and literal stores across all four data pages')
    a,z=s['state']['frame'],b['state']['frame']
    need(a['fp_bytes']==z['fp_bytes'] and a['fp']==z['fp'] and a['mask']==z['mask'] and
         a['greg'][18]==z['greg'][18] and s['selectors']==b['selectors'],
         'full initialized kernel FP/tail, application mask and selectors preserved')


def backing(b,p):
    if p['backing']==2:
        need(b['retained_fd']==-1 and zero({k:v for k,v in b.items()if k!='retained_fd'}),
             'actual anonymous backing has fd minus one and no sealed-file observations');return
    need(p['backing']==1 and b['retained_fd']>=0 and b['seals_observed']==b['stat_observed']==1 and
         b['seals']==15 and b['stat_result']==0 and b['stat']['st_size']==16384 and
         b['stat']['st_mode']&0xf000==0x8000 and b['stat']['st_ino']>0,
         'actual retained immutable regular file and complete seal/stat results')
    need(p['vma_inode']==b['stat']['st_ino'],'real mapped inode matches retained descriptor')


def stable_backing(a,b):
    need(all(a[k]==b[k]for k in ('retained_fd','seals','stat_result','seals_observed','stat_observed')) and
         all(a['stat'][k]==b['stat'][k]for k in ('st_dev','st_ino','st_size','st_mode')),
         'stable complete backing identity; timestamp payload is not authority')


def view(v,c,r):
    length=15 if c['geometry']in(2,3) else (2 if c['width']==4 else 3)
    pages=2 if c['geometry']in(2,3) else 1;start=c['pc']&~4095
    need((v['pc'],v['length'],v['page_count'],v['pid'],v['tid'],v['identity_observed'])==
         (c['pc'],length,pages,r['pid'],r['pid'],1) and
         all(v[x]>0 for x in ('bytes_address','pages_address','backing_address')),
         'actual complete original source view and singleton identity')
    need(v['bytes']==r['literal'][c['pc']-c['mapping']:c['pc']-c['mapping']+length]+bytes(15-length),
         'entire actual borrowed window including following bytes and zero unused tail')
    p=v['progress'];need(p['held']==p['complete']==p['identity_observed']==1 and
         p['first_error']==p['first_detail']==0 and p['pages_copied']==pages and
         p['bytes_copied']==length and p['sequence']==v['ref']['sequence']>0 and v['ref']['owner']>0,
         'genuine fresh completed held borrow, never a supplied descriptor')
    need(p['validation_calls']==0 and p['last_backing_observed']==0 and v['last_backing_address']==0 and
         zero(v['last_backing']),'fresh preparation honestly has no later validation backing observation')
    for i,page in enumerate(v['pages']):
        if i>=pages:need(zero(page)and zero(v['backing'][i]),'unused source rows zero');continue
        address=start+4096*i;offset=4096+address-c['mapping']
        need(page['address']==address and page['allocation']>0 and page['generation']>0 and
             page['logical']==5 and page['closed_prot']==1 and page['backing']==(2 if r['mode']==8 else 1) and
             page['vma_first']<=address<address+4096<=page['vma_end'],
             'each current owned logical RX / actual R page and exact generation')
        if r['mode']!=8:
            need(page['offset']==offset and page['vma_offset']+address-page['vma_first']==offset,
                 'actual mapped sealed-file offset for each page')
        backing(v['backing'][i],page)
    if pages==2:need(v['pages'][0]['allocation']==v['pages'][1]['allocation'],
                     'two borrowed pages from one actual managed allocation')


def permission(p):
    need(all(p[k]==1 for k in ('attempted','complete','validate_attempted','sync_attempted')) and
         all(p[k]==0 for k in ('result','validate_result','sync_result')),
         'real native mprotect/full validation/synchronization success')


def request(p,c,mutated=False):
    q=p['request'];pages=2 if c['geometry']==2 else 1
    need(q['decoded']==c['decoded'] and q['original_flags']==c['flags'] and q['page_count']==pages,
         'whole real source-bound decoded request and original flags')
    for i,x in enumerate(q['pages']):
        if i>=pages:need(zero(x),'unused owner page zero');continue
        v=c['view'][1]['pages'][i]
        need(x==dict(address=v['address'],object=v['allocation'],generation=v['generation']+int(mutated and i==0),
                     offset=v['offset'],closed_prot=1,open_prot=5),'exact owner/allocation/source page join')
    need(p['session']>0 and all(p['hooks'][k]>0 for k in ('context','authenticate','failure')),
         'actual installed session and authentication/cleanup hooks')


def io(p,pages,opened,closed):
    expected=[int(i<pages)for i in range(2)]
    need(p['open_started']==p['opened']==(expected if opened else [0,0]) and
         p['revoke_started']==p['revoked']==(expected if closed else [0,0]) and
         p['open_result']==p['revoke_result']==[0,0] and p['open_sync']==p['revoke_sync']==0 and
         p['revoke_sync_started']==int(closed),'exact performed page permission/close prefixes')


def owner_context(data,layout,path,o,s,name):
    need(o[name+'_frame_address']==s['uc_address'] and raw(data,layout,path+(name+'_context',))==s['uc'],
         'full actual owner-retained ucontext and its genuine handler address')


def custody(x,c,phase,event_number,closed=False):
    need(x['initialized']==1 and x['phase']==phase and x['first_error']==x['first_detail']==0 and
         x['bound']==int(not closed) and x['ticket']==int(not closed) and x['reset_ready']==0 and
         x['attempt']==c['index']+1 and x['closed']==c['index']+int(closed) and
         x['event']==event_number and x['borrow_sequence']==c['view'][1]['ref']['sequence'] and
         x['page']==c['view'][1]['pages'][0] and x['seeds']==c['index']+1,
         'real custody phase/ticket/event and exact same borrowed source')
    total=c['first_event']+event_number
    validations=total-int(phase==6)
    returns=total+int(phase==5)
    need(x['entries']==total and x['validations']==validations and x['returns']==returns and
         x['epoch']==x['seeds']+x['closed']+x['invalidations'] and
         (not closed or x['last_reason']==3),'all actual seed/event/validation/return/epoch counters')
    backing(x['seed_backing'],x['page']);backing(x['last_backing'],x['page'])
    stable_backing(x['seed_backing'],x['last_backing'])
    v=x['cold_maps'];need(v['opened']==v['close_started']==v['closed']==1 and
         v['close_result']==v['last_read']==0 and v['rows']>0 and v['bytes']>0 and
         v['observation']['kind']==v['observation']['io_performed']==1 and
         v['observation']['acquisition_id']>0,'one actual fresh RX maps acquisition at cold seed')


def write_guard(o,c,remaining,at):
    width=c['width'];size=remaining*width
    first=at-(size-width)if remaining and c['direction'] else at if remaining else 0
    need(o['write_first']==first and o['write_bytes']==size and
         o['write_query_attempted']==int(bool(remaining)) and o['write_result']==0,
         'actual complete remaining write span, including zero-count no-query')


def registration(o,r,mutated=False):
    want={k:r['registration_before'][k]for k in REGISTRATION}
    if mutated:want['epoch']+=1
    need(o['registration']==want,'whole actual owner registration joins the independent kernel pin snapshot')


def old_custody(x):
    need(x['initialized']==1 and zero({k:v for k,v in x.items()if k!='initialized'}),
         'legacy fallback performed no lease phase, ticket, seed, epoch or publication work')


def identity_owner(o,anchor,c):
    p=o['step'];a=anchor['step']
    need(p['before']==c['before'][1]['state']['frame'] and p['session']==a['session'] and
         p['hooks']==a['hooks'] and o['hooks']==anchor['hooks'] and o['hooks']['step']==p['hooks'] and
         o['hooks']['continue_closed']>0,'full original NX frame and exact installed owner/session/callback continuity')


def cold(r,c,data,layout,returned=True):
    if not c['eligible']:
        need(zero(c['begun'])and zero(c['cold_returned'])and zero(c['custody_begin'])and zero(c['custody_ready']),
             'legacy fallback cannot fabricate retained lease observations')
        o=c['old_begun'];p=o['step'];request(p,c);io(p,2 if c['geometry']==2 else 1,True,False)
        need(p['phase']==3 and not p['first_error'] and p['before']==c['before'][1]['state']['frame'] and
             c['fallback_rseq_attempted']==1 and c['fallback_rseq_result']==0,
             'actual old fallback opening follows genuine initial rseq guard')
        a,b=c['fallback_rseq_before'],c['fallback_rseq_after']
        need(all(a[k]==b[k]for k in REGISTRATION)and b['repeat_checks']==a['repeat_checks']+1 and
             b['first_error']==0,'fallback retained exact pin and performed one real REP write guard')
    else:
        need(zero(c['old_begun'])and not c['fallback_rseq_attempted'] and not c['fallback_rseq_result'] and
             zero(c['fallback_rseq_before'])and zero(c['fallback_rseq_after']),
             'new owner guard is distinct from the old outer fallback guard')
        o=c['begun'];p=o['repeat']['step'];request(p,c);io(p,1,True,False);registration(o,r)
        need(p['phase']==3 and p['in_handler']==0 and p['first_error']==0 and p['trace_seen']==0 and
             p['before']==c['before'][1]['state']['frame'] and o['begin_checked']==o['cold_seeded']==
             o['borrow_held']==o['return_pending']==1 and o['handler_returned']==0 and
             o['rseq_checks']==o['write_checks']==2 and o['attempts']==c['index']+1 and o['completed']==c['index'] and
             o['borrow']==c['view'][1]['ref'],'real cold opening and two live owner guards')
        write_guard(o,c,c['count'],c['seed'][7]);owner_context(data,layout,('row',c['index'],'begun'),o,c['before'][1],'entry')
        owner_context(data,layout,('row',c['index'],'begun'),o,c['cold'],'return')
        custody(c['custody_begin'],c,4,0)
        if returned:
            custody(c['custody_ready'],c,5,0)
            need(c['custody_ready']==dict(c['custody_begin'],phase=5,returns=c['custody_begin']['returns']+1),
                 'actual handler_end consumes only its cold return ticket')
            unchanged(c['cold'],c['cold_returned'],layout['frame'],c['flags']|RF|TF)
        else:
            need(r['mode']==16 and zero(c['custody_ready'])and zero(c['cold_returned']),
                 'real nested RETURN stops before the unperformed cold handler_end')
    unchanged(c['before'][1],c['cold'],layout['frame'],c['flags']|RF|TF)


def trace_prefix(r,c,e,j,layout):
    final=e['remaining']==0;progress=c['count']-e['remaining'];pc=c['next_pc']if final else c['pc']
    need(e['case_index']==c['index'] and e['old_route']==int(not c['eligible']) and
         e['progress']==progress and e['final']==int(final),'literal event identity/progress projection')
    event(e['before'],'trace',pc,c['flags']|TF|(0 if final else RF),layout,c['pc'])
    model(c,e['before'],c['before'][1],progress)
    if c['eligible']:
        custody(e['custody_before'],c,6,j+1)
        prior=c['custody_ready']if j==0 else r['event'][c['first_event']+j-1]['custody_returned']
        need(e['custody_before']==dict(prior,phase=6,event=j+1,entries=prior['entries']+1),
             'actual READY ticket consumed once with no epoch/source/backing mutation')
    else:need(not e['custody_before']['bound']and not e['custody_before']['ticket'],
              'fallback has no retained lease ticket')


def trace_complete(r,c,e,j,layout):
    trace_prefix(r,c,e,j,layout['frame']);final=e['final'];o=e['owner'];p=o['repeat']['step'];q=o['repeat']
    need(e['checked']==1 and p['phase']==(5 if final else 3) and p['first_error']==p['first_detail']==p['in_handler']==0 and
         p['trace_seen']==1 and p['after']==e['before']['state']['frame'] and q['traces']==j+1 and
         q['initial_count']==c['count'] and q['remaining']==e['remaining'] and q['final']==final and
         q['actual_post_pc']==(c['next_pc']if final else c['pc']) and
         q['actual_post_flags']==c['flags']|TF|(0 if final else RF),'actual completed TRACE owner and complete saved frame')
    request(p,c);identity_owner(q,c['begun']['repeat']if c['eligible']else c['old_begun'],c)
    unchanged(e['before'],e['after'],layout['frame'],c['flags']if final else c['flags']|TF|RF)
    need(e['fetch']['sequence']==c['view'][1]['ref']['sequence'] and not e['fetch']['first_error'],
         'same original fetch sequence for every actual TRACE')
    if c['eligible']:
        registration(o,r);io(p,1,True,bool(final));write_guard(o,c,e['remaining'],u(e['before']['state']['frame']['greg'][8]))
        need(o['rseq_checks']==o['write_checks']==j+3 and q['closed_cycles']==final and q['reopened_cycles']==0 and
             o['retained_transfers']==j+1-final and o['borrow_held']==1-final and
             o['return_pending']==1-final and o['close_started']==o['close_complete']==
             o['release_started']==o['release_complete']==final and
             o['custody_result']==o['rseq_result']==o['release_result']==0 and o['borrow']==c['view'][1]['ref'],
             'retained RX preserves borrow until the one actual final close/release')
        custody(e['custody_after'],c,0 if final else 4,j+1,bool(final))
        before,after=e['custody_before'],e['custody_after']
        need(after['cold_maps']==before['cold_maps'] and after['seed_backing']==before['seed_backing'] and
             (final or all(after[k]==before[k]for k in ('epoch','invalidations','last_reason'))),
             'retained work does not invalidate/reseed its ticket or replace cold acquisition')
        need(e['continuation_calls']==final,'closed continuation only after actual final TRACE')
        if final:
            release(e['fetch'],c['view'][1]['ref']['sequence'])
            need(zero(e['returned'])and zero(e['custody_returned']),'no invented final handler_end after released completion')
        else:
            need(e['fetch']['held']==1,'intermediate borrow still held')
            unchanged(e['after'],e['returned'],layout['frame'],c['flags']|TF|RF)
            custody(e['custody_returned'],c,5,j+1)
            need(e['custody_returned']==dict(e['custody_after'],phase=5,returns=e['custody_after']['returns']+1),
                 'genuine post-helper return capture and once-only ticket')
    else:
        need(q['closed_cycles']==j+1 and q['reopened_cycles']==j+1-final and e['fetch']['held']==1 and
             e['continuation_calls']==1 and zero(e['returned'])and zero(e['custody_returned']),
             'old fallback still closes/reopens on every TRACE and keeps its old caller-owned borrow')
        io(q['last_closed'],2 if c['geometry']==2 else 1,True,True)
        need(zero({k:v for k,v in o.items()if k!='repeat'}),'legacy event carries no invented new lease owner')
        old_custody(e['custody_before']);old_custody(e['custody_after'])
    if e['continuation_calls']:
        need(e['continuation_result']==0,'actual continuation callback success');query(e['continuation'],c['next_pc']if final else c['pc'])
    else:need(zero(e['continuation'])and e['continuation_result']==0,'no premature closed query fabricated')


def case_shape(r,c,i):
    m=r['mode'];c=dict(c,index=i,data_address=r['data_address'])
    if m<8:width=4 if m//2<2 else 8;direction=(m//2)%2;count=24 if m&1 else (0,1,3)[i]
    elif m<12:width=8 if i else 4;direction=i;count=3
    elif m<14:width=4 if m==12 else 8;direction=int(m==13);count=24
    elif m>=30:k=(m-30)%8;width=4 if k<4 else 8;direction=(k//2)%2;count=3
    else:width=8;direction=0;count=3
    geometry=2 if m==9 else 3 if m==10 else 1 if m==8 else 0
    n=2 if width==4 else 3;pc=c['mapping']+(4096 if width==4 else 8192)-n+int(geometry==2)
    need((c['width'],c['direction'],c['count'],c['geometry'],c['pc'],c['next_pc'],c['flags'])==
         (width,direction,count,geometry,pc,pc+n,0x247|(0x400 if direction else 0)) and
         c['mapping']>0 and c['mapping']%4096==0 and c['started']==1 and c['phase']==0,
         'fixed literal width/direction/count/source geometry, no table-supplied acceptance')
    seed=[u(0x123456789abcdef+0x101010101010101*j)for j in range(16)]
    seed[0]=0x0123456789abcdef;seed[1]=count;seed[4]=r['subject_address']+4096
    seed[6]=r['data_address']+1024;seed[7]=r['data_address']+512
    if m in(12,13):seed[7]=r['data_address']+4096+(2*width if direction else -3*width)
    if m==24:seed[7]=r['rseq_address']+8
    need(c['seed']==seed,'independent complete sixteen-register input seed')
    d=c['decoded'];length=15 if geometry in(2,3) else n
    need(d['abi_version']==1 and d['reserved']==0 and d['decode_status']==0 and d['kind']==0 and
         d['pc']==pc and d['next_pc']==pc+n and d['length']==n and d['available']==length and
         d['code']==(345 if width==4 else 346) and d['step_disposition']==0 and
         d['bytes']==r['literal'][pc-c['mapping']:pc-c['mapping']+length]+bytes(16-length),
         'independent exact REP decode and full borrowed bytes; ordinary TF remains unsupported')
    f=c['refused'];need(f['abi_version']==1 and f['pc']==pc and f['policy']==f['family']==f['flow']==0,
                        'original ordinary-TF refusal retained')
    need(c['eligible']==int(not 8<=m<=10),'actual valid unsupported fallback is separate from a lease')
    for lane in ((0,1)if m<14 else (1,)):
        view(c['view'][lane],c,r)
        b=c['bases'][lane][0];need(b['attempted']==b['complete']==1 and b['fs_result']==b['gs_result']==0 and
             b['fetch']['held']==0,'real no-borrow pre-entry FS/GS observations')
        if lane==0 or m<12:
            end=c['bases'][lane][1];need(end['attempted']==end['complete']==1 and
                 end['fs_result']==end['gs_result']==0 and end['fetch']['held']==0 and
                 (b['fs'],b['gs'])==(end['fs'],end['gs']),'actual post-release bases match before invocation')
            release(c['released'][lane],c['view'][lane]['ref']['sequence'])
        else:need(zero(c['bases'][lane][1])and zero(c['released'][lane]),'terminal failed lane has no fabricated outer return')
    if m<14:
        first=c['bases'][0][0]
        need(all((x['fs'],x['gs'])==(first['fs'],first['gs'])for x in
                 (c['bases'][0][1],c['bases'][1][0])),
             'actual native/gated empty-borrow FS/GS bases equal, including failed gated pre-entry')
        need(c['view'][0]['ref']['owner']==c['view'][1]['ref']['owner'] and
             c['view'][0]['ref']['sequence']<c['view'][1]['ref']['sequence'] and
             c['view'][0]['pages']==c['view'][1]['pages'],'same source mapping with fresh ordered native/owner borrows')
    return c


def initial(c,s,r,layout):
    event(s,'nx',c['pc'],c['flags']|RF,layout,c['pc'])
    need([u(s['state']['frame']['greg'][x])for x in REGS]==c['seed'] and
         s['state']['stack']==bytes((j*29+11)&255 for j in range(8192)) and
         s['state']['data']+s['extra']==bytes((j*17+3)&255 for j in range(16384)),
         'full actual initial architectural state and four-page literal data seed')
    expected_mask=MASK&~sum(1<<(sig-1)for sig in(5,9,11,19,31))
    need(s['state']['frame']['mask']==expected_mask,'unchanged original three-handler signal mask')


def native(c,r,layout):
    initial(c,c['before'][0],r,layout);permission(c['open'][0]);permission(c['close'][0])
    after=c['after'][0]
    if r['mode']in(12,13):
        address=c['seed'][7]+(-1 if c['direction']else 1)*3*c['width']
        snap(after,layout);g=after['state']['frame']['greg']
        need((after['signal'],after['code'],after['error'],after['address'])==(11,2,0,address) and
             u(g[16])==c['pc'] and u(g[17])==c['flags']|RF and g[19:21]==[7,14] and u(g[22])==address and
             c['native_fault']==1 and c['native_completed']==0,
             'genuine later native write fault after three actual completed stores')
        model(c,after,c['before'][0],3)
    else:
        cross=c['geometry']==2
        event(after,'int3'if cross else 'nx',c['next_pc']+int(cross),c['flags']|(0 if cross else RF),
              layout,c['pc']if cross else c['next_pc'])
        model(c,after,c['before'][0],c['count'])
        need(c['native_completed']==1 and c['native_fault']==0,'actual full native instruction interval')
    lane=dict(before=c['before'][0]['state'],after=after['state'],live=c['live'][:2],fp=c['fp'][:2])
    live(lane,lane,[c['flags'],c['flags']],r['xsave_bytes'])


def finished(c,r,data,layout):
    initial(c,c['before'][1],r,layout['frame']);same(c['before'][0],c['before'][1]);cold(r,c,data,layout)
    need(c['checked']==c['endpoint_seen']==1 and 1<=c['event_count']<=max(1,c['count']),
         'complete actual original endpoint and bounded real TRACE count')
    prior=0
    for j,e in enumerate(r['event'][c['first_event']:c['first_event']+c['event_count']]):
        trace_complete(r,c,e,j,layout)
        need((c['count']==0 and j==0 and e['progress']==0)or c['count']>0 and e['progress']>prior,
             'strict observed hardware progress, not a required one-trap-per-element assumption')
        need(bool(e['final'])==(j+1==c['event_count']),'only last observed TRACE is final');prior=e['progress']
    need(prior==c['count'],'all requested stores actually completed')
    event(c['after'][1],'nx',c['next_pc'],c['flags']|RF,layout['frame'],c['next_pc'])
    model(c,c['after'][1],c['before'][1],c['count']);same(c['after'][0],c['after'][1])
    for k in(0,1):
        a,b=c['before'][0]if k==0 else c['after'][0],c['before'][1]if k==0 else c['after'][1]
        for index in range(23):
            if k and c['geometry']==2 and index in(16,17,19,20,22):continue
            need(a['state']['frame']['greg'][index]==b['state']['frame']['greg'][index],
                 'all native/kernel greg fields equal outside independently checked endpoint-event distinction')
    gated=dict(before=c['before'][1]['state'],after=c['after'][1]['state'],live=c['live'][2:],fp=c['fp'][2:])
    reference=dict(live=c['live'][:2],fp=c['fp'][:2]);live(gated,reference,[c['flags'],c['flags']],r['xsave_bytes'])
    if c['eligible']:
        o=c['finished'];p=o['repeat']['step'];last=r['event'][c['first_event']+c['event_count']-1]
        registration(o,r);identity_owner(o['repeat'],c['begun']['repeat'],c)
        need(o['repeat']==last['owner']['repeat'] and p['phase']==5 and not p['first_error'] and
             o['completed']==o['attempts']==c['index']+1 and o['total_closes']==o['total_releases']==o['completed'] and
             o['total_traces']==c['first_event']+c['event_count'] and
             o['total_retained']==o['total_traces']-o['completed'] and
             o['retained_transfers']==c['event_count']-1 and (c['count']!=24 or o['retained_transfers']>0) and
             all(o[k]==0 for k in ('borrow_held','return_pending','failure_started','unexpected_observed','nested_observed',
                                  'custody_result','rseq_result','release_result','write_first','write_bytes','write_query_attempted','write_result')),
             'one completed/released real lease; long case actually retained RX across a TRACE')
        for key in('close_started','close_complete','release_started','release_complete','begin_checked','cold_seeded'):
            need(o[key]==1,'complete actual final lease prefix')
        owner_context(data,layout,('row',c['index'],'finished'),o,c['before'][1],'entry')
        owner_context(data,layout,('row',c['index'],'finished'),o,last['before'],'trace')
        owner_context(data,layout,('row',c['index'],'finished'),o,last['after'],'return')
        custody(c['custody_finished'],c,0,c['event_count'],True)
    else:
        old_custody(c['custody_finished'])
        q=c['old_finished'];need(q==r['event'][c['first_event']+c['event_count']-1]['owner']['repeat'] and
             zero(c['finished'])and q['step']['phase']==5 and q['closed_cycles']==c['event_count'] and
             q['reopened_cycles']==c['event_count']-1 and not c['custody_finished']['bound'] and
             not c['custody_finished']['ticket'],'old fallback owner remains fully observed and unchanged')


def failure(r,c,data,layout):
    m=r['mode'];o=r['terminal'];p=o['repeat']['step'];error=ERRORS[m-12]if m<30 else 224 if(m-30)&1 else 225
    need(r['verified_failure']==1 and r['complete']==r['completed']==0 and r['owner_error']==error and
         p['phase']==6 and p['first_error']==error and o['failure_started']==1 and
         r['owner_detail_abs']==abs(p['first_detail']) and r['owner_detail_negative']==int(p['first_detail']<0) and
         o['completed']==0 and o['attempts']==1 and c['endpoint_seen']==c['checked']==0 and
         zero(c['after'][1])and zero(c['live'][2:])and zero(c['fp'][2:])and zero(c['finished'])and zero(c['old_finished']),
         'exact failed operation with actual cleanup prefix, never completion credit')
    need(r['source_equal']==1 and r['source_closed']==int(m!=26) and r['expected_source_pages']==1 and
         r['fetch']['held']==1 and r['fetch']['sequence']==o['borrow']['sequence']==c['view'][1]['ref']['sequence'] and
         r['custody']['phase']==8 and r['custody']['ticket']==0 and r['custody']['first_error']>0 and
         r['maps']['active']==r['maps']['valid']==r['maps']['poisoned']==0,
         'failed custody revoked its ticket and preserves actual held/cleanup/source state')
    request(p,c,m==20);registration(o,r,m==23)
    details={12:11,13:11,14:5,15:5,16:5,17:5,18:3,19:303,20:302,21:307,
             22:1209,23:1,24:1205,25:6,26:-22,27:-22,28:305,29:303}
    detail=details[m]if m<30 else (7 if c['direction']else 8)if(m-30)&1 else 1
    need(p['first_detail']==detail,'exact source-defined first failure detail, no accept-either contract')
    custody_errors={12:(7,11),13:(7,11),14:(303,18),15:(302,1),16:(302,1),17:(303,18),
                    18:(300,29),19:(303,2),20:(302,11),21:(307,13),22:(222,1209),23:(222,1),
                    24:(222,1205),25:(224,6),26:(302,4),27:(302,4),28:(204,305),29:(220,303)}
    need((r['custody']['first_error'],r['custody']['first_detail'])==
         (custody_errors[m]if m<30 else (error,detail)),
         'exact first custody failure preserves boundary/RAW ordering independently of owner error')
    writes=(r['events']+2 if m in(12,13,17,26,27,28,29)else 3 if m==25 else
            2 if m in(15,16,19)else 0 if m in(18,20,21)else 1)
    need(o['write_checks']==writes,'actual unconditional private-write guard call prefix')
    opened=m in(12,13,14,15,16,17,19,25,26,27,28,29)
    want=[int(opened),0]
    need(p['open_started']==p['opened']==want and p['open_result']==[0,0] and p['open_sync']==0 and
         p['revoke_started']==want and p['revoked']==([0,0]if m==26 else want) and
         p['revoke_result']==([-22,0]if m==26 else [0,0]) and p['revoke_sync_started']==1 and
         p['revoke_sync']==(-22 if m==27 else 0),
         'every actual attempted opening/revoke/sync, including nonissued failure injection')
    initial(c,c['before'][1],r,layout['frame'])
    if m<14:same(c['before'][0],c['before'][1])
    if m in(12,13,15,16,17,19,25,26,27,28,29):cold(r,c,data,layout,returned=m!=16)
    if m in(18,20,21):need(zero(p['before'])and zero(p['after']),'rejected before any owner frame capture')
    else:
        before=r['mutated']if m>=30 else c['before'][1]
        need(p['before']==before['state']['frame'],'entire actual initial owner frame survives every failure')
        owner_context(data,layout,('terminal',),o,before,'entry')
        if r['events']:need(p['after']==r['event'][r['events']-1]['before']['state']['frame'],
                           'last genuine TRACE frame survives cleanup and supplied later mutation')
        else:need(zero(p['after']),'no TRACE frame invented before a real owner TRACE')
    # Every completed prefix TRACE retains the same full comparison. The last
    # failed event has a real incoming frame but no invented helper return.
    failed_event=m in(17,19,25,26,27,28,29)
    for j,e in enumerate(r['event'][:r['events']]):
        if failed_event and j+1==r['events']:
            trace_prefix(r,c,e,j,layout['frame'])
            need(e['checked']==0 and zero(e['after'])and zero(e['returned'])and zero(e['owner'])and
                 zero(e['custody_after'])and zero(e['custody_returned']),
                 'last failed TRACE retains input only, not a fabricated helper completion')
        else:trace_complete(r,c,e,j,layout)
    need(c['event_count']==r['events'] and all(zero(x)for x in r['event'][r['events']:]),
         'exact real successful/failed TRACE population and zero unused records')
    if m in(12,13):
        s=r['delivered'];snap(s,layout['frame']);same(s,c['after'][0]);model(c,s,c['before'][1],3)
        g=s['state']['frame']['greg'];n=c['after'][0]['state']['frame']['greg']
        need((s['signal'],s['code'],s['error'],s['address'])==(11,2,0,c['after'][0]['address']) and
             all(g[i]==n[i]for i in range(23)if i!=17)and u(g[17])==u(n[17])|TF and
             o['unexpected_observed']==o['unexpected_info_complete']==o['unexpected_context_complete']==1 and
             o['nested_observed']==0 and o['unexpected_frame']==s['state']['frame'] and
             raw(data,layout,('terminal','unexpected_context'))==s['uc'] and
             raw(data,layout,('terminal','unexpected_info'))==s['si'] and r['events']>0 and o['retained_transfers']>0,
             'genuine later write fault matches native full frame/effects with only owned TF distinction')
    elif 14<=m<=17:
        s=r['delivered'];snap(s,layout['frame']);snap(r['outer'],layout['frame'])
        at,n=layout['frame']['sender_pid'];pid=int.from_bytes(s['si'][at:at+n],'little',signed=True)
        at,n=layout['frame']['sender_uid'];uid=int.from_bytes(s['si'][at:at+n],'little')
        name='unexpected'if m==15 else 'nested'
        need((s['signal'],s['code'],s['error'])==(5,-6,0)and pid==r['pid']and uid==r['uid'] and
             r['real_signals']==1 and r['nested_outer_observed']==1 and r['nested_site']==m-13 and
             r['nested_owner_phase']==(4 if m==17 else 3)and
             r['nested_custody_phase']=={14:2,15:6,16:4,17:7}[m] and
             o[name+'_observed']==o[name+'_info_complete']==o[name+'_context_complete']==1 and
             o[name+'_frame']==s['state']['frame'] and
             raw(data,layout,('terminal',name+'_context'))==s['uc'] and
             raw(data,layout,('terminal',name+'_info'))==s['si'],
             'source-phase proven real tgkill delivery and actual owner label/full raw incoming state')
        need(o['nested_observed']==int(m!=15)and o['unexpected_observed']==int(m==15),
             'pre-owner ENTRY is genuinely unexpected; never relabel it as owner nested')
        outer=r['outer']
        if m==14:
            unchanged(c['before'][1],outer,layout['frame'],c['flags']|RF|TF)
            need(p['before']==c['before'][1]['state']['frame']and o['begin_checked']==1 and o['cold_seeded']==0,
                 'real cold SEEDING interruption before the helper returns')
        elif m==15:
            remaining=u(outer['state']['frame']['greg'][14]);progress=c['count']-remaining
            need(0<progress<=c['count']and r['events']==0 and p['trace_seen']==0,
                 'actual outer TRACE reached the boundary before the owner consumed it')
            event(outer,'trace',c['pc']if remaining else c['next_pc'],c['flags']|TF|(RF if remaining else 0),
                  layout['frame'],c['pc']);model(c,outer,c['before'][1],progress)
        elif m==16:
            unchanged(c['before'][1],c['cold'],layout['frame'],c['flags']|RF|TF)
            unchanged(c['cold'],outer,layout['frame'],c['flags']|RF|TF)
            need(zero(c['cold_returned'])and o['return_pending']==1 and o['handler_returned']==0,
                 'real RETURN interruption retains exact outer frame before handler_end')
        else:
            last=r['event'][r['events']-1]['before']
            unchanged(last,outer,layout['frame'],c['flags']|TF)
            need(p['after']==last['state']['frame']and o['repeat']['final']==1 and o['close_started']==1,
                 'real final REVOKING interruption preserves the full proved outer TRACE')
        owner_context(data,layout,('terminal',),o,c['before'][1],'entry')
    else:
        need(zero(r['delivered'])and zero(r['outer'])and r['real_signals']==0 and r['supplied_mutations']==1,
             'supplied negative cannot acquire actual kernel fault/signal credit')
        if m==18:
            need(p['first_detail']==3 and r['clone']['repeat']['step']['phase']==1 and
                 r['clone']['borrow']==o['borrow']and zero(p['before'])and zero(p['after']),
                 'genuine armed-owner copy rejected without redirecting cleanup into the clone')
        if m==21:
            a,b=r['stat_actual'],r['stat_supplied'];need(b==dict(a,st_ino=a['st_ino']^1)and
                r['injection_issued']==r['injection_returned']==1 and r['injection_actual']==r['injection_result']==0,
                'actual fstat return followed by exact one-field supplied corruption')
        if m==22:need(r['injected_word']>0 and o['rseq_result']==1209 and r['registration_after']['first_error']==1209,
                       'actual nonzero pinned word rejected, no invented final kernel word')
        if m==23:need(o['registration']['epoch']==r['registration_before']['epoch']+1 and p['first_detail']==1,
                       'exact supplied owner pin epoch mutation rejected against real unchanged registration')
        if m==24:need(o['rseq_result']==1205 and r['registration_after']['first_error']==1205,
                       'actual dynamic rseq interval is separately protected')
        if m==25:
            last=r['event'][r['events']-1]['before']
            snap(r['mutated'],layout['frame']);uc_edit(last,r['mutated'],layout['frame'],14,MASK)
            need(p['first_detail']==6 and o['write_query_attempted']==0 and
                 r['mutated']['extra']==last['extra']and r['mutated']['selectors']==last['selectors'],
                 'exact supplied remaining-count multiplication overflow before any private query')
        if m>=30:
            snap(r['mutated'],layout['frame']);at=1 if c['direction']else MASK-1
            if not(m-30)&1:at=r['marker']+2 if c['direction']else r['marker']-2
            uc_edit(c['before'][1],r['mutated'],layout['frame'],8,at)
            need(r['span_supplied']==1 and r['mutated']['extra']==c['before'][1]['extra'] and
                 r['mutated']['selectors']==c['before'][1]['selectors'] and o['write_checks']==1 and o['rseq_checks']==0,
                 'exact supplied initial RDI only; unconditional private guard runs before registered guard')
            if(m-30)&1:
                need(o['write_query_attempted']==0 and o['write_first']==o['write_bytes']==0 and
                     p['first_detail']==(7 if c['direction']else 8),'DF underflow/end overflow before a private query')
            else:
                size=3*c['width'];first=at-(size-c['width'])if c['direction']else at
                need(o['write_query_attempted']==1 and o['write_first']==first and o['write_bytes']==size and
                     o['write_result']==1 and first<r['marker']<first+size<r['marker']+4096 and
                     r['private_first']==first and r['private_bytes']==size and r['private_result']==1,
                     'actual partial overlap, not a full-containment approximation')
    if m in(26,27,28,29):
        need(r['injection_attempted']==1 and r['injection_issued']==r['injection_returned']==0 and
             r['injection_result']==(-22 if m in(26,27)else 305 if m==28 else 303),
             'explicit nonissued RAW/query/release result injection, not a kernel failure')
    need(o['repeat']['traces']==o['total_traces']==r['events'] and
         o['retained_transfers']==o['total_retained']==r['events']-int(failed_event) and
         o['total_closes']==o['close_complete']==int(m in(28,29)) and
         o['close_started']==int(m in(17,26,27,28,29)),
         'exported failed-prefix totals equal actual TRACE/return/close commit points')
    need(o['release_complete']==0 and o['total_releases']==o['completed']==0,
         'no release/completion fabricated by expected-error label')


def private_queries(r,rows):
    expected=[];m=r['mode']
    def add(c,count,at,result=0):
        if count:
            size=count*c['width'];first=at-(size-c['width'])if c['direction']else at
            expected.append((first,size,result))
    for c in rows:
        if not c['eligible']:continue
        repeats=2 if m<14 or m in(15,16,17,19,25,26,27,28,29)else 1 if m in(14,22,23,24)else 0
        for unused in range(repeats):add(c,c['count'],c['seed'][7])
        for e in r['event'][c['first_event']:c['first_event']+c['event_count']]:
            if e['checked']:add(c,e['remaining'],u(e['before']['state']['frame']['greg'][8]))
        if m>=30 and not(m-30)&1:add(c,3,u(r['mutated']['state']['frame']['greg'][8]),1)
    need(r['private_queries']==len(expected),'actual fixed protected-range query count, including unregistered mode')
    need((r['private_first'],r['private_bytes'],r['private_result'])==(expected[-1]if expected else (0,0,0)),
         'actual final complete private overlap query and result')


def check(data,layout,mode,pid):
    need(type(mode)is int and 0<=mode<46 and set(layout)=={'rl','samples','frame'} and
         layout['samples']['kind']=='array'and layout['samples']['count']==21,'fixed 46-mode layout')
    size=layout['rl']['bytes'];need(len(data)==size+layout['samples']['element']['bytes']<16<<20,
                                  'whole exact bounded retained record and unchanged startup')
    r=unpack(data,layout['rl']);startup(unpack(data,layout['samples']['element'],size))
    need((r['magic'],r['version'],r['bytes'],r['mode'])==(0x31455341454c3252,1,size,mode) and
         r['pid']==r['tid']==pid>0 and 0<=r['uid']<=0xffffffff and r['first_error']==0 and
         r['old_refusals']==47 and r['startup_pairs']==1 and r['decoder']['phase']==2 and
         r['xcr0']&3==3 and 576<=r['xsave_bytes']<=65536,
         'actual child singleton, decoder, startup, all old refusal checks and hardware envelope')
    count=(1 if mode&1 else 3)if mode<8 else 2 if mode<12 else 1
    need(r['cases']==count and len(r['row'])==3 and len(r['event'])==24 and
         all(zero(x)for x in r['row'][count:])and 0<=r['events']<=24 and
         all(zero(x)for x in r['event'][r['events']:]),'fixed whole case/event storage and zero unused state')
    need(all(r[k]>0 and r[k]%4096==0 for k in ('subject_address','data_address','rseq_address'))and
         r['marker']==r['data_address']+12288,'actual disjoint application/private-marker geometry')
    header=bytearray(4096)
    struct.pack_into('<16sHHIQQQIHHHHHH',header,0,b'\x7fELF\x02\x01\x01'+bytes(9),3,62,1,0,64,0,0,64,56,2,0,0,0)
    struct.pack_into('<IIQQQQQQ',header,64,1,4,0,0,0,4096,4096,4096)
    struct.pack_into('<IIQQQQQQ',header,120,1,5,4096,4096,0,12288,12288,4096)
    literal=bytearray(b'\xcc'*12288)
    literal[4096-(1 if mode==9 else 2):4096-(1 if mode==9 else 2)+2]=bytes.fromhex('f3ab')
    literal[8192-(2 if mode==9 else 3):8192-(2 if mode==9 else 3)+3]=bytes.fromhex('f348ab')
    need(r['header']==header and r['literal']==literal,'entire independent sealed ELF header and all literal source pages')
    unregistered=mode==11 or mode>=38;a,b=r['registration_before'],r['registration_after']
    need(r['registered']==1 and r['unregistered']==int(unregistered)and a['initialized']==1 and
         a['registered']==a['held']==int(not unregistered)and a['phase']==(0 if unregistered else 3)and
         a['pid']==a['tid']==pid and a['address']==r['rseq_address'] and a['page']==r['rseq_address'] and
         a['length']==32 and a['signature']==0x53053053 and a['registrations']==1 and
         a['unregistrations']==int(unregistered)and a['calls']==1+int(unregistered)and a['kernel_errors']==0 and
         a['first_error']==0 and a['tls_attempted']==a['tls_complete']==1 and a['fs_result']==a['gs_result']==0,
         'actual kernel registration/unregistration and retained inactive pin, never a supplied Boolean')
    need(all(a[k]==b[k]for k in REGISTRATION)and
         b['first_error']==(1209 if mode==22 else 1205 if mode==24 else 0),
         'same actual registration identity through every outcome, with exact real guard failure')
    total=0;rows=[]
    for i,original in enumerate(r['row'][:count]):
        c=case_shape(r,original,i);rows.append(c)
        need(c['first_event']==total,'contiguous actual per-case TRACE window');total+=c['event_count']
        if mode<14:native(c,r,layout['frame'])
        else:
            need(zero(c['view'][0])and zero(c['bases'][0])and zero(c['before'][0])and zero(c['after'][0])and
                 zero(c['open'])and zero(c['close'])and zero(c['live'][:2])and zero(c['fp'][:2])and
                 c['native_completed']==c['native_fault']==0,'supplied/nested terminal process does not invent native execution')
        if mode<12:finished(c,r,data,layout)
    need(total==r['events'],'all actual event records belong to the declared case windows')
    if mode>=12:failure(r,rows[0],data,layout)
    private_queries(r,rows)
    guards=ranges=0
    if not unregistered:
        if mode<12:
            for c in rows:
                guards+=c['event_count']+2 if c['eligible']else 1
                ranges+=(2*int(c['count']>0)+c['event_count']-1)if c['eligible']else 1
        else:
            o=r['terminal']
            guards=(r['events']+2 if mode in(12,13,17,26,27,28,29)else 1 if mode in(14,24)else
                    2 if mode in(15,16,19,25)else 0)
            need(o['rseq_checks']==guards+int(mode==22),
                 'owner counter equals the exact actual failure boundary, not its asserted label')
            ranges=guards
            if mode in(17,26,27,28,29):ranges-=1  # final zero-RCX guard performs no span query
    need(b['instruction_checks']-a['instruction_checks']==guards and
         b['repeat_checks']-a['repeat_checks']==guards and b['range_checks']-a['range_checks']==ranges and
         all(b[k]==a[k]for k in ('run_checks','syscall_checks','calls','registrations','unregistrations','kernel_errors')),
         'actual global guard counters join every real registered owner/fallback call and zero-count exception')
    if mode<12:
        need(r['complete']==1 and r['completed']==r['native_completed']==count and r['native_faults']==0 and
             r['source_equal']==r['source_closed']==1 and r['expected_source_pages']==0 and
             all(r[k]==0 for k in ('verified_failure','owner_error','owner_detail_abs','owner_detail_negative','real_signals',
                 'supplied_mutations','injection_attempted','injection_issued','injection_returned','injection_actual','injection_result',
                 'nested_site','nested_owner_phase','nested_custody_phase','nested_outer_observed','span_supplied','injected_word'))and
             zero(r['clone'])and zero(r['delivered'])and zero(r['outer'])and zero(r['mutated'])and
             zero(r['stat_actual'])and zero(r['stat_supplied']),'complete cohort has no hidden failed/injected/nested prefix')
        release(r['fetch'],rows[-1]['view'][1]['ref']['sequence'])
        need(r['terminal']==rows[-1]['finished'] and r['custody']==rows[-1]['custody_finished'] and
             r['maps']['poisoned']==r['maps']['reserved']==0,'actual final unchanged owner/custody and no poisoned maps')
    need(r['native_completed']==(count if mode<12 else 0)and r['native_faults']==int(mode in(12,13)) and
         r['real_signals']==int(14<=mode<=17)and r['supplied_mutations']==int(mode>=18),
         'exact native, actual kernel fault/signal and supplied-negative denominators')
    return dict(operation='completed'if mode<12 else 'failed',completed_pairs=r['completed'],
        native_completed=r['native_completed'],native_failed=r['native_faults'],old_startup_pairs=1,refusal_bytes=47,
        actual_traces=r['events'],retained_transfers=r['terminal']['total_retained'],
        actual_lease_closes=r['terminal']['total_closes'],actual_lease_releases=r['terminal']['total_releases'],
        supplied_mutations=r['supplied_mutations'],real_signals=r['real_signals'],owner_error=r['owner_error'],
        expected_failure_verified=bool(r['verified_failure']),
        endpoint_scope='architectural effects with separately exact INT3/NX events'if mode==9 else 'identical NX endpoints or exact failed prefix',
        bases_scope='actual no-borrow outer boundaries; no per-TRACE FS/GS base claim')


def controls(data,layout,mode,pid):
    """Two supplied corruptions per process, plus16 representative seam/prefix controls; never real cases."""
    check(data,layout,mode,pid)
    paths=[('mode',),('terminal','repeat','step','revoke_sync')if mode>=12 else
           ('row',0,'after',1,'state','frame','fp',160)]
    if mode==0:
        paths += [('row',0,'begun','registration','address'),
                  ('row',0,'custody_finished','epoch'),
                  ('event',0,'owner','repeat','step','hooks','authenticate'),
                  ('row',0,'cold_returned','state','frame','fp',160),
                  ('row',0,'cold','uc',layout['frame']['greg'][0]+13*8),
                  ('row',0,'after',1,'extra',12287),
                  ('event',0,'progress'),('event',0,'before','state','frame','greg',16),
                  ('event',0,'before','state','frame','greg',17),
                  ('row',0,'view',1,'bytes',0),('row',0,'view',1,'ref','sequence'),
                  ('event',0,'custody_before','event'),('row',0,'finished','release_complete')]
    if mode==1:paths += [('event',0,'returned','uc',layout['frame']['greg'][0]+13*8)]
    if mode==12:paths += [('terminal','unexpected_context_complete')]
    if mode==26:paths += [('injection_issued',)]
    for path in paths:
        at,_=position(layout,path);altered=bytearray(data);altered[at]^=1
        try:check(bytes(altered),layout,mode,pid)
        except ValueError:pass
        else:raise ValueError('violating supplied record accepted: '+repr(path))
    return len(paths)
