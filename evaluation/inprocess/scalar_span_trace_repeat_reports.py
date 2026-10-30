"""Finite TRACE's actually completed interpreter REP before first rseq registration.

The original unused-owner and registered REP validators stay unchanged. This
separate report predicate preserves every completion/source/permission/custody
check and keeps the later global span failure visible. External source matching
has only its original file-byte/segment scope; no full REP-frame or historical
mapping observation is invented. Fresh finite/native qualification is separate.
"""
import copy
from page_selected import need
from page_selected_repeat_lease_app_reports import LEASE_SCALARS,LEASE_ARRAYS
from page_selected_repeat_lease_app_reports import lease_request,closed_io,query,carrier_extent,MASK
from page_selected_repeat_lease_ls_reports import external_source

def completed(p,pid,images,image_bytes,carrier,carrier_bytes):
    need(p['repeat_lease']['version']==1,'exact REP lease version')
    need(p['repeat']is None,'finite TRACE has no separate old-cycle REP observation')
    binding=external_source(p,images,image_bytes,carrier,carrier_bytes)
    r=p['repeat_lease'];pc,nxt,flags,mask,width=lease_request(r)
    n,remaining,traces,retained,final,post_pc,post_flags,started,complete,err,neg,checks=r['progress']
    need(all(r[k]==p['loader'][k]for k in ('status','failure_code','detail_abs','detail_negative')) and
         r['route']==p['loader']['step_route']==p['run']['route'] and r['pending']==p['run']['pending'],
         'prior completed REP retains actual global outcome and current distinct route')
    need(r['attempts']==r['completed']==r['closes']==r['releases']==r['queries']>0 and
         r['traces']==r['retained']+r['completed'] and r['traces']>=traces>=1 and
         r['retained']>=retained and retained==traces-1,
         'one real close/query/release per completed lease; retained transfers are separate')
    if r['attempts']==1:need(r['traces']==traces,'single lease owns every recorded trace')
    need((n==0 and traces==1)or(n>0 and traces<=n),'bounded real REP progress allows hardware chunks')
    need([remaining,final,post_pc,post_flags,started,complete,err,neg,checks]==
         [0,1,nxt,flags|0x100,1,1,0,0,traces+2],'exact final progress and pre/post-seed plus per-TRACE rseq guards')
    need(r['owner']==[5,0,0,0,0,1,0,0,0,0,1,1,1,1] and
         r['event']==[5,0,2,0,0,0,nxt,0,1],
         'actual complete accepted final TRACE, never an incomplete fault or nested event')
    f=r['frames']
    need(f[:3]==[pc,flags|0x10000,n] and f[4]<(1<<47) and 512<=f[5]<=65536 and f[6]==f[5] and
         f[7:10]==[nxt,flags|0x100,0] and f[11:]==[f[4],f[5],f[5]],
         'actual initial/final raw frame identity with complete initialized FP extent')
    expected=(f[3]+(-width if flags&0x400 else width)*n)&MASK
    need(f[10]==expected,'literal full-width final RDI progress')
    need(n<=MASK//width,'initial full REP destination span multiplication does not overflow')
    if n:
        size=n*width;first=f[3]
        if flags&0x400:
            need(first>=size-width and first<=MASK-width,'backward REP span endpoints do not overflow')
            first-=size-width
        need(first<=MASK-size,'complete initial REP write span does not wrap')
    closed_io(r['io'],1);query(r['query'],nxt)
    q=r['query'];source=r['source']
    if q[17]==source[0]:need(q[17:23]==source[:4]+[source[5],source[4]],
         'final query identity matches the same retained source page')
    need(r['release']==[1,1,0,0] and r['borrow'][1]==0 and r['writes']==[traces+2,0,0],
         'actual successful source release and every unconditional private-write guard')
    c=r['custody']
    need(c[:8]==[1,0,0,0,0,0,0,0] and c[9]==c[11]==c[15]==r['attempts'] and
         c[10]==traces and c[12]==c[13]==c[14]==r['traces'] and
         c[8]==c[11]+c[15]+c[16] and c[16]>=r['attempts'] and c[17]==3 and
         c[18]==r['borrow'][0] and c[19:]==[0,0],
         'actual once-only ticket/event chain is empty after all final releases; epochs count real invalidations')
    b=r['backing'];image=images[binding['module']]
    backing_bytes=carrier_extent(carrier,images[0]['bytes'])if binding['module']==0 else image['bytes']
    need(b[0]<=0x7fffffff and b[1]==0 and b[2]&15==15 and b[3:8]==[0,0,0,1,1] and
         b[8]==backing_bytes>0 and b[9]==0 and b[10]&0o170000==0o100000,
         'actual retained sealed regular-file stat/FD proof matches exact main carrier or original dependency extent')
    owner=p['rseq']['owner'];tls=p['rseq']['tls'];registration=r['registration']
    need(registration==[1,0,0,0,pid,pid]+[0]*8 and
         owner[:4]==[1,1,1,3] and owner[7:9]==[pid,pid] and owner[13]>0 and
         p['rseq']['counts'][6]==0,
         'actual prior REP predates first registration: whole IDLE identity and zero pin/TLS snapshot')
    return dict(attempts=r['attempts'],completed=r['completed'],traces=r['traces'],retained=r['retained'],
        closes=r['closes'],releases=r['releases'],queries=r['queries'],last_code=r['request'][2],
        last_initial_count=n,last_traces=traces,last_guard_checks=checks,source_module=binding['module'],
        source_file_offset=binding['file_offset'],custody_epoch=c[8],custody_invalidations=c[16],registration_scope='before_first_registration',source_binding=binding)


def mutations(p):
    r=p['repeat_lease'];need(list(r)==LEASE_SCALARS+list(LEASE_ARRAYS)and len(r)==28,
        'all28 actual REP fields retain their original ordered schema')
    trials=[]
    for key in r:
        row=copy.deepcopy(r)
        if key in LEASE_ARRAYS:row[key][2 if key=='backing'else 0]^=1
        else:row[key]^=1
        trials.append(('prior_repeat_'+key,row))
    # A coherent erased old-owner row must not pass this actually-used domain.
    erased=dict.fromkeys(LEASE_SCALARS,0);erased['version']=1
    for key in ('status','failure_code','detail_abs','detail_negative'):erased[key]=r[key]
    erased['route']=r['route'];erased['pending']=r['pending']
    for key,size in LEASE_ARRAYS.items():erased[key]=[0]*size
    erased['owner'][-1]=1;erased['custody'][0]=1
    trials.append(('prior_repeat_erased',erased))
    need(len(trials)==29,'all28 REP field mutations and one coherent erased owner')
    return trials
