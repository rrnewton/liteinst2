"""Five dynamic persistent subjects, not a whole-program owner qualification.

The new row joins the complete protected owner. Legacy rows retain their exact
schemas/outcomes and actual input, effect, gate and registered-rseq checks; no
legacy full-row protected capture or old65 qualification is claimed.
"""
import copy,json
from page_selected import need
import linked_epoch_reports as prior
from page_selected_repeat_lease_app_reports import lease_request,closed_io,query,carrier_extent,MASK
from page_selected_repeat_lease_ls_reports import external_source
old,reuse,unrolled,current,maps_view=prior.old,prior.reuse,prior.unrolled,prior.current,prior.maps_view
rseq=prior.linked_base.rseq
H=prior.H
PREFIX=b'LI2_PERSISTENT_DYNAMIC '
SCALARS='version status failure_code detail_abs detail_negative phase serial generation build_serial offers cold_attempts publications hits cancelled retirements permit_claims entries completed unexpected permit opened_pages closed_pages anchor_released registration_rechecked guest_data_fault recovery_complete first_error active busy'.split()
KEYS=SCALARS+['misses']
OUTCOME=('status','failure_code','detail_abs','detail_negative')
CONTROL_COUNTS={(m,0):60 for m in range(3)}


def split(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete persistent terminal stream')
    lines=stderr[:-1].split(b'\n')
    need(len(lines)>1 and lines[-1].startswith(PREFIX)and sum(x.startswith(PREFIX)for x in lines)==1 and
         len(lines[-1])<=4096 and b'\r'not in lines[-1],'one bounded final persistent row')
    row=maps_view.pair.pair_reports.rseq.decode(lines[-1][len(PREFIX):])
    need(type(row)is dict and list(row)==KEYS and all(type(row[k])is int and 0<=row[k]<1<<64 for k in SCALARS)and
         type(row['misses'])is list and len(row['misses'])==15 and
         all(type(n)is int and 0<=n<1<<64 for n in row['misses']),
         'complete ordered exact-int persistent row')
    need(row['version']==1 and PREFIX+json.dumps(row,separators=(',',':'),allow_nan=False).encode()==lines[-1],
         'canonical distinct dynamic persistent v1 row')
    return row,b'\n'.join(lines[:-1])+b'\n'


def registration_completed(loader,r,pid,mode):
    need(type(mode)is int and mode in(0,1,2),'exact persistent registered profile')
    active=int(mode!=0)
    need(r['owner'][:4]==[1,active,active,3 if active else 0]and
         r['owner'][9:14]==[0x500000200000,0x500000200000,32,0x53053053,1]and
         r['counts'][:4]==([1,1,0,0]if active else[2,1,1,0]),
         'exact real registered terminal lifecycle')
    owner, counts, t, args = r['owner'], r['counts'], r['transaction'], r['args']
    initialized, registered, held, phase = owner[:4]
    need(initialized == 1 and registered in (0,1) and held == registered and
         phase == (3 if registered else 0) and owner[4:7] == [0,0,0] and
         owner[7] == owner[8] == pid > 0,
         'real terminal IDLE or ACTIVE registration, no synthetic unregister')
    calls, registrations, unregistrations, errors = counts[:4]
    need(registrations == unregistrations+registered and owner[13] == registrations and
         calls == registrations+unregistrations+errors == loader['rseq'],
         'every actual rseq return accounted, including retained active registration')
    if registrations:
        need(r['identity'][0] == 1 and r['identity'][1] > 0 and r['identity'][2] > 0 and
             owner[9] > 0 and owner[9] & 31 == 0 and owner[10] == owner[9] & ~4095 and
             owner[9] <= (1 << 64)-32 and owner[11] == 32 and owner[12] < 1 << 32 and
             r['tls'][:6] == [1,1,0,0,0,0],
             'successful registration has actual mapping identity and successful TLS observations')
    else:
        need(r['identity'] == [0]*4 and r['tls'][:6] == [1,1,0,0,0,0],
             'unregistered native pair observes actual TLS without a registration mapping')
    if not calls:
        need(owner[9:14] == [0]*5 and t == [0]*8 and args == [0]*6 and
             r['before'] == r['after'] == [0]*28 and counts == [0]*9,
             'zero registration calls retain their exact untouched transaction and counters')
        version,pc,nxt,code,length,policy,first,end=r['footprint']
        need(version==1 and 0<pc<=(1<<64)-1-length and 1<=length<=15 and
             nxt==pc+length and code>0 and policy==1 and first==end==0 and
             r['last']==[pc,code,1,0,0],
             'unregistered cold proof retains its complete actual static NONE footprint')
        return
    need(t[:3] == [1,1,1] and t[3] in (0,1) and t[5] in (0,1) and
         t[6] in (0,1) and t[7] == 0 and (args[2] & 0xffffffff) in (0,1),
         'last actual transaction issued and returned with scoped flags')
    prior, flags = t[3], args[2] & 0xffffffff
    if t[4]:
        need(t[5] == 1 and 1 <= t[4] <= 4095 and errors > 0 and registered == prior,
             'actual kernel error preserves prior registration')
    else:
        need(t[5] == 0 and registered == int(not flags) and prior == flags and
             args[0] == owner[9] and args[1] & 0xffffffff == owner[11] and
             args[3] & 0xffffffff == owner[12], 'actual successful register/unregister tuple')
    if not prior and not flags:
        need(t[6:] == [1,0] and args[0] == owner[9] and args[1] & 0xffffffff == 32 and
             args[3] & 0xffffffff == owner[12], 'fresh registration observed actual zero input before issue')
        identity = rseq.observed_data(r['before'], owner, pid)
        if not t[4]:
            need(rseq.observed_data(r['after'], owner, pid) == identity == r['identity'] and
                 r['before'][:7] == r['after'][:7], 'same actual registration mapping before and after kernel')
            need(r['after'][26:] == [0,1] and r['after'][23] > r['before'][23] and
                 r['after'][25] > r['before'][25] and r['after'][24] == r['before'][24],
                 'actual raw registration invalidated maps before the fresh post-kernel query')
        else:
            need(r['after'] == [0]*28, 'failed raw registration has no invented post-registration query')
    else:
        need(t[6:] == [0,0] and r['before'] == r['after'] == [0]*28,
             'existing-registration or unregister transaction has no fabricated fresh mapping observation')

def repeat_completed(p,pid,images,image_bytes,carrier,carrier_bytes,mode):
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
         owner[:4]==([1,0,0,0]if mode==0 else[1,1,1,3]) and owner[7:9]==[pid,pid] and
         owner[13]==p['rseq']['counts'][1]==1 and p['rseq']['counts'][2]==int(mode==0) and
         p['rseq']['counts'][6]==0,
         'actual prior REP has whole unregistered identity; final persistent registration is source-exact')
    return dict(attempts=r['attempts'],completed=r['completed'],traces=r['traces'],retained=r['retained'],
        closes=r['closes'],releases=r['releases'],queries=r['queries'],last_code=r['request'][2],
        last_initial_count=n,last_traces=traces,last_guard_checks=checks,source_module=binding['module'],
        source_file_offset=binding['file_offset'],custody_epoch=c[8],custody_invalidations=c[16],registration_scope='before_first_registration',source_binding=binding)

def effect_exit(p):
    calls=27
    l,e,o,cp=(p[k]for k in('loader','effect','oneshot','cpuid_nx'))
    need(l['last_syscall']in(60,231)and l['source_syscalls']==l['syscalls']==l['forwarded']>0,'actual successful exit syscall path')
    need(all(e[k]==v for k,v in dict(first_error=0,stage=4,busy=1,finished=0,kind=7,action=1,phase=5,error=0,
        callback_entered=0,callback_returned=0,native_entered=1,native_returned=0,exit_entered=1,
        post_guards_complete=0,post_callback_entered=0,post_callback_returned=0,committed=0,
        random_backend_returned=0,random_backend_status=0,fp_after_initialized=0,raw_entered=0,raw_returned=0).items()),
        'literal report-before-raw nonreturning exit prefix; never completed')
    need(0<e['pc']<=(1<<64)-3 and e['next_pc']==e['pc']+2 and
         512<=e['fp_bytes']==e['fp_before_initialized']<=65536 and
         e['sequence']==e['attempts']==e['completed']+1 and e['completed']==e['commits']==e['native_completed']and
         e['scripted_completed']==0 and e['classes']==[l['cpuid'],l['rdrand'],l['rdseed'],l['rdpid'],l['rdtsc'],l['rdtscp'],l['syscalls']-1]and
         sum(e['classes'])==e['completed'],'every returning Native class accounted separately from final exit')
    need(o['published']>8 and o['attempted']==o['published']==o['restored']==o['effect_started']==o['backend_prepared']==l['source_patches']and
         o['completed']==o['retired']==o['effect_returned']==o['backend_completed']==o['last_completed_sequence']==o['published']-1 and
         o['refused']==o['resetting']==o['last_refused_sequence']==o['rseq_error']==0 and o['active_phase']==7 and
         o['rseq_phase']==6 and o['rseq_attempts']==o['published']and o['rseq_retired']==o['retired'],
         'all temporary patches restored; only final exit remains unreturned and unretired')
    need([o['cpuid_patches']+67,o['syscall_patches']+calls,o['rdtsc_patches']]==[l['cpuid'],l['syscalls'],l['rdtsc']]and
         o['published']==o['cpuid_patches']+o['syscall_patches']+o['rdtsc_patches']and
         o['generations']==l['generations']and o['retained_records']>0,'exact application publication and unpatched class accounting')
    need(e['attempts']==o['published']+67+calls,
         'complete fixed application direct-effect partition')
    # Each restored plan renews its fixed one or two source pages twice.
    # Page counts are not separately reported; do not invent an exact split.
    generation_delta=l['generations']-o['retained_records']
    need(generation_delta%2==0 and 2*o['published']<=generation_delta<=4*o['published'],
         'two in-place generation advances per restored one-or-two-page publication')
    need(cp['hardware_entered']==cp['hardware_returned']==1 and cp['phase']==3 and
         cp['attempts']==cp['samples']==cp['commits']==l['cpuid']>0 and cp['next_pc']==cp['pc']+2 and
         cp['raw']==cp['result'],'real complete unmodified hardware CPUID path')

def effect_prefix(p):
    l,e,o,cp=(p[k]for k in('loader','effect','oneshot','cpuid_nx'))
    need(l['last_syscall']==158 and l['source_syscalls']==l['syscalls']==l['forwarded']>0,'exact returned machine-prefix final arch_prctl')
    need(all(e[k]==v for k,v in dict(first_error=0,stage=8,busy=0,finished=1,kind=7,action=1,phase=9,error=0,
        callback_entered=0,callback_returned=0,native_entered=1,native_returned=1,exit_entered=0,
        post_guards_complete=1,post_callback_entered=0,post_callback_returned=0,committed=1,
        random_backend_returned=0,random_backend_status=0,raw_entered=1,raw_returned=1).items()),
        'every actual last direct effect completed before the required target failure')
    need(0<e['pc']<=(1<<64)-3 and e['next_pc']==e['pc']+2 and
         512<=e['fp_bytes']==e['fp_before_initialized']==e['fp_after_initialized']<=65536 and
         e['sequence']==e['attempts']==e['completed']==e['commits']==e['native_completed']and
         e['scripted_completed']==0 and e['classes']==[l['cpuid'],l['rdrand'],l['rdseed'],l['rdpid'],l['rdtsc'],l['rdtscp'],l['syscalls']]and
         sum(e['classes'])==e['completed'],'all returned prefix effects and complete FP preservation')
    need(o['published']>8 and all(o[k]==o['published']for k in('attempted','restored','effect_started','backend_prepared',
         'completed','retired','effect_returned','backend_completed','last_completed_sequence','rseq_attempts','rseq_retired'))and
         o['published']==l['source_patches']and all(o[k]==0 for k in('refused','resetting','last_refused_sequence','rseq_error','active_phase','rseq_phase')),
         'all actual temporary publications completed and retired before target failure')
    need([o['cpuid_patches']+67,o['syscall_patches']+18,o['rdtsc_patches']]==[l['cpuid'],l['syscalls'],l['rdtsc']]and
         o['published']==o['cpuid_patches']+o['syscall_patches']+o['rdtsc_patches']and
         o['generations']==l['generations']and o['retained_records']>0 and e['attempts']==o['published']+85,
         'exact18 direct syscalls and67 CPUID before either required failure')
    delta=l['generations']-o['retained_records']
    need(delta%2==0 and 2*o['published']<=delta<=4*o['published'],'actual two generation advances per restored source page')
    need(cp['hardware_entered']==cp['hardware_returned']==1 and cp['phase']==3 and
         cp['attempts']==cp['samples']==cp['commits']==l['cpuid']>0 and cp['next_pc']==cp['pc']+2 and cp['raw']==cp['result'],
         'complete unmodified hardware CPUID prefix')

def gate_prefix(p,pid,exit_code,parent):
    o=p['tcgets']
    need(type(pid) is int and pid > 0 and type(exit_code) is int and exit_code in (0,125),
         'actual report-bearing terminal process')
    need(o['version'] == 1 and o['status'] == exit_code and
         all(o[k] == p['loader'][k] for k in ('status','failure_code','detail_abs','detail_negative')),
         'same terminal outcome, never a failed operation relabel')
    x,q,m = o['prefix'],o['query'],o['mount']
    need(x[0] == 1 and o['launch'] == parent['identity'] and
         all(v in (0,1) for v in (x[1],x[5],*q[:2],q[4],q[6],*m[:5],m[6],m[8],o['detail_negative'])) and
         x[2] <= 8 and x[11] <= x[10] <= x[9] <= x[8] <= x[7] and q[1] <= q[0] and
         m[9] <= 256<<10 and m[10] <= 2048 and m[11] <= 1,
         'actual normal-open launch identity and bounded truthful gate prefixes')
    need((x[1] == 0 and x[6] == 0) or (x[1] == 1 and x[6] == 3),
         'permanent invalidation records attempted close(1)')
    if x[8] and x[7] == x[8]:
        need(o['current'][:5] == o['launch'][:5] and
             o['current'][5] & 0o170000 == o['launch'][5] & 0o170000 == 0o100000 and
             not o['current'][6] & 0o10000000 and x[13] > 0 and x[14] > 0,
             'actual admitted descriptor identity and registration/check prefix')
    if x[11] and x[7] == x[11]:
        need(x[7] == x[8] == x[9] == x[10] == x[11] and q[5:] == [25,1] and
             q[:2] == [1,1] and m[:5] == [1]*5 and m[7:9] == [0,0] and
             m[9] > 0 and m[10] > 0 and m[11] == 1,
             'actual last completed result is -ENOTTY with full unique mount closure')
    commands=o['commands']
    need(commands[0]+commands[1]==x[11] and commands[2]in(0,0x5401,0x5413) and
         (commands[2]==0)==(x[7]==0),'exact per-command actual validated-return accounting')
    if x[11] and x[7]==x[11]:
        need(commands[0 if commands[2]==0x5401 else 1]>0,
             'actual last completed command belongs to its nonempty counter')
    if exit_code == 0:
        need(o['failure_code'] == o['detail_abs'] == o['detail_negative'] == x[3] == x[4] == x[5] == 0 and
             x[2] in (2,7) and x[7] == x[8] == x[9] == x[10] == x[11],
             'no pending or failed gate at application completion')
        if x[11]:
            need(x[2] == 7 and q[5:] == [25,1] and q[:2] == [1,1] and
                 m[:5] == [1]*5 and m[7:9] == [0,0] and m[9] > 0 and m[10] > 0 and m[11] == 1,
                 'actual last -ENOTTY and complete unique mount proof before commit')
        if not x[7]:
            need(x[2]==2 and o['current']==[0]*7 and commands==[0]*3 and
                 x[12]>0 and x[13:]==[0,0] and q==[1,1,3,0,0,0,0] and
                 m[:5]==[1]*5 and m[5]<=2147483647 and m[6:9]==[0,0,0] and
                 m[9]>0 and m[10]>0 and m[11]==1,
                 'zero app ioctls retain the real startup close/query and complete unique mount proof')
    return dict(attempts=x[7],permitted=x[8],issued=x[9],returned=x[10],validations=x[11])


def validate(p,view,pid,exit_status,parent,images,image_bytes,carrier,carrier_bytes,owner,owner_reader,mode):
    need(type(mode)is int and mode in(0,1,2)and type(exit_status)is int and
         exit_status==(0 if mode==0 else 125)and owner['mode']==mode,'actual persistent five-subject outcome')
    expected=dict(status=exit_status,failure_code=0 if mode==0 else 3304,detail_abs=0 if mode==0 else 11 if mode==1 else 4,detail_negative=0)
    for name in('loader','dynamic','linked','linked_reuse','scalar_region','scalar_reuse','unrolled','current_tf'):
        need(all(p[name][k]==v for k,v in expected.items()if k in p[name]),'actual consistent persistent outcome '+name)
    joined=owner_reader.terminal(p['dynamic'],owner)
    gate=gate_prefix(p,pid,exit_status,parent)
    registration_completed(p['loader'],p['rseq'],pid,mode)
    if mode==0:effect_exit(p)
    else:effect_prefix(p)
    return dict(application_completed=mode==0,required_failure=int(mode!=0),mode=mode,terminal_join=joined,
        gate=gate,maps_view=view,repeat_lease=repeat_completed(p,pid,images,image_bytes,carrier,carrier_bytes,mode),
        input_authentication=prior.cost._retained_inputs(images,image_bytes,carrier,carrier_bytes),
        whole_profile_qualified=False,legacy_protected_rows=False)


def check(stderr,*args):
    dynamic,suffix=split(stderr);linked,linked_reuse,suffix=prior.split(suffix)
    scalar,scalar_reuse,suffix=reuse.split(suffix);u,suffix=unrolled.split(suffix)
    cur,suffix=current.split_current(suffix);view,original=maps_view.split_report(suffix,'maintained')
    parsed=old.reports(original);old.extensions(parsed)
    parsed.update(dynamic=dynamic,linked=linked,linked_reuse=linked_reuse,
        scalar_region=scalar,scalar_reuse=scalar_reuse,unrolled=u,current_tf=cur)
    return parsed,validate(parsed,view,*args)


def controls(stderr,*args):
    p,_=check(stderr,*args);owner,owner_reader,mode=args[-3:];refused=[]
    for key,index in [(key,None)for key in SCALARS]+[('misses',i)for i in range(15)]:
        value=copy.deepcopy(p['dynamic'])
        if index is None:value[key]^=1
        else:value[key][index]^=1
        try:owner_reader.terminal(value,owner)
        except ValueError as error:
            need(str(error)=='whole actual protected dynamic terminal row','exact isolated protected-row refusal')
            refused.append('protected_'+key+(''if index is None else '_'+str(index)))
        else:raise ValueError('accepted changed actual protected dynamic row')
    for name,row,key,index in(('effect_sequence','effect','sequence',None),('effect_fp','effect','fp_before_initialized',None),
        ('effect_class','effect','classes',6),('effect_raw_return','effect','raw_returned',None),
        ('direct_syscalls','oneshot','syscall_patches',None),('direct_cpuid','oneshot','cpuid_patches',None),
        ('retirement','oneshot','retired',None),('last_syscall','loader','last_syscall',None)):
        value=copy.deepcopy(p)
        if index is None:value[row][key]^=1
        else:value[row][key][index]^=1
        try:(effect_exit if mode==0 else effect_prefix)(value)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted changed actual effect census')
    for name,key,index in(('registration_calls','counts',0),('registration_phase','owner',3),
                          ('registration_epoch','owner',13),('registration_flags','args',2)):
        value=copy.deepcopy(p['rseq']);value[key][index]^=1
        try:registration_completed(p['loader'],value,args[0],mode)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted changed actual registration')
    lines=stderr[:-1].split(b'\n')
    for name,data in(('missing_persistent',b'\n'.join(lines[:-1])+b'\n'),('truncated',stderr[:-1]),
        ('duplicate_persistent',stderr+lines[-1]+b'\n'),('wrong_version',stderr.replace(PREFIX+b'{"version":1,',PREFIX+b'{"version":2,',1))):
        need(data!=stderr,'actual causal parser control')
        try:split(data)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted malformed persistent terminal stream')
    need(len(refused)==len(set(refused))==CONTROL_COUNTS[mode,0],'all60 distinct dynamic terminal refusals')
    return dict(refusals=refused,native_operations=0,original_stderr_sha256=H(stderr))
