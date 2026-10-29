"""Distinct retained-RX REP report; all original app/seed/native guards remain.

Only this parser admits LI2_REPEAT_LEASE. It does not strip a row, alter an
observed counter or normalize a report before calling the original closures.
The complete original app reader/native pair must run first.
"""
import copy,hashlib,json,struct
from page_selected import need
import page_selected_run_reuse_app_reports as original
import page_selected_run_reuse_ls_reports as shared
from page_selected_run_reuse_ls_reports import (ORDER,_unsigned,REUSE_SCALARS,REUSE_ARRAYS,
    rseq,generic,NATIVE_KEYS,register,run_schema,chain,lease,ZERO,RSEQ_SCHEMA,repetition,trace_prefix)
H=lambda b:hashlib.sha256(b).hexdigest()
MASK=original.MASK
words=original.words
closed_io=original.closed_io
query=original.query
binary_join=original.binary_join
repeat_source=original.repeat_source
gate=original.gate
LEASE_SCALARS='version status failure_code detail_abs detail_negative attempts completed traces retained closes releases queries route pending'.split()
LEASE_ARRAYS=dict(request=8,source=6,owner=14,event=9,progress=12,frames=14,io=17,query=31,
    release=4,writes=3,borrow=2,custody=21,backing=11,registration=14)

def reports(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete actual stderr')
    lines=stderr[:-1].split(b'\n');parts=[line.partition(b' ')for line in lines]
    names=[p[0]for p in parts];order=['LI2_'+x for x in ORDER]
    if b'LI2_REPEAT'in names:order.insert(4,'LI2_REPEAT')
    order.insert(order.index('LI2_ONESHOT'),'LI2_REPEAT_LEASE')
    need(names==[s.encode()for s in order]and all(p[1]==b' 'and 0<len(line)+1<=4096 and b'\r'not in line for p,line in zip(parts,lines)),
         'exact bounded report order with no duplicate or unrecognized rows')
    values={name:rseq.decode(raw)for name,_,raw in parts}
    loader,native=values[b'LI2_LOADER'],values[b'LI2_NATIVE']
    run,c,registration=(values[k]for k in(b'LI2_RUN',b'LI2_CHAIN',b'LI2_RSEQ'))
    repeat=values.get(b'LI2_REPEAT')
    rep_lease=values[b'LI2_REPEAT_LEASE']
    _unsigned(rep_lease,set(LEASE_SCALARS),LEASE_ARRAYS)
    need(list(rep_lease)==LEASE_SCALARS+list(LEASE_ARRAYS) and rep_lease['version']==1,
         'exact ordered distinct REP lease row, not an old-cycle report')
    trace=values[b'LI2_TRACE_RUN']
    reuse=values[b'LI2_RUN_REUSE']
    _unsigned(reuse, REUSE_SCALARS, REUSE_ARRAYS)
    extension=dict(effect=values[b'LI2_SELECTED_EFFECT'],oneshot=values[b'LI2_ONESHOT'],
        cpuid_nx=values[b'LI2_CPUID_NX'],rseq_native=values[b'LI2_RSEQ_NATIVE'],
        rseq_boundary=values[b'LI2_RSEQ_BOUNDARY'],tcgets=values[b'LI2_RSEQ_BTRFS_TTY_QUERY'])
    # Preserve generic.parse's actual startup/attribution/lifecycle/vDSO facts.
    # Its zero-admission assertion belongs to the old profile and is replaced
    # here by the explicit native profile's actual positive-count contract.
    _unsigned(loader, generic.KEYS-{'scope'}, scope='partial_selected_reusable_effects')
    need(loader['selected_profile'] == loader['generic_tf_profile'] == 1 and
         loader['source_patches'] > 0, 'actual reusable selected publication mechanism')
    need(loader['selected_selftests'] == loader['first_target_is_interpreter_entry'] ==
         loader['interpreter_entry_faults'] == 1, 'actual startup and first interpreter entry')
    need(loader['nx_faults'] == loader['main_faults']+loader['interpreter_faults']+
         loader['dependency_faults'], 'actual fault attribution')
    records=extension['oneshot']
    need(type(records)is dict and type(records.get('retained_records'))is int and
         records['retained_records']==loader['retired']+loader['live_pages'], 'retained record equation')
    need(loader['sync_core'] >= loader['admissions'], 'actual admission sync prefix')
    need(loader['vdso_close_attempted'] == loader['vdso_close_observed'] == loader['vdso_closed'] == 1 and
         loader['vdso_close_result_abs'] == loader['vdso_close_result_negative'] == 0, 'actual vDSO closure')

    need(type(native) is dict and type(native.get('revisit_count')) is int and
         0 <= native['revisit_count'] <= 16, 'bounded actual revisit count')
    _unsigned(native, NATIVE_KEYS-{'revisit_ns'}, {'revisit_ns': native['revisit_count']})
    need(native['close_complete'] in (0, 1) and native['close_busy'] in (0, 1) and
         native['closed'] <= native['admissions'] <= native['attempts'] and
         native['main_admissions'] <= native['admissions'] and native['main_refaults'] <= native['refaults'],
         'actual native publication/close counts and main subsets')
    need(all(x > 0 for x in native['revisit_ns']), 'nonzero actual revisit intervals')
    need(native['first_source_offset'] % 4096 == 0 and
         native['revisit_count'] <= max(native['admissions']-1, 0),
         'page-aligned first source and revisits after an actual first admission')
    need(all(native[k] == loader[k] for k in ('status', 'failure_code')), 'same native terminal outcome')

    need(type(run) is dict and type(run.get('cache_present')) is int and
         type(run.get('publication_present')) is int and
         run['cache_present'] in (0, 1) and run['publication_present'] in (0, 1), 'actual RUN presence')
    arrays = {k: n for k, n in register.ARRAYS.items()
              if k not in ('cache', 'initialization', 'attempt', 'publication')}
    if run['cache_present']:
        arrays.update({k: register.ARRAYS[k] for k in ('cache', 'initialization', 'attempt')})
    if run['publication_present']:
        arrays['publication'] = register.ARRAYS['publication']
    run_schema(run, arrays)
    need(run['route'] == loader['step_route'], 'same actual RUN route')

    _unsigned(c, (chain.KEYS-{'scope'})|lease.EXTRA, scope='opt_in_same_page_tf_lease')
    need(c['active'] in (0, 1) and c['pending'] in (0, 1) and c['proof_valid'] in (0, 1) and
         c['attempts'] == loader['generic_tf_attempts'] and c['steps'] == loader['generic_tf_steps'],
         'actual chain route/counters')
    for index in (0, 1):
        slot = chain.slot(c, index)
        need(slot['phase'] <= 7 and slot['origin'] <= 2 and slot['fallback'] <= 6 and slot['owner_phase'] <= 6 and
             all(slot[k] in (0, 1) for k in ('prepare', 'prepared', 'retry', 'trace', 'held', 'query',
                                           'queried', 'release', 'released', 'unexpected')) and
             all(slot[k] <= 3 for k in ('open', 'opened', 'revoke', 'revoked')) and slot['length'] <= 15,
             'exact old chain slot domains')
    if any(c[k] for k in ZERO) or c['pending'] or c['error'] or c['proof_valid'] or loader['step_route']:
        chain.same_slot(loader, chain.slot(c, c['active']))

    _unsigned(registration, RSEQ_SCHEMA['scalar_keys'],
              {k: len(v) for k, v in RSEQ_SCHEMA['arrays'].items()}, RSEQ_SCHEMA['scope'])
    need(registration['maps_profile'] == 1, 'actual RSEQ maps profile')
    if repeat is not None:
        _unsigned(repeat, repetition.SCALARS, repetition.ARRAYS)
        need(repeat['attempts'] > 0 and repeat['completed'] <= repeat['attempts'] and
             repeat['route'] == loader['step_route'], 'actual optional REP prefix')
    trace_prefix(trace,run,c,loader)
    for row in (run, c, registration, trace, reuse, rep_lease)+(() if repeat is None else (repeat,)):
        need(all(row[k] == loader[k] for k in ZERO), 'same actual outcome in every old report')
    need(rep_lease['route']==loader['step_route'] and rep_lease['pending']==run['pending'],
         'same genuine terminal route and pending state in REP lease')
    parsed=dict(loader=loader,native=native,repeat=repeat,repeat_lease=rep_lease,run=run,chain=c,rseq=registration,
        lease={k:c[k]for k in lease.EXTRA},trace_run=trace,reuse=reuse,**extension)
    return parsed



def lease_request(r):
    pc,nxt,code,length,available,opcode,flags,pages=r['request']
    need((code,length)in((346,3),(345,2)) and 0<pc<=MASK-length and nxt==pc+length and
         length<=available<=15 and 0<=opcode<1<<24 and flags&0x10100==0,
         'exact canonical STOSQ or STOSD original lease request')
    width=8 if code==346 else 4
    emitted=opcode.to_bytes(3,'little')
    need(emitted==b'\xf3\x48\xab' if width==8 else
         emitted[:2]==b'\xf3\xab' and (available>2 or emitted[2]==0),
         'exact lease instruction bytes and only genuinely unavailable zero tail')
    need(pages==1 and pc//4096==(nxt-1)//4096 and (pc&4095)+available<=4096,
         'one retained source page and complete original fetched bytes')
    p=r['source']
    need(p[0]==pc&~4095 and p[1]>0 and p[2]>0 and p[3]%4096==0 and p[4:]==[1,5],
         'authenticated lease source page, allocation and generation')
    need(r['borrow'][0]>0,'retained genuine lease borrow identity')
    return pc,nxt,flags,1,width

def lease_completed(p,pid,binding,images):
    r=p['repeat_lease'];pc,nxt,flags,mask,width=lease_request(r)
    n,remaining,traces,retained,final,post_pc,post_flags,started,complete,err,neg,checks=r['progress']
    need(all(r[k]==0 for k in('status','failure_code','detail_abs','detail_negative','route','pending')),
         'successful REP lease has no unfinished or failed terminal prefix')
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
    need(b[0]<=0x7fffffff and b[1]==0 and b[2]&15==15 and b[3:8]==[0,0,0,1,1] and
         b[8]==image['bytes']>0 and b[9]==0 and b[10]&0o170000==0o100000,
         'actual retained sealed regular-file stat/FD proof matches the independently built original ELF')
    owner=p['rseq']['owner'];tls=p['rseq']['tls'];registration=r['registration']
    need(registration==owner[:4]+owner[7:14]+tls[6:8]+[tls[1]] and
         registration[:4]==[1,1,1,3] and registration[4]==registration[5]==pid and
         registration[-1]==1 and p['rseq']['counts'][6]>=checks,
         'last lease preserves the same actual default registration/pin/TLS identity and contributes real guards')
    return dict(attempts=r['attempts'],completed=r['completed'],traces=r['traces'],retained=r['retained'],
        closes=r['closes'],releases=r['releases'],queries=r['queries'],last_code=r['request'][2],
        last_initial_count=n,last_traces=traces,last_guard_checks=checks,source_module=binding['module'],
        source_file_offset=binding['file_offset'],custody_epoch=c[8],custody_invalidations=c[16])

def lease_source(p,raw,layout,result,record,images,image_bytes):
    rr=p['repeat_lease']
    pc,nxt,flags,mask,width=lease_request(rr)
    need(type(images)is list and type(image_bytes)is list and len(images)==len(image_bytes)==2,
         'same two independently authenticated complete original app images')
    root=record.View(raw,layout,'pao_record')
    biases=words(root.blob('module_bias'))
    need(biases==list(result['application']['header'][12:14])and len(biases)==2 and
         all(type(b)is int and 0<b<=MASK and b%4096==0 for b in biases),
         'actual full-reader module biases, never inferred from the REP report')
    modules=root.sub('bootstrap','pab_state').array('modules','pab_module')
    need(len(modules)==2,'same two trusted bootstrap bindings')
    captured=min(rr['request'][4],3);matches=[]
    for module,(data,image,bias)in enumerate(zip(image_bytes,images,biases,strict=True)):
        need(type(data)is bytes and len(data)==image['bytes']and H(data)==image['sha256']and len(data)>=64,
             'whole exact original ELF bytes already parsed by the unchanged app reader')
        h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
        need(h[0][:7]==b'\x7fELF\x02\x01\x01'and h[1:4]==(3,62,1)and h[8:10]==(64,56)and
             0<h[10]<=32 and h[5]<=len(data)and 56*h[10]<=len(data)-h[5],
             'actual bounded x86-64 PIE/DSO program headers')
        loads=[p for i in range(h[10])if (p:=struct.unpack_from('<IIQQQQQQ',data,h[5]+56*i))[0]==1]
        need(loads==image['loads'],'actual ELF headers equal the original accepted load metadata')
        for load in loads:
            _,prot,offset,va,_,size,memory,alignment=load
            need(size<=memory and offset<=len(data)and size<=len(data)-offset and
                 va<=MASK-memory and bias<=MASK-va-memory,
                 'bounded original ELF file and runtime load geometry')
            if prot!=5 or pc<bias+va or captured>size or pc-(bias+va)>size-captured:continue
            matches.append((module,data,image,bias,load,offset+pc-(bias+va)))
    need(len(matches)==1,'one actual file-backed RX load owns the retained REP source')
    module,data,image,bias,load,offset=matches[0]
    expected=data[offset:offset+captured]+bytes(3-captured)
    need(rr['request'][5]==int.from_bytes(expected,'little'),
         'all three emitted source bytes equal original ELF, including the actual following byte')
    _,prot,file_start,va,_,file_size,memory,_=load
    need(va<=image['page'] and image['page']-va<=file_size and
         4096<=file_size-(image['page']-va) and
         file_start+image['page']-va==image['page_offset']and
         (file_start&4095)==(va&4095),
         'REP and independently captured fixture page belong to the same original RX load')
    binding=modules[module].sub('binding','li2_effect_object_binding')
    need(binding.number('complete')==1 and binding.number('object_id')>0,
         'retained trusted sealed-object binding')
    sampled=[row for row in root.array('rows','pao_row')if row.number('module')==module]
    need(sampled,'independent actual source observations exist for this module')
    allocations=set()
    for row in sampled:
        page=row.sub('source','li2_fetch_page')
        need(page.number('address')==bias+image['page']and page.number('offset')==image['page_offset']and
             page.number('object')+1==binding.number('object_id')and page.number('backing')==1 and
             page.number('allocation')>0,
             'accepted sampled page connects actual allocation to the separate sealed object identity')
        allocations.add(page.number('allocation'))
    need(len(allocations)==1,'one actually observed RX allocation, not assumed equal to object ID')
    allocation=next(iter(allocations));first=bias+(va&~4095)
    end=(bias+va+memory+4095)&~4095
    need(end<=MASK,'bounded rounded actual source mapping')
    for i in range(rr['request'][7]):
        page=rr['source'];at=page[0]
        need(first<=at<end and page[1]==allocation and
             page[3]==(file_start&~4095)+at-first,
             'actual REP page allocation and file offset match that source mapping')
    return dict(module=module,image_sha256=H(data),file_offset=offset,emitted_bytes=expected.hex(),
        code=rr['request'][2],length=rr['request'][3],width=width,available=rr['request'][4],
        allocation=allocation,object_id=binding.number('object_id'),
        source_binding='original ELF plus accepted bias and independently sampled same-RX-load allocation')


def check(stderr,pid,exit_code,parent,raw,layout,result,record,images,image_bytes):
    need(type(pid)is int and pid>0 and type(exit_code)is int and exit_code==0 and
        result['pid']==pid,'actual successful app process and original binary reader identity')
    parsed=reports(stderr);shared.extensions(parsed)
    joined=binary_join(parsed,raw,layout,result,record)
    joined['repeat_source']=repeat_source(parsed,raw,layout,result,record,images,image_bytes)
    joined['repeat_lease_source']=lease_source(parsed,raw,layout,result,record,images,image_bytes)
    _,same,tty=gate(parsed,pid,exit_code,parent,joined['scripted_syscalls'])
    need(same is parsed,'actual reports are never normalized or rewritten')
    lease=shared.lease.counters(parsed);trace=shared.trace_completed(parsed)
    cache=shared.reuse_completed(parsed['run'],parsed['reuse'])
    retained=lease_completed(parsed,pid,joined['repeat_lease_source'],images)
    return parsed,dict(binary_join=joined,cache_reuse=cache,trace_run=trace,lease=lease,tty=tty,repeat_lease=retained,
        full_state_reader_unchanged=True,performance_credit=False)


def supplied_controls(stderr,pid,exit_code,parent,raw,layout,result,record,images,image_bytes):
    """Supplied report-only mutations after genuine acceptance; zero subjects."""
    accepted,_=check(stderr,pid,exit_code,parent,raw,layout,result,record,images,image_bytes)
    actual_hash=H(stderr);raw_hash=H(raw)
    cases=(
        ('generation','reuse','state',0,accepted['reuse']['state'][0]+1),
        ('handle_slot','reuse','current',1,(accepted['reuse']['current'][1]+1)%64),
        ('handle_attempt','reuse','current',3,0),
        ('completed_generation','reuse','last_completed',3,accepted['reuse']['last_completed'][3]+1),
        ('copied_count','reuse','last_completed',1,accepted['reuse']['last_completed'][1]+1),
        ('retired_completion','reuse','retirement',1,0),
        ('revoke_query','reuse','revoked',1,0),
        ('nx_permission','reuse','writable',7,7),
        ('cleanup_prefix','reuse','retirement',11,1),
        ('pending_lease','reuse','state',5,1),
        ('source_validation_passes','run','attempt',11,3),
        ('class_count','effect','classes',0,accepted['effect']['classes'][0]+1),
        ('scripted_count','effect','scripted_completed',None,accepted['effect']['scripted_completed']+1),
        ('exit_callback','effect','callback_returned',None,0),
        ('rseq_run_checks','rseq','counts',7,accepted['rseq']['counts'][7]+1),
        ('query_count','tcgets','commands',0,accepted['tcgets']['commands'][0]+1),
        ('forwarded_native_only','loader','forwarded',None,accepted['loader']['forwarded']+1),
        ('startup_query_returned','tcgets','query',1,0),
        ('startup_mount_complete','tcgets','mount',4,0),
    )
    if accepted['repeat']is not None:
        rr=accepted['repeat'];width=8 if rr['request'][2]==346 else 4
        initial=rr['progress'][0];direction=-1 if rr['request'][6]&0x400 else 1
        wrong=(rr['frames'][3]+direction*(12-width)*initial)&MASK
        if wrong==rr['frames'][10]:wrong=rr['frames'][10]^width
        cases+=(
            ('repeat_literal','repeat','request',5,rr['request'][5]^1),
            ('repeat_following_byte','repeat','request',5,rr['request'][5]^(1<<16)),
            ('repeat_next_pc','repeat','request',1,rr['request'][1]+1),
            ('repeat_element_width','repeat','frames',10,wrong),
            ('repeat_source_offset','repeat','source0',3,rr['source0'][3]+4096),
            ('repeat_source_allocation','repeat','source0',1,rr['source0'][1]+1),
            ('repeat_available','repeat','request',4,1),
            ('repeat_code_length','repeat','request',2,345 if rr['request'][2]==346 else 346),
        )
    rr=accepted['repeat_lease']
    cases+=(
        ('lease_literal','repeat_lease','request',5,rr['request'][5]^1),
        ('lease_following_byte','repeat_lease','request',5,rr['request'][5]^(1<<16)),
        ('lease_next_pc','repeat_lease','request',1,rr['request'][1]+1),
        ('lease_source_offset','repeat_lease','source',3,rr['source'][3]+4096),
        ('lease_source_allocation','repeat_lease','source',1,rr['source'][1]+1),
        ('lease_two_page','repeat_lease','request',7,2),
        ('lease_available','repeat_lease','request',4,1),
        ('lease_progress','repeat_lease','frames',10,rr['frames'][10]^4),
        ('lease_close','repeat_lease','closes',None,rr['closes']+1),
        ('lease_retained','repeat_lease','retained',None,rr['retained']+1),
        ('lease_release','repeat_lease','release',1,0),
        ('lease_revoke','repeat_lease','io',3,0),
        ('lease_final_query','repeat_lease','query',3,0),
        ('lease_ticket','repeat_lease','custody',4,1),
        ('lease_event_count','repeat_lease','custody',10,rr['custody'][10]+1),
        ('lease_return_count','repeat_lease','custody',14,rr['custody'][14]+1),
        ('lease_epoch','repeat_lease','custody',8,rr['custody'][8]+1),
        ('lease_borrow','repeat_lease','borrow',1,1),
        ('lease_rseq_checks','repeat_lease','progress',11,rr['progress'][11]+1),
        ('lease_write_checks','repeat_lease','writes',0,rr['writes'][0]+1),
        ('lease_registration','repeat_lease','registration',10,rr['registration'][10]+1),
        ('lease_seals','repeat_lease','backing',2,0),
        ('lease_elf_size','repeat_lease','backing',8,rr['backing'][8]+1),
        ('lease_event_kind','repeat_lease','event',7,1),
        ('lease_event_complete','repeat_lease','event',8,0),
    )
    prefixes=dict(reuse=b'LI2_RUN_REUSE ',run=b'LI2_RUN ',effect=b'LI2_SELECTED_EFFECT ',
                  rseq=b'LI2_RSEQ ',tcgets=b'LI2_RSEQ_BTRFS_TTY_QUERY ',loader=b'LI2_LOADER ',repeat=b'LI2_REPEAT ',repeat_lease=b'LI2_REPEAT_LEASE ')
    names=[]
    for name,key,field,index,value in cases:
        changed=copy.deepcopy(accepted[key]);before=changed[field]if index is None else changed[field][index]
        need(before!=value,'supplied mutation actually changes '+name)
        if index is None:changed[field]=value
        else:changed[field][index]=value
        prefix=prefixes[key];lines=stderr[:-1].split(b'\n');places=[i for i,line in enumerate(lines)if line.startswith(prefix)]
        need(len(places)==1,'one actual report mutation target')
        lines[places[0]]=prefix+json.dumps(changed,sort_keys=key!='repeat_lease',separators=(',',':'),allow_nan=False).encode()
        refused=False
        try:check(b'\n'.join(lines)+b'\n',pid,exit_code,parent,raw,layout,result,record,images,image_bytes)
        except ValueError:refused=True
        need(refused,'same complete reader refuses supplied '+name);names.append(name)
    need(H(stderr)==actual_hash and H(raw)==raw_hash,'actual stderr and whole binary record unchanged')
    return dict(scope='supplied report mutations after actual complete app lane',actual_subjects=0,
        stderr_sha256=actual_hash,record_sha256=raw_hash,refusals=names,native_qualification_credit=False)
