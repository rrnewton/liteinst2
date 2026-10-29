"""Current release late-DSO terminal reports, with the general application gate.

The enclosing evaluator first checks the full fixed native/gated live records.
This leaf preserves the complete current report schema and successful runtime
closure predicates, including the real unreturned exit. Its external file-byte
join provides no mapping, ASLR, controller-frame or loader-unmap authority.
It requires actual cache reuse and a completed REP lease in this finite cohort.
"""
import copy,hashlib,json,struct
from page_selected import need
from page_selected_repeat_lease_app_reports import reports,lease_completed
from page_selected_repeat_lease_ls_reports import external_source
from page_selected_run_reuse_app_reports import gate,repeat_request
from page_selected_run_reuse_ls_reports import (extensions,lease,effect_exit,
    trace_completed,reuse_completed)

H=lambda b:hashlib.sha256(b).hexdigest()

def legacy_source(p,images,image_bytes):
    """Optional old REP: exact external bytes only, without mapping authority."""
    r=p['repeat']
    if r is None:return None
    pc,nxt,flags,mask,width=repeat_request(r)
    count=r['request'][7];captured=min(r['request'][4],3)
    source=r['source0'];within=pc-source[0]
    need(0<=within<4096 and source[3]<=(1<<64)-1-within,
         'bounded actual legacy source page and original-PC offset')
    site=source[3]+within
    need(site<=(1<<64)-1-captured,'bounded actual legacy captured-byte extent')
    for i in range(count):
        need(r['source'+str(i)][3]==source[3]+4096*i and source[3]+4096*i<1<<64,
             'actual legacy source fragments have contiguous file-page offsets')
    # check() already authenticated every complete image/PHDR and the actual
    # carrier, including whole original-main RX slices, through external_source.
    matches=[]
    for index,(image,data)in enumerate(zip(images,image_bytes,strict=True)):
        need(type(data)is bytes and len(data)==image['bytes']and H(data)==image['sha256'],
             'same complete authenticated external ELF for legacy byte join')
        h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
        for i in range(h[10]):
            load=struct.unpack_from('<IIQQQQQQ',data,h[5]+56*i)
            if load[0]!=1 or load[1]!=5:continue
            _,_,offset,va,_,size,memory,align=load
            need((align in(0,1)or align&(align-1)==0)and (offset&4095)==(va&4095),
                 'actual legacy RX load alignment and file/virtual page congruence')
            if site<offset or captured>size or site-offset>size-captured:continue
            if not all((offset&~4095)<=r['source'+str(j)][3]<((offset+size+4095)&~4095)
                       for j in range(count)):continue
            expected=data[site:site+captured]+bytes(3-captured)
            if int.from_bytes(expected,'little')!=r['request'][5]:continue
            matches.append(dict(module=index,file_offset=site,roles=image['roles'],
                image_sha256=image['sha256'],image_bytes=image['bytes'],
                load_file_offset=offset,load_file_bytes=size,source_pages=count,
                source_file_pages=[r['source'+str(j)][3]for j in range(count)],
                emitted_bytes=expected.hex()))
    need(len(matches)==1,'one complete external RX candidate matches all actual legacy REP captured bytes and file pages')
    result=matches[0]
    result.update(scope='external file bytes and RX segment geometry only',
        allocation_mapping_provenance=False,aslr_bias_inferred=False,object_identity_inferred=False)
    return result


def check(stderr,pid,exit_code,parent,images,image_bytes,carrier,carrier_bytes):
    need(type(exit_code)is int and exit_code==0,'actual successful process required')
    p=reports(stderr);extensions(p)
    _,same,gate_summary=gate(p,pid,exit_code,parent,0)
    need(same is p,'original actual report values retained')
    lease_summary=lease.counters(p);effect_exit(p)
    trace_summary=trace_completed(p)
    binding=external_source(p,images,image_bytes,carrier,carrier_bytes)
    retained=lease_completed(p,pid,binding,images,carrier)
    legacy=legacy_source(p,images,image_bytes)
    n=p['native'];e=p['effect'];o=p['oneshot']
    return p,dict(application_completed=True,default_rseq_registered=True,cache_reuse=reuse_completed(p['run'],p['reuse']),gate=gate_summary,lease=lease_summary,trace_run=trace_summary,repeat_lease=retained,repeat_lease_source=binding,legacy_repeat_source=legacy,
        selected=dict(attempts=e['attempts'],completed=e['completed'],classes=e['classes'],unreturned_exit=1),
        publication={k:o[k]for k in('attempted','published','restored','completed','retired','refused','cpuid_patches','syscall_patches','rdtsc_patches','rseq_attempts','rseq_retired','retained_records','generations')},
        native={k:n[k]for k in('attempts','admissions','closed','blocked','epoch_exits','refaults','main_admissions','main_refaults')},
        admission_timing=dict(first_admission_ns=n['first_admission_ns'],first_source_offset=n['first_source_offset'],revisit_count=n['revisit_count'],revisit_ns=n['revisit_ns']))



def supplied_controls(stderr, pid, exit_code, parent, images, image_bytes, carrier, carrier_bytes):
    """Run only after this exact genuine report passed; no additional subject."""
    accepted, _ = check(stderr, pid, exit_code, parent, images, image_bytes, carrier, carrier_bytes)
    actual_hash = hashlib.sha256(stderr).hexdigest()
    cases = (
        ('generation', 'reuse', 'state', 0, accepted['reuse']['state'][0]+1),
        ('handle_slot', 'reuse', 'current', 1, (accepted['reuse']['current'][1]+1)%64),
        ('handle_attempt', 'reuse', 'current', 3, 0),
        ('completed_generation', 'reuse', 'last_completed', 3, accepted['reuse']['last_completed'][3]+1),
        ('copied_count', 'reuse', 'last_completed', 1, accepted['reuse']['last_completed'][1]+1),
        ('retired_completion', 'reuse', 'retirement', 1, 0),
        ('revoke_query', 'reuse', 'revoked', 1, 0),
        ('nx_permission', 'reuse', 'writable', 7, 7),
        ('cleanup_prefix', 'reuse', 'retirement', 11, 1),
        ('pending_lease', 'reuse', 'state', 5, 1),
        ('source_validation_passes', 'run', 'attempt', 11, 3),
    )
    rr=accepted['repeat_lease']
    cases+=(
        ('lease_literal','repeat_lease','request',5,rr['request'][5]^1),
        ('lease_following_byte','repeat_lease','request',5,rr['request'][5]^(1<<16)),
        ('lease_next_pc','repeat_lease','request',1,rr['request'][1]+1),
        ('lease_source_offset_alignment','repeat_lease','source',3,rr['source'][3]+1),
        ('lease_source_allocation_zero','repeat_lease','source',1,0),
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
    if accepted['repeat']is not None:
        cases+=(('legacy_rep_captured_byte','repeat','request',5,accepted['repeat']['request'][5]^(1<<16)),
                ('legacy_rep_file_page','repeat','source0',3,accepted['repeat']['source0'][3]+1))
    names=[]
    for name, key, field, index, value in cases:
        changed=copy.deepcopy(accepted[key])
        before=changed[field]if index is None else changed[field][index]
        need(before!=value, 'supplied mutation actually changes '+name)
        if index is None:changed[field]=value
        else:changed[field][index]=value
        prefix={"reuse":b'LI2_RUN_REUSE ',"run":b'LI2_RUN ',"repeat_lease":b'LI2_REPEAT_LEASE ',"repeat":b'LI2_REPEAT '}[key]
        lines=stderr[:-1].split(b'\n')
        places=[i for i,line in enumerate(lines)if line.startswith(prefix)]
        need(len(places)==1, 'one exact original mutation target')
        lines[places[0]]=prefix+json.dumps(changed,sort_keys=key!='repeat_lease',separators=(',',':'),allow_nan=False).encode()
        refused=False
        try:check(b'\n'.join(lines)+b'\n',pid,exit_code,parent,images,image_bytes,carrier,carrier_bytes)
        except ValueError:refused=True
        need(refused, 'same complete reader refuses supplied '+name)
        names.append(name)
    # Supplied external-input changes exercise the limited byte join, not
    # actual native events or changes to the retained production evidence.
    binding=external_source(accepted,images,image_bytes,carrier,carrier_bytes)
    for name in ('external_instruction_byte','external_duplicate_candidate'):
        altered_images=copy.deepcopy(images);altered_bytes=list(image_bytes)
        if name=='external_instruction_byte':
            i=binding['module'];data=bytearray(altered_bytes[i]);data[binding['file_offset']]^=1
            altered_bytes[i]=bytes(data);altered_images[i]['sha256']=H(altered_bytes[i])
        else:
            altered_images.append(copy.deepcopy(images[binding['module']]))
            altered_bytes.append(image_bytes[binding['module']])
        refused=False
        try:check(stderr,pid,exit_code,parent,altered_images,altered_bytes,carrier,carrier_bytes)
        except ValueError:refused=True
        need(refused,'same complete reader refuses supplied '+name);names.append(name)
    changed_carrier=dict(carrier,bytes=carrier['bytes']+1);refused=False
    try:check(stderr,pid,exit_code,parent,images,image_bytes,changed_carrier,carrier_bytes)
    except ValueError:refused=True
    need(refused,'same complete reader refuses supplied mismatched carrier extent');names.append('carrier_extent')
    legacy=legacy_source(accepted,images,image_bytes)
    if legacy is not None:
        altered_images=copy.deepcopy(images);altered_bytes=list(image_bytes)
        i=legacy['module'];data=bytearray(altered_bytes[i]);data[legacy['file_offset']]^=1
        altered_bytes[i]=bytes(data);altered_images[i]['sha256']=H(altered_bytes[i])
        refused=False
        try:check(stderr,pid,exit_code,parent,altered_images,altered_bytes,carrier,carrier_bytes)
        except ValueError:refused=True
        need(refused,'same complete reader refuses supplied legacy external instruction byte')
        names.append('legacy_external_instruction_byte')
    need(hashlib.sha256(stderr).hexdigest()==actual_hash, 'actual report bytes unchanged')
    return dict(scope='supplied-reader mutations after actual completion',actual_subjects=0,
        original_stderr_sha256=actual_hash,refusals=names,native_qualification_credit=False)
