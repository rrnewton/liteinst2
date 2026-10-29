"""Real-LS closure with a distinct REP lease and limited external-file join.

The unchanged LS gate validates the actual unmodified parsed rows. The new
last-source match is file-byte/segment consistency only: it grants no mapping,
ASLR bias, allocation, object-ID or full-state observation authority.
"""
import copy,hashlib,json,struct
from page_selected import need
import page_selected_run_reuse_ls_reports as original
from page_selected_repeat_lease_app_reports import reports,lease_request,lease_completed
from page_selected_run_reuse_ls_reports import (extensions,gate,lease,effect_exit,
    trace_completed,reuse_completed)
MASK=(1<<64)-1
H=lambda b:hashlib.sha256(b).hexdigest()

def external_source(p,images,image_bytes):
    r=p['repeat_lease'];pc,nxt,flags,mask,width=lease_request(r)
    need(type(images)is list and type(image_bytes)is list and len(images)==len(image_bytes)>0,
         'complete independent external original/interpreter/dependency inputs')
    source=r['source'];within=pc-source[0];captured=min(r['request'][4],3)
    need(0<=within<4096 and source[3]<=MASK-within,'bounded source file-page plus PC-in-page offset')
    site=source[3]+within;matches=[];identities=set()
    for index,(image,data)in enumerate(zip(images,image_bytes,strict=True)):
        need(type(image)is dict and set(image)=={'bytes','sha256','roles'}and type(image['bytes'])is int and
             type(image['sha256'])is str and type(image['roles'])is list and image['roles'] and
             all(type(role)is str for role in image['roles']) and type(data)is bytes and
             len(data)==image['bytes'] and H(data)==image['sha256'] and len(data)>=64,
             'each exact retained external ELF identity and bytes')
        need(image['sha256']not in identities,'one retained input per complete external content identity')
        identities.add(image['sha256'])
        h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
        need(h[0][:7]==b'\x7fELF\x02\x01\x01'and h[1]in(2,3)and h[2:4]==(62,1)and
             h[8:10]==(64,56)and 0<h[10]<=32 and h[5]<=len(data)and 56*h[10]<=len(data)-h[5],
             'bounded actual x86-64 external ELF program headers')
        for i in range(h[10]):
            load=struct.unpack_from('<IIQQQQQQ',data,h[5]+56*i)
            if load[0]!=1:continue
            _,prot,offset,va,_,size,memory,align=load
            need(offset<=len(data)and size<=len(data)-offset and size<=memory and va<=MASK-memory,
                 'complete actual external load extent')
            if prot!=5 or image['bytes']!=r['backing'][8]:continue
            need(align in(0,1)or align&(align-1)==0,'power-of-two actual ELF load alignment')
            need((offset&4095)==(va&4095),'file and virtual RX page offsets agree')
            if site<offset or captured>size or site-offset>size-captured:continue
            if not (offset&~4095)<=source[3]<((offset+size+4095)&~4095):continue
            if len(data)>MASK-4095 or source[3]>=((len(data)+4095)&~4095):continue
            expected=data[site:site+captured]+bytes(3-captured)
            if int.from_bytes(expected,'little')!=r['request'][5]:continue
            matches.append(dict(module=index,file_offset=site,roles=image['roles'],image_sha256=image['sha256'],
                image_bytes=image['bytes'],load_file_offset=offset,load_file_bytes=size,
                source_file_page=source[3],emitted_bytes=expected.hex()))
    need(len(matches)==1,'one complete retained RX file-load candidate matches actual size/offset/instruction bytes')
    result=matches[0]
    result.update(scope='external file bytes and RX segment geometry only',
        allocation_mapping_provenance=False,aslr_bias_inferred=False,object_identity_inferred=False)
    return result

def check(stderr,pid,exit_code,parent,images,image_bytes):
    need(type(exit_code)is int and exit_code==0,'actual successful process required')
    p=reports(stderr);extensions(p)
    _,same,gate_summary=gate(p,pid,exit_code,parent)
    need(same is p,'original actual report values retained')
    lease_summary=lease.counters(p);effect_exit(p)
    trace_summary=trace_completed(p)
    binding=external_source(p,images,image_bytes)
    retained=lease_completed(p,pid,binding,images)
    n=p['native'];e=p['effect'];o=p['oneshot']
    return p,dict(application_completed=True,default_rseq_registered=True,cache_reuse=reuse_completed(p['run'],p['reuse']),gate=gate_summary,lease=lease_summary,trace_run=trace_summary,repeat_lease=retained,repeat_lease_source=binding,
        selected=dict(attempts=e['attempts'],completed=e['completed'],classes=e['classes'],unreturned_exit=1),
        publication={k:o[k]for k in('attempted','published','restored','completed','retired','refused','cpuid_patches','syscall_patches','rdtsc_patches','rseq_attempts','rseq_retired','retained_records','generations')},
        native={k:n[k]for k in('attempts','admissions','closed','blocked','epoch_exits','refaults','main_admissions','main_refaults')},
        admission_timing=dict(first_admission_ns=n['first_admission_ns'],first_source_offset=n['first_source_offset'],revisit_count=n['revisit_count'],revisit_ns=n['revisit_ns']))


def supplied_controls(stderr, pid, exit_code, parent, images, image_bytes):
    """Run only after this exact genuine report passed; no additional subject."""
    accepted, _ = check(stderr, pid, exit_code, parent, images, image_bytes)
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
    names=[]
    for name, key, field, index, value in cases:
        changed=copy.deepcopy(accepted[key])
        before=changed[field]if index is None else changed[field][index]
        need(before!=value, 'supplied mutation actually changes '+name)
        if index is None:changed[field]=value
        else:changed[field][index]=value
        prefix={"reuse":b'LI2_RUN_REUSE ',"run":b'LI2_RUN ',"repeat_lease":b'LI2_REPEAT_LEASE '}[key]
        lines=stderr[:-1].split(b'\n')
        places=[i for i,line in enumerate(lines)if line.startswith(prefix)]
        need(len(places)==1, 'one exact original mutation target')
        lines[places[0]]=prefix+json.dumps(changed,sort_keys=key!='repeat_lease',separators=(',',':'),allow_nan=False).encode()
        refused=False
        try:check(b'\n'.join(lines)+b'\n',pid,exit_code,parent,images,image_bytes)
        except ValueError:refused=True
        need(refused, 'same complete reader refuses supplied '+name)
        names.append(name)
    # Supplied external-input changes exercise the limited byte join, not
    # actual native events or changes to the retained production evidence.
    binding=external_source(accepted,images,image_bytes)
    for name in ('external_instruction_byte','external_duplicate_candidate'):
        altered_images=copy.deepcopy(images);altered_bytes=list(image_bytes)
        if name=='external_instruction_byte':
            i=binding['module'];data=bytearray(altered_bytes[i]);data[binding['file_offset']]^=1
            altered_bytes[i]=bytes(data);altered_images[i]['sha256']=H(altered_bytes[i])
        else:
            altered_images.append(copy.deepcopy(images[binding['module']]))
            altered_bytes.append(image_bytes[binding['module']])
        refused=False
        try:check(stderr,pid,exit_code,parent,altered_images,altered_bytes)
        except ValueError:refused=True
        need(refused,'same complete reader refuses supplied '+name);names.append(name)
    need(hashlib.sha256(stderr).hexdigest()==actual_hash, 'actual report bytes unchanged')
    return dict(scope='supplied-reader mutations after actual completion',actual_subjects=0,
        original_stderr_sha256=actual_hash,refusals=names,native_qualification_credit=False)
