"""Exact terminal acceptance for the whole-process ls/true comparison.

The old ls/hot reader is unchanged. True is a separate named profile and
inherits its positive pair/REP/cache requirements: an exit0 without those
proofs remains unsupported. No report field or recorded state is rewritten.
"""
import copy
from functools import partial
import hashlib
import json

from page_selected import need
import page_native_pair_reports as original
from page_native_pair_reports import external_source, legacy_source

H = lambda value: hashlib.sha256(value).hexdigest()


def check(stdout, stderr, pid, exit_code, parent, images, image_bytes, carrier,
          carrier_bytes, *, workload):
    """Return actual parsed rows and closure only after exact application output."""
    need(workload in ('ls', 'true'), 'explicit whole-process ls or true subject')
    need(type(stdout) is bytes and stdout == (b'.\n' if workload == 'ls' else b''),
         'complete exact real-program stdout')
    need(type(exit_code) is int and exit_code == 0, 'actual successful process required')
    if workload == 'ls':
        return original.check(stderr, pid, exit_code, parent, images, image_bytes,
                              carrier, carrier_bytes, workload='ls')

    parsed = original.reports(stderr)
    original.extensions(parsed)
    _, same, gate = original.gate(parsed, pid, exit_code, parent, 0)
    need(same is parsed, 'original actual true report values retained')
    lease = original.lease.counters(parsed)
    original.effect_exit(parsed)
    trace = original.trace_completed(parsed)
    binding = external_source(parsed, images, image_bytes, carrier, carrier_bytes)
    retained = original.lease_completed(parsed, pid, binding, images, carrier)
    legacy = legacy_source(parsed, images, image_bytes)
    native, effect, oneshot = parsed['native'], parsed['effect'], parsed['oneshot']
    return parsed, dict(
        workload='true', application_completed=True,
        native_pair=original.pair_completed(parsed, pid),
        default_rseq_registered=parsed['rseq']['owner'][1] == 1,
        cache_reuse=original.reuse_completed(parsed['run'], parsed['reuse']),
        gate=gate, lease=lease, trace_run=trace, repeat_lease=retained,
        repeat_lease_source=binding, legacy_repeat_source=legacy,
        selected=dict(attempts=effect['attempts'], completed=effect['completed'],
                      classes=effect['classes'], unreturned_exit=1),
        publication={k: oneshot[k] for k in (
            'attempted', 'published', 'restored', 'completed', 'retired', 'refused',
            'cpuid_patches', 'syscall_patches', 'rdtsc_patches', 'rseq_attempts',
            'rseq_retired', 'retained_records', 'generations')},
        native={k: native[k] for k in (
            'attempts', 'admissions', 'closed', 'blocked', 'epoch_exits',
            'refaults', 'main_admissions', 'main_refaults')},
        admission_timing=dict(first_admission_ns=native['first_admission_ns'],
            first_source_offset=native['first_source_offset'],
            revisit_count=native['revisit_count'], revisit_ns=native['revisit_ns']))


# Exact donor mutation generators, with a reader callable instead of binding
# their global ls/hot check. Their actual records and predicates are preserved.
def _pair_controls(stderr, args, workload, *, read):
    accepted,_=read(stderr,*args,workload=workload);actual_hash=H(stderr)
    p=accepted['native_pair']
    cases=[('pair_live','control',6,1),('pair_pending','control',7,1),
        ('pair_closed','counts',3,p['counts'][3]+1),('pair_two_closes','counts',5,p['counts'][5]+1),
        ('pair_refault','counts',9,p['counts'][9]+1),('pair_publications','lifecycle',12,p['lifecycle'][12]+1),
        ('pair_close_calls','lifecycle',14,p['lifecycle'][14]+1),('pair_rseq_active','rseq',2,1),
        ('pair_rseq_refresh','rseq',15,p['rseq'][15]+1),('pair_word','rseq',24,1),
        ('pair_pin_complete','pin_after',4,0 if p['pin_after'][4]else 1),
        ('pair_close_complete','close',7,0),('pair_nx_code','last_nx',1,1)]
    for slot,s in enumerate(p['slots']):
        if s!=[0]*26:
            cases.extend((('pair_slot_allocation','slots',(slot,5),0),
                ('pair_slot_generation','slots',(slot,6),0),
                ('pair_slot_window','slots',(slot,15),s[15]-1),
                ('pair_slot_seals','slots',(slot,18),0)))
            break
    names=[]
    for name,key,index,value in cases:
        changed=copy.deepcopy(p)
        target=changed[key][index[0]]if type(index)is tuple else changed[key]
        at=index[1]if type(index)is tuple else index
        need(target[at]!=value,'actual supplied pair mutation '+name);target[at]=value
        lines=stderr[:-1].split(b'\n');prefix=b'LI2_NATIVE_PAIR '
        places=[i for i,line in enumerate(lines)if line.startswith(prefix)]
        need(len(places)==1,'one exact native-pair report')
        lines[places[0]]=prefix+json.dumps(changed,separators=(',',':'),allow_nan=False).encode()
        refused=False
        try:read(b'\n'.join(lines)+b'\n',*args,workload=workload)
        except ValueError:refused=True
        need(refused,'same complete reader refuses supplied '+name);names.append(name)
    original=stderr[:-1].split(b'\n');prefix=b'LI2_NATIVE_PAIR '
    index=next(i for i,line in enumerate(original)if line.startswith(prefix))
    for name,changed in(('pair_missing_row',original[:index]+original[index+1:]),
                         ('pair_duplicate_row',original[:index]+[original[index]]+original[index:])):
        refused=False
        try:read(b'\n'.join(changed)+b'\n',*args,workload=workload)
        except ValueError:refused=True
        need(refused,'complete actual row order refuses supplied '+name);names.append(name)
    need(H(stderr)==actual_hash,'original complete pair stderr remains unchanged')
    return names


def _terminal_controls(stderr, pid, exit_code, parent, images, image_bytes, carrier, carrier_bytes, *, workload, read):
    """Run only after this exact genuine report passed; no additional subject."""
    accepted, _ = read(stderr, pid, exit_code, parent, images, image_bytes, carrier, carrier_bytes,workload=workload)
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
    if workload=='true'and accepted['repeat']is not None:
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
        try:read(b'\n'.join(lines)+b'\n',pid,exit_code,parent,images,image_bytes,carrier,carrier_bytes,workload=workload)
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
        try:read(stderr,pid,exit_code,parent,altered_images,altered_bytes,carrier,carrier_bytes,workload=workload)
        except ValueError:refused=True
        need(refused,'same complete reader refuses supplied '+name);names.append(name)
    changed_carrier=dict(carrier,bytes=carrier['bytes']+1);refused=False
    try:read(stderr,pid,exit_code,parent,images,image_bytes,changed_carrier,carrier_bytes,workload=workload)
    except ValueError:refused=True
    need(refused,'same complete reader refuses supplied mismatched carrier extent');names.append('carrier_extent')
    legacy=legacy_source(accepted,images,image_bytes)if workload=='true'else None
    if legacy is not None:
        altered_images=copy.deepcopy(images);altered_bytes=list(image_bytes)
        i=legacy['module'];data=bytearray(altered_bytes[i]);data[legacy['file_offset']]^=1
        altered_bytes[i]=bytes(data);altered_images[i]['sha256']=H(altered_bytes[i])
        refused=False
        try:read(stderr,pid,exit_code,parent,altered_images,altered_bytes,carrier,carrier_bytes,workload=workload)
        except ValueError:refused=True
        need(refused,'same complete reader refuses supplied legacy external instruction byte')
        names.append('legacy_external_instruction_byte')
    names.extend(_pair_controls(stderr,(pid,exit_code,parent,images,image_bytes,carrier,carrier_bytes),workload,read=read))
    need(hashlib.sha256(stderr).hexdigest()==actual_hash, 'actual report bytes unchanged')
    return dict(scope='supplied-reader mutations after actual completion',actual_subjects=0,
        original_stderr_sha256=actual_hash,refusals=names,native_qualification_credit=False)


def supplied_controls(stdout, stderr, pid, exit_code, parent, images,
                      image_bytes, carrier, carrier_bytes, *, workload):
    """Supplied changes to accepted actual evidence; no additional native credit."""
    args = (pid, exit_code, parent, images, image_bytes, carrier, carrier_bytes)
    check(stdout, stderr, *args, workload=workload)
    actual_stdout, actual_stderr = H(stdout), H(stderr)
    if workload == 'ls':
        result = original.supplied_controls(stderr, *args, workload='ls')
    else:
        result = _terminal_controls(stderr, *args, workload='true',
                                    read=partial(check, stdout))
    names = list(result['refusals'])
    for name, changed_stdout, changed_exit in (
            ('unexpected_stdout', stdout + b'!', exit_code),
            ('nonzero_exit', stdout, 125)):
        refused = False
        try:
            check(changed_stdout, stderr, pid, changed_exit, parent, images,
                  image_bytes, carrier, carrier_bytes, workload=workload)
        except ValueError:
            refused = True
        need(refused, 'same complete reader refuses supplied ' + name)
        names.append(name)
    need(len(names) == len(set(names)), 'unique supplied terminal controls')
    need(H(stdout) == actual_stdout and H(stderr) == actual_stderr,
         'actual application output and complete report bytes unchanged')
    return dict(result, scope='supplied report/input/output mutations after actual completion',
                original_stdout_sha256=actual_stdout, refusals=names)
