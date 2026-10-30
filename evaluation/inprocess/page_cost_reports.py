"""Exact terminal acceptance for the whole-process ls/true comparison.

The old ls/hot reader is unchanged. True requires positive pair/cache closure
and an initialized, entirely unused REP owner. It has no REP instruction or
source identity. Actual report fields and recorded state are never rewritten.
"""
import copy
from functools import partial
import hashlib
import json
import struct

from page_selected import need
import page_native_pair_reports as original
from page_selected_repeat_lease_app_reports import carrier_extent

H = lambda value: hashlib.sha256(value).hexdigest()


def _unused_repeat(parsed):
    """The actual initialized owner never armed; no completed REP credit."""
    r = parsed['repeat_lease']
    expected = dict.fromkeys(original.LEASE_SCALARS, 0)
    expected['version'] = 1
    for key, size in original.LEASE_ARRAYS.items():
        expected[key] = [0] * size
    expected['owner'][-1] = 1
    expected['custody'][0] = 1
    need(r == expected, 'entire unused REP report is canonical empty, with only initialization flags')
    need(parsed['repeat'] is None, 'true unused-REP profile has no legacy REP observation')
    return dict(scope='initialized unused REP owner', attempts=0, completed=0,
                traces=0, retained=0, closes=0, releases=0, queries=0,
                source_observed=False, native_qualification_credit=False)


def _retained_inputs(images, image_bytes, carrier, carrier_bytes):
    """Whole input identity/ELF checks, without inventing an unused REP source."""
    need(type(images)is list and type(image_bytes)is list and len(images)==len(image_bytes)>0,
         'complete independent external original/interpreter/dependency inputs')
    identities=set();main_rx=[];mask=(1<<64)-1
    for index,(image,data)in enumerate(zip(images,image_bytes,strict=True)):
        need(type(image)is dict and set(image)=={'bytes','sha256','roles'}and type(image['bytes'])is int and
             type(image['sha256'])is str and type(image['roles'])is list and image['roles'] and
             all(type(role)is str for role in image['roles']) and type(data)is bytes and
             len(data)==image['bytes'] and H(data)==image['sha256'] and len(data)>=64,
             'each exact retained external ELF identity and bytes')
        need(('original'in image['roles'])==(index==0),'one explicit original-main role at the first retained input')
        if index==0:
            need(type(carrier_bytes)is bytes and
                 len(carrier_bytes)==carrier_extent(carrier,image['bytes']) and H(carrier_bytes)==carrier['sha256'],
                 'whole exact carrier bytes independently built and joined to actual sealed launch')
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
            need(offset<=len(data)and size<=len(data)-offset and size<=memory and va<=mask-memory,
                 'complete actual external load extent')
            if prot!=5:continue
            need(align in(0,1)or align&(align-1)==0,'power-of-two actual ELF load alignment')
            need((offset&4095)==(va&4095),'file and virtual RX page offsets agree')
            if index==0:
                need(carrier_bytes[offset:offset+size]==data[offset:offset+size],
                     'actual carrier preserves the complete original main RX file-load bytes')
                main_rx.append((offset,size))
    need(any(size>0 for offset,size in main_rx), 'actual main has a nonempty RX file load')
    return dict(scope='whole input identities and ELF RX geometry only',
                inputs=len(images), main_rx_loads=main_rx,
                source_observed=False, allocation_mapping_provenance=False,
                aslr_bias_inferred=False, object_identity_inferred=False)


def check(stdout, stderr, pid, exit_code, parent, images, image_bytes, carrier,
          carrier_bytes, *, workload, cache_completed=None, chain_closure=None):
    """Return actual parsed rows and closure only after exact application output."""
    need(workload in ('ls', 'true'), 'explicit whole-process ls or true subject')
    need(type(stdout) is bytes and stdout == (b'.\n' if workload == 'ls' else b''),
         'complete exact real-program stdout')
    need(type(exit_code) is int and exit_code == 0, 'actual successful process required')
    if workload == 'ls':
        return original.check(stderr, pid, exit_code, parent, images, image_bytes,
                              carrier, carrier_bytes, workload='ls',cache_completed=cache_completed,chain_closure=chain_closure)

    parsed = original.reports(stderr)
    original.extensions(parsed)
    _, same, gate = original.gate(parsed, pid, exit_code, parent, 0,cache_completed=cache_completed,chain_closure=chain_closure)
    need(same is parsed, 'original actual true report values retained')
    lease = original.lease.counters(parsed)
    original.effect_exit(parsed)
    trace = original.trace_completed(parsed)
    retained = _unused_repeat(parsed)
    inputs = _retained_inputs(images, image_bytes, carrier, carrier_bytes)
    native, effect, oneshot = parsed['native'], parsed['effect'], parsed['oneshot']
    return parsed, dict(
        workload='true', application_completed=True,
        native_pair=original.pair_completed(parsed, pid),
        default_rseq_registered=parsed['rseq']['owner'][1] == 1,
        cache_reuse=(original.reuse_completed if cache_completed is None else cache_completed)(parsed['run'], parsed['reuse']),
        gate=gate, lease=lease, trace_run=trace, repeat_lease=retained,
        repeat_lease_source=None, legacy_repeat_source=None, input_authentication=inputs,
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


# The complete pair-control generator is retained. True's REP controls below
# exercise its exact unused-state contract, not fabricated completed REP rows.
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


def _terminal_controls(stderr, pid, exit_code, parent, images, image_bytes, carrier, carrier_bytes, *, workload, read, cache_completed=None):
    """Run only after this exact genuine report passed; no additional subject."""
    accepted, _ = read(stderr, pid, exit_code, parent, images, image_bytes, carrier, carrier_bytes,workload=workload)
    actual_hash = hashlib.sha256(stderr).hexdigest()
    cases = (
        ('generation', 'reuse', 'state', 0, accepted['reuse']['state'][0]+1),
        ('handle_slot', 'reuse', 'current', 1, (accepted['reuse']['current'][1]+1)%64),
        ('handle_attempt', 'reuse', 'current', 3, 0),
        ('completed_generation', 'reuse', 'last_completed', 3, accepted['reuse']['last_completed'][3]+1),
        ('copied_count', 'reuse', 'last_completed', 1, accepted['reuse']['last_completed'][1]+1),
        ('retired_completion', 'reuse', 'retirement', 1, 1 if cache_completed is not None and accepted['reuse']['retirement'][1]==0 else 0),
        ('revoke_query', 'reuse', 'revoked', 1, 1 if cache_completed is not None and accepted['reuse']['revoked'][1]==0 else 0),
        ('nx_permission', 'reuse', 'writable', 7, 7),
        ('cleanup_prefix', 'reuse', 'retirement', 11, 1),
        ('pending_lease', 'reuse', 'state', 5, 1),
        ('source_validation_passes', 'run', 'attempt', 11, 3),
    )
    rr=accepted['repeat_lease']
    # Mutate each actual scalar and every array element, including retained
    # unused tails and both initialization flags. No source/frame is invented
    # in the accepted baseline and no mutation is a native operation.
    cases+=tuple(('unused_lease_'+field,'repeat_lease',field,None,rr[field]^1)
                 for field in original.LEASE_SCALARS)
    cases+=tuple(('unused_lease_'+field+'_'+str(index),'repeat_lease',field,index,value^1)
                 for field in original.LEASE_ARRAYS for index,value in enumerate(rr[field]))
    need(len(cases)==191, 'eleven original general plus all 180 unused REP fields')
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
    # Every complete input and carrier remains authenticated. There is no
    # actual REP source to match, so input controls target actual identity,
    # ELF geometry, duplicate content and the original/carrier RX byte join.
    inputs=_retained_inputs(images,image_bytes,carrier,carrier_bytes)
    for name in ('external_identity','external_duplicate_identity','external_elf_magic',
                 'external_original_role','carrier_rx_byte','carrier_extent'):
        altered_images=copy.deepcopy(images);altered_bytes=list(image_bytes)
        altered_carrier=dict(carrier);altered_carrier_bytes=carrier_bytes
        if name in ('external_identity','external_elf_magic'):
            data=bytearray(altered_bytes[0]);data[0]^=1;altered_bytes[0]=bytes(data)
            if name=='external_elf_magic':altered_images[0]['sha256']=H(altered_bytes[0])
        elif name=='external_duplicate_identity':
            altered_images.append(dict(images[0],roles=['supplied-duplicate']))
            altered_bytes.append(image_bytes[0])
        elif name=='external_original_role':
            altered_images[0]['roles']=['supplied-nonoriginal']
        elif name=='carrier_rx_byte':
            offset=next(offset for offset,size in inputs['main_rx_loads'] if size>0)
            data=bytearray(carrier_bytes);data[offset]^=1;altered_carrier_bytes=bytes(data)
            altered_carrier['sha256']=H(altered_carrier_bytes)
        else:altered_carrier['bytes']+=1
        refused=False
        try:read(stderr,pid,exit_code,parent,altered_images,altered_bytes,
                 altered_carrier,altered_carrier_bytes,workload=workload)
        except ValueError:refused=True
        need(refused,'same complete reader refuses supplied '+name);names.append(name)
    names.extend(_pair_controls(stderr,(pid,exit_code,parent,images,image_bytes,carrier,carrier_bytes),workload,read=read))
    need(len(names)==216, '191 general/unused-field plus six input and nineteen pair refusals')
    need(hashlib.sha256(stderr).hexdigest()==actual_hash, 'actual report bytes unchanged')
    return dict(scope='supplied-reader mutations after actual completion',actual_subjects=0,
        original_stderr_sha256=actual_hash,refusals=names,native_qualification_credit=False)


def supplied_controls(stdout, stderr, pid, exit_code, parent, images,
                      image_bytes, carrier, carrier_bytes, *, workload, cache_completed=None, chain_closure=None):
    """Supplied changes to accepted actual evidence; no additional native credit."""
    args = (pid, exit_code, parent, images, image_bytes, carrier, carrier_bytes)
    check(stdout, stderr, *args, workload=workload,cache_completed=cache_completed,chain_closure=chain_closure)
    actual_stdout, actual_stderr = H(stdout), H(stderr)
    if workload == 'ls':
        result = original.supplied_controls(stderr, *args, workload='ls',cache_completed=cache_completed,chain_closure=chain_closure)
    else:
        result = _terminal_controls(stderr, *args, workload='true', cache_completed=cache_completed,
                                    read=partial(check, stdout, cache_completed=cache_completed,chain_closure=chain_closure))
    names = list(result['refusals'])
    for name, changed_stdout, changed_exit in (
            ('unexpected_stdout', stdout + b'!', exit_code),
            ('nonzero_exit', stdout, 125)):
        refused = False
        try:
            check(changed_stdout, stderr, pid, changed_exit, parent, images,
                  image_bytes, carrier, carrier_bytes, workload=workload,cache_completed=cache_completed,chain_closure=chain_closure)
        except ValueError:
            refused = True
        need(refused, 'same complete reader refuses supplied ' + name)
        names.append(name)
    need(len(names) == len(set(names)), 'unique supplied terminal controls')
    need(H(stdout) == actual_stdout and H(stderr) == actual_stderr,
         'actual application output and complete report bytes unchanged')
    return dict(result, scope='supplied report/input/output mutations after actual completion',
                original_stdout_sha256=actual_stdout, refusals=names)
