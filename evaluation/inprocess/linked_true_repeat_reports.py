"""Explicit linked-true prior-registration REP contract, not unused-owner acceptance.

This is a terminal-report predicate. The exact retained interpreter recipe and
runtime completion records are checked; no full REP capture or memory-output
observation is invented. Old unused and registered-REP validators stay intact.
"""
import copy
import hashlib
import json

from page_selected import need
import page_cost_reports as cost
import scalar_span_trace_repeat_reports as prior

H=lambda value:hashlib.sha256(value).hexdigest()
PROFILE='linked-true-before-first-rseq-v1'
COMMON_CONTROL_COUNT=38  # 11 general + 6 inputs + 19 pair + 2 stdout/exit.
POSITIVE_CONTROL_COUNT=55
RECIPE=bytes.fromhex('31c0488d7c2488488d5608b934000000f348ab')
RECIPE_ERROR='linked true exact authenticated interpreter 52-element initializer recipe'
COUNT_ERROR='linked true one complete 52-element qword REP initializer'
STACK_ERROR='linked true exact forward 416-byte stack-relative initializer interval'
REGISTRATION_ERROR='linked true historical IDLE precedes one successful terminal registration'


def completed(p,pid,images,image_bytes,carrier,carrier_bytes):
    # Keep every inherited completed-lease/source/protection/progress/custody
    # and prior-IDLE registration assertion. This is never an accept-either
    # route for an empty, partial, failed or finally registered REP owner.
    result=prior.completed(p,pid,images,image_bytes,carrier,carrier_bytes)
    r=p['repeat_lease'];binding=result['source_binding'];i=binding['module']
    at=binding['file_offset'];data=image_bytes[i]
    need('interpreter'in images[i]['roles'] and at>=16 and
         at+3<=len(data) and data[at-16:at+3]==RECIPE,RECIPE_ERROR)
    need(r['attempts']==r['completed']==r['closes']==r['releases']==r['queries']==1 and
         r['request'][2:5]==[346,3,15] and
         r['progress'][0]==r['frames'][2]==52 and
         r['progress'][1]==r['frames'][9]==0,COUNT_ERROR)
    # The exact source describes RDI=RSP-120, ECX=52 and a forward STOSQ.
    # Do not predict undefined AF or infer the unreported stored RAX value.
    # The donor preserves all actual before/after flags including actual AF.
    f=r['frames'];flags=r['request'][6]
    need(flags&0x400==0 and f[4]>=120 and f[3]==f[4]-120 and
         f[3]<=(1<<64)-1-416 and f[10]==f[3]+416,STACK_ERROR)
    owner=p['rseq']['owner'];counts=p['rseq']['counts']
    need(r['registration']==[1,0,0,0,pid,pid]+[0]*8 and
         owner[:4]==[1,1,1,3] and owner[7:9]==[pid,pid] and owner[13]==1 and
         counts[:4]==[1,1,0,0] and counts[6]==0,REGISTRATION_ERROR)
    need(all(r[k]==0 for k in ('status','failure_code','detail_abs','detail_negative','route','pending')),
         'linked true completed REP accompanies actual successful quiescent exit')
    return dict(result,profile=PROFILE,source_recipe_bytes=RECIPE.hex(),elements=52,
        destination_bytes=416,scope='completed historical REP terminal report and exact external recipe',
        full_rep_frame_observation=False,rep_memory_output_observation=False,
        native_qualification_credit=False)


def mutations(p,pid,images,image_bytes,carrier,carrier_bytes):
    """Named positive-domain refusals; no unused-state control is relabelled."""
    trials=[]
    def add(name,changed,*,error=None,im=None,ib=None):
        trials.append((name,changed,images if im is None else im,
                       image_bytes if ib is None else ib,error))
    for name,row in prior.mutations(p):
        changed=copy.deepcopy(p);changed['repeat_lease']=row
        add(name,changed)
    for index in range(1,14):
        changed=copy.deepcopy(p);changed['repeat_lease']['registration'][index]+=1
        add('historical_registration_'+str(index),changed)
    for count in (0,51,53):
        changed=copy.deepcopy(p);r=changed['repeat_lease'];traces=max(count,1)
        r['traces']=traces;r['retained']=traces-1
        r['progress'][0]=count;r['progress'][2]=traces;r['progress'][3]=traces-1
        r['progress'][11]=traces+2;r['writes'][0]=traces+2
        r['frames'][2]=count;r['frames'][10]=r['frames'][3]+count*8
        for index in (10,12,13,14):r['custody'][index]=traces
        add('coherent_elements_'+str(count),changed,error=COUNT_ERROR)
    changed=copy.deepcopy(p);r=changed['repeat_lease']
    r['frames'][3]+=8;r['frames'][10]+=8
    add('coherent_destination_shift',changed,error=STACK_ERROR)
    changed=copy.deepcopy(p);r=changed['repeat_lease']
    r['request'][6]|=0x400;r['progress'][6]|=0x400
    r['frames'][1]|=0x400;r['frames'][8]|=0x400
    r['frames'][10]=r['frames'][3]-416
    add('coherent_reverse_direction',changed,error=STACK_ERROR)
    changed=copy.deepcopy(p);r=changed['repeat_lease']
    for key in ('attempts','completed','closes','releases','queries'):r[key]=2
    r['traces']*=2;r['retained']*=2
    for index in (9,11,15):r['custody'][index]=2
    for index in (12,13,14):r['custody'][index]=r['traces']
    r['custody'][8]=r['custody'][11]+r['custody'][15]+r['custody'][16]
    add('coherent_second_completed_lease',changed,error=COUNT_ERROR)
    changed=copy.deepcopy(p);r=changed['repeat_lease'];s=changed['rseq']
    r['registration']=s['owner'][:4]+s['owner'][7:14]+s['tls'][6:8]+[s['tls'][1]]
    add('historical_registration_replaced_by_terminal',changed)
    changed=copy.deepcopy(p);changed['rseq']['owner'][13]=2
    add('terminal_registration_epoch',changed,error=REGISTRATION_ERROR)
    changed=copy.deepcopy(p);changed['rseq']['owner'][13]=2
    changed['rseq']['counts'][:4]=[2,2,0,0]
    add('coherent_second_registration',changed,error=REGISTRATION_ERROR)
    changed=copy.deepcopy(p);changed['rseq']['counts'][6]=1
    add('invented_registered_repeat_check',changed)
    binding=prior.external_source(p,images,image_bytes,carrier,carrier_bytes)
    i=binding['module'];at=binding['file_offset']
    im=copy.deepcopy(images);ib=list(image_bytes);data=bytearray(ib[i])
    data[at-4]=51;ib[i]=bytes(data);im[i]['sha256']=H(ib[i])
    add('coherent_recipe_count_bytes',copy.deepcopy(p),error=RECIPE_ERROR,im=im,ib=ib)
    im=copy.deepcopy(images);im[i]['roles']=[role for role in im[i]['roles']if role!='interpreter']
    if not im[i]['roles']:im[i]['roles']=['supplied-noninterpreter']
    add('recipe_without_interpreter_role',copy.deepcopy(p),error=RECIPE_ERROR,im=im)
    im=copy.deepcopy(images);ib=list(image_bytes);data=bytearray(ib[i])
    data[at:at+3]=b'\xf3\xab\x90';ib[i]=bytes(data);im[i]['sha256']=H(ib[i])
    changed=copy.deepcopy(p);r=changed['repeat_lease'];nxt=r['request'][0]+2
    r['request'][1:4]=[nxt,345,2];r['request'][5]=int.from_bytes(b'\xf3\xab\x90','little')
    r['progress'][5]=nxt;r['frames'][7]=nxt;r['frames'][10]=r['frames'][3]+208
    r['event'][6]=nxt;r['query'][0]=nxt
    add('coherent_dword_instruction',changed,error=RECIPE_ERROR,im=im,ib=ib)
    need(len(trials)==len({name for name,*_ in trials})==POSITIVE_CONTROL_COUNT,
         'exact55 separately declared positive REP controls')
    return trials


def controls(stderr,pid,exit_code,parent,images,image_bytes,carrier,carrier_bytes,*,read,cache_completed):
    accepted,_=read(stderr,pid,exit_code,parent,images,image_bytes,carrier,carrier_bytes,workload='true')
    result=common_controls(stderr,pid,exit_code,parent,images,image_bytes,carrier,carrier_bytes,
                           workload='true',read=read,cache_completed=cache_completed)
    original_hash=H(stderr);names=[]
    for name,changed,im,ib,expected_error in mutations(accepted,pid,images,image_bytes,carrier,carrier_bytes):
        caught=False
        try:completed(changed,pid,im,ib,carrier,carrier_bytes)
        except ValueError as exc:caught=expected_error is None or str(exc)==expected_error
        need(caught,'exact positive REP cause '+name)
        lines=stderr[:-1].split(b'\n')
        for key,prefix in (('repeat_lease',b'LI2_REPEAT_LEASE '),('rseq',b'LI2_RSEQ ')):
            if changed[key]==accepted[key]:continue
            places=[i for i,line in enumerate(lines)if line.startswith(prefix)]
            need(len(places)==1,'one actual positive REP mutation target')
            lines[places[0]]=prefix+json.dumps(changed[key],separators=(',',':'),allow_nan=False).encode()
        altered=b'\n'.join(lines)+b'\n'
        need(altered!=stderr or im!=images or ib!=image_bytes,'actual positive REP stimulus changes its input')
        caught=False
        try:read(altered,pid,exit_code,parent,im,ib,carrier,carrier_bytes,workload='true')
        except ValueError:caught=True
        need(caught,'complete true reader rejects positive REP '+name);names.append(name)
    need(len(names)==len(set(names))==POSITIVE_CONTROL_COUNT and H(stderr)==original_hash,
         'separate55 positive REP refusals preserve the actual report')
    return dict(result,positive_repeat_refusals=names,positive_repeat_profile=PROFILE)


# BEGIN EXACT COMMON-CONTROL DONORS
def common_controls(stderr, pid, exit_code, parent, images, image_bytes, carrier, carrier_bytes, *, workload, read, cache_completed=None):
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
    need(len(cases)==11,'all eleven unchanged general terminal controls')
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
    # Retain every old complete-input and carrier control. Positive REP
    # source/registration/coherent controls are a separately named population.
    inputs=cost._retained_inputs(images,image_bytes,carrier,carrier_bytes)
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
    names.extend(cost._pair_controls(stderr,(pid,exit_code,parent,images,image_bytes,carrier,carrier_bytes),workload,read=read))
    need(len(names)==36, 'eleven general plus six input and nineteen pair refusals')
    need(hashlib.sha256(stderr).hexdigest()==actual_hash, 'actual report bytes unchanged')
    return dict(scope='supplied-reader mutations after actual completion',actual_subjects=0,
        original_stderr_sha256=actual_hash,refusals=names,native_qualification_credit=False)
