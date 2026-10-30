"""Three supported-cut required failures; never application-completion credit.

The distinct raw reader owns both real failed chronologies. This module joins
whole protected terminal rows, retains inherited input/gate/REP/owner guards,
and checks the source-derived completed17-syscall/67-CPUID prefix. The original
primitive/full profiles and their mutation populations remain unchanged.
"""
import copy,json
from page_selected import need
import linked_preedge_reports as primitive
prior=primitive.prior
old,reuse,unrolled,current,maps_view=prior.old,prior.reuse,prior.unrolled,prior.current,prior.maps_view
terminal,linked_base,H=prior.terminal,prior.linked_base,prior.H
OUTCOME=primitive.OUTCOME
# These are new supplied controls, separately scoped from old full26 controls.
PROTECTED=(
 ('linked_preedge','cut_exits',None),('linked_preedge','offers',None),('linked_preedge','closed',None),
 ('linked_preedge','entries',None),('linked_preedge','completed',None),('linked_preedge','refaults',None),
 ('linked_preedge','graph_refaults',None),('linked_preedge','active',None),('linked_preedge','busy',None),
 ('linked_preedge','transfer',0),('linked_preedge','transfer',1),('linked_preedge','transfer',19),
 ('linked_preedge','current',3),('linked_preedge','current',4),('linked_preedge','current',9),
 ('linked_preedge','current',11),('linked_preedge','current',12),('linked_preedge','current',13),
 ('linked_preedge','current',14),('linked_preedge','current',15),('linked_preedge','current',27),
 ('linked_preedge_reuse','permits_issued',None),('linked_preedge_reuse','claims',None),
 ('current_tf','commits',None),('chain','s0_generation',None),('chain','s1_generation',None),
 ('chain','unexpected',None),('chain','releases',None),('lease','lease_phase',None),
 ('native','closed',None),('native_pair','counts',3),('rseq','owner',3),('native_hint','hits',None))
EFFECT_TRIALS=(('stage',None),('busy',None),('finished',None),('phase',None),('native_returned',None),
 ('exit_entered',None),('post_guards_complete',None),('committed',None),('raw_returned',None),
 ('fp_after_initialized',None),('classes',6),('attempts',None))
CONTROL_COUNTS={(0,0):53,(1,0):53}


def split(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete cut-failure terminal stream')
    lines=stderr[:-1].split(b'\n');prefixes=(primitive.REUSE_PREFIX,primitive.PREFIX,terminal.HINT_PREFIX)
    need(len(lines)>3 and all(lines[-3+i].startswith(p)and sum(x.startswith(p)for x in lines)==1 for i,p in enumerate(prefixes))and
         not any(x.startswith((terminal.PREFIX,terminal.REUSE_PREFIX))for x in lines)and
         all(len(x)<=4096 and b'\r'not in x for x in lines[-3:]),'exact final v2 failure rows without legacy substitution')
    decode=maps_view.pair.pair_reports.rseq.decode
    retirement,linked,hint=(decode(line[len(prefix):])for prefix,line in zip(prefixes,lines[-3:],strict=True))
    for row,keys,arrays in((linked,primitive.KEYS,primitive.ARRAYS),(retirement,reuse.KEYS,{}),(hint,terminal.HINT_KEYS,{})):
        need(type(row)is dict and list(row)==keys and all(type(row[k])is int and 0<=row[k]<1<<64 for k in keys if k not in arrays),'whole typed ordered failure row')
        for k,n in arrays.items():need(type(row[k])is list and len(row[k])==n and all(type(v)is int and 0<=v<1<<64 for v in row[k]),'whole typed failure array')
    need(linked['version']==retirement['version']==2 and hint['version']==1,'distinct failure v2 schemas')
    for row,prefix,line in zip((retirement,linked,hint),prefixes,lines[-3:],strict=True):
        need(prefix+json.dumps(row,separators=(',',':'),allow_nan=False).encode()==line,'complete canonical failure terminal row')
    return linked,retirement,hint,b'\n'.join(lines[:-3])+b'\n'


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
    need([o['cpuid_patches']+67,o['syscall_patches']+17,o['rdtsc_patches']]==[l['cpuid'],l['syscalls'],l['rdtsc']]and
         o['published']==o['cpuid_patches']+o['syscall_patches']+o['rdtsc_patches']and
         o['generations']==l['generations']and o['retained_records']>0 and e['attempts']==o['published']+84,
         'exact17 direct syscalls and67 CPUID before either required failure')
    delta=l['generations']-o['retained_records']
    need(delta%2==0 and 2*o['published']<=delta<=4*o['published'],'actual two generation advances per restored source page')
    need(cp['hardware_entered']==cp['hardware_returned']==1 and cp['phase']==3 and
         cp['attempts']==cp['samples']==cp['commits']==l['cpuid']>0 and cp['next_pc']==cp['pc']+2 and cp['raw']==cp['result'],
         'complete unmodified hardware CPUID prefix')
    need(p['rseq']['owner'][1:4]==[0,0,0]and l['rseq']==0 and p['rseq']['counts'][:4]==[0,0,0,0],
         'no invented rseq registration or held registered owner')


def validate(parsed,view,pid,exit_status,parent,images,image_bytes,carrier,carrier_bytes,owner,owner_reader,mode):
    need(type(mode)is int and mode in(0,1)and type(exit_status)is int and exit_status==125 and
         type(owner['mode'])is int and owner['mode']==mode and type(owner['control'])is int and owner['control']==0,
         'only the two exact genuine required-failure subjects')
    expected=dict(status=125,failure_code=7 if mode==0 else 3103,detail_abs=11 if mode==0 else 9,detail_negative=0)
    need(all(all(row[k]==v for k,v in expected.items()if k in row)for row in
         (parsed['loader'],parsed['linked_preedge'],parsed['linked_preedge_reuse'],parsed['scalar_region'],parsed['scalar_reuse'],parsed['unrolled'],parsed['current_tf'],parsed['native_hint']))and owner['outcome']==expected,
         'all actual rows retain exact data-fault or revoke-failure outcome')
    joined=owner_reader.terminal(parsed,owner)
    span=parsed['linked_preedge'];scalar=parsed['scalar_region'];row=parsed['unrolled']
    # The raw reader proves failed ordinary and held linked states separately;
    # successful chain_quiet is not applicable to either required failure.
    _,same,gate=linked_base.gate(parsed,pid,125,parent,0,cache_completed=prior.prior_cache.completed)
    need(same is parsed and gate['original_completed_rejected']is True,'old successful completion rejects both actual target failures')
    prior.completed_tls(parsed);terminal.hint_native(span,parsed['native_hint'],parsed,finite=True)
    reuse.prior_unrolled(row);prior.prior_scalar(scalar,parsed['scalar_reuse'])
    need(scalar['events']==row['events']==span['events']and scalar['signals']==row['signals']==span['signals'],
         'both actual failure events pass all three owner preentry counters before abort')
    need(parsed['current_tf']['first_error']==parsed['current_tf']['first_detail_abs']==parsed['current_tf']['first_detail_negative']==0,
         'current custody remained error-free before the actual target failure')
    effect_prefix(parsed)
    return dict(application_completed=False,required_failure=1,mode=mode,gate=gate,terminal_join=joined,
        maps_view=view,repeat_lease=linked_base.repeat_completed(parsed,pid,images,image_bytes,carrier,carrier_bytes),
        input_authentication=prior.cost._retained_inputs(images,image_bytes,carrier,carrier_bytes),whole_profile_qualified=0)


def check(stderr,*args):
    span,retirement,hint,suffix=split(stderr)
    scalar,scalar_retirement,suffix=reuse.split(suffix);row,suffix=unrolled.split(suffix)
    current_row,suffix=current.split_current(suffix);view,original=maps_view.split_report(suffix,'maintained')
    parsed=old.reports(original);old.extensions(parsed)
    parsed.update(linked_preedge=span,linked_preedge_reuse=retirement,native_hint=hint,current_tf=current_row,
                  scalar_region=scalar,scalar_reuse=scalar_retirement,unrolled=row)
    return parsed,validate(parsed,view,*args)


def controls(stderr,*args):
    parsed,summary=check(stderr,*args);owner,owner_reader,mode=args[-3:];refused=[]
    # Isolate the actual whole-row join: each supplied numeric alteration must
    # be rejected for that exact protected row, with original capture unchanged.
    for row,key,index in PROTECTED:
        value=copy.deepcopy(parsed)
        if index is None:value[row][key]^=1
        else:value[row][key][index]^=1
        name='protected_'+row+'_'+key+(''if index is None else '_'+str(index))
        try:owner_reader.terminal(value,owner)
        except ValueError as error:
            need(str(error)=='entire actual protected terminal row '+row,'isolated exact protected-row refusal');refused.append(name)
        else:raise ValueError('accepted altered actual protected terminal row')
    for key,index in EFFECT_TRIALS:
        value=copy.deepcopy(parsed)
        if index is None:value['effect'][key]^=1
        else:value['effect'][key][index]^=1
        try:effect_prefix(value)
        except ValueError:refused.append('effect_'+key)
        else:raise ValueError('accepted altered completed-effect prefix')
    for name,row,key in(('direct_syscalls','oneshot','syscall_patches'),('direct_cpuid','oneshot','cpuid_patches'),
        ('publication_retire','oneshot','retired'),('last_machine_syscall','loader','last_syscall')):
        value=copy.deepcopy(parsed);value[row][key]^=1
        try:effect_prefix(value)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted altered source-derived effect census')
    lines=stderr[:-1].split(b'\n')
    for name,data in(('missing_v2',b'\n'.join(lines[:-2]+lines[-1:])+b'\n'),('truncated',stderr[:-1]),
        ('duplicate_hint',stderr+lines[-1]+b'\n'),('wrong_version',stderr.replace(b'LI2_LINKED_PREEDGE {"version":2,',b'LI2_LINKED_PREEDGE {"version":1,',1))):
        need(data!=stderr,'actual causal failure parser stimulus')
        try:split(data)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted altered complete failure stream')
    need(len(refused)==len(set(refused))==CONTROL_COUNTS[mode,0],'complete exact cut-failure terminal refusal population')
    return dict(refusals=refused,native_operations=0,original_stderr_sha256=H(stderr))
