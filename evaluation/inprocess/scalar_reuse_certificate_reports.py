"""Distinct generation-certificate terminal accounting; no owner proof by itself.

The protected actual certificate capture must qualify before terminal(). The
original scalar/reuse report modules remain unchanged. Full actual failure
prefixes remain failures; success equations reflect the new proof callsites.
"""
import copy,json
from page_selected import need
import scalar_reuse_reports as donor
old=donor.old
H,maps_view,cost,unrolled=donor.H,donor.maps_view,donor.cost,donor.unrolled
prior=donor.prior
prior_unrolled,unused_repeat,application_effect_exit=donor.prior_unrolled,donor.unused_repeat,donor.application_effect_exit
COUNTERS,KEYS,PREFIX=donor.COUNTERS,donor.KEYS,donor.PREFIX
CERTIFICATE_PREFIX=b'LI2_SCALAR_REUSE_CERTIFICATE '
CERTIFICATE_KEYS=('version status failure_code detail_abs detail_negative initialized publications retirements '
                  'certificate_checks live_rseq_checks terminal_matches pending').split()


def split(stderr):
    """One certificate row immediately before the unchanged final reuse/scalar rows."""
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete certificate terminal stream')
    lines=stderr[:-1].split(b'\n')
    need(len(lines)>3 and lines[-3].startswith(CERTIFICATE_PREFIX) and
         sum(line.startswith(CERTIFICATE_PREFIX)for line in lines)==1 and
         len(lines[-3])<=4096 and b'\r'not in lines[-3],
         'one bounded certificate row before final reuse and scalar rows')
    certificate=old.maps_view.pair.pair_reports.rseq.decode(lines[-3][len(CERTIFICATE_PREFIX):])
    need(type(certificate)is dict and list(certificate)==CERTIFICATE_KEYS and
         all(type(certificate[k])is int and 0<=certificate[k]<1<<64 for k in CERTIFICATE_KEYS),
         'complete ordered duplicate-free certificate schema with unsigned integers')
    need(certificate['version']==1 and certificate['status']in(0,125) and
         all(certificate[k]in(0,1)for k in('detail_negative','initialized','pending')),
         'exact certificate version, actual status and booleans')
    scalar,reuse,suffix=donor.split(b'\n'.join(lines[:-3]+lines[-2:])+b'\n')
    need(all(certificate[k]==scalar[k]for k in('status','failure_code','detail_abs','detail_negative')),
         'certificate retains the same actual terminal outcome')
    return scalar,reuse,certificate,suffix


def scalar_completed(row,reuse,certificate):
    """Successful complete accounting only; failures require their actual prefix."""
    need(row['status']==row['failure_code']==row['detail_abs']==row['detail_negative']==row['first_error']==
         row['active']==row['busy']==row['decoding']==row['unexpected']==0 and row['initialized']==1 and
         reuse['status']==reuse['failure_code']==reuse['detail_abs']==reuse['detail_negative']==
         reuse['pending']==reuse['retiring']==0,'successful reuse has no pending or failed owner')
    need(row['events']==sum(row['signals'])>0 and all(row['signals'][i]>0 for i in (0,1,2)) and
         row['signals'][3:]==[0,0],'complete actual scalar handler population')
    need(0<row['used']==min(row['publications'],64) and
         row['candidates']==row['source_misses']+row['plan_misses']+row['capacity_misses']+
             row['publications']+row['hits'] and row['plan_misses']==sum(row['refusals']) and
         row['entries']==row['publications']+row['hits']==row['completed']==sum(row['exit_indices']) and
         row['plan_checks']==row['publications']+reuse['retirement_attempts'] and
         row['rseq_checks']==row['publications'],
         'all actual candidates, static proofs, live guards and original exits close')
    need(reuse['generation']==row['publications'] and
         reuse['retirement_attempts']==reuse['retirements']==row['publications']-row['used'] and
         reuse['claims']==reuse['permits_issued']==row['completed'] and
         reuse['cursor']==reuse['retirements']%64,
         'monotonic generations, completed retirement and one consumed/reissued permit per entry')
    need(certificate['initialized']==1 and certificate['pending']==certificate['terminal_matches']==0 and
         certificate['publications']==row['publications'] and certificate['retirements']==reuse['retirements'] and
         certificate['certificate_checks']==2*row['entries'] and certificate['live_rseq_checks']==3*row['entries'],
         'actual certificate publications, complete comparisons and live guards close separately')


def check(stderr,pid,exit_status,parent,images,image_bytes,carrier,carrier_bytes,owner,owner_reader,mode):
    scalar,reuse,certificate,suffix=split(stderr);row,suffix=unrolled.split(suffix)
    view,original=maps_view.split_report(suffix,'maintained')
    parsed=prior.reports(original);prior.extensions(parsed)
    _,same,gate=prior.gate(parsed,pid,exit_status,parent,0)
    need(same is parsed and all(scalar[k]==row[k]==parsed['loader'][k]for k in
         ('status','failure_code','detail_abs','detail_negative')),'all terminal rows retain one actual outcome')
    owner_reader.terminal(parsed,scalar,row,owner,reuse,certificate)
    inputs=cost._retained_inputs(images,image_bytes,carrier,carrier_bytes)
    prior_unrolled(row);retained=unused_repeat(parsed)
    summary=dict(application_completed=exit_status==0,gate=gate,repeat_lease=retained,input_authentication=inputs,
        maps_view=view,certificate={k:certificate[k]for k in CERTIFICATE_KEYS},reuse={k:reuse[k]for k in KEYS},scalar={k:scalar[k]for k in COUNTERS},unrolled={k:row[k]for k in unrolled.COUNTERS},
        required_refusal=int(exit_status==125))
    if exit_status==0:
        scalar_completed(scalar,reuse,certificate);unrolled.completed(row,False)
        summary.update(lease=prior.lease.counters(parsed),trace_run=prior.trace_completed(parsed),
            native_pair=prior.pair_completed(parsed,pid),cache_reuse=prior.reuse_completed(parsed['run'],parsed['reuse']))
        application_effect_exit(parsed,mode)
    else:
        need(exit_status==125 and gate['original_completed_rejected']is True and
             scalar['first_error']==scalar['failure_code']>0,
             'actual scalar failure retains first error and original completion refusal')
    return parsed,summary


def controls(stderr,*args):
    parsed,_=check(stderr,*args);scalar,reuse,certificate,suffix=split(stderr);row,suffix=unrolled.split(suffix)
    view,original=maps_view.split_report(suffix,'maintained');lines=stderr[:-1].split(b'\n');trials=[];specific=set()
    def changed(name,prefix,record):
        places=[i for i,line in enumerate(lines)if line.startswith(prefix)]
        need(len(places)==1,'one actual supplied report target');data=list(lines)
        data[places[0]]=prefix+json.dumps(record,separators=(',',':'),allow_nan=False).encode()
        trials.append((name,b'\n'.join(data)+b'\n'))
    for key in ('version','status','failure_code','first_error','initialized','entries','completed','used','events','plan_checks','rseq_checks','decoding'):
        value=copy.deepcopy(scalar);value[key]^=1;changed('scalar_'+key,old.PREFIX,value)
    for key in ('signals','refusals','exit_indices','current'):
        value=copy.deepcopy(scalar);value[key][0]^=1;changed('scalar_'+key,old.PREFIX,value)
    for key in ('version','status','failure_code','first_error','initialized','observe_only','entries','completed','used','events'):
        value=copy.deepcopy(row);value[key]^=1;changed('unrolled_'+key,unrolled.PREFIX,value)
    for key in ('signals','current'):
        value=copy.deepcopy(row);value[key][0]^=1;changed('unrolled_'+key,unrolled.PREFIX,value)
    for key in ('version','enabled','differential','poisoned','reserved','mismatches','queries','comparisons'):
        value=dict(view);value[key]^=1;changed('maps_'+key,maps_view.PREFIX,value)
    for name,key,field,index in (('pair_slot','native_pair','slots',(0,5)),
         ('pair_live','native_pair','control',6),('pair_closes','native_pair','counts',3),
         ('rseq_pin','rseq','identity',1),('rseq_epoch','rseq','owner',13),
         ('unused_owner','repeat_lease','owner',0),('unused_source','repeat_lease','source',0),
         ('unused_frame','repeat_lease','frames',0),('unused_custody','repeat_lease','custody',4)):
        value=copy.deepcopy(parsed[key]);target=value[field][index[0]]if type(index)is tuple else value[field]
        at=index[1]if type(index)is tuple else index;target[at]^=1
        prefix={'native_pair':b'LI2_NATIVE_PAIR ','rseq':b'LI2_RSEQ ','repeat_lease':b'LI2_REPEAT_LEASE '}[key]
        changed(name,prefix,value)
    if parsed['loader']['status']==0:
        for name,add,subtract in (('publication_cpuid_syscall','cpuid_patches','syscall_patches'),
                                 ('publication_syscall_rdtsc','syscall_patches','rdtsc_patches')):
            value=copy.deepcopy(parsed['oneshot']);need(value[subtract]>0,'actual positive class for supplied redistribution')
            value[add]+=1;value[subtract]-=1;changed(name,b'LI2_ONESHOT ',value);specific.add(name)
    trials.extend([('truncated',stderr[:-1]),('duplicate_scalar',stderr+lines[-1]+b'\n'),
        ('missing_scalar',b'\n'.join(lines[:-1])+b'\n'),('missing_maps',b'\n'.join(lines[1:])+b'\n')])
    for key in KEYS:
        value=dict(reuse);value[key]^=1;changed('reuse_'+key,PREFIX,value)
    trials.extend([('duplicate_reuse',stderr+lines[-2]+b'\n'),
        ('missing_reuse',b'\n'.join(lines[:-2]+lines[-1:])+b'\n'),
        ('reordered_complete_rows',b'\n'.join(lines[:-2]+[lines[-1],lines[-2]])+b'\n')])
    total=67 if parsed['loader']['status']==0 else 65
    need(len(trials)==total and len({n for n,_ in trials})==total,'all fixed named scalar terminal refusals')
    names=[]
    for name,data in trials:
        rejected=False
        try:check(data,*args)
        except ValueError as error:
            rejected=name not in specific or str(error)=='exact application publication and unpatched class accounting'
        need(rejected,'complete scalar terminal reader rejects '+name);names.append(name)
    original_total=len(trials)
    for key in CERTIFICATE_KEYS:
        value=dict(certificate);value[key]^=1;changed('certificate_'+key,CERTIFICATE_PREFIX,value)
    trials.extend([('duplicate_certificate',stderr+lines[-3]+b'\n'),
        ('missing_certificate',b'\n'.join(lines[:-3]+lines[-2:])+b'\n'),
        ('reordered_certificate',b'\n'.join(lines[:-3]+[lines[-2],lines[-3],lines[-1]])+b'\n')])
    added=trials[original_total:]
    need(len(added)==15 and len({name for name,_ in trials})==len(trials),
         'all original terminal refusals plus15 distinct certificate refusals')
    certificate_names=[]
    for name,data in added:
        rejected=False
        try:check(data,*args)
        except ValueError:rejected=True
        need(rejected,'complete certificate terminal reader rejects '+name);certificate_names.append(name)
    return dict(refusals=names,certificate_refusals=certificate_names,native_operations=0,
                original_stderr_sha256=H(stderr))
