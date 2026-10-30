#!/usr/bin/env python3
"""Reproduce the architecture cost model from four pinned public artifacts only."""
import argparse
import csv
import hashlib
import io
import json
import sys
from fractions import Fraction
from pathlib import Path

EVENT = '20261030T042205.505845Z-page-event-budget-22e5225612c4'
BASE = '20261030T030044.789458Z-page-cost-compare-f7dd159db74f'
REV = '22e5225612c495f63bc5fedc6960e8f1a6a33c0e'
BASE_REV = 'f7dd159db74f7ca1181a89bd48c11a329d7a49a5'
PINS = {
    EVENT+'.json': (33477, '7e7b08af855e8f56a5dc61b4b6f31ee8880f7ff2ca6cc56574aa5af10a1b61ed'),
    EVENT+'.csv': (6351, 'fd058847b56d243c532ebe978f7be8adb89b3fe8f4266f08d2da8c643375f217'),
    BASE+'.json': (46040, 'b91f673efc6cfb83ee83eaf2afe1955b6b78828fc78b698d7eeccdb6cf523333'),
    BASE+'.csv': (4608, 'd18b574556702bf380fecb05d69ae9f282e8b913169ebc913ee1bebfab017e15'),
}
REGIONS = 'handler_other maps_other maps_open maps_read maps_close maps_parse decoder_decode decoder_classify decoder_footprint decoder_scan native_policy admission_prepare admission_publish native_close'.split()
SIGNALS = ['SIGSEGV','SIGTRAP','SIGSYS','SIGILL','other']
ROUTES = ['NO_STEP','OLD_STEP','GENERIC_TF','REPEAT','ONESHOT','REGISTER_RUN','REPEAT_LEASE']
RAW = 'openat read close pread64 fstat fcntl mprotect membarrier getpid gettid clock_gettime ptrace other'.split()
FIELDS = 'ordinal workload repeat lane status exit process_ns timed_out reaped user_cpu_ns system_cpu_ns minor_faults major_faults voluntary_switches involuntary_switches'.split()


def need(ok, message):
    if not ok:
        raise ValueError(message)


def quantile(values, numerator, denominator):
    v = sorted(values)
    position = Fraction((len(v)-1)*numerator, denominator)
    lo = position.numerator // position.denominator
    return Fraction(v[lo]) + (position-lo)*(v[min(lo+1,len(v)-1)]-v[lo])


def summary(values):
    q1, median, q3 = (quantile(values,p,4) for p in (1,2,3))
    return dict(samples=len(values), median_ns=float(median), q1_ns=float(q1),
                q3_ns=float(q3), iqr_ns=float(q3-q1))


def rows(names, counts, durations):
    return [dict(name=name,count=n,total_ns=t,mean_ns_ratio=[t,n] if n else None)
            for name,n,t in zip(names,counts,durations)]


def event_csv(cases):
    cost_names = ['admission_'+n for n in ('initialized','valid','busy','overflow','count','sum_ns','min_ns','max_ns')]
    cost_names += ['maps_'+n for n in ('fresh_calls','acquisitions','reuses','invalidations','handler_id','mutation_epoch','active','valid','poisoned','reserved')]
    event_names = ['handler_entries','handler_returns','terminal_fences','observer_clock_calls','observed_envelope_ns','handler_ns','unmeasured_process_residual_ns']
    event_names += [kind+'_'+name for kind in ('calls','exclusive_ns','inclusive_ns') for name in REGIONS]
    event_names += ['internal_c_raw_ptrace_attempts','internal_c_raw_ptrace_returns','internal_c_raw_ptrace_negative_returns','site_total','site_unique','site_retained','site_other']
    buf = io.StringIO(newline='')
    writer = csv.writer(buf,lineterminator='\n'); writer.writerow(FIELDS+cost_names+event_names)
    for c in cases:
        values = ['']*len(event_names)
        if c['event'] is not None:
            e,v = c['event'],c['event_summary']
            values = e['handlers']+[e['clock'][0],v['observed_envelope_ns'],v['handler_ns'],v['unmeasured_process_residual_ns']]
            values += e['region_calls']+e['exclusive_ns']+e['inclusive_ns']+e['raw'][11]
            values += [e[k] for k in ('site_total','site_unique','site_retained','site_other')]
        writer.writerow([c[k] for k in FIELDS]+(c['cost']['admission']+c['cost']['maps'] if c['cost'] else ['']*18)+values)
    return buf.getvalue().encode()


def project(root):
    data = {}
    for name,(size,digest) in PINS.items():
        raw = (root/'evaluation/inprocess/results'/name).read_bytes()
        need(len(raw)==size and hashlib.sha256(raw).hexdigest()==digest,'exact public input '+name)
        data[name] = raw
    pub,base = json.loads(data[EVENT+'.json']),json.loads(data[BASE+'.json'])
    for x,revision in ((pub,REV),(base,BASE_REV)):
        need(x['expected_revision']==x['source']['revision']==revision,'exact source revision')
        need(x['status']=='passed' and x['source_unchanged'] and x['cleanup_complete'] and x['final_error_count']==0,'reported closed successful input')
        need(x['source']['head_sources_match'] and x['source']['tracked_clean'],'reported source closure')
    need(pub['commands']==52 and len(pub['cases'])==12,'fixed event cohort')
    need(pub['bounds']['program']==[30,536870912,16777216,60],'original event process bounds')
    need(pub['region_names']==REGIONS and pub['signal_names']==SIGNALS and pub['route_names']==ROUTES and pub['raw_names']==RAW,'exact public schema labels')
    order = [(w,n,l) for n in range(3) for w in (('ls','true') if n%2==0 else ('true','ls')) for l in (('unobserved','events') if n%2==0 else ('events','unobserved'))]
    for i,(c,expected) in enumerate(zip(pub['cases'],order)):
        need(c['ordinal']==i and (c['workload'],c['repeat'],c['lane'])==expected,'exact fixed attempt order')
        need(c['status']=='passed' and c['exit']==0 and c['reaped'] and not c['timed_out'],'all actual outcomes')
        e = c['event']
        if c['lane']=='unobserved':
            need(e is None and c['cost'] is None and c['event_summary'] is None,'unobserved means unobserved')
            continue
        need(all(e[k]==v for k,v in zip(('version','initialized','sealed','valid','error','busy','active','depth'),(1,1,1,1,0,0,0,0))),'reported successful event row')
        need(e['region_calls']==e['region_returns'] and len(e['region_calls'])==14,'complete measured region counts')
        h = e['inclusive_ns'][0]
        need(sum(e['exclusive_ns'])==sum(e['signal_ns'])==sum(e['route_ns'])==h,'exact exclusive and overlapping partitions')
        need(sum(e['signals'])==sum(e['routes'])==e['handlers'][0]==e['region_calls'][0],'complete signal and ingress-route populations')
        need(e['handlers'][0]==e['handlers'][1]+e['handlers'][2] and e['handlers'][2]==1,'terminal fence is not a returned handler')
        need(e['clock'][0]==e['clock'][1]==2*sum(e['region_calls']),'counted diagnostic clock boundaries')
        need(all(n or t==0 for counts,times in ((e['region_calls'],e['exclusive_ns']),(e['signals'],e['signal_ns']),(e['routes'],e['route_ns'])) for n,t in zip(counts,times)),'zero-count mean is absent')
        need(0<h<=e['clock'][3]-e['clock'][2]<=c['process_ns'],'whole reported interval bounds')
        v = c['event_summary']
        need(v['handler_ns']==h and v['observed_envelope_ns']==e['clock'][3]-e['clock'][2] and v['unmeasured_process_residual_ns']==c['process_ns']-h,'exact residual arithmetic')
        need(e['maps_end']==c['cost']['maps'] and e['maps_end'][0]-e['maps_start'][0]==e['maps'][0],'reported maps baseline/end join')
        need(e['owner_end'][0]-e['owner_start'][0]==e['handlers'][0],'measured handler baseline/end join')
        need(e['site_total']==e['site_end']-e['site_start']==e['site_retained']+e['site_other'],'fallback population without whole-program coverage')
        need(all(a==b and n<=b for a,b,n in e['raw']),'returned ordinary RAW requests')
    need(event_csv(pub['cases'])==data[EVENT+'.csv'],'complete public CSV byte reconstruction')
    stats = {}
    for workload in ('ls','true'):
        stats[workload] = {}
        for lane in ('unobserved','events'):
            times = [r['process_ns'] for r in pub['cases'] if r['workload']==workload and r['lane']==lane]
            need(len(times)==3,'three fixed launch intervals')
            s = summary(times)
            need(all(s[k]==pub['statistics'][workload][lane][k] for k in ('median_ns','q1_ns','q3_ns','iqr_ns')),'published event quantiles')
            stats[workload][lane] = dict(s,process_ns=times)
        a,b = (stats[workload][lane]['median_ns'] for lane in ('unobserved','events'))
        need(pub['statistics'][workload]['observer_overhead']==dict(median_difference_ns=b-a,median_ratio=b/a),'reported observer overhead; no subtraction')
        stats[workload]['observer_overhead'] = pub['statistics'][workload]['observer_overhead']
    original = list(csv.DictReader(io.StringIO(data[BASE+'.csv'].decode())))
    need(len(original)==60 and [int(r['ordinal']) for r in original]==list(range(60)),'all original baseline attempts')
    need(all(r['status']=='passed' and r['exit']=='0' and r['reaped']=='True' and r['timed_out']=='False' for r in original),'all original baseline outcomes')
    baseline = {}
    for workload in ('ls','true'):
        baseline[workload] = {}
        for lane in ('native','gated','dynamorio'):
            times = [int(r['process_ns']) for r in original if r['workload']==workload and r['lane']==lane]
            need(len(times)==10,'ten actual original baseline launches')
            s = summary(times)
            need(all(s[k]==base['statistics'][workload][lane][k] for k in ('median_ns','q1_ns','q3_ns','iqr_ns')),'original baseline quantiles')
            baseline[workload][lane] = s
    for key in ('architecture','model name','cpu family','model','stepping','microcode','isa_flags_sha256','kernel_release_sha256'):
        need(pub['hardware'][key]==base['hardware'][key],'reported same hardware/kernel '+key)
    c = pub['cases'][6]; e = c['event']; whole = c['process_ns']; h = e['inclusive_ns'][0]
    dr = Fraction(str(baseline['ls']['dynamorio']['median_ns'])); target = 10*dr
    need(target==263060775,'specified ten-times-DR target')
    model = dict(schema=1,scope='Public-data arithmetic only; reported source/cleanup facts are provenance, not re-executed validation',
        inputs={name:dict(bytes=n,sha256=d) for name,(n,d) in PINS.items()},source=pub['source'],
        private_receipt_provenance=pub['private_receipt'],
        independent_review_provenance=dict(bytes=7140,sha256='e6abe9ebae07244efdec87f5f00a9b1461943574322b0cfbfc0d98f5756b4ef1',
            scope='Recorded private DATA_CLEAR review identity only; not an arithmetic prerequisite or re-executed audit'),
        hardware=pub['hardware'],bounds=pub['bounds']['program'],
        row=dict(ordinal=6,workload='ls',repeat=1,lane='events',process_ns=whole,handler_ns=h,residual_ns=whole-h,user_cpu_ns=c['user_cpu_ns'],system_cpu_ns=c['system_cpu_ns']),
        exclusive=rows(REGIONS,e['region_calls'],e['exclusive_ns']),
        overlapping_signals=rows(SIGNALS,e['signals'],e['signal_ns']),overlapping_routes=rows(ROUTES,e['routes'],e['route_ns']),
        amplification=dict(handler_entries=e['handlers'][0],generic_tf_ingress=e['routes'][2],register_run_ingress=e['routes'][5],
            fresh_maps=e['maps'][0],maps_read_calls=e['maps'][4],maps_read_bytes=e['maps'][6],maps_rows=e['maps'][12],maps_reuses_end=e['maps_end'][2],
            decoder_wrapper_calls=sum(e['region_calls'][6:10]),ordinary_c_raw_calls=sum(r[0] for r in e['raw']),diagnostic_clock_calls=e['clock'][0],
            raw={name:row for name,row in zip(RAW,e['raw'])},fallback=dict(total=e['site_total'],unique_tuples=e['site_unique'],overflow=e['site_other'],top32_count=sum(r[4] for r in e['sites']))),
        statistics=stats,baseline=dict(source=base['source'],cpu=base['cpu'],statistics=baseline),
        target=dict(ns=int(target),dr_ls_median_ns=float(dr),current_unobserved_factor=stats['ls']['unobserved']['median_ns']/int(target),
            current_unobserved_elapsed_reduction_fraction=1-int(target)/stats['ls']['unobserved']['median_ns'],
            formula='T_native + unique_translations*unit_cold + remaining_exits*unit_exit + incremental_linked_execution_overhead_above_native',
            conditional_coverage='f >= 1-(target-F-O)/D; D is proven bypassable elapsed work, not instruction coverage',
            assumed_budget=dict(native_reference_ns=baseline['ls']['native']['median_ns'],cold_translation_ns=100000000,
                complete_exits_ns=100000000,incremental_linked_execution_overhead_ns=50000000,
                total_ns=baseline['ls']['native']['median_ns']+250000000,
                margin_ns=int(target)-baseline['ls']['native']['median_ns']-250000000,
                count_constraints=['unique_translations*unit_cold <= 100000000 ns','remaining_exits*unit_exit <= 100000000 ns'],
                scope='Feasible algebra with assumed allocations only; neither coverage nor these budgets is demonstrated'),
            component_costs=None,full_application_coverage=None,achieved=False),
        isolated_zero_cost_counterfactuals_ns=dict(no_maps_subtree=whole-e['inclusive_ns'][1],no_decoder_wrappers=whole-sum(e['exclusive_ns'][6:10]),no_measured_handlers=whole-h),
        limits=['Inclusive signal/route/COST views overlap; never add them to exclusive time.',
                'Observer overhead is not subtracted or used to normalize an unobserved ledger.',
                'Handler-body means are not complete trap/exit latency; residual is not isolated trap cost.',
                'Fallback tuples are not all blocks, dynamic instruction count or translation coverage.',
                'Ordinary C ptrace requests are zero in row6; external ptrace stops remain unavailable.',
                'Separate f7dd DR baseline is a target reference, not equivalent interception guarantees.',
                'Private raw records, finer cache counters and region-component results are not inputs.'])
    encoded = (json.dumps(model,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
    need(len(encoded)<16*1024 and b'/home/' not in encoded and b'/target/' not in encoded,'bounded path-free derived artifact')
    return encoded


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2],help='repository or retained-artifact root containing evaluation/inprocess/results')
    group = ap.add_mutually_exclusive_group()
    group.add_argument('--output',type=Path,help='create exact model JSON at this path; refuses overwrite')
    group.add_argument('--check',type=Path,help='require byte equality with the existing model JSON')
    a = ap.parse_args(); data = project(a.root)
    if a.check:
        need(a.check.read_bytes()==data,'exact model byte reproduction')
        print(json.dumps(dict(status='byte_identical',bytes=len(data),sha256=hashlib.sha256(data).hexdigest())))
    elif a.output:
        with a.output.open('xb') as f:
            f.write(data)
    else:
        sys.stdout.buffer.write(data)


if __name__=='__main__':
    main()
