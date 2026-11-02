#!/usr/bin/env python3
"""Arithmetic over published closed observations; no imports, builds or workloads."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import statistics

ROOT=Path(__file__).resolve().parents[3]
RESULTS=ROOT/'evaluation/inprocess/results'
STEM='20261102-admission-unit-cost-4ed9d1ca1ee6'
HISTORY=(
 ('20261030T030044.789458Z-page-cost-compare-f7dd159db74f.json','b91f673efc6cfb83ee83eaf2afe1955b6b78828fc78b698d7eeccdb6cf523333'),
 ('20261029T231615.636586Z-page-cost-counters-3675540b8ada.json','4ab36a3f5c6642b3a0f24d11b323c5750df9980b113f997f11b5092c9dd4bb0c'),
 ('20261030T042205.505845Z-page-event-budget-22e5225612c4.json','7e7b08af855e8f56a5dc61b4b6f31ee8880f7ff2ca6cc56574aa5af10a1b61ed'))

def need(ok,label):
    if not ok:raise ValueError(label)
def fact(path):
    b=path.read_bytes();return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--micro',type=Path,default=RESULTS/(STEM+'.json'))
    ap.add_argument('--raw',type=Path,default=RESULTS/(STEM+'.csv'))
    ap.add_argument('--output',type=Path);args=ap.parse_args()
    pub=json.loads(args.micro.read_bytes())
    need(pub['status']=='observed_component_unit_costs' and fact(args.raw)=={k:pub['raw_csv'][k] for k in ('bytes','sha256')},'closed micro/raw identity')
    need(pub['bounds']==[30,512<<20,16<<20,60] and len(pub['commands'])==3 and
         all(x['exit']==0 and x['timed_out'] is False and x['reaped'] is True for x in pub['commands']),'original three bounded children')
    with args.raw.open() as f:rows=list(csv.DictReader(f))
    for row in rows:
        for k in row:
            if k!='name':row[k]=int(row[k])
    need(len(rows)==245 and pub['measured_batches']==10 and pub['warmup_batches']==1,'245 original observations')
    units={}
    for old in pub['statistics']:
        batch=[x for x in rows if x['name']==old['name'] and x['sample']>0]
        need(len(batch)==10 and sorted(x['sample'] for x in batch)==list(range(1,11)),'ten fixed batches')
        ns=[x['elapsed_ns']/x['iterations'] for x in batch];q1,_,q3=statistics.quantiles(ns,n=4,method='inclusive');median=statistics.median(ns)
        need((median,q1,q3)==tuple(old[k] for k in ('median_ns_per_iteration','q1_ns_per_iteration','q3_ns_per_iteration')),'whole published timing cells')
        units[old['name']]={'median_ns':median,'q1_ns':q1,'q3_ns':q3,'iqr_ns':q3-q1}
    need(len(units)==22,'all unit rows')
    history=[];references=[]
    for name,sha in HISTORY:
        p=RESULTS/name;f=fact(p);need(f['sha256']==sha,'fixed historical public input');value=json.loads(p.read_bytes())
        need(value['status']=='passed' and value['source_unchanged'] is True and value['cleanup_complete'] is True,'closed historical cohort')
        history.append(value);references.append({'file':name,**f})
    a,b,c=history;observed=[x for x in b['cases'] if x['workload']=='ls' and x['lane']=='counters']
    need(len(observed)==3 and all(x['cost']['admission'][4]==5393 and x['status']=='passed' for x in observed),'historical N only')
    baseline={w:{'lanes':lanes,'gated_over_dr':lanes['gated']['median_ns']/lanes['dynamorio']['median_ns']} for w,lanes in a['statistics'].items()}
    need(all(x['passed']==x['planned']==10 for w in baseline.values() for x in w['lanes'].values()),'all sixty historical completions')
    N=5393;budget=a['statistics']['ls']['dynamorio']['median_ns']-a['statistics']['ls']['native']['median_ns'];med=lambda n:units[n]['median_ns']
    base=med('nx_fault_grant_ret_cycle')+2*med('membarrier_sync_core');probe=med('mincore_absent_predecessor');scenarios=[]
    for name,scan,h in [('NX + 2 sync',None,0),('NX + 2 sync + one probe',None,1)]+[(n,n,1) for n in units if n.startswith(('native_policy_','decoder_scan_'))]:
        ns=base+h*probe+(med(scan) if scan else 0)
        scenarios.append({'name':name,'scan_row':scan,'probes_per_page':h,'ns_per_page':ns,'N5393_ns':N*ns,'over_page_budget':ns/(budget/N)})
    case=next(x for x in c['cases'] if (x['workload'],x['lane'],x['repeat'])==('ls','events',1));ex=dict(zip(c['region_names'],case['event']['exclusive_ns']))
    need(len(ex)==14 and sum(ex.values())==case['event_summary']['handler_ns'],'exclusive handler conservation')
    partition={'maps':sum(v for k,v in ex.items() if k.startswith('maps_')),'other_handler':ex['handler_other'],
       'decode_classify_footprint':sum(ex[k] for k in ('decoder_decode','decoder_classify','decoder_footprint','decoder_scan')),
       **{k:ex[k] for k in ('native_policy','admission_prepare','admission_publish','native_close')},
       'outside_handlers':case['event_summary']['unmeasured_process_residual_ns']}
    need(sum(partition.values())==case['process_ns']==20671929099,'same-run exact total')
    value={'schema':1,'scope':'conditional planning, not measured whole-program latency or a strict lower bound',
      'inputs':{'micro':fact(args.micro),'raw':fact(args.raw),'historical':references},'source':pub['source'],'hardware':pub['hardware'],
      'micro_receipt':pub['receipt'],'raw_rows':245,'bounds':pub['bounds'],'units_ns':units,'first_samples':pub['first_samples'],
      'historical_baseline':baseline,'N_cross_cohort':N,'DR_minus_native_budget_ns':budget,'budget_ns_per_page':budget/N,
      'scenarios':scenarios,'formula':'A*NX+(A+C)*sync+H*probe+P*chosen_scan+R*fresh_maps+init+U',
      'condition':'A*NX requires F=A: one successful measured-style execute-fault cycle, grant and eventual revoke per published page. A is not an observed fault count. Extra NX/TRACE/refault/failure routes remain U; speculative or multi-page publication needs separate event and permission counts.',
      'counts':{'A':'actual published pages','C':'actual nonempty closes, no assumed pair amortization','H':'actual predecessor probes','P':'actual chosen scan attempts including refusals','R':'actual fresh acquisitions after initialization, relevant invalidations or unexplained changes, never logical queries'},
      'unpriced':['R*fresh_maps','one-time init in table subtotals','seals/fstat/pread/backing bytes','aliases/generations/lifetimes','source copies/equality','maps parser and validation','CFG/proof/patch/emission','other traps/failed attempts/startup/exit/application'],
      'example':'A=C=N; P=N only with a scan; H=0 or N as stated. R and U stay unknown, not zero. C policy and shared decoder are alternatives; lease refusal is not admission.',
      'same_run_C':{'partition_ns':partition,'process_ns':case['process_ns'],'added_micro_ns':0,'residual_is_trap_cost':False},
      'current_full19_completion':None,'qualification_credit':False,'performance_credit':False}
    text=json.dumps(value,sort_keys=True,separators=(',',':'))+'\n'
    if args.output:
        need(not args.output.exists(),'fresh analysis output');args.output.write_text(text)
    else:print(text,end='')
if __name__=='__main__':main()
