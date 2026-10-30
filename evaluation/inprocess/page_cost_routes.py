#!/usr/bin/env python3
"""Project overlapping route counters from two exact, already-audited closed receipts."""
from pathlib import Path
import argparse,csv,hashlib,io,json,sys
R=Path(__file__).resolve().parents[2];H=lambda b:hashlib.sha256(b).hexdigest()
PINS={
 'bbd0bbed5ffb56fe6503deb199ba3b521598af29083d5fcbc5d4713dc03377a0':('20261029T224041.992538Z-page-cost-compare-c97096fad229','c97096fad229e3988c6ad12e464874da626cd612','2bc3395779b692c89c412ed6e1a1b875b45b68bba4dde3082d836e485416a1b0'),
 '76d5417c1525425488f8e2277eeea787a29cee485c04c0a4e1adcbfc35c3a79d':('20261029T234233.369460Z-page-cost-compare-c14f3078a1b5','c14f3078a1b59c637f3cf5fe29e0849ca11f3abf','99ff000c346a28bd3d23e1b1efd8c22fb08279f6a0f526a7ca356f0e40e54782')}
FIELDS={'loader':('nx_faults','selected_steps','generic_tf_attempts','generic_tf_steps'),
 'chain':('nx_entries','trace_entries','steps','lease_transfers'),
 'trace_run':('candidates','preflight_misses','attempts','entries','completed','plan_misses','full_misses')}
ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--receipt',required=True,type=Path)
ap.add_argument('--public-results',type=Path,default=R/'evaluation/inprocess/results');ap.add_argument('--output',type=Path,default=R/'evaluation/inprocess/results');a=ap.parse_args()
assert not sys.flags.optimize
raw=a.receipt.read_bytes();private_hash=H(raw);assert private_hash in PINS
stem,revision,public_hash=PINS[private_hash];r=json.loads(raw);pb=(a.public_results/(stem+'.json')).read_bytes();assert H(pb)==public_hash;p=json.loads(pb)
assert p['private_receipt']==dict(bytes=len(raw),sha256=private_hash)
assert r['status']==p['status']=='passed' and r['error'] is None and r['final_errors']==[] and p['final_error_count']==0
assert r['source_unchanged'] is True and r['cleanup_complete'] is True and p['source_unchanged'] is True and p['cleanup_complete'] is True
assert r['expected_revision']==revision==r['source']['revision'] and r['source']==r['source_after']==p['source']
assert r['source']['head_sources_match'] is True and r['source']['tracked_clean'] is True
assert all(r[k+'_before']==r[k+'_after'] for k in ('inputs','artifacts','aliases'))
assert r['configuration_presence']=={'/etc/ld.so.cache':True,'/etc/ld.so.preload':False}
assert len(r['commands'])==p['commands']==96 and all(c['exit']==c['expected_exit'] and c['reaped'] is True and c['timed_out'] is False and c['error'] is None and c['cleanup_errors']==[] for c in r['commands'])
orders=(('native','gated','dynamorio'),('gated','dynamorio','native'),('dynamorio','native','gated'),('dynamorio','gated','native'),('gated','native','dynamorio'),('native','dynamorio','gated'))
order=[(i,k,n,l) for i,(k,n,l) in enumerate((k,n,l) for n in range(10) for k in (('ls','true') if n%2==0 else ('true','ls')) for l in orders[n%6])]
assert [(c['ordinal'],c['workload'],c['repeat'],c['lane']) for c in r['cases']]==order and len(order)==60
assert all(c['status']=='passed' and c['exit']==0 and c['reaped'] is True and c['timed_out'] is False for c in r['cases'])
gated=[c for c in r['cases'] if c['lane']=='gated'];names={f"{c['workload']}-{c['repeat']}-gated" for c in gated}
assert len(gated)==len(names)==20 and set(r['terminal_reports'])==set(r['reader_controls'])==names
columns=['ordinal','workload','repeat']+[s+'.'+f for s,fields in FIELDS.items() for f in fields];rows=[]
for c in gated:
 name=f"{c['workload']}-{c['repeat']}-gated";t=r['terminal_reports'][name];control=r['reader_controls'][name]
 assert len(control['refusals'])==len(set(control['refusals']))==p['reader_controls'][name]==(60 if c['workload']=='ls' else 218)
 assert control['actual_subjects']==0 and control['native_qualification_credit'] is False
 assert all(control['original_'+s+'_sha256']==c['captures'][s]['sha256'] for s in ('stdout','stderr'))
 assert all(t[s]['status']==0 and t[s]['failure_code']==0 for s in FIELDS)
 values=[t[s][f] for s,fields in FIELDS.items() for f in fields];assert all(type(v)is int and 0<=v<1<<64 for v in values)
 rows.append([c['ordinal'],c['workload'],c['repeat'],*values])
stream=io.StringIO(newline='');writer=csv.writer(stream,lineterminator='\n');writer.writerow(columns);writer.writerows(rows);cb=stream.getvalue().encode();name=stem+'-routes'
script=Path(__file__).read_bytes()
v=dict(schema=1,status='projected_from_passed_receipt',scope='Overlapping terminal route counters, not disjoint instructions or new execution/qualification; no ptrace-stop count.',
 source=r['source'],cpu=r['cpu'],hardware=p['hardware'],private_receipt=dict(bytes=len(raw),sha256=private_hash),
 original_public=dict(file=stem+'.json',bytes=len(pb),sha256=public_hash),projector=dict(file='page_cost_routes.py',bytes=len(script),sha256=H(script)),
 closed_population=dict(subjects=60,gated_terminals=20,commands=96,supplied_refusals=sum(len(c['refusals'])for c in r['reader_controls'].values())),
 source_unchanged=True,cleanup_complete=True,columns=columns,rows=rows,csv=dict(file=name+'.csv',bytes=len(cb),sha256=H(cb)),
 reproduce=['python3','-B','evaluation/inprocess/page_cost_routes.py','--receipt','${CLOSED_RECEIPT}'])
jb=(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
assert len(jb)<8192 and len(cb)<8192 and not any(s in jb for s in (b'/home/',b'/target/',b'/proc/'))
a.output.mkdir(parents=True,exist_ok=True)
for suffix,data in (('.csv',cb),('.json',jb)):
 with (a.output/(name+suffix)).open('xb') as f:f.write(data)
print(json.dumps(dict(file=name+'.json',bytes=len(jb),sha256=H(jb),rows=len(rows)),sort_keys=True))
