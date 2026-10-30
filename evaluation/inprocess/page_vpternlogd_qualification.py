#!/usr/bin/env python3
"""Exact closed qualification projection. No native execution or architectural reader replay."""
from pathlib import Path
import argparse,collections,gzip,hashlib,json,subprocess,sys
PINS=[['fd3_precursor', '20261030T003321.040956Z-page-selected-vpternlogd256-69f258e36b03.json', 6807, '1b4e228118c6e3fe14b3aef2edc8a0568b6189610e2baf58464aa0f1dc0dc106', 7281694, '2b4007deb55979bbfd15163bc0bcd9836b54f7653c3362a9d4e2ff62002cf9e5', 'failed'], ['ternary', '20261030T004746.599472Z-page-selected-vpternlogd256-9b60724f14fe.json', 11919, '514c83cd4f5d03de3a4a6977179d73fe4f90399cf4602cb8016d957572e8acd6', 8772881, '104b6e573f5d5bfb78e0e16c772881b684733461a1490f18835cf452205641c9', 'passed'], ['checks', '20261030T004747.955900Z-checks-9b60724f14fe.json', 11146, '6f88620e7dd34a973ad8ba3eed920c51622171a686b97d3978b44e14c1ed53ef', 11146, '6f88620e7dd34a973ad8ba3eed920c51622171a686b97d3978b44e14c1ed53ef', 'passed'], ['late_dso', '20261030T011020.114844Z-late-dso-9b60724f14fe.json', 4238, '45c6bbe5d16c29bd0c3299e7826a6ba19618e027fb6602939def752154f92d14', 961525, '9e6667ecf6111199f81c29fdf65dd12c5ff3076b4738b56ae7efa3fe6f79524d', 'failed'], ['zero', '20261030T011138.836552Z-page-selected-repeat-zero-9b60724f14fe.json', 3903, '4cd4b752ff8cb69ccff82e4efbd0db07c8c656fcf941a4fab29ec45c994381fe', 815734, 'd3c4dc6b17ac92c276b38fa232413cea00d6c6c12b8c642ffadac460bfe9b4c0', 'passed'], ['q', '20261030T011154.233195Z-page-selected-repeat-oracle-9b60724f14fe.json', 14097, 'd5511b75049b750b747227e68918483bdf69b129e296ea04f0b816a4b7e8c7e4', 708288, '887c8e5c865ea60738e8f2229c781ebf546c10cb792131b835e12b6d3da12d40', 'passed'], ['d', '20261030T011208.633185Z-page-selected-repeat-dword-oracle-9b60724f14fe.json', 14128, '553abccb1710f550c57cb368cd2366aeb3f1a17c54ea2f61b67e4330f60a6e76', 708589, 'bf7ae2d333c1236bd1161562756bccdd1c1bd68903e0462b494c63ca0eca3bbe', 'passed'], ['oneshot', '20261030T011316.714463Z-page-selected-oneshot-9b60724f14fe.json', 56045, '54e656b6673f13ce9d43cb9de59b9abd486eebd4767e3b82121affce09ed8d23', 1544249, '41045efc6730f71b506f49bd5ce09d99d84d6a369a651e42773c2b02171c6929', 'passed'], ['failure49', '20261030T011340.157194Z-page-selected-oneshot-failure-9b60724f14fe.json', 170782, 'ea8a4a56fb2c2801c002c027255162afca4ae13af1e0f4e7c4e16007e5dd1ab7', 2958990, 'd6a215c4b4d9abf1893c96c8016a01fda91cbcf9f3f2f5d1de9b61156da2a8ef', 'passed'], ['rseq17', '20261030T011524.916567Z-page-selected-rseq-application-fast-memset-9b60724f14fe.json', 20954, '04f4960382a38ea4a093c1323cd04911568eaba1b726e13b8facdf4b1439d277', 977408, '1f8f327bb55bfea6b3d2c61680022b0c959a3a55a77b04c5a513416542594c2f', 'passed_finite_inactive_profile'], ['pair', '20261030T011720.752442Z-page-native-pair-finite-9b60724f14fe.json', 15298, '210637e237ba45c51a9c8241437af7edba16f5c457d64489bded5f46432e2855', 12641528, 'b158f5aaf1c50918122a1e3c40515f620ba190a32d1e50e99ef6d007a1d64681', 'passed'], ['bzhi', '20261030T012449.025169Z-page-selected-bzhi-9b60724f14fe.json', 12534, 'f59bb34104c60022faccdcce18394f1a2aa2920be8f24b5f00b1ebdef1c58be4', 1097983, '7ac7452f5bb2468c21857451f9b2d216bf072800458c8e0a4d89351376da81dd', 'passed'], ['kortestq', '20261030T012508.656929Z-page-selected-kortestq-9b60724f14fe.json', 21228, '6363fcb7b1ce7094a412adac38b9dc4fdbe505872cc0a8f6dcff88f478d9567b', 1253373, 'fa24224d5e5cbcc6218b2eece18213f03bf85d8d9373c503c5c9ebd46171ad5c', 'passed'], ['xor128', '20261030T012623.552388Z-page-selected-vpxorq128-9b60724f14fe.json', 24314, '5c97a47e0c7ba7966dd6938018c0d861c2a527a9f899a4c1f3675181df451aad', 1305519, 'ce9644d69ce07bd10ab3118ef01bb43dd72c80754a87d715c34126cc5078cb3f', 'passed'], ['bmi1', '20261030T012705.051436Z-page-selected-bmi1-register-9b60724f14fe.json', 24271, '6a6513eb33240e408ac468b6ff9138894ab91fa4459ce789a78fd3b857d06cbc', 1307656, '579ef0c982d90748a71c1fa31ed6eeb2af91feac77633c4fd9467c4e9f54bdfc', 'passed'], ['xor256', '20261030T013140.700964Z-page-selected-vpxorq256-9b60724f14fe.json', 9572, '5099b2fcf3ce002dfa1d5f7943af90a4893fd86648969d009cb2d916f0b07088', 1666334, 'e2c8d8f97926d3374eb96fa71b733cdc26cf86bb9aeaf0fbf0f3de1082248685', 'passed'], ['vpminub', '20261030T013247.068477Z-page-selected-vpminub-register-9b60724f14fe.json', 24403, '2a133a90bdc91d25ca98ad4f4eb9b3b23a2b8cb63694b1cbd5d28e0ec7724051', 1309444, '2227eba7d81ac3a5ffd6d785cccbc1eed95aa76bb8fb4103bfed02191fcf3ce1', 'passed'], ['rep46', '20261030T013709.142293Z-page-selected-repeat-lease-9b60724f14fe.json', 13393, '5ce00a76dceb5d119b27d222f3af46e4abd1cf20f269528e558f75020d226916', 3267387, '39cc906509145731273b579439a8c0f0e884576345f189efbba92995a486c479', 'passed']]
BASE='69f258e36b03b9e99247392a2e9693b21a859188';REV='9b60724f14fe2ab99ffc046ab41ae22da8b62ff8'
PENDING=() # every fixed cohort is now closed and independently audited
H=lambda b:hashlib.sha256(b).hexdigest()
J=lambda v:(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def fact(b):return dict(bytes=len(b),sha256=H(b))
def digest(v):return H(J(v)[:-1])
def sub(v):return {k:v[k]for k in('bytes','sha256')}
ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--root',type=Path,default=Path.cwd());ap.add_argument('--output',type=Path,required=True)
a=ap.parse_args();assert not sys.flags.optimize
R=a.root.resolve();sources=[];hardware=[];bounds=[];rows=[];verified={};archives={};capture_refs=capture_bytes=0
def pool(values,value):
 if value not in values:values.append(value)
 return values.index(value)
def git(*args):return subprocess.check_output(['git','-C',str(R),*args])
def original(path,want):
 global capture_refs,capture_bytes
 key=str(path)
 if key not in verified:
  packed=Path(str(path)+'.gz');assert not(path.exists()and packed.exists()),'one retained representation'
  if not path.exists():assert packed.is_file();archives[str(packed.relative_to(R))]=fact(packed.read_bytes())
  with(path.open('rb')if path.exists()else gzip.open(packed,'rb'))as f:
   h=hashlib.sha256();n=0
   while chunk:=f.read(1<<20):h.update(chunk);n+=len(chunk);assert n<=want['bytes']
  verified[key]=dict(bytes=n,sha256=h.hexdigest())
 assert verified[key]==sub(want),key
 capture_refs+=1;capture_bytes+=want['bytes']
def checks(p,r,private):
 assert p==r and len(p['commands'])==6 and p['status']=='passed'and p['configuration_unchanged']
 assert [c['id']for c in p['commands']]==['recorder_tests','fmt','clippy','workspace_tests','workspace_check','serial_launch']
 out=[]
 for c in p['commands']:
  assert c['status']=='passed'and c['exit_code']==0 and c['cleanup_complete']and c['termination']is None
  data=(private/(c['id']+'.log')).read_bytes();assert H(data)==c['private_log_sha256']
  out.append([c['id'],c['argv'],c['status'],c['exit_code'],c['seconds'],c['timeout_seconds'],c.get('tests_passed'),c.get('harness_totals'),c['private_log_sha256'],{k:v for k,v in c.items()if k.endswith('_count')}])
 return dict(columns=['id','argv','status','exit','seconds','wall_limit_seconds','recorder_tests','harness_totals','log_sha256','required_case_counts'],rows=out)
def ternary(p,r):
 commands={c['name']:c for c in r['commands']};cases={c['name']:c for c in r['cases']};assert len(cases)==len(r['cases'])
 assert p['command_recipe']['groups']==list(range(141))and len(p['command_recipe']['selectors'])==6
 names=['group'+str(g)for g in range(141)]+['full-read-fault','cross-read-fault','indexed-full-read-fault','indexed-cross-read-fault','constant-zero-read-fault','constant-one-read-fault']
 table=[];public_rows=[]
 for index,name in enumerate(names):
  c=commands.get(name);case=cases.get(name);v=case.get('outcome')if case else None;cap=c.get('captures',{}).get('record')if c else None
  group=index if index<141 else 0;fault=0 if index<141 else index-140
  if case:assert case['group']==group and case['fault_kind']==fault
  accepted=int(case is not None and case['status']=='accepted_observation')
  table.append([group,fault,int(c is not None and c.get('pid')is not None),accepted,c.get('exit')if c else None,cap['bytes']if cap else None,*[v[k]if v else None for k in('pairs','new_pairs','verified_memory_failures','actual_before_queries','refusals')],c.get('duration_ns')if c else None])
  if case:public_rows.append([group,fault,accepted,case.get('actual_exit'),case.get('record',{}).get('bytes'),*[v[k]if v else None for k in('pairs','new_pairs','verified_memory_failures','actual_before_queries','refusals')]])
 assert public_rows==p['cases']
 if p['status']=='passed':assert len(cases)==147 and all(x[2:4]==[1,1]for x in table)and p['totals']['new_pairs']==2250 and p['totals']['verified_memory_failures']==6
 else:assert p['status']=='failed'and table[0][2:4]==[1,1]and table[1][2:6]==[0,0,None,0]and all(x[2:4]==[0,0]for x in table[2:])
 return dict(required_processes=147,actual_processes=sum(x[2]for x in table),qualified_processes=sum(x[3]for x in table),unexecuted_processes=147-sum(x[2]for x in table),totals=p['totals'],columns=['group','fault','launched','qualified','exit','record_bytes','pairs','new_pairs','verified_read_fault','actual_before_queries','refusals','whole_command_ns'],rows=table,original_public_rows_sha256=digest(p['cases']),generated=p['generated'],record_storage=p['record_storage'])
def summary(label,p,r,private):
 if label=='checks':return checks(p,r,private)
 if label in('ternary','fd3_precursor'):return ternary(p,r)
 if label=='zero':return dict(required_processes=p['required_native_processes'],actual_processes=p['actual_native_processes'],result=p['cases'][0]['result'])
 if label=='failure49':
  assert [c['mode']for c in r['cases']]==list(range(1,50))
  return dict(**{k:p[k]for k in('required_cases','attempted_cases','qualified_failed_operations','qualified_refused_sites','full_cohort_qualified','B2_completion_credit')},columns=['selector','exit','refused_site','owner_error','report_error'],rows=[[c['mode'],c['exit'],int(c['mode']==47),c['expected']['owner_error'],c['expected']['report_error']]for c in r['cases']])
 if label=='oneshot':return dict(native_gated_pairs=p['accepted_pairs'],selected_owners=p['oneshot']['owners'],effect_started=p['oneshot']['effect_started'],effect_returned=p['oneshot']['effect_returned'],owners_restored=p['oneshot']['restored'],owners_completed=p['oneshot']['completed'])
 if label=='rseq17':return dict(**{k:p[k]for k in('required_cases','accepted_cases','completed_cases','required_refusals','finite_command_count')},columns=['name','accepted','exit','guard_kind','new_rx_calls','target_raw_calls'],rows=[[c['name'],int(c['accepted']),c['operation_exit'],c['guard_kind'],c['new_rx_calls'],c['target_raw_calls']]for c in p['cases']])
 if label=='pair':
  x=p['native_pair'];assert x['qualified_cases']==22 and x['qualified_subjects']==44 and x['supplied_reader_refusals']==675 and x['completed_pairs']==x['required_refusals']==11
  assert p['rseq_native']['accepted_pairs']==16 and p['rseq_native_boundary']['accepted_pairs']==4
  return dict(pair={k:x[k]for k in('planned_cases','qualified_cases','planned_subjects','actual_subjects','qualified_subjects','completed_pairs','required_refusals','actual_native_fault_references','supplied_reader_refusals','supplied_reader_native_operation_credit','full_b2_complete','full_b3_complete')},columns=x['columns'][:-1],rows=[row[:-1]for row in x['rows']],original_rows_sha256=digest(x['rows']),control_columns=x['reader_control_columns'],control_rows=x['reader_control_rows'],old_registered=p['rseq_native'],old_boundary=p['rseq_native_boundary'],companions=p['companions'])
 if label=='late_dso':
  ts=[json.loads(l.partition(b' ')[2])for l in(private/'gated.stderr').read_bytes().splitlines()if l.startswith(b'LI2_LOADER ')];assert len(ts)==1;t=ts[0];n,g=p['cases']
  assert n['lane']=='native'and g['lane']=='gated'and n['exit']==0 and g['exit']==125 and t['status']==125 and t['failure_code']==1207 and t['detail_abs']==2784
  return dict(namespace=p['namespace_controls'],columns=['gated','exit','whole_process_ns','stdout_bytes','stderr_bytes','record_bytes'],rows=[[int(c['lane']=='gated'),c['exit'],c['whole_process_ns'],*[c['captures'].get(k,{}).get('bytes')for k in('stdout','stderr','record')]]for c in p['cases']],native=dict(effects=n['application']['effects'],cycles=n['application']['cycles'],live_snapshots=n['application']['live_state_snapshots'],supplied_refusals=n['reader_controls']['rejected']),gated_failure={k:t[k]for k in('status','failure_code','detail_abs','detail_negative','last_syscall','selected_steps')},pair_qualified=p['pair']is not None,full_b3_qualification=p['full_b3_qualification'])
 if label=='xor256':
  assert p['totals']==r['totals']and len(p['cases'])==16 and p['totals']['new_pairs']==193 and p['totals']['verified_memory_failures']==4
  return dict(actual_processes=16,totals=p['totals'],columns=['name','exit','operation','pairs','new_pairs','verified_memory_failures','actual_before_queries','refusals'],rows=[[c[k]for k in('name','exit','operation','pairs','new_pairs','verified_memory_failures','actual_before_queries','refusals')]for c in p['cases']])
 if label=='rep46':
  assert p['totals']==r['totals']and p['required_native_processes']==p['attempted_native_processes']==len(p['cases'])==46
  return dict(actual_processes=46,totals=p['totals'],columns=p['case_columns'][:-1],rows=[c[:-1]for c in p['cases']],original_rows_sha256=digest(p['cases']))
 assert p['totals']==r['totals'];out=dict(actual_processes=len(p['cases']),totals=p['totals'])
 if label in('q','d'):out.update(columns=['accepted','exit','operation_completed','actual_failed_operation'],rows=[[int(c['accepted']),c['actual_exit'],int(c['operation_completed']),int(c['actual_failed_operation'])]for c in p['cases']])
 else:out.update(columns=['name','exit','pairs','new_pairs','refusals'],rows=[[c['name'],c['actual_exit'],*[c['outcome'][k]for k in('pairs','new_pairs','refusals')]]for c in p['cases']])
 return out
for label,name,pn,psha,rn,rsha,status in PINS:
 path=R/'evaluation/inprocess/results'/name;private=R/'target/evaluation/inprocess'/path.stem;pb=path.read_bytes();rb=(private/'receipt.json').read_bytes()
 assert fact(pb)==dict(bytes=pn,sha256=psha)and fact(rb)==dict(bytes=rn,sha256=rsha);p=json.loads(pb);r=json.loads(rb)
 assert p['status']==r['status']==status and p['source']==r['source']and p['source_unchanged']is True and r['source_unchanged']is True
 src=p['source'];assert src['revision']==p['expected_revision']==r['expected_revision']and src['tracked_clean']and src['head_sources_match']and src['revision']==(BASE if label=='fd3_precursor'else REV)
 assert git('rev-parse',src['revision']+'^{tree}').decode().strip()==src['tree']
 if 'source_after'in r:assert r['source_after']==src
 if 'private_receipt'in p:assert p['private_receipt']==fact(rb)
 for key in('inputs','artifacts','binaries','aliases'):
  if key+'_before'in r:assert r[key+'_before']==r[key+'_after']
 commands=r['commands'];assert len(commands)==p.get('command_count',p.get('commands')if isinstance(p.get('commands'),int)else len(commands))
 if label!='checks':
  for c in commands:
   if label=='fd3_precursor'and c['name']=='group1':assert 'pid'not in c and c['exit']is None and c['reaped']is False and not c['timed_out']and c['error']=='ValueError: standalone step requires actual fixed fd 3'and len(c['cleanup_errors'])==2 and c['descriptors']==[dict(closed=True,fd=4,name='record')]
   else:assert c['reaped']is True and not c['timed_out']and not c['error']and not c['cleanup_errors']
   for cap in c.get('captures',{}).values():assert Path(cap['file']).name==cap['file'];original(private/cap['file'],cap)
  if 'cleanup_complete'in p:assert p['cleanup_complete']is(label!='fd3_precursor')
  assert p['final_error_count']==len(r['final_errors'])==0
 result=summary(label,p,r,private);hw=dict(p['hardware']);cpu=hw.pop('probe_cpu');affinity=hw.pop('affinity_cpu_count')
 if 'isa_flags'in hw:flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
 failures=[[c['name'],int(c.get('pid')is not None),c.get('exit'),c.get('reaped'),c.get('error'),len(c.get('cleanup_errors',[])),c.get('descriptors',[])]for c in commands if label!='checks'and(c.get('error')or c.get('cleanup_errors')or not c.get('reaped')or(c['expected_exit']is not None and c['exit']!=c['expected_exit']))]
 rows.append([label,name,pn,psha,rn,rsha,pool(sources,src),pool(hardware,hw),cpu,affinity,pool(bounds,p.get('bounds',{'log_limit_bytes_per_command':p['log_limit_bytes_per_command']}if label=='checks'else{})),status,p['reproduce'],len(commands),dict(collections.Counter(str(c.get('exit',c.get('exit_code')))for c in commands)),sum(c.get('duration_ns',0)for c in commands)if label!='checks'else None,p.get('cleanup_complete'),digest(commands),result,dict(error=r.get('error'),command_columns=['name','launched','exit','reaped','error','cleanup_error_count','descriptors'],commands=failures)if status=='failed'else None])
assert len({x[0]for x in rows})==len(rows)and sum(x[11]=='failed'for x in rows)==2
STORAGE_PINS=[['target/page-vpternlogd-next/storage-review/fd-r1/TEST-EXECUTION.json', 972, '3f107e3b8b19fb3bf02ff21d4eb094f90fef6ab9a766180fb3dd4c3ac059f65e'], ['target/page-vpternlogd-next/storage-review/fd-r1/test-output/result.json', 1997, 'b73f065c4cd7f0bdf84e3ca5a2197522b3a95e7af5c6c8f964118cc621343113'], ['target/page-vpternlogd-next/storage-review/fd-r1/DATA-REVIEW.json', 1617, 'f51fce156b4ea5b94177e3a38885a9335eca51bdb3a850a4b7d41536e0bad277']]
sv={}
for name,n,sha in STORAGE_PINS:
 data=(R/name).read_bytes();assert fact(data)==dict(bytes=n,sha256=sha);sv[Path(name).name]=json.loads(data)
exe=sv['TEST-EXECUTION.json'];res=sv['result.json'];review=sv['DATA-REVIEW.json']
assert exe['exit']==0 and exe['stderr']==''and res['status']=='passed'and len(res['cases'])==12 and res['native_subjects']==res['reader_replays']==0 and all(c['status']=='passed'for c in res['cases'])
assert review['status']=='DATA_CLEAR'and review['execution']==fact((R/STORAGE_PINS[0][0]).read_bytes())and review['result']==fact((R/STORAGE_PINS[1][0]).read_bytes())
assert fact(Path(__file__).with_name('page_record_storage_controls.py').read_bytes())=={'bytes': 10462, 'sha256': 'b0dac6292c3efd4b38a1301b588eb8adb9c6e4726b3446cdaffecf1499d2580f'}
cmd=exe['command'];portable=['python3','-B','evaluation/inprocess/page_record_storage_controls.py','--helper','evaluation/inprocess/page_record_storage.py',*cmd[5:9],'--output','${NEW_PRIVATE_OUTPUT}']
storage=dict(status='passed',component_only=True,native_subjects=0,reader_replays=0,cases=res['cases'],original_records=res['original_records'],inputs=res['inputs'],bounds=exe['bounds'],cpu=exe['cpu'],seconds=exe['seconds'],exit=exe['exit'],evidence=[dict(file=name,bytes=n,sha256=sha)for name,n,sha in STORAGE_PINS],control_script=dict(file='evaluation/inprocess/page_record_storage_controls.py',**{'bytes': 10462, 'sha256': 'b0dac6292c3efd4b38a1301b588eb8adb9c6e4726b3446cdaffecf1499d2580f'}),recorded_argv_after_executable=cmd[1:],recorded_executable_basename=Path(cmd[0]).name,portable_replay=portable,scope='Historical storage component only; c14 identities retained. Replay requires private captures; prior eleven controls superseded only within this component.')
changes=git('diff','--name-only',BASE,REV).decode().splitlines();assert changes==['evaluation/inprocess/page_record_storage.py']
changed=[dict(file=n,before=fact(git('show',BASE+':'+n)),after=fact(git('show',REV+':'+n)))for n in changes]
v=dict(schema=1,status='pending_regressions'if PENDING else'finite_regressions_complete_application_failed',scope='Closed finite correctness and failed attempts; no performance or full-B3 credit.',sources=sources,hardware=hardware,bounds=bounds,columns=['label','file','public_bytes','public_sha256','private_bytes','private_sha256','source','hardware','cpu','affinity_cpu_count','bounds','status','reproduce','commands','exit_counts','command_duration_ns_sum','cleanup_complete','commands_sha256','summary','failure'],rows=rows,storage_component=storage,pending=[dict(label=k,status='pending_closed_independent_audit')for k in PENDING],source_change=dict(before=BASE,after=REV,only_changed_files=changed,scope='Only journal descriptor lifetime changed; the prior failed revision/status/incomplete cleanup remain.'),audit=dict(receipts=len(rows),capture_references=capture_refs,capture_bytes=capture_bytes,distinct_capture_files=len(verified),lossless_archive_files=len(archives),archive_facts_sha256=digest(archives),scope='Exact receipt/capture/source/configuration/cleanup closure; no reader replay or new execution.'),limitations=['2250 selected successes plus141 successful startup pairs make2391 completed pairs; six genuine read-fault references remain failed operations. All147 startup prefixes are retained.','The69f fixed-FD failure and9b late-DSO Code2784 failure remain failed. Native-only loader cycles are not gated lifecycle qualification.','No assertions/comparators/tolerances/resource caps changed, case skipped/exempted, failure relabelled or check deleted. Storage controls have no native-operation credit.','All fixed receipt slots are closed and independently audited; both failed overall attempts retain their original status.'],reproduce=['python3','-B','evaluation/inprocess/page_vpternlogd_qualification.py','--root','${REPOSITORY}','--output','${NEW_OUTPUT}'])
# Compact repeated metadata and never-launched absence only; every inverse is asserted.
shared=dict(total_columns=[],generated=[],bounds_values=[],reproduce_rule="[python3]+flags+[evaluation/inprocess/+module,--expect-revision,sources[row.source].revision]+tail")
for r in rows:
 original_argv=r[12];flags=['-B']if original_argv[1]=='-B'else[];i=1+len(flags);module=original_argv[i].removeprefix('evaluation/inprocess/');tail=original_argv[i+3:]
 assert ['python3',*flags,'evaluation/inprocess/'+module,'--expect-revision',sources[r[6]]['revision'],*tail]==original_argv
 r[12]=[flags,module,tail];s=r[18]
 if 'totals'in s:
  old=s['totals'];cols=list(old);encoded=[pool(shared['total_columns'],cols),list(old.values())];assert dict(zip(shared['total_columns'][encoded[0]],encoded[1]))==old;s['totals']=encoded
 if 'generated'in s:
  old=s['generated'];s['generated']=pool(shared['generated'],old);assert shared['generated'][s['generated']]==old
 if r[0]=='fd3_precursor':
  old=s['rows'];template=[0,0,None,None,None,None,None,None,None,None];absence=dict(group_inclusive=[2,140],fault_inclusive=[1,6],suffix=template)
  rebuilt=old[:2]+[[g,0,*template]for g in range(2,141)]+[[0,f,*template]for f in range(1,7)]
  assert rebuilt==old and len(rebuilt)==147;s['rows']=old[:2];s['unobserved_rows']=absence;s['all_rows_sha256']=digest(old)
 if r[0]in('pair','rep46'):
  old=s['rows'];columns=('qualification','operation_status')if r[0]=='pair'else('status','operation','evidence');codes={c:[]for c in columns};encoded=[]
  for row in old:
   row=list(row)
   for c,values in codes.items():i=s['columns'].index(c);row[i]=pool(values,row[i])
   encoded.append(row)
  rebuilt=[list(row)for row in encoded]
  for row in rebuilt:
   for c,values in codes.items():i=s['columns'].index(c);row[i]=values[row[i]]
  assert rebuilt==old;s['rows']=encoded;s['string_values']=codes
for b in bounds:
 for name,value in list(b.items()):
  if isinstance(value,list):index=pool(shared['bounds_values'],value);assert shared['bounds_values'][index]==value;b[name]=index
old=storage['cases'];cols=['name','actual_source_exit','raw_bytes','status'];encoded=[[c[k]for k in cols]for c in old]
assert [dict(zip(cols,c))for c in encoded]==old;storage['cases']=encoded;storage['case_columns']=cols
v['shared']=shared;v['columns'][12]='reproduce_flags_module_tail';v['bounds_value_units']=['cpu_seconds','address_space_bytes','file_size_bytes','wall_seconds']
data=J(v);assert len(data)<=40*1024 and b'/home/'not in data and b'/usr/local/'not in data
with a.output.open('xb')as f:f.write(data)
print(json.dumps(dict(output=a.output.name,**fact(data),receipts=len(rows),pending=list(PENDING),native_execution=False),sort_keys=True))
