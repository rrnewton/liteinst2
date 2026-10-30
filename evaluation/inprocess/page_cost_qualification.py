#!/usr/bin/env python3
"""Exact closed qualification receipts; no native execution, replay or performance aggregation."""
from pathlib import Path
import argparse,collections,gzip,hashlib,json,subprocess,sys
PINS=[
 ['20261029T232141.322544Z-page-selected-repeat-zero-8e575e9f18d1.json', '9b02389f973abb636172f47228c8161da8f1363a82f56249db2fe03a919d9c48', 'd4d64c00aa56b41bb4273f4b52a7b4de8b6de2206a647409c0b6f04396b4a5f5'],
 ['20261029T232424.230355Z-page-selected-repeat-zero-c14f3078a1b5.json', 'd25822df22aa9b4ad6f72667f1f46e10a219fc80d958a6566fa1ac5d6db66a72', '3fbd1d07aca0926c32482a6082b1f28522ab4be5670c6bbdb1ed298579ec31dc'],
 ['20261029T232435.849304Z-page-selected-repeat-oracle-c14f3078a1b5.json', '47d2fecfe75e35dcfff3c2582e6b89e4e1841f6ac044b2b8c1066f6ed6626981', '96e28c240828f62607f99c02c50f0219843b6b082760d47d6747f95cf4eece48'],
 ['20261029T232447.227068Z-page-selected-repeat-dword-oracle-c14f3078a1b5.json', 'ba5c35e2bc93e7200fa9375e08d0f9a58e6b2380f913e5362cab7bba7bcc9139', 'ce6364a2d9703283ccd5302fc95d85d12f1023ea8a5ce4b2fd61cafc724af98f'],
 ['20261029T232458.165583Z-page-selected-repeat-lease-c14f3078a1b5.json', '63b55c35798da4763e47de852d0aeb3f522e4baf5c83b53b082cf96c2924062d', 'ce6ab4a7fd0a49c7a069a8bb5ebb3953291f5eba3cb2ca1fd733b73b11378465'],
 ['20261029T232611.256388Z-checks-c14f3078a1b5.json', 'd914d2fa43aec707358fc0fc55391b9ea0e1280068de0a4803528e8e3f87bb07', 'd914d2fa43aec707358fc0fc55391b9ea0e1280068de0a4803528e8e3f87bb07'],
 ['20261029T233605.849922Z-page-selected-vpxorq256-c14f3078a1b5.json', 'fc2a10e3587d30275e6d00f0fcaf80586117380889556698a5853f4ee3578469', '45e27943431739a6eff8eec28218bb65794e177aaa530afe67f8055a6108a0a6'],
 ['20261029T233702.862450Z-page-selected-vpxorq128-c14f3078a1b5.json', '04305fd8bea2aa1b132576a3127f81e798d08629b7829198604501fa9687e61b', 'd7b7e816a1000a29594f783726200b55cf2a354b81dc41f2e150b88ecc38ce2c'],
 ['20261029T233734.720769Z-page-selected-bzhi-c14f3078a1b5.json', 'd654300bd820fd38b267b08fe1a4c0ce442bbf31c5ff041d2bc50e5bfa5d75ae', '33ecdb3edac0e84eff7837e76523abbf82f50d739becf5c2eb06f695e39464a8'],
 ['20261029T233752.501988Z-page-selected-bmi1-register-c14f3078a1b5.json', '81a1e084f4e5596ffe4c3a761ff97c1af138386c611ade0588f742fcc60c5902', 'c1e9e74a8f2f84a1d6cc2e5ede33bdc6c4751436d3b2dc0b2979ff3ac9da8edd'],
 ['20261029T233823.364407Z-page-selected-vpminub-register-c14f3078a1b5.json', '3fae7d5e90a1a1496d9e75f5ed4c9324f9c02a856e79f493c7ed965b6247e08b', '0bfe69a7f7442227f0a4654e81f1b70bc8541cd4579321ab906ffe9e3260e007'],
 ['20261029T233853.806390Z-page-selected-kortestq-c14f3078a1b5.json', '8a11b16b90c2a605939458511618ad43601f771692c08da06e94d36f4a212cf6', 'cca8e2a3be14aa01991ad8b78d38f566ac544f3c134b31fea7aadbdb22aae7c2'],
 ['20261029T233920.080627Z-page-selected-oneshot-c14f3078a1b5.json', '7326648c5a7dfce3c761b1785180560ec25e4081bdfc2d862c518f023ead70ce', '88d8fc6ea1b178bea2524057a97d9f12a8ca120713e4a0d161be0eee656b29d5'],
 ['20261029T233942.670293Z-page-selected-oneshot-failure-c14f3078a1b5.json', '35e0b62ae675084022c79d63f0eec728baf3b094671f649ab0b933aa0cd97783', '5b2d1fab05c224f2fb10874cd9b0132d1e4092de974c30bb3a66bf368a426135'],
 ['20261029T234131.452711Z-page-selected-rseq-application-fast-memset-c14f3078a1b5.json', 'baded5b260f898e1076a829647dc2241591ab6c3820a097b443790e1e88cab4b', '4247f41aceb67da5790d07401bbc182174e828e3b8b096b3dedfb266e3774185'],
 ['20261029T235043.164017Z-page-selected-oneshot-5a35f755f0b2.json', 'b807d28ef0f0aac5b06f6468316ccdbc594de1a8d01465ba69a174b768c396f9', '20d1807db1268c25ea4def284ae7c3f0400009deac2a388c4c6eb56815b58228'],
 ['20261029T235105.035133Z-page-selected-oneshot-failure-5a35f755f0b2.json', '17e8aa25a1e53473fa1fbcc90c0a5049db79ea85117bcf2c5cacc9e6a1f447f2', 'cfb2e1b21f3f61540d74dd34e163c28b280aeb123653a181e064d79fc16e3b67'],
 ['20261029T235257.086702Z-page-selected-rseq-application-fast-memset-5a35f755f0b2.json', 'e38c16b1c2279b56829eb04d0fce3b55d9c1166305c042d718c227a4753cf3f5', '6af3a584226df91d80eb6000728c0d8f70481812477ad373c228afaafe4b8747'],
 ['20261029T235327.081702Z-page-native-pair-finite-5a35f755f0b2.json', '3cd3f76e70fddc295af2b135d56d4237f752619424acf77ed1b0d2e631b04c87', 'b689680620ef49d2861893b027fd8f7e7995c0b85784a8495bac094caa53ddd4'],
 ['20261030T000127.955502Z-late-dso-5a35f755f0b2.json', '29672cf08da3b23b3ac00673e3fd20ec2fab9ce69025304cb2b1890c36b68517', 'dadb25e937f1c8c9a264bd77a3e52848c196a3230de7049330ae521b3fc374c1']
]
C14='c14f3078a1b59c637f3cf5fe29e0849ca11f3abf';FINAL='5a35f755f0b2359b6ae05b51221aea032048923b'
H=lambda b:hashlib.sha256(b).hexdigest()
J=lambda v:(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def fact(b):return dict(bytes=len(b),sha256=H(b))
ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--root',type=Path,default=Path.cwd());ap.add_argument('--output',required=True,type=Path)
ap.add_argument('--final-checks');ap.add_argument('--final-checks-sha256');a=ap.parse_args();assert not sys.flags.optimize
R=a.root.resolve();sources=[];hardware=[];bounds=[];rows=[];verified={};capture_count=capture_bytes=0;archives={}

def pool(values,value):
 if value not in values:values.append(value)
 return values.index(value)
def git(*args):return subprocess.check_output(['git','-C',str(R),*args])
def hash_file(path,want):
 global capture_count,capture_bytes
 key=str(path)
 if key not in verified:
  packed=path.with_name(path.name+'.gz')
  if not path.exists():
   assert packed.is_file();archives[str(packed.relative_to(R))]=fact(packed.read_bytes())
  with (path.open('rb')if path.exists()else gzip.open(packed,'rb'))as f:
   h=hashlib.sha256();size=0
   while chunk:=f.read(1<<20):
    h.update(chunk);size+=len(chunk);assert size<=want['bytes']
  verified[key]=dict(bytes=size,sha256=h.hexdigest())
 assert verified[key]=={k:want[k]for k in('bytes','sha256')},key
 capture_count+=1;capture_bytes+=want['bytes']
def checks(p,r,private):
 assert p==r and len(p['commands'])==6 and p['status']=='passed'and p['configuration_unchanged'] is True
 assert [c['id']for c in p['commands']]==['recorder_tests','fmt','clippy','workspace_tests','workspace_check','serial_launch']
 out=[]
 for c in p['commands']:
  assert c['status']=='passed'and c['exit_code']==0 and c['cleanup_complete'] is True and c['termination'] is None
  path=private/(c['id']+'.log');data=path.read_bytes();assert H(data)==c['private_log_sha256']
  out.append([c['id'],c['argv'],c['status'],c['exit_code'],c['seconds'],c['timeout_seconds'],c.get('tests_passed'),c.get('harness_totals'),c['private_log_sha256'],{k:v for k,v in c.items()if k.endswith('_count')}])
 return dict(check_columns=['id','argv','status','exit','seconds','wall_limit_seconds','recorder_tests','harness_totals','log_sha256','required_case_counts'],checks=out)
def summary(name,p,r,private):
 if '-checks-'in name:return checks(p,r,private)
 if 'repeat-zero-'in name:return dict(required_processes=p['required_native_processes'],actual_processes=p['actual_native_processes'],result=p['cases'][0]['result']if p['cases']else None)
 if 'oneshot-failure-'in name:return {k:p[k]for k in('required_cases','attempted_cases','qualified_failed_operations','qualified_refused_sites','full_cohort_qualified','B2_completion_credit')}
 if 'oneshot-'in name:return dict(native_gated_pairs=p['accepted_pairs'],selected_owners=p['oneshot']['owners'],effect_started=p['oneshot']['effect_started'],effect_returned=p['oneshot']['effect_returned'],owners_restored=p['oneshot']['restored'],owners_completed=p['oneshot']['completed'])
 if 'rseq-application-'in name:return dict(unexecuted_cases=p['required_cases']-len(p['cases']),**{k:p[k]for k in('required_cases','accepted_cases','completed_cases','required_refusals','finite_command_count')})
 if 'native-pair-finite-'in name:
  pair=p['native_pair'];assert pair['qualified_cases']==22 and pair['qualified_subjects']==44 and pair['supplied_reader_refusals']==675
  assert pair['completed_pairs']==pair['required_refusals']==11 and p['rseq_native']['accepted_pairs']==16 and p['rseq_native_boundary']['accepted_pairs']==4
  return dict(pair={k:pair[k]for k in('planned_cases','qualified_cases','planned_subjects','actual_subjects','qualified_subjects','completed_pairs','required_refusals','actual_native_fault_references','supplied_reader_refusals','supplied_reader_native_operation_credit','full_b2_complete','full_b3_complete')},old_registered=p['rseq_native'],old_boundary=p['rseq_native_boundary'],companions=p['companions'])
 if 'late-dso-'in name:
  terminal=[json.loads(x.split(b' ',1)[1])for x in(private/'gated.stderr').read_bytes().splitlines()if x.startswith(b'LI2_LOADER ')];assert len(terminal)==1;t=terminal[0]
  n,g=p['cases'];assert n['lane']=='native'and g['lane']=='gated'
  return dict(namespace=p['namespace_controls'],native=dict(status=n['status'],exit=n['exit'],whole_process_ns=n['whole_process_ns'],effects=n['application']['effects'],cycles=n['application']['cycles'],live_snapshots=n['application']['live_state_snapshots'],supplied_refusals=n['reader_controls']['rejected']),gated=dict(status=g['status'],exit=g['exit'],whole_process_ns=g['whole_process_ns'],stdout_bytes=g['captures']['stdout']['bytes'],failure={k:t[k]for k in('status','failure_code','detail_abs','detail_negative','last_syscall','selected_steps')}),pair_qualified=p['pair']is not None,full_b3_qualification=p['full_b3_qualification'])
 assert 'totals'in p and p['totals']==r['totals']
 return dict(actual_processes=len(p['cases']),totals=p['totals'])
if a.final_checks is not None:
 assert a.final_checks_sha256 and a.final_checks.endswith('-checks-'+FINAL[:12]+'.json')and Path(a.final_checks).name==a.final_checks
 PINS.append([a.final_checks,a.final_checks_sha256,a.final_checks_sha256])
else:assert a.final_checks_sha256 is None
for name,public_sha,private_sha in PINS:
 path=R/'evaluation/inprocess/results'/name;private=R/'target/evaluation/inprocess'/path.stem;pb=path.read_bytes();qb=(private/'receipt.json').read_bytes()
 assert H(pb)==public_sha and H(qb)==private_sha;p=json.loads(pb);r=json.loads(qb)
 assert p['status']==r['status']and p['source']==r['source']and p['source_unchanged']is True and r['source_unchanged']is True
 src=p['source'];assert src['revision']==p['expected_revision']==r['expected_revision']and src['tracked_clean']is True and src['head_sources_match']is True
 if name==a.final_checks:assert src['revision']==FINAL
 assert git('rev-parse',src['revision']+'^{tree}').decode().strip()==src['tree']
 if 'source_after'in r:assert r['source_after']==src
 if 'private_receipt'in p:assert p['private_receipt']==fact(qb)
 for key in('inputs','artifacts','binaries','aliases'):
  if key+'_before'in r:assert r[key+'_before']==r[key+'_after']
 commands=r['commands'];assert len(commands)==p.get('command_count',p.get('commands')if isinstance(p.get('commands'),int)else len(commands))
 if '-checks-'not in name:
  assert all(c['reaped']is True and c['timed_out']is False and c['cleanup_errors']==[]for c in commands)
  for c in commands:
   for cap in c.get('captures',{}).values():
    assert Path(cap['file']).name==cap['file'];hash_file(private/cap['file'],cap)
  if 'cleanup_complete'in p:assert p['cleanup_complete']is True
  assert p['final_error_count']==len(r['final_errors'])
 else:assert p['configuration_unchanged']is True
 error=dict(error=r.get('error'),report_error=r.get('report_error'),final_errors=r.get('final_errors',[]))
 assert not any('/home/'in str(v)for v in error.values())
 result=summary(name,p,r,private)
 count=collections.Counter(str(c.get('exit',c.get('exit_code')))for c in commands)
 hw=dict(p['hardware']);cpu=hw.pop('probe_cpu');affinity=hw.pop('affinity_cpu_count')
 if 'isa_flags'in hw:
  flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=H(J(flags)[:-1]))
 assert not hardware or hardware[0]==hw
 row=dict(receipt=dict(file=name,public=fact(pb),private=fact(qb)),source=pool(sources,src),hardware=pool(hardware,hw),cpu=cpu,affinity=affinity,bounds=pool(bounds,p.get('bounds',{'log_limit_bytes_per_command':p['log_limit_bytes_per_command']}if '-checks-'in name else{})),status=p['status'],reproduce=p['reproduce'],commands=len(commands),exit_counts=dict(count),summary=result)
 row['duration_ns_sum']=sum(c.get('duration_ns',0)for c in commands)if '-checks-'not in name else None
 if r.get('error')or r.get('final_errors'):row['failure']=error
 rows.append(row)
changes=git('diff','--name-only',C14,FINAL).decode().splitlines();assert changes==['evaluation/inprocess/page_selected_rseq_inputs.json','tools/page-entry/selected/tests/rseq_application/ADAPTERS.json']
changed=[]
for name in changes:changed.append(dict(file=name,before=fact(git('show',C14+':'+name)),after=fact(git('show',FINAL+':'+name))))
assert sum(x['status']=='failed'for x in rows)==3
columns=['file','public_bytes','public_sha256','private_bytes','private_sha256','source','cpu','affinity_cpu_count','bounds','status','reproduce','commands','exit_counts','command_duration_ns_sum','summary','failure']
packed_rows=[[x['receipt']['file'],x['receipt']['public']['bytes'],x['receipt']['public']['sha256'],x['receipt']['private']['bytes'],x['receipt']['private']['sha256'],x['source'],x['cpu'],x['affinity'],x['bounds'],x['status'],x['reproduce'],x['commands'],x['exit_counts'],x['duration_ns_sum'],x['summary'],x.get('failure')]for x in rows]
v=dict(schema=1,scope='Closed finite qualification and failure history across exact revisions. Required refusals stay failed operations; no new native or performance credit.',sources=sources,hardware=hardware[0],bounds=bounds,columns=columns,rows=packed_rows,
 source_comparison=dict(before=C14,after=FINAL,only_changed_files=changed,scope='Two observation-fixture/pin files only. c14 results remain c14; unchanged product bytes do not turn them into 5a executions.'),
 final_checks=dict(revision=FINAL,status='passed'if a.final_checks else'pending_closed_receipt',receipt=a.final_checks),
 absent=dict(c14_late_dso='No closed public/private receipt selected; no result inferred.'),
 audit=dict(receipts=len(rows),capture_references=capture_count,capture_bytes=capture_bytes,distinct_capture_files=len(verified),lossless_archive_files=len(archives),archive_facts_sha256=H(J(archives)),scope='Exact public/private/capture hashes, recorded source/config/cleanup closure and Git trees; no architectural reader replay, source recompilation or fresh execution. Full case data remains in pinned original receipts.'),
 limitations=['Finite instruction/REP/registered-native coverage is not full B2/B3 completion. Supplied reader mutations have no native-operation credit.','Late DSO remains failed; c14 rseq and 8e inspection failures are preserved. No failed operation is relabelled completed.','Performance inputs/results remain separate and are not duplicated here. All runtime cases, assertions, comparators, tolerances and resource limits are unchanged.'],
 reproduce=['python3','-B','evaluation/inprocess/page_cost_qualification.py','--root','${REPOSITORY}','--output','${NEW_OUTPUT}']+(['--final-checks',a.final_checks,'--final-checks-sha256',a.final_checks_sha256]if a.final_checks else[]))
data=J(v);assert len(data)<=25*1024 and b'/home/'not in data and b'/target/'not in data
with a.output.open('xb')as f:f.write(data)
print(json.dumps(dict(output=a.output.name,**fact(data),receipts=len(rows),capture_references=capture_count,final_checks=v['final_checks']['status']),sort_keys=True))
