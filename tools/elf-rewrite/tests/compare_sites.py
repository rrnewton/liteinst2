"""Prospective pure comparator calibrations; no E9/application execution."""
import importlib.util
import json
from pathlib import Path
import sys
if sys.flags.optimize:raise SystemExit('optimized Python disables tests')
spec=importlib.util.spec_from_file_location('comparison',Path(__file__).resolve().parents[1]/'compare-sites.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
manifest=('LI2TOOL 1\noriginal '+'a'*64+'\nsite 1 4096 5 4096 4096 6 4096 6 4096 6 7 observe original-decode\nsite 2 4101 1 4101 4096 6 4096 6 4096 6 7 observe original-decode\n').encode()
common='original_sha256\t'+'a'*64+'\nselection_sha256\t'+m.sha(manifest)+'\n'
report='LI2REPORT\t1\n'+common+'candidate_complete\tfalse\nqualification_complete\tfalse\nsite\tpc\tfile_offset\tlength\tcore_tactic\tcandidate_emitted\trefusal_code\tstage\tdetail_hex\n1\t4096\t4096\t5\tB1\tfalse\t10003\tatomic-selection\t61\n2\t4101\t4101\t1\tnone\tfalse\t9\tcore\t62\n'
e9='LI2E9SITES\t1\n'+common+'e9_revision\t'+m.PINNED_E9+'\ninstrumentation\tnull\nselection_style\tforced-puzzle\nsite\tpc\tfile_offset\tlength\toutcome\treason_hex\n1\t4096\t4096\t5\ttrampoline\t\n2\t4101\t4101\t1\ttrap\t63\n'
policy_record=dict(schema=1,original_sha256='a'*64,selection_sha256=m.sha(manifest),e9_revision=m.PINNED_E9,instrumentation='null',selection_style='forced-puzzle')
policy=json.dumps(policy_record,sort_keys=True).encode()
policy_sha=m.sha(policy)
result=m.compare(manifest,report,e9,policy,policy_sha);assert result['lost_e9_trampoline_sites']==[1] and result['e9_trap_sites']==[2] and not result['qualification_complete']
changes=[report.replace('4096\t4096\t5','4097\t4096\t5'),report.replace('2\t4101\t4101\t1\tnone\tfalse\t9\tcore\t62\n',''),report+report.splitlines()[-1]+'\n',report.replace('qualification_complete\tfalse','qualification_complete\ttrue')]
for changed in changes:
    try:m.compare(manifest,changed,e9,policy,policy_sha)
    except AssertionError:pass
    else:raise AssertionError('required exact-inventory refusal did not occur')
try:m.compare(manifest,report,e9.replace(m.PINNED_E9,'0'*40),policy,policy_sha)
except AssertionError:pass
else:raise AssertionError('wrong E9 revision accepted')
print('comparison calibrations: one exact loss/trap inventory and five required refusals')

# Additive review regressions. The complete original one/five cohort above is
# required before these new syntax, atomicity and trusted-policy cases.
assert result['comparison_policy_sha256']==policy_sha
assert result['comparison_policy']==policy_record
assert result['instrumentation']=='null' and result['selection_style']=='forced-puzzle'
assert result['selection_sha256']==m.sha(manifest)
added_positive=[];added_negative=[]
for name,selection in [('tab original record',manifest.replace(b'original ',b'original\t')),
                       ('uppercase original digest',manifest.replace(('a'*64).encode(),('A'*64).encode()))]:
    new_policy=dict(policy_record,selection_sha256=m.sha(selection))
    encoded=json.dumps(new_policy,sort_keys=True).encode()
    new_report=report.replace(m.sha(manifest),m.sha(selection))
    new_e9=e9.replace(m.sha(manifest),m.sha(selection))
    observed=m.compare(selection,new_report,new_e9,encoded,m.sha(encoded))
    assert observed['lost_e9_trampoline_sites']==[1] and observed['e9_trap_sites']==[2]
    assert observed['original_sha256']=='a'*64
    assert observed['selection_sha256']==m.sha(selection)!=m.sha(manifest)
    assert observed['comparison_policy_sha256']==m.sha(encoded)
    added_positive.append(name)

def rejected(name,selection=manifest,tool=report,prior=e9,policy_bytes=policy,expected_policy_sha=policy_sha):
    try:m.compare(selection,tool,prior,policy_bytes,expected_policy_sha)
    except (AssertionError,ValueError,KeyError):added_negative.append(name)
    else:raise AssertionError('required comparison refusal did not occur: '+name)

rejected('mixed partial candidate',tool=report.replace('B1\tfalse\t10003\tatomic-selection\t61','B1\ttrue\tnone\tnone\t61'))
rejected('untrusted E9 instrumentation relabel',prior=e9.replace('instrumentation\tnull','instrumentation\treal-hook'))
rejected('untrusted E9 selection-style relabel',prior=e9.replace('selection_style\tforced-puzzle','selection_style\theap-write'))
rejected('wrong policy digest pin',expected_policy_sha='0'*64)
for name,changes in [('unknown policy key',dict(extra='not-allowed')),
                     ('boolean policy schema',dict(schema=True)),
                     ('wrong policy original identity',dict(original_sha256='b'*64)),
                     ('wrong policy selection identity',dict(selection_sha256='c'*64)),
                     ('wrong policy E9 revision',dict(e9_revision='0'*40)),
                     ('unknown instrumentation vocabulary',dict(instrumentation='anything')),
                     ('unknown selection-style vocabulary',dict(selection_style='anything'))]:
    encoded=json.dumps(dict(policy_record,**changes),sort_keys=True).encode()
    rejected(name,policy_bytes=encoded,expected_policy_sha=m.sha(encoded))
encoded=policy.replace(b'"schema": 1',b'"schema": 1,"schema": 1')
rejected('duplicate policy key',policy_bytes=encoded,expected_policy_sha=m.sha(encoded))
missing=dict(policy_record);del missing['instrumentation'];encoded=json.dumps(missing).encode()
rejected('missing policy field',policy_bytes=encoded,expected_policy_sha=m.sha(encoded))
encoded=policy.replace(b'"schema": 1',b'"schema": NaN')
rejected('non-JSON policy constant',policy_bytes=encoded,expected_policy_sha=m.sha(encoded))
rejected('invalid original digest character',selection=manifest.replace(('a'*64).encode(),('g'*64).encode()))
rejected('extra original record token',selection=manifest.replace(b'original ',b'original extra '))
rejected('duplicate original record',selection=manifest+('original '+'a'*64+'\n').encode())
rejected('short original digest',selection=manifest.replace(('a'*64).encode(),('a'*63).encode()))
rejected('exact selection bytes remain bound',selection=manifest.replace(('a'*64).encode(),('A'*64).encode()))
assert len(added_positive)==2 and len(added_negative)==19
assert len(set(added_positive+added_negative))==21
print('comparison calibrations: original one/five retained; total three positives and 24 required refusals')
