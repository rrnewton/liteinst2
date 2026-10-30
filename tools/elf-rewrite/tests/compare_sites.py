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


# Supplied full-mode projections exercise the unchanged comparator. Mode grammar
# admission belongs to the explicit adapter, never to a comparison result.
def owned_projection_comparison_controls():
    lines = manifest.split(b'\n')
    lines[2:2] = [b'neighbor-victims short-only', b'neighbor-ownership inherited-t3']
    owned = b'\n'.join(lines)
    full_sha, stripped_sha = m.sha(owned), m.sha(manifest)
    assert full_sha != stripped_sha
    tool = report.replace(stripped_sha, full_sha)
    prior = e9.replace(stripped_sha, full_sha)
    record = dict(policy_record, selection_sha256=full_sha)
    encoded = json.dumps(record, sort_keys=True).encode()
    expected_sha = m.sha(encoded)
    observed = m.compare(owned, tool, prior, encoded, expected_sha)
    assert observed['selection_sha256'] == full_sha
    assert observed['comparison_policy_sha256'] == expected_sha
    assert observed['comparison_policy'] == record
    assert observed['selected_sites'] == 2
    assert observed['lost_e9_trampoline_sites'] == [1] and observed['e9_trap_sites'] == [2]
    assert not observed['qualification_complete'] and observed['scope'] == 'STRUCTURAL_CANDIDATE_SITE_INVENTORY_ONLY'
    assert [r['site'] for r in observed['sites']] == [1, 2]
    assert all(not r['candidate_emitted'] for r in observed['sites'])
    complete = tool.replace('candidate_complete\tfalse', 'candidate_complete\ttrue')
    complete = complete.replace('B1\tfalse\t10003\tatomic-selection\t61', 'B1\ttrue\tnone\tnone\t61')
    complete = complete.replace('none\tfalse\t9\tcore\t62', 'T3\ttrue\tnone\tnone\t62')
    retained = m.compare(owned, complete, prior, encoded, expected_sha)
    assert retained['retained_e9_trampoline_sites'] == 1 and retained['lost_e9_trampoline_sites'] == []
    assert retained['e9_trap_sites'] == [2] and all(r['candidate_emitted'] for r in retained['sites'])
    assert not retained['qualification_complete']
    refused_prior = prior.replace('2\t4101\t4101\t1\ttrap\t63', '2\t4101\t4101\t1\trefused\t63')
    refused = m.compare(owned, tool, refused_prior, encoded, expected_sha)
    assert refused['lost_e9_trampoline_sites'] == [1] and refused['e9_trap_sites'] == []
    assert [r['e9'] for r in refused['sites']] == ['trampoline', 'refused']
    negatives = []
    def reject(name, selection=owned, tool_report=tool, e9_report=prior, policy_bytes=encoded, policy_pin=expected_sha):
        try:
            m.compare(selection, tool_report, e9_report, policy_bytes, policy_pin)
        except AssertionError:
            negatives.append(name)
        else:
            raise AssertionError('owned projection comparison accepted: ' + name)
    reject('tool uses stripped identity', tool_report=report)
    reject('E9 uses stripped identity', e9_report=e9)
    reject('policy uses stripped identity', policy_bytes=policy, policy_pin=policy_sha)
    reject('all reports use stripped identity', tool_report=report, e9_report=e9, policy_bytes=policy, policy_pin=policy_sha)
    reject('stripped manifest with full reports', selection=manifest)
    reject('stale independently trusted policy digest', policy_pin=policy_sha)
    reject('missing tool site', tool_report=tool.replace(tool.splitlines()[-1] + '\n', ''))
    reject('extra tool site', tool_report=tool + tool.splitlines()[-1].replace('2\t4101', '3\t4101', 1) + '\n')
    reject('duplicate tool site', tool_report=tool + tool.splitlines()[-1] + '\n')
    reject('missing E9 site', e9_report=prior.replace(prior.splitlines()[-1] + '\n', ''))
    reject('extra E9 site', e9_report=prior + prior.splitlines()[-1].replace('2\t4101', '3\t4101', 1) + '\n')
    reject('duplicate E9 site', e9_report=prior + prior.splitlines()[-1] + '\n')
    reject('tool geometry changed', tool_report=tool.replace('4096\t4096\t5', '4097\t4096\t5'))
    reject('E9 geometry changed', e9_report=prior.replace('4096\t4096\t5', '4097\t4096\t5'))
    reject('partial candidate mixture', tool_report=tool.replace('B1\tfalse\t10003\tatomic-selection\t61', 'B1\ttrue\tnone\tnone\t61'))
    reject('qualification promotion', tool_report=tool.replace('qualification_complete\tfalse', 'qualification_complete\ttrue'))
    reject('E9 fact schema remains five keys', e9_report=prior.replace('LI2E9SITES\t1\n', 'LI2E9SITES\t1\nselection_profile\telf-disassembly-null-jumps-short-t3-ownership-v1\n'))
    assert len(negatives) == len(set(negatives)) == 17
    print('owned projection comparison controls: supplied complete/refused/trap structure and 17 exact refusals; no mode admission or runtime credit')


owned_projection_comparison_controls()
# The pending projection keeps all three mode rows in the identity passed to
# the unchanged comparator. Its results do not establish mode or producer trust.
def pending_projection_comparison_controls():
    lines = manifest.split(b'\n')
    lines[2:2] = [b'neighbor-victims short-only', b'neighbor-ownership inherited-t3',
                  b'pending-selected full-instruction-ownership']
    pending = b'\n'.join(lines)
    owned = pending.replace(b'pending-selected full-instruction-ownership\n', b'')
    full_sha = m.sha(pending)
    assert len({full_sha, m.sha(owned), m.sha(manifest)}) == 3
    tool = report.replace(m.sha(manifest), full_sha)
    prior = e9.replace(m.sha(manifest), full_sha)
    record = dict(policy_record, selection_sha256=full_sha)
    encoded = json.dumps(record, sort_keys=True).encode()
    expected_sha = m.sha(encoded)
    observed = m.compare(pending, tool, prior, encoded, expected_sha)
    assert observed['selection_sha256'] == full_sha
    assert observed['comparison_policy_sha256'] == expected_sha
    assert observed['comparison_policy'] == record and observed['selected_sites'] == 2
    assert observed['lost_e9_trampoline_sites'] == [1] and observed['e9_trap_sites'] == [2]
    assert not observed['qualification_complete'] and observed['scope'] == 'STRUCTURAL_CANDIDATE_SITE_INVENTORY_ONLY'
    assert [r['site'] for r in observed['sites']] == [1, 2]
    assert all(not r['candidate_emitted'] for r in observed['sites'])
    complete = tool.replace('candidate_complete\tfalse', 'candidate_complete\ttrue')
    complete = complete.replace('B1\tfalse\t10003\tatomic-selection\t61', 'B1\ttrue\tnone\tnone\t61')
    complete = complete.replace('none\tfalse\t9\tcore\t62', 'T3\ttrue\tnone\tnone\t62')
    retained = m.compare(pending, complete, prior, encoded, expected_sha)
    assert retained['retained_e9_trampoline_sites'] == 1 and retained['lost_e9_trampoline_sites'] == []
    assert retained['e9_trap_sites'] == [2] and all(r['candidate_emitted'] for r in retained['sites'])
    assert not retained['qualification_complete']
    refused_prior = prior.replace('2\t4101\t4101\t1\ttrap\t63', '2\t4101\t4101\t1\trefused\t63')
    refused = m.compare(pending, tool, refused_prior, encoded, expected_sha)
    assert refused['lost_e9_trampoline_sites'] == [1] and refused['e9_trap_sites'] == []
    assert [r['e9'] for r in refused['sites']] == ['trampoline', 'refused']
    negatives = []
    def reject(name, selection=pending, tool_report=tool, e9_report=prior, policy_bytes=encoded, policy_pin=expected_sha):
        try:
            m.compare(selection, tool_report, e9_report, policy_bytes, policy_pin)
        except AssertionError:
            negatives.append(name)
        else:
            raise AssertionError('pending projection comparison accepted: ' + name)
    for label, stripped in [('legacy', manifest), ('owned', owned)]:
        stripped_sha = m.sha(stripped)
        stripped_tool = tool.replace(full_sha, stripped_sha)
        stripped_e9 = prior.replace(full_sha, stripped_sha)
        stripped_record = dict(record, selection_sha256=stripped_sha)
        stripped_policy = json.dumps(stripped_record, sort_keys=True).encode()
        stripped_pin = m.sha(stripped_policy)
        assert stripped_pin != expected_sha
        reject(label + ' tool identity', tool_report=stripped_tool)
        reject(label + ' E9 identity', e9_report=stripped_e9)
        reject(label + ' policy identity', policy_bytes=stripped_policy, policy_pin=stripped_pin)
        reject(label + ' all reports stripped', tool_report=stripped_tool, e9_report=stripped_e9,
               policy_bytes=stripped_policy, policy_pin=stripped_pin)
        reject(label + ' manifest stripped', selection=stripped)
        reject(label + ' stale independent policy pin', policy_pin=stripped_pin)
    reject('missing tool site', tool_report=tool.replace(tool.splitlines()[-1] + '\n', ''))
    reject('extra tool site', tool_report=tool + tool.splitlines()[-1].replace('2\t4101', '3\t4101', 1) + '\n')
    reject('duplicate tool site', tool_report=tool + tool.splitlines()[-1] + '\n')
    reject('missing E9 site', e9_report=prior.replace(prior.splitlines()[-1] + '\n', ''))
    reject('extra E9 site', e9_report=prior + prior.splitlines()[-1].replace('2\t4101', '3\t4101', 1) + '\n')
    reject('duplicate E9 site', e9_report=prior + prior.splitlines()[-1] + '\n')
    reject('tool geometry changed', tool_report=tool.replace('4096\t4096\t5', '4097\t4096\t5'))
    reject('E9 geometry changed', e9_report=prior.replace('4096\t4096\t5', '4097\t4096\t5'))
    reject('partial candidate mixture', tool_report=tool.replace('B1\tfalse\t10003\tatomic-selection\t61', 'B1\ttrue\tnone\tnone\t61'))
    reject('qualification promotion', tool_report=tool.replace('qualification_complete\tfalse', 'qualification_complete\ttrue'))
    reject('E9 fact schema remains five keys', e9_report=prior.replace('LI2E9SITES\t1\n', 'LI2E9SITES\t1\nselection_profile\telf-disassembly-null-jumps-short-t3-pending-v1\n'))
    assert len(negatives) == len(set(negatives)) == 23
    print('pending projection comparison controls: supplied complete/refused/trap structure and 23 exact refusals; no mode admission or runtime credit')


pending_projection_comparison_controls()
