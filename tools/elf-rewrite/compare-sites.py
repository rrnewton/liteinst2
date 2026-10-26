#!/usr/bin/env python3
"""Exact common-manifest structural-site comparison, never an A3 pass claim."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
if sys.flags.optimize:
    raise SystemExit('optimized Python disables exact site comparison')
PINNED_E9 = '0d5d36e4c4edcac37ca2499694d64302a391136f'
sha=lambda b:hashlib.sha256(b).hexdigest()

def table(text,magic,columns):
    rows=[line.split('\t') for line in text.splitlines()]
    assert rows[0]==[magic,'1']
    header=next(i for i,row in enumerate(rows) if row==columns)
    facts={row[0]:row[1] for row in rows[1:header] if len(row)==2}
    assert len(facts)==header-1
    data={}
    for row in rows[header+1:]:
        assert len(row)==len(columns)
        record=dict(zip(columns,row));key=int(record['site']);assert key not in data
        data[key]=record
    return facts,data

def content_digest(value):
    assert isinstance(value,str) and len(value)==64
    assert all(c in '0123456789abcdefABCDEF' for c in value)
    return bytes.fromhex(value).hex()


def comparison_policy(raw,expected_sha256):
    # The expected digest is a separately trusted caller input, not learned
    # from the E9 report or from the policy file being authenticated.
    assert isinstance(raw,bytes) and 0<len(raw)<=65536
    assert sha(raw)==content_digest(expected_sha256)
    def unique(pairs):
        result={}
        for key,value in pairs:
            assert key not in result,'duplicate policy key'
            result[key]=value
        return result
    def invalid_constant(value):
        raise AssertionError('non-JSON policy constant: '+value)
    policy=json.loads(raw,object_pairs_hook=unique,parse_constant=invalid_constant)
    assert type(policy) is dict
    assert policy.keys()=={'schema','original_sha256','selection_sha256','e9_revision','instrumentation','selection_style'}
    assert type(policy['schema']) is int and policy['schema']==1
    policy['original_sha256']=content_digest(policy['original_sha256'])
    policy['selection_sha256']=content_digest(policy['selection_sha256'])
    assert policy['e9_revision']==PINNED_E9
    assert policy['instrumentation'] in ('null','real-hook')
    assert policy['selection_style'] in ('jump-site','heap-write','forced-puzzle')
    return policy


def compare(manifest,report,e9,policy_bytes,expected_policy_sha256):
    policy=comparison_policy(policy_bytes,expected_policy_sha256)
    lines=manifest.decode('utf-8').splitlines();assert lines[0]=='LI2TOOL 1'
    originals=[line.split() for line in lines if line.split() and line.split()[0]=='original']
    assert len(originals)==1 and len(originals[0])==2
    original=content_digest(originals[0][1])
    expected={}
    for line in lines:
        f=line.split()
        if f and f[0]=='site':
            number=lambda s:int(s,16) if s.startswith('0x') else int(s)
            key=number(f[1]);assert key not in expected
            expected[key]=(number(f[2]),number(f[3]),number(f[4]))
    assert expected
    tf,tool=table(report,'LI2REPORT',['site','pc','file_offset','length','core_tactic','candidate_emitted','refusal_code','stage','detail_hex'])
    ef,prior=table(e9,'LI2E9SITES',['site','pc','file_offset','length','outcome','reason_hex'])
    assert tf.keys()=={'original_sha256','selection_sha256','candidate_complete','qualification_complete'}
    assert ef.keys()=={'original_sha256','selection_sha256','e9_revision','instrumentation','selection_style'}
    assert tf['candidate_complete'] in ('true','false')
    assert tf['original_sha256']==ef['original_sha256']==original==policy['original_sha256']
    assert tf['selection_sha256']==ef['selection_sha256']==sha(manifest)==policy['selection_sha256']
    assert tf['qualification_complete']=='false'
    assert ef['e9_revision']==PINNED_E9
    assert ef['instrumentation'] in ('null','real-hook')
    assert ef['instrumentation']==policy['instrumentation']
    assert ef['selection_style'] in ('jump-site','heap-write','forced-puzzle')
    assert ef['selection_style']==policy['selection_style']
    assert tool.keys()==prior.keys()==expected.keys()
    rows=[]
    for key,geometry in expected.items():
        t=tool[key];e=prior[key]
        assert tuple(int(t[k]) for k in ('pc','length','file_offset'))==geometry
        assert tuple(int(e[k]) for k in ('pc','length','file_offset'))==geometry
        bytes.fromhex(t['detail_hex']);bytes.fromhex(e['reason_hex'])
        assert e['outcome'] in ('trampoline','trap','refused')
        assert t['candidate_emitted'] in ('true','false')
        assert t['candidate_emitted']==tf['candidate_complete']
        assert t['core_tactic'] in ('none','B1','B2','T1','T2','T3')
        if e['outcome']!='trampoline':assert e['reason_hex']
        emitted=t['candidate_emitted']=='true'
        if emitted:assert t['core_tactic']!='none' and t['refusal_code']=='none' and t['stage']=='none'
        else:assert t['refusal_code']!='none' and t['stage']!='none'
        # A trap is a separate category and never a retained E9 trampoline site.
        rows.append(dict(site=key,pc=geometry[0],e9=e['outcome'],core_tactic=t['core_tactic'],candidate_emitted=emitted,lost_e9_trampoline=(e['outcome']=='trampoline' and not emitted),tool_refusal=t['refusal_code'],tool_stage=t['stage'],e9_reason_hex=e['reason_hex'],tool_detail_hex=t['detail_hex']))
    assert (tf['candidate_complete']=='true')==all(row['candidate_emitted'] for row in rows)
    return dict(schema=1,comparison_policy=policy,comparison_policy_sha256=sha(policy_bytes),instrumentation=policy['instrumentation'],selection_style=policy['selection_style'],original_sha256=original,selection_sha256=sha(manifest),scope='STRUCTURAL_CANDIDATE_SITE_INVENTORY_ONLY',selected_sites=len(rows),retained_e9_trampoline_sites=sum(r['e9']=='trampoline' and r['candidate_emitted'] for r in rows),lost_e9_trampoline_sites=[r['site'] for r in rows if r['lost_e9_trampoline']],e9_trap_sites=[r['site'] for r in rows if r['e9']=='trap'],qualification_complete=False,application_output_comparison='not-supplied',abi_unwind_cet='not-qualified',sites=rows)

def main():
    p=argparse.ArgumentParser();p.add_argument('manifest',type=Path);p.add_argument('report',type=Path);p.add_argument('e9_sites',type=Path);p.add_argument('policy',type=Path);p.add_argument('new_output',type=Path);p.add_argument('--policy-sha256',required=True);a=p.parse_args()
    assert not a.new_output.exists()
    for path in [a.manifest,a.report,a.e9_sites,a.policy]:assert path.stat().st_size<=16*1024*1024
    inputs=[a.manifest.read_bytes(),a.report.read_bytes(),a.e9_sites.read_bytes()]
    policy_bytes=a.policy.read_bytes()
    result=compare(inputs[0],inputs[1].decode(),inputs[2].decode(),policy_bytes,a.policy_sha256);result['input_sha256']=[sha(data) for data in inputs]
    with a.new_output.open('x') as f:f.write(json.dumps(result,indent=2)+'\n')
    if result['lost_e9_trampoline_sites']:raise SystemExit(2)
if __name__=='__main__':main()
