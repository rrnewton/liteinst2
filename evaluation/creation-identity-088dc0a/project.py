#!/usr/bin/env python3
"""Project explicit CLOSED cleanup records; never run tests or read live state."""
import argparse
import csv
import difflib
import hashlib
import io
import json
from pathlib import Path
import re
import sys

BASE = '84d004098e57245528de5d11657892fffd0cb010'
REV = '088dc0a3662a4661328604db6e96f28c7cd80775'
FIX = '88d1b9076c26d2877572859de33f56814eb204ab'
INPUTS = {
    'G1': ('concurrent-gates-v1/receipt.json', 'b04d75e28a3b603c98b54bec28de9e127aafbad7872e15fc4ca0eaf3acc2a398'),
    'D1': ('cleanup-root-v1/reproduction.json', 'b6f1e1d3097a6bd507cc4a78c052cf03e2be79991c6a1085cfe5ac66c77a1704'),
    'O': ('cleanup-root-v1/old-implementation-control.json', 'b97797b1e6159edff41fb50818199156fe67b1156fe3cdd92ae0f5e8b9afc903'),
    'M': ('cleanup-root-v1/guard-mutation.json', '06553756e1ddc94761029b5472d380f3b4d69db6398791943542694ab3d9c33f'),
    'G2': ('concurrent-gates-v2/receipt.json', '78e8ce98bf18fc8f07fc684f9c07a3a16887d466764e96676bec3e5ead4a4cbf'),
    'D2': ('backing-child-root-v1/reproduction.json', 'da755460a93d1351849ab6f8bc86452893b9b35e381fee0eb8d4c3e0ed850c1b'),
    'W2': ('backing-child-root-v1/workspace.json', 'ece245f14c74b2100be7ed8766eef6089149fb9dca1a9875d6618c9afcfee7e2'),
}
CAMPAIGN_NAMES = ['fmt', 'clippy', 'check', 'creation-controls'] + [f'creation-library-{i:02}' for i in range(1, 6)] + ['workspace-default', 'serial-launch', 'staged-allocation', 'prefixed-pun']
FINAL_NAMES = ['fmt', 'clippy', 'check', 'workspace-default', 'serial-launch', 'staged-allocation', 'prefixed-pun']
FINAL_ARGV = [s.split() for s in (
    'cargo fmt --check', 'cargo clippy --workspace --all-targets --all-features -- -D warnings',
    'cargo check --workspace --all-features --all-targets', 'cargo test --workspace',
    'cargo test -p liteinst-launch -- --test-threads=1 --nocapture',
    'cargo test -p liteinst2 --lib staged', 'cargo test -p liteinst2 --test prefixed_pun_oracle')]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def counts(text):
    groups, raw = [], 0
    for line in text.splitlines():
        if re.match(r'^\s+(?:Running|Doc-tests) ', line): groups.append([])
        m = re.match(r'^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', line)
        if m:
            assert groups
            groups[-1].append(tuple(map(int, m.groups()))); raw += 1
    terminal = [g[-1] for g in groups if g]
    return dict(heads=len(groups), groups=len(terminal), nested=raw-len(terminal),
                passed=sum(x[0] for x in terminal), failed=sum(x[1] for x in terminal), ignored=sum(x[2] for x in terminal))


def main():
    if sys.flags.optimize: raise SystemExit('assertions required')
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--records', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--final-gates', type=Path)
    ap.add_argument('--final-gates-sha256')
    a = ap.parse_args(); assert bool(a.final_gates) == bool(a.final_gates_sha256)
    documents, records, rows, commands, summaries = {}, {}, [], [], {}
    inputs = dict(INPUTS)
    if a.final_gates: inputs['F'] = (str(a.final_gates), a.final_gates_sha256)
    for record, (relative, expected) in inputs.items():
        path = a.final_gates/'receipt.json' if record == 'F' else a.records/relative
        raw = path.read_bytes(); assert sha(raw) == expected
        d = json.loads(raw); documents[record] = d
        assert d['revision'] == (BASE if record in ('G1', 'D1', 'O', 'M') else REV)
        records[record] = dict(sha256=expected, bytes=len(raw), revision=d['revision'])
        entries = d.get('commands', [d])
        for i, e in enumerate(entries):
            name = e.get('name', {'O':'old-implementation-control', 'M':'guard-mutation', 'W2':'workspace'}.get(record))
            assert name
            log = path.parent/(name+'.log'); raw_log = log.read_bytes(); text = raw_log.decode()
            c = e['closed']; assert sha(raw_log) == c['private_log_sha256']
            assert c['cleanup_complete'] is True and c['reaped_descendants'] == 0 and c['termination'] is None
            argv = list(e['argv']); assert Path(argv[0]).name == 'cargo'; argv[0] = '$CARGO'
            assert all(not x.startswith('/') for x in argv)
            if argv not in commands: commands.append(argv)
            n = counts(text)
            rows.append(dict(record=record, index=i, run=name, command=commands.index(argv), status='PASS' if c['exit_code']==0 else 'FAILED',
                expected_failure=record in ('O', 'M'), exit_code=c['exit_code'], seconds=c['seconds'], wall_limit_seconds=e.get('wall_limit_seconds', ''),
                cleanup_complete=True, rescued=0, **n, log_sha256=sha(raw_log)))
            summaries[record, name] = (n, text)
        if record in ('G1', 'G2'): assert d['status'] == 'FAILED'
        if record == 'F':
            assert d['status'] == 'PASS' and [e['name'] for e in entries] == FINAL_NAMES
            assert [e['argv'] for e in entries] == FINAL_ARGV
            assert d['runner_sha256'] == documents['G2']['runner_sha256']
            assert d['recipe'] == documents['G2']['recipe'].replace('--include-creation-identity', '--checks-only')
            assert all(e['closed']['exit_code'] == 0 for e in entries)
            assert [e['wall_limit_seconds'] for e in entries] == [180, 180, 180, 360, 180, 180, 180]
    for record, count in [('G1',4), ('D1',26), ('O',1), ('M',1), ('G2',10), ('D2',25), ('W2',1)]:
        assert sum(r['record']==record for r in rows)==count
    assert [e['name'] for e in documents['G2']['commands']] == CAMPAIGN_NAMES[:10]
    for r in rows:
        if r['record']=='D1' and r['run'].startswith('focused-'): assert (r['exit_code'],r['passed'],r['failed'])==(0,1,0)
        if r['record']=='G2' and r['run'].startswith('creation-library-'): assert (r['exit_code'],r['passed'],r['failed'],r['ignored'])==(0,745,0,0)
        if r['record']=='D2': assert r['exit_code']==0 and r['groups']==0
    def require(record, name, expected):
        n, text = summaries[record, name]
        assert (n['passed'], n['failed'], n['ignored']) == expected
        return text
    require('D1','library-default',(741,1,0))
    require('O','old-implementation-control',(0,1,0)); require('M','guard-mutation',(1,2,0))
    require('G2','creation-controls',(3,0,0))
    require('W2','workspace',(2546,0,5)); assert summaries['W2','workspace'][0] == dict(heads=101,groups=100,nested=5,passed=2546,failed=0,ignored=5)
    diagnostic = summaries['D1','library-default'][1]
    assert 'lost_wait=false missing_pin=false owned={9}' in diagnostic
    backing = summaries['G2','workspace-default'][1]
    assert 'left: 1' in backing and 'right: 0' in backing and 'SIGABRT' in backing
    assert len(re.findall(r'^LITEINST_BACKING_CLEANUP_V1 ',backing,re.M)) == 1
    for key in [('D2',f'backing-{i:02}') for i in range(1,26)]+[('W2','workspace')]:
        events=[json.loads(line.split(' ',1)[1]) for line in summaries[key][1].splitlines() if line.startswith('LITEINST_BACKING_CLEANUP_V1 ')]
        assert len(events)==8 and events[0]['kind']=='begin' and events[-1]==dict(schema_version=1,kind='complete',controls=5,trajectories=6,physical_cleanup=True)
        assert [e['index'] for e in events[1:-1]]==list(range(6))
    files = {}
    for src, dst in [('cleanup-root-v1/diagnostics.patch','cleanup-diagnostics.patch'),('backing-child-root-v1/diagnostics.patch','backing-diagnostics.patch')]:
        files[dst]=(a.records/src).read_bytes()
    assert sha(files['cleanup-diagnostics.patch'])==documents['D1']['diagnostic_patch_sha256']
    assert sha(files['backing-diagnostics.patch'])==documents['D2']['diagnostic_patch_sha256']==documents['W2']['diagnostic_patch_sha256']
    fixed=(a.records/'cleanup-root-v1/owner-shared-fixed.rs').read_bytes(); mutant=(a.records/'cleanup-root-v1/owner-guard-mutant.rs').read_bytes()
    assert sha(fixed)==documents['M']['fixed_owner_sha256'] and sha(mutant)==documents['M']['mutant_owner_sha256']
    owner='crates/liteinst-launch/src/linux/remote/dynamic/owner.rs'
    files['guard-mutation.patch']=''.join(difflib.unified_diff(fixed.decode().splitlines(True),mutant.decode().splitlines(True),fromfile='a/'+owner,tofile='b/'+owner)).encode()
    fields='record index command status exit_code seconds groups passed failed ignored nested log_sha256'.split()
    s=io.StringIO(newline=''); w=csv.DictWriter(s,fieldnames=fields,lineterminator='\n');w.writeheader();w.writerows({k:r[k] for k in fields} for r in rows);files['commands.csv']=s.getvalue().encode()
    final=dict(status='PENDING',record=None,kind='seven required hand-back checks only',planned_commands=7)
    if a.final_gates:
        n=summaries['F','workspace-default'][0]
        assert n == dict(heads=101,groups=100,nested=5,passed=2546,failed=0,ignored=5)
        final=dict(status='PASS',record='F',revision=REV,commands=7,kind='seven required hand-back checks only',workspace=n)
    kernel={}
    for name in ('exit','ptrace','signal'):
        b=(a.records/f'cleanup-root-v1/linux-{name}.c').read_bytes()
        kernel[name]=dict(sha256=sha(b),url=f'https://github.com/gregkh/linux/blob/v7.1.3/kernel/{name}.c')
    g2=documents['G2']
    receipt=dict(schema=1,source_fix=FIX,tested_revision=REV,final_validation=final,
        status='FINAL_VALIDATION_PASS_WITH_RETAINED_FAILURES' if a.final_gates else 'FINAL_VALIDATION_PENDING',
        records=records,command_catalog={str(i):argv for i,argv in enumerate(commands)},
        count_policy='Last libtest terminal per Cargo Running/Doc-tests group; nested summaries excluded. Failed/incomplete workspace counts are partial, not complete-denominator passes. Custom cleanup controls/trajectories receive no libtest credit. Repeated commands are repeated observations, not unique tests.',
        parent_policy='Each CSV row joins its exact closed parent via records[record] and commands[index] (or the whole singleton record). All observed parents terminated normally with cleanup_complete=true and zero rescued descendants; nonzero subject exits stay FAILED. Original limits remain in the pinned records when recorded; no limit is invented for historical diagnostics.',
        historical=dict(original_workspace='FAILED: original creation-identity cleanup error',diagnostic_focused_runs=25,diagnostic_library=dict(passed=741,failed=1),
            old_code_control=dict(status='FAILED',expected=True,passed=0,failed=1,owner_sha256=documents['O']['old_owner_sha256'],scope='Recorded old implementation with additive forced test, not an unmodified checkout.'),
            guard_mutant=dict(status='FAILED',expected=True,passed=1,failed=2,owner_sha256=sha(mutant)),fixed_controls=3,fixed_libraries=[dict(passed=745,failed=0)]*5,
            campaign_v2=dict(status='FAILED',planned_commands=13,completed_commands=10,creation_specific_pass_commands=6,static_pass_commands=3,failed_command='workspace-default',unrun=['serial-launch','staged-allocation','prefixed-pun']),
            separate_backing_failure=dict(status='FAILED',child_exit=1,parent_signal='SIGABRT',root_cause='UNPROVEN; join/singleton interaction is a source-level hypothesis only'),
            backing_diagnostics=dict(focused_passes=25,controls_per_run=5,trajectories_per_run=6,workspace=summaries['W2','workspace'][0],workspace_seconds=documents['W2']['closed']['seconds'],temporary_diagnostics_only=True,fix_credit=False),
            earlier_orig_rax='Unresolved separate fixture issue; see ../reachable-allocation-48f2225/README.md'),
        variants={'G1':'Exact BASE','D1':'BASE plus cleanup-diagnostics.patch','O':'BASE plus additive forced test and recorded old owner hash','M':'BASE development tests plus recorded guard-mutant owner hash','G2':'Exact tested_revision','D2':'tested_revision plus backing-diagnostics.patch','W2':'Same diagnostic variant as D2','F':'Exact tested_revision after diagnostic revert; seven checks-only gates, not the failed 13-command campaign'},
        source_variants=dict(base_revision=BASE,fixed_owner_sha256=sha(fixed),fixed_lifecycle_sha256='6a958ab6657dc64bc307c7f4277439f5890bacf49dd83b46c227e2504c4582b5',fixed_tests_sha256='20fb27ed14a65257673ce60e16900cc4e76508f084b0007279cf55ec24f59522'),
        hardware=g2['hardware'],rustc=g2['rustc'],kernel_version=g2['kernel_version'],kernel_source=kernel,
        kernel_scope='Source evidence at Linux v7.1.3; not authentication of the running kernel binary. Zero-info membership relies on exclusive tracer-thread ownership and no foreign reaping.',
        creation_campaign_recipe=g2['recipe'],final_gate_recipe=g2['recipe'].replace('--include-creation-identity','--checks-only'),runner_sha256=g2['runner_sha256'],helper_sha256=g2['helper_sha256'],compiler_jobs=g2['compiler_jobs'],parallelism=g2['parallelism'],
        scope='Functional cleanup identity validation, not performance or proof that unrelated backing/interrupt fixture failures are fixed.',
        projector=dict(path='project.py',sha256=sha(Path(__file__).read_bytes())),files={n:dict(sha256=sha(b),bytes=len(b)) for n,b in files.items()})
    files['receipt.json']=(json.dumps(receipt,sort_keys=True,separators=(',',':'))+'\n').encode()
    assert all(not re.search(rb'/ho'+rb'me/|\bdevbig[0-9]', b) for b in files.values())
    assert not a.out.exists();a.out.mkdir(parents=True)
    for n,b in files.items():(a.out/n).write_bytes(b)


if __name__=='__main__':main()
