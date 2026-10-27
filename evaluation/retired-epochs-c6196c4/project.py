#!/usr/bin/env python3
"""Project this exact closed run's metadata; does not run or replay workloads."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import sys

REVISION = 'c6196c448e01da0875724938262d5e0070f16e76'
RESULT_SHA256 = 'd6c8664bb268de77889229d43ad792df2637503696a437ef4e121c8a78dbb7e5'
INPUTS_SHA256 = '090806c0a6a9b7a19a2ec80effbfd57158586e21638e9b11f2d3ff7f47de9789'
GATES_SHA256 = 'e020b8e9e34f57078aa84c7264aef92438403f0e4bba51fdb5174494619c1a13'
STAGES = ['c-build', 'build', 'oracle', 'native', 'exact-build', 'exact-oracle'] + [
    f'exact-{s}-k{k}' for s in ('short', 'long', 'alternating', 'late-long') for k in (24, 1, 10)
] + ['concurrent-oracle', 'concurrent-test-build', 'concurrent-native', 'timed-native',
     'retirement-sixteen-epochs', 'retirement-function-closed']

def digest(b): return dict(bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
def encoded(v):
    return ('{\n'+',\n'.join('  '+json.dumps(k)+': '+json.dumps(v[k], sort_keys=True, separators=(',', ':'), allow_nan=False) for k in sorted(v))+'\n}\n').encode()
def pick(v, keys): return {k: v[k] for k in keys.split()}
def table(fields, rows):
    f = io.StringIO(newline=''); w = csv.DictWriter(f, fields, lineterminator='\n')
    w.writeheader(); w.writerows(rows); return f.getvalue().encode('ascii')

def main():
    if sys.flags.optimize: raise SystemExit('assertions required')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--raw', type=Path, required=True); p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    names = ['result.json', 'sources-before.json', 'sources-after.json', 'tools.json', 'rustc-version.txt']
    names += [s+'/'+f for s in STAGES for f in ('request.json', 'receipt.json', 'parent-command.json', 'parent-closed.json', 'stdout.txt', 'stderr.txt')]
    data = {}
    for n in names:
        f = a.raw/n
        assert not f.is_symlink() and f.is_file() and f.stat().st_size < 8*1048576
        data[n] = f.read_bytes()
    owners = {n: digest(data[n]) for n in sorted(data)}
    assert hashlib.sha256(json.dumps(owners, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == INPUTS_SHA256
    assert owners['result.json']['sha256'] == RESULT_SHA256
    def js(n): return json.loads(data[n])
    r = js('result.json')
    assert r['revision'] == REVISION and r['status'] == 'PASS' and r['stage'] == 'complete'
    assert r['sources'] == js('sources-before.json') == js('sources-after.json')
    assert len(r['commands']) == len(STAGES) == 24 and r['epoch_retirement']['status'] == 'PASS'
    commands = []
    for name, argv in zip(STAGES, r['commands']):
        q, h, p, c = [js(name+'/'+f+'.json') for f in ('request', 'receipt', 'parent-command', 'parent-closed')]
        assert h['exit'] == c['exit_code'] == 0 and c['cleanup_complete'] is True and c['reaped_descendants'] == 0
        assert c['termination'] is None and h['absence_proof'] == 'ECHILD' and h['inputs_unchanged'] is True
        assert h['unexpected_descendants'] == h['cleanup_events'] == [] and h['wall_timeout'] is False
        assert h['aborted'] is h['cleanup_error'] is None
        commands.append(dict(stage=name, cpu_seconds=q['cpu_seconds'], wall_seconds=q['wall_seconds'], file_bytes=q['file_bytes'],
            parent_wall_seconds=p['wall_seconds'], exit=0, helper_seconds=h['elapsed_seconds'],
            argv_json=json.dumps(argv, separators=(',', ':'))))
    command_bytes = table(list(commands[0]), commands)
    fields = 'case,status,epochs,originals,calls,sampled,closed,rows,events,actions,registrations,report_permit_refusals,report_ready_before_return,receipt_permit_refusal,post_return_stage,joined'.split(',')
    cases = [{k: ('true' if c[k] is True else c[k]) for k in fields if k in c} for c in r['epoch_retirement']['cases']]
    assert len(cases) == 2 and [c['status'] for c in cases] == ['PASS', 'PASS']
    case_bytes = table(fields, cases)
    exact, concurrent = r['exact_work'], r['concurrent_epochs']
    selected_sources = ['tools/rapid-profiler/verify_ordinary_interval.py', 'tools/unwind-oracle/bounded_command.py',
        'evaluation/admission/processes.py', 'tools/rapid-profiler/src/frontend_native/always_on/tests/concurrent_native/retirement_native.rs']
    receipt = dict(schema=1, revision=REVISION, status='NATIVE_PASS',
        gate_validation=dict(record='gates.json', sha256=GATES_SHA256, status='PASS'),
        stages=dict(passed=24, failed=0, unrun=0, retained_regression_stages=22, new_retirement_stages=2),
        closure=dict(helper_ECHILD=24, parent_cleanup_complete=24, rescued_descendants=0),
        retirement=dict(fresh_processes=2, scope=r['epoch_retirement']['scope']),
        regressions=dict(checksum=pick(r, 'originals calls completed unsampled reports'),
            state_oracles={k: pick(v, 'pairs children comparisons') for k, v in [('checksum', r['oracle']), ('exact', exact['oracle']), ('concurrent_mode_uncontended', concurrent['oracle'])]},
            exact=pick(exact, 'fresh_processes originals calls sampled closed'),
            forced_native=concurrent['forced_native'], timed=concurrent['timed']),
        native_state_qualification=r['native_state_qualification'], native_setup=r['native_setup'],
        hardware=r['hardware'], versions=r['versions'],
        source_pins={n: r['sources'][n] for n in selected_sources},
        source_observations=dict(selected_files=len(r['sources']), before_after_equal=True, scope='Producer checked clean exact HEAD and selected sources/tools at each stage.'),
        artifacts=dict(r['build']['artifacts'], rapid_profiler_libtest=concurrent['test_artifact'], checksum_dso=r['dso'], exact_dso=exact['dso']),
        artifact_scope='Hashes observed by the producer and joined to Cargo metadata; projection does not reopen executables.',
        saved_projection=dict(result_sha256=RESULT_SHA256, selected_metadata_files=len(names), selected_metadata_map_sha256=INPUTS_SHA256,
            scope='Exact closed metadata and stream projection; not an independent saved-state replay.'),
        files={'cases.csv': digest(case_bytes), 'commands.csv': digest(command_bytes)})
    outputs = {'cases.csv': case_bytes, 'commands.csv': command_bytes, 'receipt.json': encoded(receipt)}
    for b in outputs.values(): assert b'/home/' not in b and b'.facebook.com' not in b and b'.fbinfra.net' not in b
    a.out.mkdir(parents=True, exist_ok=True)
    assert all(not (a.out/n).exists() for n in outputs)
    for n, b in outputs.items():
        with (a.out/n).open('xb') as f: f.write(b)

if __name__ == '__main__': main()
