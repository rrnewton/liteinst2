#!/usr/bin/env python3
"""Project this exact closed run's metadata; does not run or replay workloads."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import sys

REVISION = 'aa911072c32912dfb7b73c1dee168c429289bb2e'
RESULT_SHA256 = '65319240e0bc2b3e85e9c467883159d6630e70686a78a28802e82eb179a9f92d'
INPUTS_SHA256 = '656e3900565381c6dde834b09b7a37e343247871e095ffc6efb13efada97d6cb'
GATES_SHA256 = '3692ba4e4d36fe6815ea8590875f305bcd2dfb25f3f4e61dc2aae658874c4eca'
STAGES = ['c-build', 'build', 'oracle', 'native', 'exact-build', 'exact-oracle'] + [
    f'exact-{s}-k{k}' for s in ('short', 'long', 'alternating', 'late-long') for k in (24, 1, 10)
] + ['concurrent-oracle', 'concurrent-test-build', 'concurrent-native', 'timed-native',
     'retirement-sixteen-epochs', 'retirement-function-closed', 'drain-native']

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
    assert len(r['commands']) == len(STAGES) == 25 and r['completed_drain']['status'] == 'PASS'
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
    fields = 'case,status,originals,calls,sampled,batches,rows,events,actions,registrations,capacity_refusals,empty_drains,report_records,detached,input_unchanged'.split(',')
    drain = r['completed_drain']
    case = dict(case='two-completed-batches', **{k: ('true' if drain[k] is True else drain[k]) for k in fields[1:]})
    assert drain['status'] == 'PASS' and drain['fresh_processes'] == 1
    case_bytes = table(fields, [case])
    exact, concurrent = r['exact_work'], r['concurrent_epochs']
    selected_sources = ['tools/rapid-profiler/verify_ordinary_interval.py', 'tools/unwind-oracle/bounded_command.py',
        'evaluation/admission/processes.py', 'tools/rapid-profiler/src/frontend_native/always_on/drain.rs',
        'tools/rapid-profiler/src/frontend_native/always_on/gate.rs',
        'tools/rapid-profiler/src/frontend_native/always_on/tests/concurrent_native.rs',
        'tools/rapid-profiler/src/frontend_native/always_on/tests/concurrent_native/drain_native.rs']
    receipt = dict(schema=1, revision=REVISION, status='NATIVE_PASS',
        gate_validation=dict(record='gates.json', sha256=GATES_SHA256, status='PASS'),
        stages=dict(passed=25, failed=0, unrun=0, retained_regression_stages=24, new_drain_stages=1),
        closure=dict(helper_ECHILD=25, parent_cleanup_complete=25, rescued_descendants=0, scope='Each named stage has its own bounded helper and parent closure.'),
        completed_drain=drain,
        regressions=dict(checksum=pick(r, 'originals calls completed unsampled reports'),
            state_oracles={k: pick(v, 'pairs children comparisons') for k, v in [('checksum', r['oracle']), ('exact', exact['oracle']), ('concurrent_mode_uncontended', concurrent['oracle'])]},
            exact=pick(exact, 'fresh_processes originals calls sampled closed'),
            forced_native=concurrent['forced_native'], timed=concurrent['timed'],
            retirement=r['epoch_retirement'], exact_truth=pick(exact['oracle'], 'original_instructions conditional_branches taken_branches input_reads return_reads')),
        native_state_qualification=r['native_state_qualification'], native_setup=r['native_setup'],
        hardware=r['hardware'], versions=r['versions'], tools=r['tools'],
        source_pins={n: r['sources'][n] for n in selected_sources},
        source_observations=dict(selected_files=len(r['sources']), before_after_equal=True, scope='Producer checked clean exact HEAD and selected sources/tools at each stage.'),
        artifacts=dict(r['build']['artifacts'], rapid_profiler_libtest=concurrent['test_artifact'], checksum_dso=r['dso'], exact_dso=exact['dso']),
        artifact_scope='Hashes observed by the producer and joined to Cargo metadata; projection does not reopen executables.',
        saved_projection=dict(result_sha256=RESULT_SHA256, selected_metadata_files=len(names), selected_metadata_map_sha256=INPUTS_SHA256,
            scope='Exact closed metadata and stream projection; not an independent saved-state replay.'),
        failure_history=['../concurrent-epochs-84d0040/README.md', '../ordinary-interval-ff18353/README.md', '../exact-work-723f09e/README.md'],
        files={'cases.csv': digest(case_bytes), 'commands.csv': digest(command_bytes)})
    outputs = {'cases.csv': case_bytes, 'commands.csv': command_bytes, 'receipt.json': encoded(receipt)}
    for b in outputs.values(): assert b'/home/' not in b and b'.facebook.com' not in b and b'.fbinfra.net' not in b
    a.out.mkdir(parents=True, exist_ok=True)
    assert all(not (a.out/n).exists() for n in outputs)
    for n, b in outputs.items():
        with (a.out/n).open('xb') as f: f.write(b)

if __name__ == '__main__': main()
