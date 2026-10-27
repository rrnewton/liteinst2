#!/usr/bin/env python3
"""Project this closed cohort's metadata; never execute subjects or open captures."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import sys

REV = '84d004098e57245528de5d11657892fffd0cb010'
RESULT = '633bbfc699b5c7d07b326c8d65ed93680e79da283957da6ae0936bf14f2742b5'
GATES = 'b04d75e28a3b603c98b54bec28de9e127aafbad7872e15fc4ca0eaf3acc2a398'
INPUT_CSV = {'concurrent-state-pairs.csv': {'bytes': 361, 'sha256': '97bebc921410cf6b319ee7d7947d90065d3268b122e6e07b7b5b74f94f83b287'}, 'concurrent-truth.csv': {'bytes': 347, 'sha256': '535aa12a158497ebe542521fd61d10d56cb7f8489672469ae774064d14604335'}, 'timed-calls.csv': {'bytes': 4466, 'sha256': '395aec73b7b1be829dc7e41caeab424762bef080e0dee71cbb7aa53cc5fbd5d6'}, 'timed-reports.csv': {'bytes': 916, 'sha256': 'f86739239d9010d46ec879116c6c9432ca60c955d448a4ab09a9cd47a1833c40'}, 'timed-transitions.csv': {'bytes': 261, 'sha256': '723a93d04d7f5cebc4ff0e6cac616c539c7c077b68bde5c0db46dc0dbc425353'}}
NAMES = ['c-build', 'build', 'oracle', 'native', 'exact-build', 'exact-oracle'] + [
    f'exact-{s}-k{k}' for s in ('short', 'long', 'alternating', 'late-long') for k in (24, 1, 10)
] + ['concurrent-oracle', 'concurrent-test-build', 'concurrent-native', 'timed-native']


def pin(b):
    return dict(sha256=hashlib.sha256(b).hexdigest(), bytes=len(b))


def csv_bytes(rows, fields):
    s = io.StringIO(newline='')
    w = csv.DictWriter(s, fieldnames=fields, lineterminator='\n')
    w.writeheader(); w.writerows(rows)
    return s.getvalue().encode()


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--native', required=True, type=Path)
    ap.add_argument('--gates', required=True, type=Path)
    ap.add_argument('--out', required=True, type=Path)
    a = ap.parse_args()
    b = (a.native/'result.json').read_bytes(); g = (a.gates/'receipt.json').read_bytes()
    assert pin(b)['sha256'] == RESULT and pin(g)['sha256'] == GATES
    d, gates = json.loads(b), json.loads(g)
    assert d['revision'] == gates['revision'] == REV
    assert (d['status'], d['stage'], d['checksum_status']) == ('PASS', 'complete', 'PASS')
    assert d['exact_work_requested'] is d['concurrent_epochs_requested'] is True
    assert len(d['commands']) == len(NAMES) == 22
    assert (d['originals'], d['calls'], d['completed'], d['unsampled']) == (8, 8, 6, 2)
    exact, con = d['exact_work'], d['concurrent_epochs']
    assert exact['status'] == con['status'] == 'PASS'
    assert (exact['fresh_processes'], exact['originals'], exact['calls'], exact['sampled'], exact['closed']) == (12, 288, 288, 140, 148)
    assert [d['oracle']['comparisons'], exact['oracle']['comparisons'], con['oracle']['comparisons']] == [978, 844, 844]
    force, timed = con['forced_native'], con['timed']
    assert [force[k] for k in ('originals', 'calls', 'sampled', 'closed', 'removed', 'writer_contentions', 'registry_contentions', 'inflight_rearm')] == [6, 6, 4, 1, 1, 2, 0, 1]
    assert [timed[k] for k in ('originals', 'calls', 'sampled', 'unsampled', 'epochs', 'actions')] == [24, 24, 18, 6, 3, 6]
    assert timed['coverage'] == [6, 2, 6, 2, 6, 2] and timed['controller_cpu'] != timed['worker_cpu']
    outputs, input_csv, parsed = {}, {}, {}
    for name in ('timed-calls.csv', 'timed-transitions.csv', 'timed-reports.csv', 'concurrent-state-pairs.csv', 'concurrent-truth.csv'):
        raw = (a.native/name).read_bytes(); input_csv[name] = pin(raw)
        assert input_csv[name] == INPUT_CSV[name]
        parsed[name] = list(csv.DictReader(io.StringIO(raw.decode())))
        if name != 'timed-calls.csv': outputs[name] = raw
    calls, transitions, reports = (parsed[n] for n in ('timed-calls.csv', 'timed-transitions.csv', 'timed-reports.csv'))
    assert (len(calls), len(transitions), len(reports)) == (24, 6, 18)
    report_index = {(int(r['generation']), int(r['invocation'])): r for r in reports}
    assert len(report_index) == 18
    keep = 'external_id ordinal length owner generation invocation before_ns after_ns value start_ticks end_ticks start_aux end_aux'.split()
    projected = []
    for i, row in enumerate(calls):
        n = lambda k: int(row[k])
        assert (n('external_id'), n('ordinal'), n('length')) == (1000+i, i+1, (1, 64)[i % 2])
        assert n('before_ns') < n('after_ns') and n('start_ticks') <= n('end_ticks')
        assert n('start_aux') == n('end_aux') and n('entry_rsp') == n('pre_rsp')-8 and n('resumed_rsp') == n('pre_rsp')
        assert n('return_pc')-n('entry_pc') == 36 and n('generation') == i//8+1
        assert row['owner'] == ('sampled' if i % 8 < 6 else 'removed')
        if row['owner'] == 'sampled':
            assert n('invocation') == i % 8
            r = report_index[(n('generation'), n('invocation'))]
            assert (int(r['entry_ticks']), int(r['end_ticks']), int(r['rank'])) == (n('start_ticks'), n('end_ticks'), n('invocation'))
        else:
            assert row['invocation'] == ''
        projected.append(dict({k: row[k] for k in keep}, entry_rsp_delta=-8, resumed_rsp_delta=0, return_offset=36))
    outputs['timed-calls.csv'] = csv_bytes(projected, keep+['entry_rsp_delta', 'resumed_rsp_delta', 'return_offset'])
    pairs, truth = parsed['concurrent-state-pairs.csv'], parsed['concurrent-truth.csv']
    assert len(pairs) == len(truth) == 4 and sum(int(p['comparisons']) for p in pairs) == 844
    for p, t in zip(pairs, truth):
        assert p['status'] == t['status'] == 'PASS' and int(p['children']) == 2
        assert [p[k] for k in ('seed', 'length', 'value')] == [t[k] for k in ('seed', 'length', 'value')]
        n = int(t['length'])
        assert [int(t[k]) for k in ('instructions', 'conditional_branches', 'taken_branches', 'input_reads', 'return_reads')] == [6*n+5, n, n-1, n, 1]
    rows = []
    for name, argv in zip(NAMES, d['commands']):
        rb = (a.native/name/'receipt.json').read_bytes(); pb = (a.native/name/'parent-closed.json').read_bytes()
        r, p, limits = json.loads(rb), json.loads(pb), d[name]
        assert r['exit'] == p['exit_code'] == limits['process_exit'] == 0
        assert r['wall_timeout'] is False and r['inputs_unchanged'] is True and r['absence_proof'] == 'ECHILD'
        assert r['unexpected_descendants'] == r['cleanup_events'] == [] and r['cleanup_error'] is r['aborted'] is None
        assert r['helper_sha256'] == d['sources']['tools/unwind-oracle/bounded_command.py']['sha256']
        assert p['cleanup_complete'] is True and p['reaped_descendants'] == 0 and p['termination'] is None
        rows.append(dict(phase='release-native', name=name, status='PASS', command=' '.join(argv), exit_code=0,
            seconds=p['seconds'], cpu_seconds=limits['cpu_seconds'], wall_seconds=limits['wall_seconds'], parent_wall_seconds=limits['wall_seconds']+25,
            file_bytes=limits['file_bytes'], receipt_sha256=pin(rb)['sha256'], parent_sha256=pin(pb)['sha256']))
    assert gates['status'] == 'FAILED'
    assert [x['name'] for x in gates['commands']] == ['fmt', 'clippy', 'check', 'workspace-default']
    assert [x['closed']['exit_code'] for x in gates['commands']] == [0, 0, 0, 101]
    for x in gates['commands']:
        p = x['closed']; assert p['cleanup_complete'] is True and p['reaped_descendants'] == 0 and p['termination'] is None
        rows.append(dict(phase='required-gates-v1', name=x['name'], status='PASS' if p['exit_code'] == 0 else 'FAILED',
            command=' '.join(x['argv']), exit_code=p['exit_code'], seconds=p['seconds'], wall_seconds=x['wall_limit_seconds'], receipt_sha256=GATES))
    fields = 'phase name status command exit_code seconds cpu_seconds wall_seconds parent_wall_seconds file_bytes receipt_sha256 parent_sha256'.split()
    outputs['commands.csv'] = csv_bytes(rows, fields)
    workspace = gates['commands'][-1]
    assert workspace['terminal_observations'][-1] == dict(failed=1, ignored=0, passed=741, result='FAILED')
    receipt = dict(schema=1, tested_revision=REV, status='NATIVE_PASS_INITIAL_GATES_FAILED', native_status='PASS',
        followup_validation=dict(receipt='../creation-identity-088dc0a/receipt.json', scope='Later source fixes and validation are separate; this receipt preserves the initial failed gate attempt'), evidence='Closed metadata projection; no subject execution, raw-stream replay or capture replay by this projector.',
        result_sha256=RESULT, projector=dict(path='project.py', **pin(Path(__file__).read_bytes())),
        hardware=d['hardware'], versions=d['versions'], tool_pins=d['tools'],
        recipe_sources={n:d['sources'][n] for n in ('tools/rapid-profiler/verify_ordinary_interval.py', 'tools/unwind-oracle/bounded_command.py', 'evaluation/admission/processes.py')},
        source_snapshot=dict(files=len(d['sources']), canonical_json_sha256=pin(json.dumps(d['sources'], sort_keys=True, separators=(',', ':')).encode())['sha256'], complete_map='sources in the pinned closed result.json'),
        artifacts=dict(release=d['build']['artifacts'], release_libtest=con['test_artifact'], checksum_dso=d['dso'], exact_dso=exact['dso']),
        build_environment=dict(CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true', CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true'),
        native_stages=22, closure=dict(strict_receipts=22, helper_exit_zero=22, helper_ECHILD=22, inputs_unchanged=22, clean_outer_parents=22, rescued_descendants=0),
        original_checksum=dict(originals=8, calls=8, sampled=6, unsampled=2, retained_reports=d['reports'], state_pairs=4, children=8, comparisons=978),
        original_exact=dict(originals=288, calls=288, fresh_processes=12, sampled=140, closed=148, state_pairs=4, children=8, comparisons=844, raw_population_rows_exported=0),
        concurrent_state={k:v for k,v in con['oracle'].items() if k != 'rows'}, forced_native=force, timed=timed,
        state_scope=d['native_state_qualification'], setup_scope=d['native_setup'], scope=con['scope'],
        required_gate_attempt=dict(status='FAILED', receipt_sha256=GATES, runner_sha256=gates['runner_sha256'], helper_sha256=gates['helper_sha256'],
            recipe=gates['recipe'], parallelism=gates['parallelism'], compiler_jobs=gates['compiler_jobs'], kernel_version=gates['kernel_version'],
            commands_completed=4, workspace_exit_code=101, workspace_terminal_observations=workspace['terminal_observations'],
            counts_scope='Individual terminals from an incomplete workspace run; not an aggregate workspace pass count.',
            failed_test='linux::remote::dynamic::owner::kernel_journal::tests::native::raw_newborn_failure_retains_unjoined_native_identity_and_actual_prefix',
            failure='dynamic physical cleanup ownership was lost', failure_identity_origin='owner-supplied closed-log diagnosis; receipt preserves the failing terminal',
            unrun=['serial-launch', 'staged-allocation', 'prefixed-pun']),
        csv={n:pin(v) for n,v in outputs.items()}, input_csv=input_csv,
        projection='Four numeric CSVs copied byte-exact; timed calls preserve IDs, outcomes and raw times, replacing private pointers with checked relative offsets. Command seconds are operational wall durations, not performance.')
    outputs['receipt.json'] = (json.dumps(receipt, sort_keys=True, separators=(',', ':'))+'\n').encode()
    assert all(not re.search(rb'/ho' + rb'me/|/Users/|\b(?:devbig|devvm)[0-9]', x) for x in outputs.values())
    assert not a.out.exists()
    a.out.mkdir(parents=True)
    for name, data in outputs.items(): (a.out/name).write_bytes(data)


if __name__ == '__main__':
    main()
