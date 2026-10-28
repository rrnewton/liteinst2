#!/usr/bin/env python3
"""Project only saved JSON/CSV metadata; never runs a workload or reads binaries."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path

if not __debug__:
    raise SystemExit('assertions required')

PASS_REV = '658872463ad4c6a5c7e773df3c47026922d107a2'
FAIL_REV = 'ab61461983c53c033f8a53c1e2d40c9d4900fd6e'
MIB = 1048576
STAGES = ['c-build', 'build', 'oracle', 'native', 'exact-build', 'exact-oracle']
STAGES += ['exact-'+s+'-k'+str(k) for s in ('short', 'long', 'alternating', 'late-long') for k in (24, 1, 10)]
STAGES += ['concurrent-oracle', 'concurrent-test-build', 'concurrent-native', 'timed-native',
           'retirement-sixteen-epochs', 'retirement-function-closed', 'drain-native',
           'streamed-native', 'history-native', 'optional-fast-state', 'optional-slow-state', 'optional-functional']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, key
        result[key] = value
    return result


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2)+'\n').encode()


def project(passed, failed, core):
    inputs = {}

    def read(root, label, name, as_json=True):
        data = (root/name).read_bytes()
        assert 0 < len(data) <= MIB
        inputs[label+'/'+name] = dict(bytes=len(data), sha256=sha(data))
        return json.loads(data, object_pairs_hook=unique) if as_json else data

    p = read(passed, 'passed', 'result.json')
    f = read(failed, 'failed', 'result.json')
    c = read(core, 'core', 'receipt.json'); cases = read(core, 'core', 'cases.json')
    closed = {}
    for root, label, names in ((passed, 'passed', STAGES), (failed, 'failed', STAGES[:29])):
        for name in names:
            closed[label, name] = (read(root, label, name+'/receipt.json'), read(root, label, name+'/parent-closed.json'))
    csvs = {mode: read(passed, 'passed', 'optional-'+mode+'-pairs.csv', False) for mode in ('fast','slow')}
    failed_fast = read(failed, 'failed', 'optional-fast-pairs.csv', False)
    functional = read(passed, 'passed', 'optional-functional.csv', False)
    # This projector binds one saved cohort. Fresh runtime validation belongs to
    # verify_ordinary_interval.py, not to a relaxed metadata acceptance path.
    assert len(inputs) == 126
    assert sha(encoded(inputs)) == '3a42c15e848643e6edbe32abf13755d1b9772f6dee810d8c4fdaff02fac5d206'
    assert (p['revision'], p['status'], p['stage']) == (PASS_REV, 'PASS', 'complete')
    assert (f['revision'], f['status'], f['stage']) == (FAIL_REV, 'FAILED', 'optional-slow-state')
    assert len(p['commands']) == 30 and f['commands'] == p['commands'][:29]
    commands, failure = [], None
    for (label, name), (h, parent) in closed.items():
        bad = label == 'failed' and name == 'optional-slow-state'
        assert (h['exit'], parent['exit_code']) == ((101, 1) if bad else (0, 0))
        assert h['wall_timeout'] is False and h['inputs_unchanged'] is True
        assert h['absence_proof'] == 'ECHILD' and h['unexpected_descendants'] == h['cleanup_events'] == []
        assert h['aborted'] is h['cleanup_error'] is None
        assert parent['cleanup_complete'] is True and parent['termination'] is None and parent['reaped_descendants'] == 0
        bounds = p[name]
        row = dict(stage=name, argv=json.dumps(p['commands'][STAGES.index(name)], separators=(',', ':')),
                   **{k:bounds[k] for k in ('cpu_seconds','wall_seconds','file_bytes')},
                   parent_wall_seconds=bounds['wall_seconds']+25, helper_exit=h['exit'], parent_exit=parent['exit_code'],
                   cleanup_complete=parent['cleanup_complete'], reaped_descendants=parent['reaped_descendants'],
                   absence_proof=h['absence_proof'], inputs_unchanged=h['inputs_unchanged'], seconds=parent['seconds'])
        if label == 'passed': commands.append(row)
        if bad:
            failure = dict(row, receipt_sha256=inputs[label+'/'+name+'/receipt.json']['sha256'],
                           parent_sha256=inputs[label+'/'+name+'/parent-closed.json']['sha256'], stderr_sha256=h['stderr_sha256'])

    rows = []
    for mode, raw in csvs.items():
        saved = [{k: (v if k == 'status' else int(v)) for k,v in row.items()}
                 for row in csv.DictReader(io.StringIO(raw.decode()))]
        observed = p['optional_frontend']['state_modes'][mode]
        assert saved == observed['rows'] and len(saved) == 4 and observed['status'] == 'PASS'
        assert sum(r['comparisons'] for r in saved) == observed['comparisons'] == 978
        rows.extend(dict(mode=mode, **r) for r in saved)
    assert failed_fast == csvs['fast']
    assert f['optional_frontend']['state_modes']['fast'] == p['optional_frontend']['state_modes']['fast']
    assert f['optional_frontend']['state_modes']['slow'] == {'status':'FAILED'}
    assert f['optional_frontend']['functional'] == 'UNRUN'
    of = p['optional_frontend']
    table = csv.DictReader(io.StringIO(functional.decode()))
    assert list(table) == [{k:str(of['functional'][k]) for k in table.fieldnames}]

    artifacts = dict(p['build']['artifacts'], rapid_profiler_libtest=p['concurrent_epochs']['test_artifact'])
    assert set(artifacts) == {'ordinary-interval', 'frontend-native-oracle', 'rapid_profiler_libtest'}
    for name, artifact in artifacts.items():
        assert artifact['profile'] == dict(debug_assertions=True, debuginfo=0, opt_level='3', overflow_checks=True, test=name == 'rapid_profiler_libtest')
        assert artifact['cargo_fresh'] is (name != 'frontend-native-oracle')
    assert p['binary'] == artifacts['ordinary-interval']['binary']
    assert (c['revision'], c['status'], c['native']) == (FAIL_REV, 'PASS', 'PASS')
    assert cases['totals']['pairs'] == 8 and cases['totals']['comparisons'] == 148 and len(cases['malformed']) == 2
    assert sum(r['comparisons'] for r in cases['pairs']) == 148
    for command in c['commands']:
        x = command['closed']; assert x['exit_code'] == 0 and x['termination'] is None and x['cleanup_complete'] is True and x['reaped_descendants'] == 0
    assert [x['libtest']['passed'] for x in c['commands'] if 'libtest' in x] == [6, 2, 8, 35]

    legacy = dict(status='PASS', stages=27, provenance='saved summaries; legacy CSVs not replayed',
        state_comparisons=dict(checksum=p['oracle']['comparisons'], exact=p['exact_work']['oracle']['comparisons'], concurrent=p['concurrent_epochs']['oracle']['comparisons']),
        checksum={k:p[k] for k in ('originals','calls','completed','unsampled','reports')},
        exact={k:p['exact_work'][k] for k in ('fresh_processes','originals','calls','sampled','closed')},
        forced_concurrent={k:p['concurrent_epochs']['forced_native'][k] for k in ('calls','sampled','closed','removed','writer_contentions','inflight_rearm')},
        timed={k:p['concurrent_epochs']['timed'][k] for k in ('epochs','calls','sampled','unsampled','coverage')},
        retirement=[{k:r[k] for k in ('case','originals','calls','sampled','status')} for r in p['epoch_retirement']['cases']],
        completed_drain={k:p['completed_drain'][k] for k in ('calls','rows','events','batches','capacity_refusals')},
        streamed={k:p['streamed_epochs'][k] for k in ('epochs','calls','batches','sampled','unsampled','coverage')},
        history={k:p['history_stream']['protocol'][k] for k in ('actions','epochs','calls','history_batches','max_resident','old_prefix','new_prefix','retired')})
    selected = ['tools/rapid-profiler/verify_ordinary_interval.py', 'tools/unwind-oracle/bounded_command.py', 'evaluation/admission/processes.py',
                'tools/rapid-profiler/native-interval/optional.rs', 'tests/support/native_optional_frontend.rs',
                'tools/rapid-profiler/src/frontend_native/always_on/optional/tests/native.rs', 'tools/rapid-profiler/optional-work/check_output.py']
    receipt = dict(schema=1, status='PASS', revision=PASS_REV,
        inputs=dict(member_count=126, normalized_manifest_sha256=sha(encoded(inputs)), passed_result=inputs['passed/result.json'], failed_result=inputs['failed/result.json']),
        hardware=p['hardware'], tools=p['tools'], versions=p['versions'], artifacts=artifacts,
        elf=dict(checksum=p['dso'], exact=p['exact_work']['dso']),
        sources=dict(count=71, manifest_sha256=sha(encoded(p['sources'])), selected={k:p['sources'][k] for k in selected}),
        commands=dict(rows=30, table='commands.csv', all_helper_and_parent_exit_zero=True, cleanup_complete=True, descendant_rescues=0, absence_proof='ECHILD',
                      provenance='Normalized argv and child limits from saved result; parent limit wall+25 from exact recipe source. Request bodies and streams not replayed here.'),
        optional=dict(pairs=8, children=16, comparisons=sum(r['comparisons'] for r in rows), helper_joins=8,
                      modes={mode:{k:v for k,v in of['state_modes'][mode].items() if k!='rows'} for mode in ('fast','slow')},
                      state_table='state-pairs.csv', functional=of['functional'], functional_table='functional.csv',
                      source_attested=of['source_attested'], scope=of['scope']),
        regressions=legacy,
        failed_attempt=dict(revision=FAIL_REV,status='FAILED',prerequisite_stages_passed=27,fast_pairs_passed=4,fast_comparisons=978,
                            slow='FAILED',functional='UNRUN',failed_stage=failure,
                            diagnosis='Executor-reported wrong historical-enabled assertion; source confirms group metadata remains true after removal while the actual selector is false. Failure stderr was not read by this projector.'),
        separate_core=dict(revision=FAIL_REV,status='PASS',receipt=inputs['core/receipt.json'],cases=inputs['core/cases.json'],
                           artifact=c['artifact'],profile=c['profile'],totals=cases['totals'],pure_controls=cases['pure_controls'],
                           prerequisite_passes=dict(core=6,compile_fail=2,planner=8,calibrations=35),
                           scope='Separate core primitive population at its own revision; not additional optional frontend cases.'),
        scope='Closed metadata only; full frame/journal/Report checks are source-attested. No raw replay, performance, backoff, indefinite-service or full-A5 claim.',
        failure_history=['../precontext/README.md','../ordinary-interval-ff18353/README.md','../exact-work-723f09e/README.md','../history-stream-4f2ddf8/README.md','../backoff-independent/README.md'])
    return receipt, rows, functional, commands, inputs


def csv_bytes(rows):
    output = io.StringIO(newline='')
    writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator='\n')
    writer.writeheader(); writer.writerows(rows)
    return output.getvalue().encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('passed','failed','core','out'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    receipt, rows, functional, commands, _ = project(args.passed,args.failed,args.core)
    outputs = {'state-pairs.csv':csv_bytes(rows),'functional.csv':functional,'commands.csv':csv_bytes(commands)}
    receipt['files'] = {k:dict(bytes=len(v),sha256=sha(v)) for k,v in outputs.items()}
    outputs['receipt.json'] = ('{\n'+',\n'.join('  '+json.dumps(k)+': '+json.dumps(v, sort_keys=True, separators=(',', ':')) for k,v in sorted(receipt.items()))+'\n}\n').encode()
    for data in outputs.values():
        assert b'/home/' not in data and b'.facebook.com' not in data and b'.internal' not in data
    args.out.mkdir(parents=True, exist_ok=False)
    for name, data in outputs.items():
        (args.out/name).write_bytes(data)


if __name__ == '__main__':
    main()
