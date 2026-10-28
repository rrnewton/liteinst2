#!/usr/bin/env python3
"""Project exact CLOSED metadata; no workload, artifact or saved-state replay."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import sys

REVISION = 'b8951894cb31bcc2d5276112c47f43f5ae97ba3f'
RESULT_SHA256 = 'f4a8e52d06c89cbe23e071e4bdeb65e1db60ff4194b23e7a6003c859c631a3b1'
INPUTS_SHA256 = 'ed444b122a29a860d4452d31eb4ceaa28060b21bfc4bdeecad51bfb577401399'
STAGES = ['c-build', 'build', 'oracle', 'native', 'exact-build', 'exact-oracle'] + [
    f'exact-{s}-k{k}' for s in ('short', 'long', 'alternating', 'late-long') for k in (24, 1, 10)
] + ['concurrent-oracle', 'concurrent-test-build', 'concurrent-native', 'timed-native',
     'retirement-sixteen-epochs', 'retirement-function-closed', 'drain-native', 'streamed-native']
DEVELOPMENT = ['clippy.json', 'clippy-fixed.json', 'clippy-final.json', 'controls-final.json', 'fmt-final.json']
CASE_FIELDS = 'case,status,originals,calls,entries,returns,sampled,unsampled,epochs,slots,retired,replacements,batches,raw_rows,events,actions,reports,active_coverage,off_coverage,original_instructions,original_branches,original_taken,input_byte_reads,return_word_reads,windowend_ns'.split(',')
SOURCE_REVIEW = '4786abe4c22ee8fbdbc9c62a083aa38e095c34d0c70bb7eafa2a3611ba34b8aa'
RECIPE_REVIEW = '62db47ba84859ff18f81a3a4a3945413e64e0c34bb2bf88cc847f57a9ea329c4'


def digest(b): return dict(bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
def encoded(v):
    return ('{\n'+',\n'.join('  '+json.dumps(k)+': '+json.dumps(v[k], sort_keys=True, separators=(',', ':'), allow_nan=False) for k in sorted(v))+'\n}\n').encode()
def pick(v, keys): return {k: v[k] for k in keys.split()}
def table(fields, rows):
    stream = io.StringIO(newline=''); writer = csv.DictWriter(stream, fields, lineterminator='\n')
    writer.writeheader(); writer.writerows(rows); return stream.getvalue().encode('ascii')


def main():
    if sys.flags.optimize: raise SystemExit('assertions required')
    p = argparse.ArgumentParser(description=__doc__)
    for n in ('raw', 'root-meta', 'out'): p.add_argument('--'+n, type=Path, required=True)
    a = p.parse_args()
    names = ['result.json'] + [s+'/'+f+'.json' for s in STAGES for f in ('request', 'receipt', 'parent-command', 'parent-closed')]
    data = {}
    for prefix, directory, members in [('native', a.raw, names), ('root', a.root_meta, ['native-command.json']+DEVELOPMENT)]:
        for name in members:
            path = directory/name
            assert not path.is_symlink() and path.is_file() and path.stat().st_size < 4*1048576
            data[prefix+'/'+name] = path.read_bytes()
    descriptors = {n: digest(data[n]) for n in sorted(data)}
    assert hashlib.sha256(json.dumps(descriptors, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == INPUTS_SHA256
    assert descriptors['native/result.json']['sha256'] == RESULT_SHA256
    def js(n): return json.loads(data[n])
    r, root = js('native/result.json'), js('root/native-command.json')
    assert r['revision'] == root['revision'] == REVISION and r['status'] == 'PASS' and r['stage'] == 'complete'
    assert len(r['commands']) == len(STAGES) == 26
    streamed, exact, concurrent = r['streamed_epochs'], r['exact_work'], r['concurrent_epochs']
    commands = []
    for name, normalized in zip(STAGES, r['commands']):
        q, h, parent, closed = [js('native/'+name+'/'+f+'.json') for f in ('request', 'receipt', 'parent-command', 'parent-closed')]
        assert h['exit'] == closed['exit_code'] == 0 and closed['cleanup_complete'] is True and closed['reaped_descendants'] == 0
        assert closed['termination'] is None and h['absence_proof'] == 'ECHILD' and h['inputs_unchanged'] is True
        assert h['unexpected_descendants'] == h['cleanup_events'] == [] and h['wall_timeout'] is False and h['aborted'] is h['cleanup_error'] is None
        commands.append(dict(stage=name, cpu_seconds=q['cpu_seconds'], wall_seconds=q['wall_seconds'], file_bytes=q['file_bytes'],
            parent_wall_seconds=parent['wall_seconds'], exit=0, helper_seconds=h['elapsed_seconds'], parent_seconds=closed['seconds'],
            argv_json=json.dumps(normalized, separators=(',', ':'))))
    artifacts = dict(r['build']['artifacts'], rapid_profiler_libtest=concurrent['test_artifact'])
    command_bytes = table(list(commands[0]), commands)
    case_bytes = table(CASE_FIELDS, [dict(case='streamed-epochs', **{k: streamed[k] for k in CASE_FIELDS[1:]})])
    development = []
    for name, expected in zip(DEVELOPMENT, (101, 101, 0, 0, 0)):
        d = js('root/'+name); c = d['closed']
        assert c['exit_code'] == expected and c['termination'] is None and c['cleanup_complete'] is True and c['reaped_descendants'] == 0
        development.append(dict(case=name.removesuffix('.json'), status='PASS' if expected==0 else 'FAILED', exit=expected,
            seconds=c['seconds'], metadata_sha256=descriptors['root/'+name]['sha256']))
    assert js('root/clippy.json')['source_sha256'] == js('root/clippy-fixed.json')['source_sha256']
    selected = ['tools/rapid-profiler/verify_ordinary_interval.py', 'tools/rapid-profiler/streamed-work/check_output.py',
        'tools/rapid-profiler/ordinary-interval/streamed.rs', 'tools/rapid-profiler/ordinary-interval/streamed/check.rs',
        'tools/rapid-profiler/exact-work/exact_work.S',
        'tools/rapid-profiler/src/frontend_native/always_on/drain.rs',
        'evaluation/admission/processes.py', 'tools/unwind-oracle/bounded_command.py']
    receipt = dict(schema=1, revision=REVISION, status='NATIVE_PASS',
        stages=dict(passed=26, failed=0, unrun=0, prior_required=25, streamed=1),
        closure=dict(helper_ECHILD=26, parent_cleanup_complete=26, rescued_descendants=0,
            scope='26 named stages; recipe exit0 additionally reported by executor, no separate outer closure JSON'),
        streamed=pick(streamed, 'status originals calls entries returns sampled unsampled epochs slots retired replacements batches raw_rows events actions reports coverage active_coverage off_coverage original_instructions original_branches original_taken input_byte_reads return_word_reads windowend_ns requested_active_ms requested_inactive_ms replacement_cutoff_before_arm_ms nominal_window_ms schedule_deadline_ms calls_per_batch channel_capacity'),
        streamed_scope='Finite160 calls/20 epochs; mandatory hooks remain active. Full input, journal, Report/terminal, gate returns and retirement ownership are source-attested, not exported full objects. No new full-state/performance/timing accuracy/indefinite service/A5 credit.',
        recorded_table_hashes=streamed['tables'], table_scope='Producer-recorded CSV descriptors; this projection does not read table bodies or full journal/Report objects.',
        regressions=dict(state_comparisons=dict(checksum=r['oracle']['comparisons'], exact=exact['oracle']['comparisons'], concurrent_uncontended=concurrent['oracle']['comparisons']),
            state_pairs_per_mode=4, state_children_per_mode=8, checksum_calls=r['calls'],
            exact=pick(exact, 'fresh_processes calls sampled closed'), timed=pick(concurrent['timed'], 'calls sampled unsampled coverage'),
            forced=pick(concurrent['forced_native'], 'calls sampled closed removed'),
            retirement_calls=[c['calls'] for c in r['epoch_retirement']['cases']], drained_calls=r['completed_drain']['calls']),
        native_state_qualification=r['native_state_qualification'], native_setup=r['native_setup'],
        hardware=pick(r['hardware'], 'architecture vendor family model stepping owner_label owner_label_origin build_affinity_cpus native_state_affinity_cpus streamed_worker_affinity_cpus streamed_controller_affinity_cpus streamed_total_active_cpus'), versions=r['versions'], tools=r['tools'],
        artifacts=dict(artifacts, checksum_dso=r['dso'], exact_dso=exact['dso']),
        artifact_scope='Producer-recorded Cargo profile/hash/fresh joins; no executable reopened by this projector.',
        source_pins={n:r['sources'][n] for n in selected},
        source_observations=dict(selected_files=len(r['sources']), scope='Producer checks clean exact HEAD and selected source/tool stability around stages.'),
        review_sha256=dict(native_source=SOURCE_REVIEW, recipe=RECIPE_REVIEW, closed_metadata='14dcf1e2455e0a5254d0e30e41af1ea860f7a90f93b5ff0d46e2f07545d4c857'),
        development_base='79d65461cdc491a712492545f4018bebbdb997fe', development_dirty=True, development_history=development, development_scope='Both needless_range_loop Clippy failures retained; equivalent iter_mut/enumerate test-fixture correction. Eight final Rust controls reported by executor; eleven synthetic Python controls passed under the recipe review. Intervening edit-script assertion failed before writing (executor report), not native execution.',
        failure_history=['../ordinary-interval-ff18353/README.md','../exact-work-723f09e/README.md','../concurrent-epochs-84d0040/README.md',
            '../creation-identity-088dc0a/README.md','../reachable-allocation-48f2225/README.md','../merged-af5a1ef/README.md'],
        saved_projection=dict(result_sha256=RESULT_SHA256, metadata_files=len(data), metadata_map_sha256=INPUTS_SHA256,
            scope='Exact closed JSON-only projection; no independent saved-state, CSV-body or artifact replay.'),
        files={'cases.csv':digest(case_bytes),'commands.csv':digest(command_bytes)})
    outputs = {'receipt.json':encoded(receipt), 'cases.csv':case_bytes, 'commands.csv':command_bytes}
    for value in outputs.values(): assert b'/home/' not in value and b'.facebook.com' not in value and b'.fbinfra.net' not in value
    assert not a.out.exists(); a.out.mkdir(parents=True)
    for name, value in outputs.items():
        with (a.out/name).open('xb') as f: f.write(value)


if __name__ == '__main__': main()
