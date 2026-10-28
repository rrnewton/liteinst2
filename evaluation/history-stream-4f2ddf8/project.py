#!/usr/bin/env python3
"""Project pinned CLOSED JSON metadata only; no workload or artifact replay."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import sys

# Exact CLOSED metadata activation; this source is not workload execution.
REVISION = '4f2ddf80a479fc33aaec2a9e0d788deeb62eaef9'
RESULT_SHA256 = '93e7fe96515b8db3051abf189e36098ccbd5054ea5f0e18b00b0f8cd820bbc11'
NATIVE_METADATA_SHA256 = '05f09719ff2b8bc0e97326e4a8d7a9f4e653eb5b3d3376c60c9cc3631f8cc753'
GATES_SHA256 = '58b025101aae26f393bdfcdfbdd73e2a02e2a7fbb1716555956a51090abaf2b6'
GATES_RECEIPT_SHA256 = '601f1bbd8ed88c04ab2a7c2e44b551db7d92c28d5020456b2694cbe91fa3758b'
GATE_SUMMARIZER_SHA256 = '0f367dcf0e6cdcf4c40451be451235ccb913ef291a7832bca7f56fdd7fbec54e'
CLEANUP_CONTROLS_SHA256 = '25bc29bd6a4721282a4b44fc5d50833052c845f7399f9e8ba1b2e4d3e96fe77b'
ANCESTRY = dict(main='3f6056f0a249e4f2ce5ce867e8bf67ae5370224d',
    fixture_correction='efa0f26e377e013a3b497de8425b56344216e21b',
    tested_parent='62cd0195f43602c365a0e1c0c10ce2ff688047ac',
    merge_parents=['efa0f26e377e013a3b497de8425b56344216e21b','3f6056f0a249e4f2ce5ce867e8bf67ae5370224d'])
NATIVE_REVIEW_SHA256 = '78f713a4d594cab39af630261be2db0340ba9ef1afbae94e2e69663d35e7c19a'
RECIPE_REVIEW_SHA256 = '52d838324267f62b40f3c43c565da2ee72dd98a4ad275dd2639ff5da4096be00'
GATES_REVIEW_SHA256 = '78f713a4d594cab39af630261be2db0340ba9ef1afbae94e2e69663d35e7c19a'
SOURCE_REVIEW_SHA256 = '0076be9618343007dd3e1bc6c385be1f46b1cc19c5a41b494103f7fb6ccccc2d'
NATIVE_SOURCE_REVIEW_SHA256 = 'cade3f98a5e053b29a9799938891ccb76e2e85e953ecf2b5cce1ef35c3843e7f'
NATIVE_MANIFEST_SHA256 = '335ad3c524fafbba73611fe0d15b8d5e36ab12fc1fa4efb8d15efde295cecc54'
CAMPAIGN_SHA256 = '5076917a4225e94dee4d7af2b2d20722405dd06c0cac405ef1b680e433245104'
CAMPAIGN_SOURCE_REVIEW_SHA256 = 'f8ea0f975b9f148f4c8aef714c0d8e43d2a7637176344c2b3a7e31ae2f0f0e93'
CAMPAIGN_REVIEW_SHA256 = '78f713a4d594cab39af630261be2db0340ba9ef1afbae94e2e69663d35e7c19a'
CLEANUP_SOURCE_REVIEW_SHA256 = '44e0bbfde3cfb5407f9cd90d34d6df9659c3a109c568e397782a75bdc878c3b1'
PRIOR_GATES_SHA256 = '686083e0df4d1c978ddf68dcd60eb3faebcc96175d83d6c52b6e4c53abdf31ba'
PRIOR_DIAGNOSTIC_SHA256 = 'daddd2088c107a1b48d02713073b90451c4b3ec3e59aa6835d787232acffaaf6'
CAMPAIGN_RUNNER_SHA256 = '2f2843416d33935d8f6e50439dafece4fadde31864101ee52bda524f7e5959f1'
CAMPAIGN_HELPER_SHA256 = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
CAMPAIGN_CONTROLS = ['admitted_exec_native_backing_probes_close_exact_owned_resources',
    'admitted_exec_native_backing_read_and_unwind_preserve_cleanup',
    'exec_backing_native_invalid_unmap_aborts_isolated_owner',
    'admitted_exec_native_backing_query_preserves_cleanup',
    'admitted_exec_native_backing_enotty_uses_exact_legacy_projection']
CAMPAIGN_ROLES = ['complete', 'read_error', 'unwind', 'invalid_unmap', 'query_error', 'legacy']
STAGES = ['c-build', 'build', 'oracle', 'native', 'exact-build', 'exact-oracle'] + [
    f'exact-{s}-k{k}' for s in ('short', 'long', 'alternating', 'late-long') for k in (24, 1, 10)
] + ['concurrent-oracle', 'concurrent-test-build', 'concurrent-native', 'timed-native',
    'retirement-sixteen-epochs', 'retirement-function-closed', 'drain-native', 'streamed-native', 'history-native']
GATES = ['fmt', 'clippy', 'check', 'workspace-default', 'serial-launch', 'staged-allocation', 'prefixed-pun']
DEVELOPMENT = {
    'model-v1': ('9216671714a0ba1cd0397ac266d7a6385ab1bdb8f42d30271ce4c00e776f6391', [101], 'Missing public facade re-exports; compilation failed.'),
    'clippy-v1': ('9b41bd90f8b830f07200b7a8adeed4192945cab6aa8ab93175881ec08a6368a0', [101], 'manual_div_ceil refusal; equivalent expression corrected.'),
    'python-controls-v1': ('8252f652b9f3dcaa446c2219ca80543f0308cfaf9b4cf46411e1ecbece1a3ace', [2], 'Root invocation omitted exact-work --runner; no tests ran.'),
    'python-controls-v2': ('e7e230aff673805efe29993d20cf0eed2f4ba6ed02a8f416e2157522eed460e3', [0, 0, 0, 0], 'Correct argv; executor reports 5+5+11+5 synthetic methods passed.'),
    'native-compile-v1': ('8baad4e22d0cde78bb21d01253a92c51afe541693ff205c4ff6ab8b2fd00c64a', [0], 'Release libtest compilation, without execution.'),
    'native-clippy-v1': ('b7887909cc7b2c70b8975c0e50d565a31a41d004563bfbec5660a7c6e9a1c3f7', [0], 'Strict workspace Clippy passed.')}


def digest(data): return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
def encoded(value): return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode('ascii')
def pick(value, names): return {name: value[name] for name in names.split()}
def read(path):
    assert not path.is_symlink() and path.is_file() and path.stat().st_size < 4*1048576
    return path.read_bytes()
def closed(value, exit_code=0):
    assert value['exit_code'] == exit_code and value['termination'] is None
    assert value['cleanup_complete'] is True and value['reaped_descendants'] == 0
def normalized(argv):
    name = Path(argv[0]).name
    result = ['$CARGO' if name == 'cargo' else '$PYTHON']
    assert name == 'cargo' or name.startswith('python3')
    for arg in argv[1:]:
        if arg.startswith('/'):
            assert arg.endswith('/tools/rapid-profiler/verify_ordinary_interval.py')
            arg = '$REPO/tools/rapid-profiler/verify_ordinary_interval.py'
        result.append(arg)
    return result


def cleanup_campaign(body, revision, native_sources):
    """Validate CLOSED producer metadata; do not replay logs or fixtures."""
    assert digest(body)['sha256'] == CAMPAIGN_SHA256
    c = json.loads(body)
    assert c['revision'] == revision and c['status'] == 'PASS' and c['phase'] == 'complete'
    for key, expected in dict(requested=100, attempted=100, passed=100, unrun=0, compiler_jobs=4,
            wall_limit_seconds=180, max_log_bytes=8*1048576).items():
        assert type(c[key]) is int and c[key] == expected
    assert c['argv'] == ['$TOOLCHAIN/bin/cargo', 'test', '-p', 'liteinst-launch', '--test', 'exec_backing_cleanup']
    assert c['controls'] == CAMPAIGN_CONTROLS and c['trajectories'] == CAMPAIGN_ROLES
    assert c['runner_sha256'] == CAMPAIGN_RUNNER_SHA256 and c['helper_sha256'] == CAMPAIGN_HELPER_SHA256
    assert c['sources_before'] == c['sources_after'] and c['sources_before']
    for name in ('crates/liteinst-launch/tests/support/b3_exec/raw.rs',
            'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/exec/native_support.rs',
            'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/exec/native_support/backing_cleanup.rs'):
        assert re.fullmatch('[0-9a-f]{64}', c['sources_before'][name])
    assert c['sources_before']['evaluation/admission/check_backing_singleton.py'] == CAMPAIGN_RUNNER_SHA256
    assert c['sources_before']['evaluation/admission/processes.py'] == CAMPAIGN_HELPER_SHA256
    for name in c['sources_before'].keys() & native_sources.keys():
        assert c['sources_before'][name] == native_sources[name]['sha256']
    assert c['hardware']['owner_label'] == 'AMD EPYC Zen 5 dev host'
    assert c['parallelism'] == 'Sequential processes; no affinity change or RUST_TEST_THREADS override; no libtest thread cap.'
    assert len(c['attempts']) == 100
    stream = io.StringIO(newline='')
    fields = ['attempt','status','exit','seconds','cleanup_complete','rescued','controls','trajectories','log_sha256']
    writer = csv.DictWriter(stream, fields, lineterminator='\n'); writer.writeheader()
    for i, row in enumerate(c['attempts'], 1):
        assert set(row) == {'attempt','status','closed'}
        assert type(row['attempt']) is int and row['attempt'] == i and row['status'] == 'PASS'
        x = row['closed']; closed(x)
        assert type(x['exit_code']) is int and type(x['reaped_descendants']) is int
        assert type(x['seconds']) in (int,float) and 0 <= x['seconds']
        assert re.fullmatch('[0-9a-f]{64}', x['private_log_sha256'])
        writer.writerow(dict(attempt=i, status='PASS', exit=0, seconds=x['seconds'], cleanup_complete=True,
            rescued=0, controls=5, trajectories=6, log_sha256=x['private_log_sha256']))
    csv_body = stream.getvalue().encode('ascii')
    summary = pick(c, 'revision status phase requested attempted passed unrun argv wall_limit_seconds max_log_bytes compiler_jobs parallelism hardware versions tools runner_sha256 helper_sha256 controls trajectories scope')
    summary.update(source_pins=c['sources_before'], clean_closures=100, rescued_descendants=0,
        receipt_sha256=CAMPAIGN_SHA256, attempts_csv=digest(csv_body),
        protocol_completions=dict(control_runs=500,trajectory_runs=600,scope='100 successful exact eight-record protocols; these are not libtest case counts.'),
        operational_seconds_sum=sum(row['closed']['seconds'] for row in c['attempts']),
        reviews=dict(source=CAMPAIGN_SOURCE_REVIEW_SHA256,closed_metadata=CAMPAIGN_REVIEW_SHA256),
        limitations='Selected source/tool hashes and producer protocol authority; not a full Cargo-configuration or compiled-artifact attestation, new native-state comparison, benchmark, blanket historical cause, or claim of eliminating every flake.',
        authority='Exact eight-record protocol and source/tool stability checked by the pinned producer; this projector reads only its CLOSED receipt, not private logs or process state.')
    return summary, csv_body


def prior_failures(gate_body, diagnostic_body):
    assert digest(gate_body)['sha256'] == PRIOR_GATES_SHA256
    assert digest(diagnostic_body)['sha256'] == PRIOR_DIAGNOSTIC_SHA256
    g, d = json.loads(gate_body), json.loads(diagnostic_body)
    old_revision = '3062a906688aa5811420205c28bf24966817abc4'
    assert g['revision'] == d['revision'] == old_revision and g['status'] == 'FAILED'
    assert [c['name'] for c in g['commands']] == GATES[:4]
    for command in g['commands'][:3]: closed(command['closed'])
    failed = g['commands'][3]; closed(failed['closed'], 101)
    assert failed['argv'] == ['cargo','test','--workspace'] and failed['wall_limit_seconds'] == 360
    for key, value in dict(attempts_requested=100, attempts_observed=36,
            complete_passes_before_failure=35, failure_attempt=36, child_exit=1, rescued_descendants=0).items():
        assert type(d[key]) is int and d[key] == value
    assert d['role'] == 'QueryError' and d['parent_signal'] == 'SIGABRT' and d['cleanup_complete'] is True
    assert d['panic'] == 'assert_main_singleton observed a non-main task in /proc/self/task'
    for key in ('diagnostic_source_sha256','reproduction_json_sha256','failure_log_sha256'):
        assert re.fullmatch('[0-9a-f]{64}', d[key])
    return [dict(case='prior-required-gates', revision=old_revision, status='FAILED',
        metadata_sha256=PRIOR_GATES_SHA256, passed_commands=GATES[:3], failed_command='workspace-default',
        unrun=GATES[4:], argv=failed['argv'], closed=failed['closed'],
        executor_reported_trigger='Unexpected backing child exit1 followed by parent SIGABRT; log body not replayed.'),
        dict(case='diagnostic-cleanup-campaign', revision=old_revision, status='FAILED',
            metadata_sha256=PRIOR_DIAGNOSTIC_SHA256, requested=100, attempted=36, passed=35, failed=1, unrun=64,
            failure_attempt=36, role='QueryError', child_exit=1, parent_signal='SIGABRT', cleanup_complete=True, rescued=0,
            diagnostic_source_sha256=d['diagnostic_source_sha256'], reproduction_sha256=d['reproduction_json_sha256'],
            private_log_sha256=d['failure_log_sha256'], observation='Post-join singleton assertion observed a non-main task.',
            limits=d['limits'])]


def cleanup_controls(body):
    assert digest(body)['sha256'] == CLEANUP_CONTROLS_SHA256
    r = json.loads(body)
    assert r['revision'] == ANCESTRY['fixture_correction'] and r['dirty'] is True
    assert r['source_sha256'] == {
        'evaluation/admission/check_backing_singleton.py': CAMPAIGN_RUNNER_SHA256,
        'evaluation/admission/test_backing_singleton.py': 'fdf7dca16a9ddd9e410ff6e65cb336ffa0a975f0b6fef49876e18578bd642c7e'}
    expected = [('parser',0,['-B','evaluation/admission/test_backing_singleton.py','--runner','evaluation/admission/check_backing_singleton.py']),
        ('runner-optimized',1,['-O','-B','evaluation/admission/check_backing_singleton.py']),
        ('controls-optimized',1,['-O','-B','evaluation/admission/test_backing_singleton.py'])]
    assert len(r['commands']) == len(expected)
    rows = []
    for c,(name,code,argv) in zip(r['commands'],expected):
        assert c['name'] == name and type(c['expected_exit']) is int and c['expected_exit'] == code
        assert c['argv'][1:] == argv; closed(c['closed'],code)
        rows.append(dict(name=name,disposition='PASS' if code==0 else 'EXPECTED_OPTIMIZATION_REFUSAL',
            expected_exit=code,argv=normalized(c['argv']),closed=c['closed']))
    return dict(metadata_sha256=CLEANUP_CONTROLS_SHA256,revision=r['revision'],dirty=True,
        source_pins=r['source_sha256'],commands=rows,executor_reported_methods=5,
        scope='Synthetic parser methods and explicit optimization refusal only; no native result. Method count and exact assertions-required message are executor-reported; logs not replayed.')


def main():
    if sys.flags.optimize: raise SystemExit('assertions required')
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('raw', 'gates', 'campaign', 'cleanup-controls', 'prior-gates', 'prior-diagnostic', 'root-meta', 'out'): p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    assert isinstance(REVISION, str) and re.fullmatch('[0-9a-f]{40}', REVISION), 'PENDING closed native/gate activation'
    for sha in (RESULT_SHA256, NATIVE_METADATA_SHA256, NATIVE_MANIFEST_SHA256, GATES_SHA256, NATIVE_REVIEW_SHA256,
            RECIPE_REVIEW_SHA256, GATES_REVIEW_SHA256, CAMPAIGN_SHA256, CAMPAIGN_REVIEW_SHA256,
            CLEANUP_SOURCE_REVIEW_SHA256, PRIOR_GATES_SHA256, PRIOR_DIAGNOSTIC_SHA256,
            GATES_RECEIPT_SHA256, GATE_SUMMARIZER_SHA256, CLEANUP_CONTROLS_SHA256):
        assert isinstance(sha, str) and re.fullmatch('[0-9a-f]{64}', sha), 'PENDING closed metadata/review pins'
    names = ['result.json', 'sources-before.json', 'sources-after.json'] + [s+'/'+f+'.json' for s in STAGES for f in ('request', 'receipt', 'parent-command', 'parent-closed')]
    data = {name: read(a.raw/name) for name in names}
    descriptors = {name: digest(value) for name, value in sorted(data.items())}
    assert digest(encoded(descriptors))['sha256'] == NATIVE_METADATA_SHA256
    assert descriptors['result.json']['sha256'] == RESULT_SHA256
    def js(name): return json.loads(data[name])
    r = js('result.json'); assert r['revision'] == REVISION and r['status'] == 'PASS' and r['stage'] == 'complete'
    assert js('sources-before.json') == js('sources-after.json') == r['sources']
    assert all(r[key+'_requested'] is True for key in ('exact_work', 'concurrent_epochs', 'retire_epochs', 'drain_completed', 'streamed_epochs', 'stream_history'))
    assert len(r['commands']) == len(STAGES) == 27
    command_rows = []
    for name, argv in zip(STAGES, r['commands']):
        q, h, parent, c = [js(name+'/'+f+'.json') for f in ('request', 'receipt', 'parent-command', 'parent-closed')]
        closed(c)
        assert h['exit'] == 0 and h['absence_proof'] == 'ECHILD' and h['inputs_unchanged'] is True
        assert h['wall_timeout'] is False and h['unexpected_descendants'] == h['cleanup_events'] == []
        assert h['aborted'] is h['cleanup_error'] is None
        assert h['request_sha256'] == descriptors[name+'/request.json']['sha256']
        assert h['helper_sha256'] == r['sources']['tools/unwind-oracle/bounded_command.py']['sha256']
        assert parent['wall_seconds'] == q['wall_seconds'] + 25
        assert all(isinstance(v, str) and not v.startswith('/') for v in argv)
        command_rows.append(dict(stage=name, argv=argv, cpu=q['cpu_seconds'], wall=q['wall_seconds'], bytes=q['file_bytes'],
            parent_wall=parent['wall_seconds'], exit=0, helper_seconds=h['elapsed_seconds'], parent_seconds=c['seconds']))
    assert (command_rows[-1]['cpu'], command_rows[-1]['wall'], command_rows[-1]['bytes'], command_rows[-1]['parent_wall']) == (10, 15, 1048576, 40)
    history, exact, concurrent, streamed = [r[n] for n in ('history_stream', 'exact_work', 'concurrent_epochs', 'streamed_epochs')]
    assert all(v['status'] == 'PASS' for v in (history, exact, concurrent, streamed, r['epoch_retirement'], r['completed_drain']))
    protocol = history['protocol']
    expected = dict(originals=2, calls=2, sampled=2, rows=2, events=4, actions=600, history_batches=77, max_resident=8,
        epochs=300, retired=300, replacements=298, interval_batches=2, registrations=1, old_prefix=1, new_prefix=599,
        history_full_refusals=1, not_drained_refusals=1, report_permit_refusals=1, stale_refusals=1, empty_drains=2, replay_refusals=4, joined=True)
    assert protocol == expected and all(type(protocol[k]) is type(v) for k, v in expected.items())
    assert history['source_assertions'] == dict(epoch_limit=2, retained_owner_release=[2, 1, 0], full_journal_pages=2, words_per_journal_page=512)
    gate_bytes = read(a.gates); assert digest(gate_bytes)['sha256'] == GATES_SHA256
    gates = json.loads(gate_bytes); assert gates['revision'] == REVISION and gates['status'] == 'PASS' and gates['unrun'] == []
    assert [c['name'] for c in gates['commands']] == GATES
    for c in gates['commands']: closed(c['closed']); assert c['libtest']['failed'] == 0
    assert gates['source_receipt_sha256'] == GATES_RECEIPT_SHA256 and gates['projector_sha256'] == GATE_SUMMARIZER_SHA256
    counts = {c['name']: c['libtest'] for c in gates['commands']}
    assert pick(counts['workspace-default'],'passed failed ignored terminal_groups excluded_nested') == dict(passed=2582,failed=0,ignored=9,terminal_groups=100,excluded_nested=5)
    assert pick(counts['serial-launch'],'passed failed ignored') == dict(passed=1039,failed=0,ignored=0)
    assert counts['staged-allocation']['passed'] == 3 and counts['prefixed-pun']['passed'] == 36
    artifacts = dict(r['build']['artifacts'], rapid_profiler_libtest=concurrent['test_artifact'])
    for name, artifact in artifacts.items():
        profile = artifact['profile']
        assert profile == dict(opt_level='3', debuginfo=0, debug_assertions=True, overflow_checks=True, test=name=='rapid_profiler_libtest')
        assert type(profile['debuginfo']) is int and type(artifact['cargo_fresh']) is bool
    development = []
    for name, (sha, exits, diagnosis) in DEVELOPMENT.items():
        body = read(a.root_meta/(name+'.json')); assert digest(body)['sha256'] == sha
        d = json.loads(body); commands = d.get('commands', [d]); assert len(commands) == len(exits)
        for command, code in zip(commands, exits):
            closed(command['closed'], code)
            development.append(dict(case=name+('/'+command['name'] if 'name' in command else ''), revision=d['revision'], dirty=d['dirty'],
                status='PASS' if code == 0 else 'FAILED', exit=code, argv=normalized(command['argv']), seconds=command['closed']['seconds'],
                metadata_sha256=sha, private_log_sha256=command['closed']['private_log_sha256'],
                source_map_sha256=digest(encoded(d['source_sha256']))['sha256'] if 'source_sha256' in d else None,
                executor_reported_diagnosis=diagnosis))
    campaign, attempt_bytes = cleanup_campaign(read(a.campaign), REVISION, r['sources'])
    failures = prior_failures(read(a.prior_gates), read(a.prior_diagnostic))
    parser_controls = cleanup_controls(read(a.cleanup_controls))
    hardware = pick(r['hardware'], 'architecture vendor family model stepping owner_label_origin build_affinity_cpus native_state_affinity_cpus')
    hardware.update(owner_label='AMD EPYC Zen 5 dev host', recorded_owner_label=r['hardware']['owner_label'])
    csv_stream = io.StringIO(newline=''); writer = csv.DictWriter(csv_stream, ['case', 'status']+list(protocol), lineterminator='\n')
    writer.writeheader(); writer.writerow(dict(case='history-stream', status='PASS', **protocol)); case_bytes = csv_stream.getvalue().encode('ascii')
    receipt = dict(schema=1, revision=REVISION, ancestry=ANCESTRY, status='NATIVE_CLEANUP_CAMPAIGN_AND_REQUIRED_GATES_PASS', stages=dict(required=27, prior_required=26, passed=27, failed=0, unrun=0),
        closure=dict(strict_ECHILD=27, clean_stage_parents=27, rescued_descendants=0, scope='Named stage parents; no invented recipe-process receipt.'),
        history=history, native_commands=command_rows, hardware=hardware, versions=r['versions'], tools=r['tools'],
        artifacts=dict(artifacts, checksum_dso=r['dso'], exact_dso=exact['dso']),
        source_pins={n:v for n,v in r['sources'].items() if 'history' in n or n in (
            'tools/rapid-profiler/verify_ordinary_interval.py', 'tools/rapid-profiler/src/frontend.rs',
            'tools/rapid-profiler/src/frontend/interval_entry.rs', 'tools/rapid-profiler/src/frontend_native/mod.rs',
            'tools/rapid-profiler/src/frontend_native/always_on.rs', 'tools/rapid-profiler/src/frontend_native/always_on/drain.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/tests/concurrent_native.rs',
            'evaluation/admission/processes.py', 'tools/unwind-oracle/bounded_command.py')},
        regressions=dict(state_comparisons=[r['oracle']['comparisons'], exact['oracle']['comparisons'], concurrent['oracle']['comparisons']],
            checksum_calls=r['calls'], exact=pick(exact, 'calls sampled closed fresh_processes'),
            forced=pick(concurrent['forced_native'], 'calls sampled closed removed writer_contentions inflight_rearm'),
            timed=pick(concurrent['timed'], 'calls sampled unsampled coverage'), retirement_calls=[c['calls'] for c in r['epoch_retirement']['cases']],
            drain=pick(r['completed_drain'], 'calls batches events'), streamed=pick(streamed, 'calls epochs slots retired replacements batches sampled unsampled coverage')),
        native_state_qualification=r['native_state_qualification'], development=development, cleanup_campaign=campaign, cleanup_parser_controls=parser_controls, prior_failures=failures,
        required_gates=dict(status="PASS",file="gates.json",sha256=GATES_SHA256,counts=counts),
        development_scope='JSON closures and exact argv/hashes checked; diagnoses and 221-pass/4-ignored model, focused1 and 26 Python method counts are executor reports, not log replay.',
        review_sha256=dict(production=SOURCE_REVIEW_SHA256, native_source=NATIVE_SOURCE_REVIEW_SHA256, recipe=RECIPE_REVIEW_SHA256, native_metadata=NATIVE_REVIEW_SHA256, gate_metadata=GATES_REVIEW_SHA256, cleanup_source=CLEANUP_SOURCE_REVIEW_SHA256, cleanup_campaign_source=CAMPAIGN_SOURCE_REVIEW_SHA256, cleanup_campaign_metadata=CAMPAIGN_REVIEW_SHA256),
        provenance=dict(result_sha256=RESULT_SHA256, native_manifest_sha256=NATIVE_MANIFEST_SHA256, native_metadata_map_sha256=NATIVE_METADATA_SHA256, metadata_files=len(data), gates_sha256=GATES_SHA256,
            selected_source_files=len(r['sources']), full_source_map_sha256=descriptors['sources-before.json']['sha256'],
            gate_source_receipt_sha256=gates['source_receipt_sha256'], projector=digest(Path(__file__).read_bytes())),
        scope='Closed JSON-only projection; producer source/tool/artifact joins and source-checked full input/journal/report/RET evidence. No artifacts, stdout, CSV bodies or machine state reopened. Range high-water does not prove historical generation association; native full Action replay provides that separate check. No new full-state, performance, indefinite-service or full-A5 claim.',
        files={'cases.csv':digest(case_bytes), 'gates.json':digest(gate_bytes), 'cleanup-attempts.csv':digest(attempt_bytes)})
    readme = README.replace('@REVISION@', REVISION)
    outputs = {'receipt.json':encoded(receipt), 'cases.csv':case_bytes, 'gates.json':gate_bytes, 'cleanup-attempts.csv':attempt_bytes,
        'README.md':readme.encode('utf-8'), 'project.py':Path(__file__).read_bytes()}
    for body in outputs.values():
        assert all(s not in body for s in (b'/' + b'home/', b'.facebook' + b'.com', b'.fbinfra' + b'.net'))
    assert not a.out.exists(); a.out.mkdir(parents=True)
    for name, body in outputs.items():
        with (a.out/name).open('xb') as stream: stream.write(body)


README = r'''# Transfer bounded controller history without losing older call bindings

Opt-in streamed history can transfer bounded resident actions while older calls
retain their absolute history and generation bindings. `drain_history()` exports
immutable chunks with carry-in and stream identity; it does not reset lifetime
counters or equate report readiness with physical RET or code quiescence.
The legacy 256-total-action policy remains available and unchanged. The new
explicit 49-bit format keeps the same event and buffer capacities. Consumers
must replay contiguous chunks for full generation association: committed
high-water alone authenticates a range.

Qualification at `@REVISION@` passed all 27 release stages, 100 sequential
cleanup attempts and seven required gates. [receipt.json](receipt.json) holds
commands, source/tool/artifact hashes and separate scopes;
[cases.csv](cases.csv) is the compact native protocol, and
[cleanup-attempts.csv](cleanup-attempts.csv) contains each cleanup disposition
without duplicating 100 records in JSON. [gates.json](gates.json) preserves
commands and grouping policy: workspace **2,582 passed / 0 failed / 9 ignored**
(100 outer terminals, five nested summaries excluded), serial launch
**1,039 / 0 / 0**, staged allocation **3**, and prefixed-pun **36**.
Workspace and serial command durations were 352.867 and 126.011 seconds,
respectively; these are operational durations, not performance measurements.
The owner label is **AMD EPYC Zen 5 dev host**; observed CPU fields are separate.

The history case makes two original and two installed C-checksum calls while
performing 600 actions, 77 history transfers and 300 staged/retired epochs.
The old call retains entry prefix 1 while the controller advances to high-water
599 and exports 76 chunks. It then returns; the second call uses prefix 599.
Action 600, chunk 77 and the last retirement occur after the second return.
Independent full Action replay checks carry-in, stream identity and generation
association.
The terminal reports two completed buffers, four events and one registration.
E=2, two full 512-word journals and owner release 2→1→0 are separately labelled
source assertions. Rust checks original values, inputs, raw/report joins and
actual CALL/RET; this metadata projection does not replay those bodies.

All 26 prerequisite stages passed again with their original checks and limits.
Their separate state comparisons remain 978 / 844 / 844; exact populations,
concurrent/timed/retirement/drain and 160-call streamed results retain their own
numbers. All three release artifacts were cached (`cargo_fresh=true`) and retain
opt3/debug0/assertions/overflow profiles; no fresh compilation is claimed.
The new finite history case adds no full-state, calibrated-timing, performance,
indefinite-service or complete-A5 qualification. The new history child's bounds
remain 10 CPU / 15 wall seconds / 1 MiB, with a 40-second parent. Other stages
retain their own recorded bounds.

The cleanup fixture correction keeps reference setup on the already isolated
main-thread route, removing an unnecessary worker while retaining singleton,
ownership, cleanup and protocol checks. Its campaign runs five controls/six
trajectories per attempt, sequentially, with 180-second / 8 MiB command bounds
and stop-on-first-failure. All 100 closures were normal and clean with zero
rescues: 600 trajectory protocol completions, not 600 libtest tests. Default
316-CPU affinity and default test parallelism were retained; compiler jobs were
four. InvalidUnmap's expected SIGABRT is one explicit fixture outcome, not an
exception for unrelated failures. Five synthetic parser methods and two
explicit optimization-refusal commands have separately pinned source/closures;
method counts and the refusal message are executor-reported, not log replay.

The earlier 3062 workspace failure and diagnostic 35-pass/attempt-36 QueryError
failure remain FAILED. The diagnostic singleton assertion observed a non-main
task after join, but its numeric identity was not independently bound to the
setup worker and no kernel trace was captured. This narrow correction does not
prove every historical backing failure had that cause or eliminate all flakes.
Development failures from missing exports, Clippy's manual_div_ceil check and
omitted --runner remain recorded. Prior [backing-child](../creation-identity-088dc0a/README.md)
and [orig_rax](../merged-af5a1ef/README.md) outcomes remain historical; no orig_rax
fix is claimed. Earlier capability failures remain linked from the
[streamed report](../streamed-epochs-b895189/README.md).

The tested commit contains main `3f6056f0a249e4f2ce5ce867e8bf67ae5370224d`
and fixture correction `efa0f26e377e013a3b497de8425b56344216e21b` through merge
`62cd0195f43602c365a0e1c0c10ce2ff688047ac`. No later revision is qualified.
From a clean checkout at the tested revision, using the recorded Python 3.12.15
and other tools, choose fresh ignored output directories:

```sh
env -u PYTHONOPTIMIZE python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision @REVISION@ --raw "$REPO/ignored/NEW_NATIVE" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --exact-work --concurrent-epochs --retire-epochs --drain-completed \
  --streamed-epochs --stream-history
env -u PYTHONOPTIMIZE python3 -B evaluation/admission/test_backing_singleton.py \
  --runner evaluation/admission/check_backing_singleton.py
env -u PYTHONOPTIMIZE python3 -B evaluation/admission/check_backing_singleton.py \
  --revision @REVISION@ --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$REPO/ignored/NEW_CLEANUP" --repetitions 100
python3 -B evaluation/admission/check_exec_identity.py \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$REPO/ignored/NEW_GATES" --checks-only
```

This projection reads pinned CLOSED JSON only. It does not reopen raw streams,
CSV bodies, journals, binaries, tools, providers or process state. Counts remain
producer-recorded/source-attested; the gate group selection was performed by
root with unchanged `evaluation/merged-af5a1ef/summarize.py`. Complete top-level
driver exit0 is root-reported; supplied per-command closures are joined. Cleanup
source/tool pins are not a full Cargo-configuration or artifact attestation.
Given the pinned private metadata, reproduce only this public projection:

```sh
python3 -B project.py --raw "$CLOSED_NATIVE" --gates "$CLOSED_GATE_PROJECTION" \
  --campaign "$CLOSED_CLEANUP_RECEIPT" --cleanup-controls "$CLOSED_PARSER_CONTROLS" \
  --prior-gates "$FAILED_3062_GATES" --prior-diagnostic "$FAILED_DIAGNOSTIC" \
  --root-meta "$CLOSED_DEVELOPMENT" --out "$NEW_OUTPUT"
```
'''

if __name__ == '__main__': main()
