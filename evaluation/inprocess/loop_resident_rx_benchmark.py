#!/usr/bin/env python3
"""Matched sixty-process LOOP RX release comparison, after complete prerequisites.

Installed clean source only. This does not replace any native, owner, maps,
causal or full-profile qualification. Parity is a separately reported outcome.
"""
import argparse
import csv
import io
import json
import os
from pathlib import Path
import re
import statistics
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from persistent_dynamic import BOUNDS, digest, imported_sources
from persistent_loop_effects_archive import Build
from persistent_loop_effects_build_default import before_loop_effects_default
from persistent_loop_effects_build import FEATURES
from page_selected_process import invoke
from page_selected_effect_ls import finalize
import page_cost_compare as cost
import loop_resident_rx_program as program
import loop_resident_rx_reports as reports
import loop_resident_rx_native as native
import loop_resident_rx_fixture as fixture

TARGET = [30, 512 << 20, 16 << 20, 60]
DR_TARGET = [30, 16 << 30, 16 << 20, 60]
SCHEDULE = program.SCHEDULE[:-2] + (
    ('dr-cmake', 'metadata'), ('dr-build', 'release_build'), ('dr-client-exports', 'metadata'),
    ('dr-proof-ls', 'program_dr'), ('dr-proof-true', 'program_dr'), ('dr-proof-false', 'program_dr')) + tuple(
    (name, 'program_dr' if lane == 'dynamorio' else 'program')
    for name, (_, _, lane) in zip(cost.NAMES, cost.ORDER, strict=True))


def prerequisite(path, sha, kind, state, pin):
    """Authenticate complete closed receipts, never promote a successful prefix."""
    need(re.fullmatch('[0-9a-f]{64}', sha) is not None, 'literal prerequisite SHA256')
    path = pin(path); need(fact(path)['sha256'] == sha, 'whole prerequisite receipt')
    value = json.loads(path.read_bytes())
    expected_profile = 'loop-resident-rx-direct44-v1' if kind == 'native' else 'loop-resident-rx-program-release-v1'
    expected_status = 'passed' if kind == 'native' else 'completed_diagnostic'
    need(value['schema'] == 1 and value['profile'] == expected_profile and
         value['status'] == expected_status and value['source'] == state['source'] and
         value['revision'] == state['revision'] and value['error'] is None and value['final_errors'] == [] and
         all(value[k] is True for k in ('source_unchanged', 'inputs_unchanged', 'cleanup_complete')),
         'whole successful current-source prerequisite with no retained failure')
    if kind == 'native':
        need(value['source_context_is_natural'] is True and
             value['compiled_source_context'] == str(ROOT/'tools/page-entry/selected') and
             value['reader_source_context'] == str(ROOT), 'native prerequisite is installed actual source')
    else:
        need(value['source_context'] == 'installed tracked source', 'program prerequisite is installed actual source')
    need(value['hardware']['probe_cpu'] == value['cpu'] and value['hardware']['affinity_cpu_count'] == 1 and
         {k: v for k, v in value['hardware'].items() if k != 'probe_cpu'} ==
         {k: v for k, v in state['hardware'].items() if k != 'probe_cpu'},
         'same hardware and security context; prerequisite CPU remains separately recorded')
    need(value['bounds'] == BOUNDS, 'unchanged prerequisite bounds')
    schedule = native.SCHEDULE if kind == 'native' else program.SCHEDULE
    need(len(schedule) == (49 if kind == 'native' else 34) and
         [(r['name'], r['profile']) for r in value['commands']] == list(schedule),
         'complete original prerequisite command population')
    for row in value['commands']:
        need(type(row['exit']) is int and row['exit'] == row['expected_exit'] and
             row['bounds'] == BOUNDS[row['profile']] and row['capture_limit'] == 16 << 20 and
             row['reaped'] is True and row['timed_out'] is False and not row['error'] and
             row['cleanup_errors'] == [] and all(d['closed'] is True for d in row.get('descriptors', [])),
             'every actual prerequisite command outcome and cleanup')
        need(json.loads((path.parent/(row['name']+'.json')).read_bytes()) == row,
             'whole prerequisite saved command record')
        need(set(row['captures']) in ({'stdout', 'stderr'}, {'stdout', 'stderr', 'record'}),
             'complete actual prerequisite capture schema')
        for stream, captured in row['captures'].items():
            capture = path.parent/captured['file']
            need(capture.parent == path.parent and capture.name == row['name']+'.'+stream and
                 fact(capture) == {k: captured[k] for k in ('bytes', 'sha256')} and
                 captured['bytes'] <= (row['bounds'][2] if stream == 'record' else row['capture_limit']),
                 'whole contained bounded prerequisite capture')
    for path_name, expected in value['inputs'].items():
        need(fact(path_name) == expected, 'whole retained prerequisite input')
    for path_name, expected in value['artifacts'].items():
        need(dict(fact(path_name), mode=Path(path_name).stat().st_mode & 0o777) == expected,
             'whole retained prerequisite artifact and mode')
    for alias, target in value['aliases'].items():
        need(str(Path(alias).resolve(strict=True)) == target, 'retained prerequisite input alias')
    for alias, target in value['namespace_aliases'].items():
        need(Path(alias).is_symlink() and os.readlink(alias) == target, 'retained prerequisite namespace alias')
    need(all(os.path.lexists(p) == present for p, present in value['presence'].items()),
         'retained prerequisite loader configuration presence')
    cases = value['cases']
    need(all(c['status'] == 'passed' for c in cases), 'all original prerequisite case predicates completed')
    if kind == 'native':
        need([c['label'] for c in cases] == ['native', 'release', 'differential', 'causal'] and
             [c['exit'] for c in cases] == [0, 0, 0, 125] and
             cases[0]['native_instructions'] == 44 and cases[0]['native_frames'] == 12 and
             len(cases[0]['application_controls']['refusals']) == 40 and
             all(c['application_complete'] is True for c in cases[:3]) and
             cases[3]['application_complete'] is False and
             value['seed_prerequisite']['status'] == 'passed' and
             len(value['extent_controls']['positives']) == 5 and
             len(value['extent_controls']['refusals']) == 62,
             'complete native44, both whole-state pairs and distinct required causal refusal')
        for case in cases[1:]:
            observed = case['observer']; control = case['label'] == 'causal'
            stderr = (path.parent/('subject-'+case['label']+'.stderr')).read_bytes()
            actual, _ = fixture.observed(stderr, int(control))
            need(actual == observed and fixture.controls(stderr, int(control)) == case['observer_controls'],
                 'whole current native observer and all causal/refusal controls, including literal8850')
            need([e['mask'] for e in observed['epochs']] == [0, 0, 2] and
                 observed['oracle']['complete'] == 1 and observed['oracle']['failure'] == 0 and
                 observed['oracle']['controls'] == observed['oracle']['restorations'] == (32 if control else 0) and
                 len(case['observer_controls']['refusals']) == (976 if control else 496),
                 'genuine retained-peer mask2 and every original observer/causal control')
            need(len(case['observer_controls']['target_refusals']) ==
                 len(set(case['observer_controls']['target_refusals'])) == 101,
                 'all current target-row schema and semantic refusals')
            for key,count in (('transit_refusals',28),('ticket_refusals',84+240*int(control))):
                rows=case['observer_controls'][key]
                need(type(rows) is list and all(type(item) is str and item for item in rows) and
                     len(rows)==len(set(rows))==count,
                     'all separate transit-counter and second-ticket prerequisite refusals')
            need(observed['transit_ticket']['complete']==1 and
                 observed['transit_ticket']['checks']==1+16*int(control) and
                 observed['transit_ticket']['restorations']==16*int(control) and
                 observed['transit_controls']==[dict(version=1,index=i,expected=0,actual=0,restored=1)
                                                for i in range(16*int(control))],
                 'genuine second DIRECT ticket and all sixteen restored actual causal controls')
            need(case['observer_controls']['abort_refusals']==
                 (['busy.0','busy.2','active.1'] if control else []),
                 'exact three separate causal abort-latch controls; none in positive subjects')
            if not control:
                need(case['pair'] == {'full_application_state_equal': True,
                                      'interior_owner_state_observed': False},
                     'exact original whole native application pairing without interior-owner credit')
        archive = value['archive_provider']['archive']
    else:
        need([(c['workload'], c['lane'], c['exit']) for c in cases] == [('ls', 'release', 0), ('true', 'release', 0)] and
             all(c['completed_program_measurement'] is True and c['namespace_complete'] is True and
                 c['observed']['application_completed'] is True for c in cases),
             'both actual real programs completed with full namespace/output/terminal predicates')
        for case in cases:
            control_counts(case['controls'], case['workload'])
            rows=case['controls']['transit_refusals']
            need(type(rows) is list and all(type(item) is str and item for item in rows) and
                 len(rows)==len(set(rows))==28,
                 'all separate actual two-program prerequisite transit-counter controls')
        archive = value['archive']
    return dict(path=str(path), receipt=fact(path), cpu=value['cpu'], profile=value['profile'],
                commands=len(value['commands']), archive=archive,
                source=value['source'], cases_sha256=digest(cases),
                inputs_sha256=digest(value['inputs']), artifacts_sha256=digest(value['artifacts']))


def control_counts(value, kind):
    for rows, count in ((value['inherited']['inherited']['refusals'], program.CONTROL_COUNTS[kind]),
                        (value['inherited']['refusals'], program.RO_CONTROL_COUNT),
                        (value['refusals'], program.RX_CONTROL_COUNT)):
        need(len(rows) == len(set(rows)) == count, 'all original447/480 plus167 plus106 controls')


def cohort(builder, products, private, pin, binary, aliases, run, r, sdk):
    states = program.prepare_workloads(builder, products, private, pin, binary, aliases, run, r)
    drrun, client, dr_env = cost.build_dr(sdk, builder, private, pin, binary, run, r)
    cost.dr_diagnostics(drrun, client, states, private, pin, binary, run, r, dr_env)
    def check(out, err, pid, status, stdout, images, image_bytes, carrier, carrier_bytes, *, workload):
        value = reports.check(out, err, (pid, status, stdout, images, image_bytes, carrier, carrier_bytes), workload, 'release')
        return value, dict(application_completed=value['application_completed'], certificate_mode='release',
                           full_state_credit=False, qualification_credit=False)
    def controls(out, err, pid, status, stdout, images, image_bytes, carrier, carrier_bytes, *, workload):
        value = reports.controls(out, err, (pid, status, stdout, images, image_bytes, carrier, carrier_bytes), workload, 'release')
        control_counts(value, workload); return value
    def cleanup(name, attempted):
        need(len(attempted) == 1 and attempted[0]['name'] == name and
             type(attempted[0].get('exit')) is int and attempted[0].get('reaped') is True and
             attempted[0].get('cleanup_errors') == [] and
             all(d.get('closed') is True for d in attempted[0].get('descriptors', [])) and not r['final_errors'],
             'continue the fixed schedule only after complete actual child and capture cleanup')
    cost.launch_cohort(builder, states, private, binary, run, r, program.namespace, drrun, client, dr_env,
                      gated_check=check, gated_controls=controls, cleanup_check=cleanup)
    need(all(x['status'] == 'passed' for x in r['dr_diagnostics']) and len(r['commands']) == 98 and
         len(r['terminal_reports']) == len(r['reader_controls']) == 20,
         'all98 original setup/build/DR-proof/sample commands, no discarded failure')


def publish(private, r, a):
    fields = ('ordinal', 'workload', 'repeat', 'lane', 'status', 'exit', 'process_ns', 'timed_out', 'reaped',
              'user_cpu_ns', 'system_cpu_ns', 'minor_faults', 'major_faults', 'voluntary_switches', 'involuntary_switches')
    stream = io.StringIO(newline=''); writer = csv.writer(stream, lineterminator='\n')
    writer.writerow(fields + ('stdout_bytes', 'stdout_sha256', 'stderr_bytes', 'stderr_sha256'))
    for c in r['cases']:
        captures = c.get('captures', {})
        writer.writerow([c.get(k) for k in fields] + [captures.get(s, {}).get(k) for s in ('stdout', 'stderr') for k in ('bytes', 'sha256')])
    data = stream.getvalue().encode(); csv_path = private/'samples.csv'
    with csv_path.open('xb') as f: f.write(data)
    stats = {}; parity = None
    if r['status'] == 'completed_comparison':
        for kind in ('ls', 'true'):
            stats[kind] = {}
            for lane in ('native', 'gated', 'dynamorio'):
                rows = [c for c in r['cases'] if c['workload'] == kind and c['lane'] == lane]
                need(len(rows) == 10 and all(c['status'] == 'passed' for c in rows), 'all ten samples before any statistic')
                times = [c['process_ns'] for c in rows]; q = statistics.quantiles(times, n=4, method='inclusive')
                stats[kind][lane] = dict(samples=10, median_ns=statistics.median(times), q1_ns=q[0], q3_ns=q[2], iqr_ns=q[2]-q[0])
            gated = stats[kind]['gated']['median_ns']
            stats[kind]['gated_over_native'] = gated/stats[kind]['native']['median_ns']
            stats[kind]['gated_over_dynamorio'] = gated/stats[kind]['dynamorio']['median_ns']
        parity = all(stats[k]['gated_over_dynamorio'] <= 1 for k in ('ls', 'true'))
    events = {}
    for name, observed in r.get('terminal_reports', {}).items():
        events[name] = dict(rx={k: v for k, v in observed['rx'].items() if k not in reports.LAST},
            maps_view=observed['maps_view'], ordinary=observed['ordinary'], linked_ingress=observed['linked_ingress'],
            persistent={k: observed['persistent'][k] for k in ('offers', 'publications', 'hits', 'cancelled', 'entries', 'completed', 'dual_entries')},
            certificate={name: {k: value[k] for k in keys} for name, keys in (
                ('byte_certificate', ('decisions', 'hits', 'issues', 'full_scans', 'postseal_bytes', 'full_scan_bytes')),
                ('history_certificate', ('decisions', 'hits', 'issues', 'full_calls', 'differential_checks')))
                for value in (observed['certificate'][name],)})
    hw = dict(r['hardware']); hw['isa_flags_sha256'] = digest(hw.pop('isa_flags'))
    value = dict(schema=1, profile=r['profile'], status=r['status'], revision=r['revision'], source=r['source'],
        cpu=r['cpu'], hardware=hw, bounds=r['bounds'], receipt=fact(private/'receipt.json'),
        script=fact(__file__), commands=len(r['commands']), command_rows_sha256=digest(r['commands']),
        prerequisites={k: {n: v for n, v in p.items() if n != 'path'} for k, p in r.get('prerequisites', {}).items()},
        archive=r.get('archive'), sdk_manifest_sha256=digest(r.get('dynamorio_sdk', {})),
        sdk_files=len(r.get('dynamorio_sdk', {})), client=r.get('dynamorio_client'),
        source_unchanged=r['source_unchanged'], inputs_unchanged=r['inputs_unchanged'], cleanup_complete=r['cleanup_complete'],
        statistics=stats, parity_target_met=parity,
        target='Gated median <= DR-null median for BOTH programs; no ten-times allowance.',
        outcome='not_measured' if parity is None else 'parity_attained' if parity else 'parity_not_attained',
        quantiles='inclusive linear interpolation at (n-1)*p; IQR=Q3-Q1',
        timing_scope='Monotonic pre-Popen through reap; includes carrier/namespace startup and terminal output. Offline builds and supplied-reader checks excluded. No first-touch, steady-state or cache-cold claim.',
        cpu_scope='RUSAGE_CHILDREN difference around the sole sequential child; CPU seconds converted to ns, microsecond accounting precision.',
        order='Ten fresh rounds; alternating program order and all six lane permutations; no retries, replacements or removed samples.',
        count_scope='Actual validated terminal vectors; overlapping event families are not summed. No inferred absent events.',
        events=events, qualification_credit=False, original_full_profile_credit=False,
        control_counts={k: dict(application=program.CONTROL_COUNTS[k.split('-')[0]], certificate=167, rx=106,
                               sha256=digest(v)) for k, v in r.get('reader_controls', {}).items()},
        samples=dict(file=csv_path.name, **fact(csv_path)),
        error_type=(r['error'] or '').split(':', 1)[0] or None, final_error_count=len(r['final_errors']),
        failed_samples=[dict(ordinal=c['ordinal'], status=c['status'], error_type=c.get('error', 'not_run').split(':', 1)[0])
                        for c in r['cases'] if c['status'] != 'passed'],
        commands_portable=dict(native_ls=['/bin/ls', '-d', '.'], native_true=['/bin/true'],
            gated=['python3.12', '-B', 'tools/page-entry/carrier.py', 'exec-loader', '--library-root', '/usr/lib64',
                   '--namespace', '$UNIQUE_NAMESPACE', '$CARRIER', '$ORIGINAL', '--', '$ORIGINAL', '$ARGS'],
            dynamorio=['$SDK/bin64/drrun', '-quiet', '-64', '-root', '$SDK', '-c', '$NULL_CLIENT', '--', '$ORIGINAL', '$ARGS']),
        reproduce=['python3.12', '-B', 'evaluation/inprocess/loop_resident_rx_benchmark.py', '--expect-revision', a.expect_revision,
                   '--sdk', '$SDK', '--native-receipt', '$NATIVE_RECEIPT', '--native-sha256', a.native_sha256,
                   '--program-receipt', '$PROGRAM_RECEIPT', '--program-sha256', a.program_sha256,
                   '--output', 'target/evaluation/inprocess/loop-resident-rx-benchmark-NEW'])
    text = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n'
    need(len(text.encode()) < 64 << 10 and len(data) < 32 << 10 and '/home/' not in text and str(ROOT) not in text,
         'compact path-free JSON/CSV with complete sample metadata')
    with (private/'summary.json').open('x') as f: f.write(text)


def execute(a):
    os.chdir(ROOT)
    need(sys.version_info[:2] == (3, 12) and not sys.flags.optimize and
         re.fullmatch('[0-9a-f]{40}', a.expect_revision) and len(os.sched_getaffinity(0)) == 1,
         'Python3.12, exact clean revision, enabled assertions and reserved singleton')
    private = a.output.resolve(); need(private.parent == ROOT/'target/evaluation/inprocess' and not private.exists(), 'fresh private benchmark output')
    private.mkdir(mode=0o700); cpu = next(iter(os.sched_getaffinity(0)))
    bounds = dict(BOUNDS, program_dr=DR_TARGET)
    need(len(SCHEDULE) == 98 and len(cost.ORDER) == len(cost.NAMES) == 60 and
         bounds['program'] == bounds['release_build'] == TARGET, 'fixed98/60 schedule and original bounds')
    r = dict(schema=1, profile='loop-resident-rx-matched-release-v1', status='failed', revision=a.expect_revision,
        source=None, source_unchanged=False, inputs_unchanged=False, cleanup_complete=False,
        cpu=cpu, hardware=hardware(cpu), bounds=bounds, commands=[], namespace_aliases={}, error=None, final_errors=[],
        cases=[dict(ordinal=i, workload=k, repeat=n, lane=l, status='not_run') for i, (k, n, l) in enumerate(cost.ORDER)])
    pins = {}; aliases = {}; artifacts = {}; presence = {}
    def pin(path, want=None):
        alias = Path(os.path.abspath(path)); p = alias.resolve(strict=True); value = fact(p)
        need(want is None or value == {k: want[k] for k in ('bytes', 'sha256')}, 'whole requested input')
        need(str(alias) not in aliases or aliases[str(alias)] == str(p), 'stable input alias')
        need(str(p) not in pins or pins[str(p)] == value, 'stable input bytes')
        aliases[str(alias)] = str(p); pins[str(p)] = value; return p
    def binary(path):
        p = Path(path).resolve(strict=True); value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'stable artifact bytes/mode')
        artifacts[str(p)] = value; return p
    def closure():
        need(os.sched_getaffinity(0) == {cpu}, 'same reserved CPU throughout')
        need(all(fact(p) == v for p, v in pins.items()), 'whole unchanged inputs')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == v for p, v in artifacts.items()), 'whole unchanged artifacts/modes')
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in aliases.items()), 'whole unchanged aliases')
        need(all(os.path.lexists(p) == v for p, v in presence.items()), 'unchanged loader configuration presence')
        finalize(r)
    def run(name, argv, profile='metadata', expected=0, env=None, record=False, step=False):
        closure(); need(not r['final_errors'] and not any(c['name'] == name for c in r['commands']), 'clean unique command')
        need(record is False and step is False and len(r['commands']) < len(SCHEDULE) and
             (name, profile) == SCHEDULE[len(r['commands'])] and type(expected) is int and
             expected == (1 if name == 'dr-proof-false' else 0), 'literal fixed schedule and outcome')
        row = dict(name=name, argv=list(map(str, argv)), profile=profile, bounds=bounds[profile], capture_limit=16 << 20,
                   environment=dict(ENV if env is None else env), expected_exit=expected)
        r['commands'].append(row)
        try:
            if name in cost.NAMES:
                lane = cost.ORDER[cost.NAMES.index(name)][2]
                need(row['bounds'] == (DR_TARGET if lane == 'dynamorio' else TARGET), 'original measured lane bounds')
                need(row['environment'] == cost.PROGRAM_ENV if lane != 'dynamorio' else
                     {k: v for k, v in row['environment'].items() if k != 'HOME'} == cost.PROGRAM_ENV and
                     Path(row['environment']['HOME']) == private/'dr-home', 'exact lane environment')
            out, err = (cost.program_invoke if name in cost.NAMES else invoke)(row, private, cpu, record=record, step=step)
            need(type(row['exit']) is int and row['exit'] == expected, 'actual command outcome '+name)
            return row, out, err
        finally:
            for stream in ('stdout', 'stderr', 'record', 'preparation'):
                path = private/(name+'.'+stream); observed = row.get('captures', {}).get(stream)
                try:
                    if path.exists() or path.is_symlink():
                        value = fact(binary(path))
                        if observed is not None: need(observed['file'] == path.name and value == {k: observed[k] for k in ('bytes', 'sha256')}, 'actual retained capture')
                    else: need(observed is None, 'missing actual capture')
                except BaseException as e: r['final_errors'].append('capture '+name+': '+repr(e))
            try:
                path = private/(name+'.json')
                if path.exists(): need(json.loads(binary(path).read_bytes()) == row, 'whole retained command JSON')
            except BaseException as e: r['final_errors'].append('command '+name+': '+repr(e))
    def build_run(name, argv, profile='metadata', env=None, expected=0):
        before_loop_effects_default(name, argv, builder, pin, aliases, run, r)
        return run(name, argv, profile=profile, env=env, expected=expected)
    builder = Build(r, private, pin, binary, build_run, ('region.rs',), scalar_span=True, linked_epoch=True, mov_guard=True)
    prerequisite_args = (('native', a.native_receipt, a.native_sha256), ('program', a.program_receipt, a.program_sha256))
    try:
        r['source'] = source(); need(r['source']['revision'] == a.expect_revision, 'exact current clean source')
        r['prerequisites'] = {kind: prerequisite(path, sha, kind, r, pin) for kind, path, sha in prerequisite_args}
        _, names, err = run('tracked-input-list', ['git', '-C', ROOT, 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'])
        need(not err and str(Path(__file__).resolve().relative_to(ROOT)).encode() in names.split(b'\0'), 'benchmark source installed and tracked')
        for name in names.split(b'\0'):
            if name and not name.startswith(b'evaluation/inprocess/results/'): pin(ROOT/os.fsdecode(name))
        for name in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            presence[name] = os.path.lexists(name)
            if presence[name]: pin(name)
        need(not presence['/etc/ld.so.preload'], 'no global preload'); imported_sources(pin)
        products = builder.prepare()
        need(builder.decoder_features == FEATURES and builder.extra_decoder_sources ==
             ('region.rs', 'mov_guard.rs', 'scalar_read.rs', 'loop_scalar.rs', 'byte_mov_guard.rs') and
             builder.record['status'] == 'passed' and builder.record['command_completed'] is True and
             builder.environment['CARGO_BUILD_JOBS'] == '1' and builder.environment['CARGO_INCREMENTAL'] == '0',
             'fresh exact archive with one Cargo job')
        r['archive'] = fact(products['archive'])
        need(all(p['archive'] == r['archive'] for p in r['prerequisites'].values()), 'same actual archive as both complete prerequisites')
        cohort(builder, products, private, pin, binary, aliases, run, r, a.sdk)
        need(not r['final_errors'], 'complete retained command custody'); r['status'] = 'completed_comparison'
    except BaseException as e: r['error'] = type(e).__name__+': '+str(e)
    finally:
        try: r['final_errors'].extend(builder.finish())
        except BaseException as e: r['final_errors'].append('build finalization: '+repr(e))
        try: imported_sources(pin)
        except BaseException as e: r['final_errors'].append('imported closure: '+repr(e))
        for path in sorted(private.rglob('*')):
            if path.is_file() and not path.is_symlink():
                try: binary(path)
                except BaseException as e: r['final_errors'].append('artifact closure: '+repr(e))
        r.update(inputs=pins, artifacts=artifacts, aliases=aliases, presence=presence)
        try:
            closure(); need(source() == r['source'], 'exact source unchanged after every child')
            if 'prerequisites' in r:
                need({kind: prerequisite(path, sha, kind, r, pin) for kind, path, sha in prerequisite_args} == r['prerequisites'],
                     'complete prerequisite custody unchanged before and after all samples')
            r['source_unchanged'] = r['inputs_unchanged'] = True
        except BaseException as e: r['final_errors'].append('final closure: '+repr(e))
        r['cleanup_complete'] = bool(r['commands']) and all(type(c.get('exit')) is int and c.get('reaped') is True and
            c.get('timed_out') is False and not c.get('error') and c.get('cleanup_errors') == [] and
            all(d.get('closed') is True for d in c.get('descriptors', [])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or not r['inputs_unchanged'] or not r['cleanup_complete']:
            r['status'] = 'failed'
        save(private/'receipt.json', r); publish(private, r, a)
        print(json.dumps(dict(status=r['status'], receipt=str(private/'receipt.json'))), flush=True)
    return int(r['status'] != 'completed_comparison')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('expect-revision', 'sdk', 'native-sha256', 'program-sha256'): parser.add_argument('--'+name, required=True)
    for name in ('native-receipt', 'program-receipt', 'output'): parser.add_argument('--'+name, required=True, type=Path)
    return execute(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
