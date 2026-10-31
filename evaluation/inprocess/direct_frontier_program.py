#!/usr/bin/env python3
"""One bounded native/counted LS and true schedule after the exact native41 gate.

This diagnostic never grants whole-profile or performance qualification. Original
392/522 qualification and the ten-run native/DR comparison remain mandatory.
"""
import argparse
import csv
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import platform
import re
import sys

sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_generic_build import Build
from page_selected_process import invoke
from page_selected_oneshot_build import before_default
from persistent_dynamic import BOUNDS, H, digest, named, imported_sources
from persistent_epoch_build import FEATURES
from persistent_direct_frontier_build import build_bridge
from page_native_pair_performance import PROGRAM_ENV, prepare_workload, program_invoke
from startup_counter import protocol, MISS_NAMES
from startup_counter_terminal import completed_terminal, counters
import persistent_group_counter_process as counter_process
import direct_frontier_loop_helpers as direct
import persistent_active_domain as component
import namespace

ROOT = Path(__file__).resolve().parents[2]
PROFILES = dict(BOUNDS)
TARGET = [30, 512 << 20, 16 << 20, 60]
PROGRAMS = (('ls', '/bin/ls', ('-d', '.'), b'.\n'), ('true', '/bin/true', (), b''))
ORDER = tuple((kind, lane) for kind, *_ in PROGRAMS for lane in ('native', 'counted'))
REQUIRED = ('same-revision original392 and cross-pair522 qualification with their original prerequisites',
            'ten-run same-host native and DR comparison')


def decode(data):
    def pairs(items):
        need(len(items) == len(dict(items)), 'no duplicate receipt keys')
        return dict(items)
    return json.loads(data, object_pairs_hook=pairs)


def command_csv(actual):
    stream = io.StringIO(); writer = csv.writer(stream, lineterminator='\n')
    writer.writerow(('revision', 'command', 'exit', 'duration_ns', 'status'))
    for row in actual['commands']:
        writer.writerow((actual['revision'], row['name'], row.get('exit'), row.get('duration_ns'), actual['status']))
    return stream.getvalue().encode()


def direct_public(actual, receipt_fact):
    """Whole existing native41 public projection, with no reader replay."""
    result = {k: actual[k] for k in ('schema', 'status', 'revision', 'source', 'source_unchanged',
        'cleanup_complete', 'cpu', 'hardware', 'bounds', 'scope', 'profile',
        'whole_profile_qualified', 'required_qualification')}
    result['cases'] = direct.public_cases(actual['cases'])
    result['capture_codec_component'] = {k: actual['capture_codec_component'][k] for k in
        ('status', 'counts', 'reader_counts', 'vector', 'exit', 'reader_exit', 'duration_ns',
         'reader_duration_ns', 'native_operations', 'qualification_credit')}
    for key in ('subentry_component', 'empty_namespace_component', 'cross_page_handoff_component',
                'direct_frontier_component'):
        result[key] = {k: actual[key][k] for k in
            ('status', 'counts', 'exit', 'duration_ns', 'native_operations', 'qualification_credit')}
    result['copy_oracle'] = {k: actual['application_build']['copy_oracle'][k] for k in
        ('status', 'counts', 'body', 'exit', 'duration_ns')}
    result['archive'] = {k: actual['build']['artifacts']['decoder.a'][k] for k in ('bytes', 'sha256')}
    result['closure'] = dict(inputs=len(actual['inputs']), artifacts=len(actual['artifacts']),
        commands=len(actual['commands']), captures=sum(len(c.get('captures', {})) for c in actual['commands']),
        final_error_count=len(actual['final_errors']))
    result.update(receipt=receipt_fact, application=actual['application_build']['artifact'],
        reproduce=['cpuset-alloc', 'run', '--cores', '1', '--', 'python3', '-B',
                   'evaluation/inprocess/direct_frontier_loop.py', '--expect-revision', actual['revision']],
        tool_versions=actual['build']['numeric_versions'], error_type=None,
        command_count=len(actual['commands']), commands_sha256=digest(actual['commands']))
    return result


def direct_prerequisite(path, r, pin, binary, archive):
    """Require the actual three-lane native41 proof on this source/CPU/archive."""
    path = pin(path)
    need(path.parent == ROOT/'evaluation/inprocess/results' and path.suffix == '.json' and
         path.stat().st_size <= 32768, 'bounded canonical public native41 receipt')
    public = decode(path.read_bytes())
    directory = ROOT/'target/evaluation/inprocess'/path.stem
    receipt = pin(directory/'receipt.json')
    need(fact(receipt) == public['receipt'], 'whole actual private native41 receipt')
    actual = decode(receipt.read_bytes())
    need(actual['schema'] == 1 and actual['status'] == 'passed' and
         actual['profile'] == 'persistent-direct-frontier-finite-v1' and
         actual['revision'] == r['revision'] and actual['source'] == r['source'] and
         actual['cpu'] == r['cpu'] and actual['hardware'] == r['hardware'] and actual['bounds'] == BOUNDS and
         actual['source_unchanged'] is True and actual['cleanup_complete'] is True and
         actual['error'] is None and actual['final_errors'] == [] and actual['whole_profile_qualified'] is False and
         actual['required_qualification'] == 'passed original392 and522 cohorts plus this finite41 cohort, exact same source/CPU/archive/hardware',
         'passed native41 on identical clean revision CPU hardware and original bounds; no whole-profile credit')
    for name, value in actual['inputs'].items():
        need(fact(pin(name)) == value, 'whole retained native41 input')
    for name, value in actual['artifacts'].items():
        p = binary(name)
        need(dict(fact(p), mode=p.stat().st_mode & 0o777) == value, 'whole retained native41 artifact and mode')
    for lexical, resolved in actual['aliases'].items():
        need(str(pin(lexical)) == resolved, 'native41 alias still resolves to the same input')
    for name, present in actual['presence'].items():
        need(os.path.lexists(name) == present, 'native41 loader configuration presence')
    for name, value in actual['namespace_aliases'].items():
        need(Path(name).is_symlink() and os.readlink(name) == value, 'native41 sealed namespace alias')
        r['namespace_aliases'][name] = value
    need(actual['build']['status'] == 'passed' and actual['build']['command_completed'] is True and
         fact(binary(actual['build']['artifacts']['decoder.a']['path'])) == fact(archive) ==
         {k: actual['build']['artifacts']['decoder.a'][k] for k in ('bytes', 'sha256')},
         'same actual complete decoder archive in native41 and this fresh build')
    rows = actual['commands']
    need(rows and len({x['name'] for x in rows}) == len(rows), 'all native41 command identities')
    for row in rows:
        need(type(row.get('exit')) is int and row.get('reaped') is True and row.get('timed_out') is False and
             row.get('error') is None and row.get('cleanup_errors') == [] and type(row.get('descriptors')) is list and
             all(d.get('closed') is True for d in row['descriptors']) and row['bounds'] == BOUNDS[row['profile']] and
             (row.get('expected_exit') is None or row['exit'] == row['expected_exit']),
             'every native41 command has its exact original bounds, outcome and complete cleanup')
        for capture in row['captures'].values():
            p = pin(directory/capture['file'])
            need(p.is_relative_to(directory) and fact(p) == {k: capture[k] for k in ('bytes', 'sha256')},
                 'every full native41 capture remains within its retained cohort')
    rows = {x['name']: x for x in rows}
    need([(c['lane'], c['mode'], c['control']) for c in actual['cases']] ==
         [('native', 0, 0), ('maintained', 0, 0), ('differential', 0, 0)], 'all three native41 lanes')
    need(direct.APP_COUNTS == {0: 40} and direct.OWNER_COUNTS == {0: 404} and direct.PAIR_COUNTS == {0: 28} and
         direct.TERMINAL_COUNTS == {(0, 0): 73}, 'exact native41 control populations')
    for case in actual['cases']:
        row = rows[case['label']]; lane = case['lane']
        need(case['status'] == direct.EXPECTED_STATUS[lane, 0] and case['launched'] is True and
             case['expected_exit'] == case['exit'] == row['expected_exit'] == row['exit'] == 0 and
             row['profile'] == 'program' and case['timed_out'] is False and
             case['whole_process_ns'] == row['duration_ns'] and
             case['captures'] == {k: {n: v[n] for n in ('bytes', 'sha256')} for k, v in row['captures'].items()},
             'each successful native41 subject is its actual bounded child')
        if lane == 'native':
            named(case['application_controls'], 40, row['captures']['stdout']['sha256'])
        else:
            for key, count, stream, hash_key in (
                ('owner_reader_controls', 404, 'record', 'original_sha256'),
                ('terminal_controls', 73, 'stderr', 'original_stderr_sha256'),
                ('repeat_tls_controls', 33, 'stderr', 'original_stderr_sha256'),
                ('native_probe_controls', 22, 'stderr', 'original_stderr_sha256'),
                ('subentry_controls', 19, 'stderr', 'original_stderr_sha256'),
                ('effect_controls', 12, 'stderr', 'original_stderr_sha256')):
                named(case[key], count, row['captures'][stream]['sha256'], hash_key=hash_key)
            need(case['pair'] == direct.PAIR_EXPECTED, 'whole exact native41 full-frame pair result')
            controls = case['pair_controls']; refusals = controls['refusals']
            need(type(refusals) is list and len(refusals) == len(set(refusals)) == 28 and
                 all(type(n) is str and n for n in refusals) and controls['native_operations'] == 0,
                 'all separate native41 pair reader controls')
            rb = actual['lanes'][lane]['release_build']
            need(rb['status'] == 'passed' and rb['profile'] == 'persistent-direct-frontier-'+
                 ('differential' if lane == 'differential' else 'capture')+'-v1' and rb['capture'] is True and
                 rb['archive'] == fact(archive) and rb['active_domain']['differential'] == (lane == 'differential') and
                 all(rb['active_domain'][k] is True and rb['persistent_binding'][k] is True for k in
                     ('unregistered', 'subentry', 'cross_pair', 'direct_frontier', 'native_probe', 'parse_memo')) and
                 rb['capture_extents']['wire'] == 4549248 and rb['capture_extents']['schema_version'] == 10 and
                 rb['capture_extents']['record_limit'] == rb['capture_extents']['stream_strictly_below'] == 4 << 20 and
                 128 < row['captures']['record']['bytes'] < 4 << 20,
                 'both real native41 builds and complete strict-cap owner transcripts')
    states = actual['component_oracles']
    need([s['name'] for s in states] == list(component.COMPONENT_ORDER) and
         all(s['status'] == 'passed' and s['summaries'] == [component.COMPONENT_SUMMARIES[s['name']]]
             and s['launched'] is True and s['exit'] == 0 for s in states) and
         states[0]['decoder_archive_used'] is False and states[1]['archive'] == fact(archive),
         'actual source-only authority and same-archive dispatch components')
    def component_output(name, expected):
        row = rows[name]
        need(row['profile'] == 'finite' and row['exit'] == row['expected_exit'] == 0 and
             (directory/row['captures']['stdout']['file']).read_bytes() == expected and
             (directory/row['captures']['stderr']['file']).read_bytes() == b'',
             'whole original actual finite component output: '+name)
    for state in states:
        component_output('component-'+state['name']+'-run', component.COMPONENT_STDOUT[state['name']])
    expected_components = {
        'subentry_component': dict(lookup=112, selection=33, entry=47, lifetime=19, history=25),
        'empty_namespace_component': dict(images=74, pairs=4, parser=18, callers=10),
        'cross_page_handoff_component': dict(eligibility=64, refusals=71, close=34, fresh=29, consume=18, total=216),
        'native_probe_component': component.PROBE_COUNTS, 'maps_parse_component': component.MAPS_PARSE_COUNTS}
    for key, expected in expected_components.items():
        need(actual[key]['status'] == 'passed' and actual[key]['counts'] == expected and actual[key]['exit'] == 0,
             'every exact mandatory native41 component: '+key)
    need(actual['subentry_component']['expected_stdout'] ==
         'subentry-authority lookup=112 selection=33 entry=47 lifetime=19 history=25 synthetic_observations=1 native_credit=0\n'
         'registered-address cases=6 controls=118 synthetic_observations=1 native_credit=0\n',
         'all236 plus118 original subentry controls')
    component_output('subentry-authority-run', actual['subentry_component']['expected_stdout'].encode())
    component_output('empty-namespace-run',
        b'empty-namespace images=74 pairs=4 parser=18 callers=10 synthetic_initialization=1 native_credit=0\n')
    component_output('cross-page-handoff-run',
        b'cross_page_handoff eligibility=64 refusals=71 close=34 fresh=29 consume=18 supplied_observations=1 native_credit=0\n')
    component_output('native-probe-run', component.PROBE_STDOUT)
    component_output('maps-parse-memo-run', component.MAPS_PARSE_STDOUT)
    component_output('app-copy-run', component.COPY_STDOUT)
    model = actual['direct_frontier_component']; observed = model['counts']
    model_stdout = (directory/rows['direct-frontier-run']['captures']['stdout']['file']).read_bytes()
    model_raw = decode(model_stdout)
    expected = dict(version=1, descriptors=66, models=21442, proofs=38, selectors=6272, budgets=4,
                    refusals=492, handoffs=192, emitted_execution=0, owner_credit=0)
    need(model['status'] == 'passed' and model['exit'] == 0 and model['archive'] == fact(archive) and
         model['bounds'] == BOUNDS['finite'] and model['native_operations'] == 0 and model['qualification_credit'] is False and
         set(observed) == set(expected) | {'typed_recoveries', 'steps'} and
         all(type(observed[k]) is int and observed[k] == v for k, v in expected.items()) and
         type(observed['typed_recoveries']) is int and 0 < observed['typed_recoveries'] < 1 << 64 and
         type(observed['steps']) is int and observed['models'] < observed['steps'] < 1 << 64 and
         digest(model_raw) == digest(observed) and
         model_stdout == (json.dumps(model_raw, separators=(',', ':'), allow_nan=False)+'\n').encode() and
         (directory/rows['direct-frontier-run']['captures']['stderr']['file']).read_bytes() == b'',
         'whole actual direct model populations and typed recoveries')
    codec = actual['capture_codec_component']; seed = actual['seed_prerequisite']
    need(codec['status'] == 'passed' and codec['exit'] == codec['reader_exit'] == 0 and codec['counts'] ==
         dict(scope='capture_codec_only', roundtrips=40, strict_cap_cases=2, argument_refusals=12, write_cases=8,
              cross_language_vectors=1, vector_stream_bytes=794, native_qualification=False) and codec['reader_counts'] ==
         dict(scope='capture_codec_reader_only', roundtrips=40, transport_refusals=824, truncations=794,
              semantic_reachability=2, cross_language_vectors=1, native_qualification=False) and
         seed['status'] == 'passed' and seed['launched'] is True and seed['exit'] == seed['expected_exit'] == 0 and
         seed['bounds'] == BOUNDS['seed'] and actual['application_build']['copy_oracle']['status'] == 'passed' and
         actual['application_build']['copy_oracle']['counts'] == component.COPY_COUNTS,
         'unchanged complete transport, seed and native helper gates')
    seed_row = rows['seed-prerequisite']
    need(seed_row['profile'] == 'seed' and seed['pid'] == seed_row['pid'] and
         seed['whole_process_ns'] == seed_row['duration_ns'] and seed['timed_out'] is False and
         seed['captures'] == {k: {n: v[n] for n in ('bytes', 'sha256')} for k, v in seed_row['captures'].items()} and
         (directory/seed_row['captures']['stderr']['file']).read_bytes() == b'',
         'seed state is the actual complete child and full retained observations')
    codec_stdout = dict(scope='capture_codec_only', roundtrips=40, strict_cap_cases=2, argument_refusals=12,
        write_cases=8, cross_language_vectors=1, vector_stream_bytes=794, native_qualification=False)
    component_output('capture-codec-run', (json.dumps(codec_stdout, separators=(',', ':'))+'\n').encode())
    component_output('capture-codec-reader', (json.dumps(codec['reader_counts'], sort_keys=True)+'\n').encode())
    need(public == direct_public(actual, fact(receipt)) and pin(path.with_suffix('.csv')).read_bytes() == command_csv(actual),
         'whole native41 public JSON and CSV projections')
    return dict(file=str(path.relative_to(ROOT)), **fact(path), receipt=fact(receipt), archive=fact(archive),
        status='passed', profile=actual['profile'], commands=len(rows), commands_sha256=digest(actual['commands']),
        controls=dict(app=40, owner=404, pair=28, terminal=73, tls=33, probe=22, subentry=19, effects=12),
        whole_profile_qualified=False)


def final_prefix(row, private, binary):
    observed = row['counter_observation']; counter = row['counter_input']
    need(row['reaped'] is True and observed['usable'] is True, 'actual authoritative post-reap counter prefix')
    path = binary(private/row['captures']['counters']['file'])
    need(fact(path) == observed['raw'], 'whole retained final counter bytes')
    initial = (counter_process.MAGIC, 2, 752, 4096, counter['nonce'], counter['parent'], counter['device'], counter['inode'])
    exact = counter_process.final_counter_prefix(path.read_bytes(), initial, row['pid'], observed['final_seals'])
    need(all(observed[k] == v for k, v in exact.items()), 'unchanged parser rejoins every actual retained cell')
    return dict(exact, miss_reasons=dict(zip(MISS_NAMES, exact['misses'], strict=True)))


def cohort(builder, products, private, pin, binary, aliases, run, r):
    states = {}
    for kind, program, args, expected_stdout in PROGRAMS:
        original = pin(program); directory = private/(kind+'-build'); directory.mkdir()
        (directory/'external-inputs').mkdir()
        holder = r['program_builds'][kind] = {}
        def lane_run(name, argv, profile='metadata', expected=0, env=None, record=False):
            return run(kind+'-'+name, argv, profile=profile, expected=expected, env=env, record=record)
        bridge = build_bridge(builder, products, directory, pin, binary, aliases, lane_run, holder, original,
                              capture=False, retained_counters=True, differential=False)
        rb = holder['release_build']
        need(rb['status'] == 'passed' and rb['profile'] == 'persistent-direct-frontier-counters-v1' and
             rb['capture'] is False and rb['counters'] is True and rb['retained_counters'] is True and
             rb['archive'] == fact(products['archive']) and rb['counter_schema'] ==
             dict(version=2, bytes=752, page=4096, initial_seals=6, final_seals=23) and
             rb['active_domain']['slots'] == rb['active_domain']['source_pairs_max'] == 2 and
             rb['active_domain']['differential'] is False and rb['dispatch']['shared_boundaries'] == 8 and
             rb['direct_frontier'] == dict(version=1, policy_version=5, conditions=16, shared_boundaries=8,
                typed_external_arms=True, unknown_target='original branch-before full drain') and
             rb['persistent_binding']['mode'] == 'counters' and
             all(rb['active_domain'][k] is True and rb['persistent_binding'][k] is True for k in
                 ('unregistered', 'subentry', 'cross_pair', 'direct_frontier', 'native_probe', 'parse_memo')),
             'exact per-original direct counter profile, full build gates and unchanged ABI2')
        state = prepare_workload(kind, original, args, bridge, builder, directory, pin, binary, lane_run, r, namespace)
        holder.update(original=fact(original), bridge=fact(bridge), carrier=fact(state['carrier']))
        states[kind] = state
    imported_sources(pin)
    need([(c['program'], c['lane']) for c in r['cases']] == list(ORDER), 'one fixed four-subject schedule')
    references = {}
    for case in r['cases']:
        kind, lane = case['program'], case['lane']; state = states[kind]
        expected_stdout = next(x[3] for x in PROGRAMS if x[0] == kind)
        ns = private/(case['label']+'-namespace')
        argv = state['argv'] if lane == 'native' else [builder.tools['python'], '-B', state['carrier_tool'],
            'exec-loader', '--counter-fd', '{counter_fd}', '--counter-nonce', '{counter_nonce}',
            '--library-root', '/usr/lib64', '--namespace', ns, state['carrier'], state['original'], '--', *state['argv']]
        case['status'] = 'failed'; row = None
        try:
            try:
                row, stdout, stderr = run(case['label'], argv, profile='program', expected=None,
                                         env=PROGRAM_ENV, counter=lane == 'counted', subject=True)
            finally:
                if r['commands'] and r['commands'][-1]['name'] == case['label']:
                    row = r['commands'][-1]
                    case.update(exit=row.get('exit'), process_ns=row.get('process_ns'),
                        wrapper_interval_ns=row.get('duration_ns'), timed_out=row.get('timed_out'),
                        launched=type(row.get('pid')) is int,
                        captures={k: {n: v[n] for n in ('bytes', 'sha256')} for k, v in row.get('captures', {}).items()})
                    if lane == 'counted' and row.get('reaped'):
                        # Prefix validation has no completed-transaction arithmetic.
                        case['counts'] = final_prefix(row, private, binary)
                        case['counter_collection'] = 'closed_usable_prefix'
                        counter_process.namespace_join(state, ns, binary, r, namespace, row['counter_input'])
                        case['namespace_complete'] = True
            need(row['exit'] == 0 and row['reaped'] is True and row['timed_out'] is False and
                 row['error'] is None and row['cleanup_errors'] == [], 'actual completed program before acceptance')
            need(type(row['process_ns']) is int and 0 < row['process_ns'] <= row['duration_ns'],
                 'actual Popen-to-reap interval within the complete wrapper interval')
            if lane == 'native':
                need(stdout == expected_stdout and stderr == b'', 'exact real native program output and empty stderr')
                references[kind] = (row['exit'], stdout)
                case.update(status='completed_native_reference', stdout_equal=True)
            else:
                need(kind in references and (row['exit'], stdout) == references[kind] and stdout == expected_stdout,
                     'complete counted stdout and exit equal the exact successful native reference')
                terminal = completed_terminal(stderr, case['counts'])
                actual = counters(stderr)
                case.update(status='completed_unqualified', stdout_equal=True, terminal=terminal,
                    terminal_counters={k: actual[k] for k in ('LI2_CHAIN', 'LI2_LINKED_NATIVE_PROBE', 'LI2_NATIVE_PAIR')})
        except Exception as exc:
            case['error'] = type(exc).__name__+': '+str(exc)
            # An unsuccessful subject never acquires a completed-terminal label.
            case['terminal'] = case['terminal_counters'] = None
        need(row is not None and row.get('reaped') is True and row.get('cleanup_errors') == [] and
             all(d['closed'] for d in row.get('descriptors', [])) and not r['final_errors'],
             'finish each child and every descriptor before the next fixed subject')
    need(all(c['status'] == ('completed_native_reference' if c['lane'] == 'native' else 'completed_unqualified')
             for c in r['cases']), 'all four original bounded subjects must complete; prefixes remain failures')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--direct-receipt', type=Path, required=True)
    args = ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0)) == 1, 'assertions and one reserved CPU')
    need(re.fullmatch('[0-9a-f]{40}', args.expect_revision), 'exact committed revision')
    os.chdir(ROOT); cpu = next(iter(os.sched_getaffinity(0)))
    args.direct_receipt = args.direct_receipt.resolve(strict=True)
    need(args.direct_receipt.parent == ROOT/'evaluation/inprocess/results' and args.direct_receipt.suffix == '.json',
         'portable canonical public native41 prerequisite')
    name = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')+'-direct-frontier-program-'+args.expect_revision[:12]
    private = ROOT/'target/evaluation/inprocess'/name; private.mkdir(parents=True, exist_ok=False)
    public = ROOT/'evaluation/inprocess/results'/(name+'.json'); public.parent.mkdir(parents=True, exist_ok=True)
    need(not public.exists() and not public.with_suffix('.csv').exists(), 'fresh public result identity')
    receipt = private/'receipt.json'
    r = dict(schema=1, profile='direct-frontier-program-probe-v1', status='failed', revision=args.expect_revision,
        source=None, source_unchanged=False, cleanup_complete=False, commands=[], cases=[], error=None, final_errors=[],
        cpu=cpu, hardware=hardware(cpu), bounds=PROFILES, namespace_aliases={}, program_builds={},
        qualification_credit=False, whole_profile_qualified=False, performance_credit=False,
        required_unmet=list(REQUIRED), scope='One fixed real LS/true native and counted schedule; no throughput or whole-profile claim.',
        counter_scope='Post-reap per-cell prefix. Events/signals count linked ingress, not all kernel traps; direct hits and stage timings unavailable.')
    for kind, lane in ORDER:
        r['cases'].append(dict(label='subject-'+kind+'-'+lane, program=kind, lane=lane, expected_exit=0,
            status='unexecuted', launched=False, stdout_equal=False, counts=None, terminal=None, terminal_counters=None,
            namespace_complete=None if lane == 'native' else False, counter_collection='not_applicable' if lane == 'native' else 'unavailable'))
    pins, artifacts, aliases, presence = {}, {}, {}, {}

    def pin(path):
        alias=Path(os.path.abspath(path));p=alias.resolve(strict=True);value=fact(p)
        need(str(alias) not in aliases or aliases[str(alias)]==str(p),'stable input alias')
        need(str(p) not in pins or pins[str(p)]==value,'stable input bytes')
        pins[str(p)]=value;aliases[str(alias)]=str(p)
        return p

    def binary(path):
        p = Path(path).resolve(strict=True)
        value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'stable artifact')
        artifacts[str(p)] = value
        return p

    def closure():
        need(all(fact(p) == v for p, v in pins.items()), 'input bytes unchanged')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == v
                 for p, v in artifacts.items()), 'artifact bytes and modes unchanged')
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in aliases.items()), 'input aliases unchanged')
        need(all(os.path.lexists(p)==v for p,v in presence.items()),'loader configuration presence')
        need(all(Path(p).is_symlink() and os.readlink(p)==v for p,v in r['namespace_aliases'].items()),'sealed namespace aliases unchanged')

    def run(name, argv, profile='metadata', expected=0, env=None, record=False, counter=False, subject=False):
        closure()
        need(not r['final_errors'] and not any(c['name'] == name for c in r['commands']), 'clean unique command/capture name')
        need(record is False and (not counter or subject) and
             (not subject or profile == 'program' and PROFILES[profile] == TARGET and env == PROGRAM_ENV),
             'only original whole-program bounds/environment and separate counter owner')
        row = dict(name=name, argv=list(map(str, argv)), environment=dict(ENV if env is None else env),
                   profile=profile, bounds=PROFILES[profile], capture_limit=16 << 20, expected_exit=expected)
        r['commands'].append(row)
        try:
            function = counter_process.program_invoke if counter else program_invoke if subject else invoke
            out, err = function(row, private, cpu, record=record)
            need(expected is None or row['exit'] == expected, 'actual command exit: ' + name)
            return row, out, err
        finally:
            for item in row.get('captures', {}).values():
                try:
                    p = private / item['file']
                    need(fact(binary(p)) == {k: item[k] for k in ('bytes', 'sha256')}, 'actual capture bytes')
                except BaseException as error:
                    r['final_errors'].append('capture ' + name + ': ' + repr(error))
            try:
                p = private / (name + '.json')
                if p.exists():
                    need(json.loads(binary(p).read_bytes()) == row, 'retained actual command row')
            except BaseException as error:
                r['final_errors'].append('command record ' + name + ': ' + repr(error))

    def build_run(name, argv, profile='metadata', env=None, expected=0):
        before_default(name, argv, builder, pin, aliases, run, r)
        return run(name, argv, profile=profile, expected=expected, env=env)

    builder = Build(r, private, pin, binary, build_run, ('region.rs',),
                    scalar_span=True, linked_epoch=True, mov_guard=True)
    try:
        r['source'] = source()
        need(r['source']['revision'] == args.expect_revision and PROFILES['program'] == TARGET, 'exact clean source and original target bounds')
        _, names, err = run('tracked-input-list', ['git', 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'])
        need(not err, 'complete tracked input list')
        for raw in names.split(b'\0'):
            if raw:
                path = os.fsdecode(raw)
                if not path.startswith('evaluation/inprocess/results/'): pin(ROOT/path)
        for path in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            presence[path] = os.path.lexists(path)
            if presence[path]: pin(path)
        need(not presence['/etc/ld.so.preload'], 'no global preload')
        imported_sources(pin)
        products = builder.prepare()
        need(builder.decoder_features == FEATURES and builder.extra_decoder_sources == ('region.rs', 'mov_guard.rs') and
             builder.record['decoder_features'] == list(FEATURES) and builder.record['status'] == 'passed' and
             builder.record['command_completed'] is True, 'fresh actual current region/span/linked/MOV decoder')
        r['archive'] = fact(products['archive'])
        r['direct_prerequisite'] = direct_prerequisite(args.direct_receipt, r, pin, binary, products['archive'])
        protocol(builder, run, r)
        cohort(builder, products, private, pin, binary, aliases, run, r)
        r['status'] = 'completed_unqualified'
    except BaseException as exc:
        r['error'] = type(exc).__name__+': '+str(exc)
    finally:
        r['final_errors'].extend(builder.finish())
        try:
            imported_sources(pin); closure()
            need(source() == r['source'], 'exact source unchanged')
            r['source_unchanged'] = True
        except BaseException as exc:
            r['final_errors'].append(type(exc).__name__+': '+str(exc))
        r['cleanup_complete'] = bool(r['commands']) and all(c.get('reaped') is True and c.get('cleanup_errors') == [] and
            all(d['closed'] for d in c.get('descriptors', [])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or not r['cleanup_complete']:
            r['status'] = 'failed'
        r.update(inputs=pins, artifacts=artifacts, aliases=aliases, presence=presence)
        save(receipt, r)
        hw = dict(r['hardware']); flags = hw.pop('isa_flags')
        hw.update(isa_flags_count=len(flags), isa_flags_sha256=digest(flags))
        summary = {k: r[k] for k in ('schema', 'profile', 'status', 'revision', 'source', 'source_unchanged',
            'cleanup_complete', 'cpu', 'bounds', 'scope', 'counter_scope', 'qualification_credit',
            'whole_profile_qualified', 'performance_credit', 'required_unmet')}
        summary.update(hardware=hw, receipt=fact(receipt), direct_prerequisite=r.get('direct_prerequisite'),
            archive=r.get('archive'), command_count=len(r['commands']), commands_sha256=digest(r['commands']),
            program_environment=PROGRAM_ENV,
            error_type=r['error'].split(':', 1)[0] if r['error'] else None, final_error_count=len(r['final_errors']),
            tool_versions=builder.record.get('numeric_versions'),
            reproduce=['cpuset-alloc', 'run', '--cores', '1', '--', 'python3', '-B',
                'evaluation/inprocess/direct_frontier_program.py', '--expect-revision', args.expect_revision,
                '--direct-receipt', str(args.direct_receipt.relative_to(ROOT))],
            counter_protocol={k: r.get('counter_protocol', {}).get(k) for k in ('scope', 'guest_executions', 'refusal_count')},
            closure=dict(inputs=len(pins), artifacts=len(artifacts), commands=len(r['commands']),
                         captures=sum(len(c.get('captures', {})) for c in r['commands'])))
        summary['programs'] = {}
        for kind, program, args_, _ in PROGRAMS:
            build = r['program_builds'].get(kind, {}); binding = build.get('release_build', {}).get('persistent_binding')
            summary['programs'][kind] = dict(argv=[program, *args_], external=r.get('system_inputs', {}).get(kind),
                bridge=build.get('bridge'), carrier=build.get('carrier'),
                binding_sha256=digest(binding) if binding else None,
                policy_sha256=binding.get('policy_sha256') if binding else None)
        summary['cases'] = [{k: c[k] for k in ('program', 'lane', 'status', 'expected_exit', 'exit', 'process_ns',
            'wrapper_interval_ns', 'timed_out', 'launched', 'captures', 'stdout_equal', 'namespace_complete',
            'counter_collection', 'counts', 'terminal', 'terminal_counters') if k in c} |
            dict(error_type=c['error'].split(':', 1)[0] if c.get('error') else None) for c in r['cases']]
        payload = (json.dumps(summary, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()
        table = io.StringIO(); writer = csv.writer(table, lineterminator='\n')
        writer.writerow(('revision', 'program', 'lane', 'status', 'exit', 'process_ns', 'wrapper_interval_ns',
                         'counter_scope', 'counter', 'value'))
        for case in summary['cases']:
            stem = (r['revision'], case['program'], case['lane'], case['status'], case.get('exit'),
                    case.get('process_ns'), case.get('wrapper_interval_ns'))
            writer.writerow((*stem, '', '', ''))
            if case['counts'] is not None:
                for name in ('events', 'signals', 'group', 'misses', 'maps', 'view', 'native'):
                    value = case['counts'][name]
                    cells = value.items() if type(value) is dict else enumerate(value) if type(value) is list else [('', value)]
                    for key, number in cells:
                        label = ('linked_events' if name == 'events' else 'linked_signals' if name == 'signals' else name)
                        writer.writerow((*stem, 'post_reap_per_cell_prefix', label+('.'+str(key) if key != '' else ''), number))
        csv_bytes = table.getvalue().encode()
        need(len(payload) <= 32 << 10 and len(csv_bytes) <= 32 << 10 and
             all(x.encode() not in payload+csv_bytes for x in (str(ROOT), str(Path.home()), '/home/', platform.node()) if len(x) > 1),
             'compact public JSON/CSV without host paths or raw logs')
        with public.open('xb') as f: f.write(payload)
        with public.with_suffix('.csv').open('xb') as f: f.write(csv_bytes)
    print(json.dumps(dict(status=r['status'], receipt=str(public.relative_to(ROOT)))))
    return int(r['status'] != 'completed_unqualified')


if __name__ == '__main__':
    raise SystemExit(main())
