"""Authenticate the whole finite bounded-fused run before any real-program probe."""
import os
from pathlib import Path
import re
from page_selected import fact, need
from persistent_dynamic import BOUNDS, digest, named
from direct_frontier_program import decode
import bounded_fused_owner_helpers as fused
import bounded_fused_fault as fault
from bounded_fused_component_prerequisite import fused_component_prerequisite
from persistent_active_domain import COPY_COUNTS, COPY_STDOUT

ROOT = Path(__file__).resolve().parents[2]


def fused_prerequisite(path, expected_sha256, r, pin, binary, archive):
    """Require current-source native2838 and both protected lanes, with native41 and PF intact."""
    path = pin(path)
    need(path.name == 'receipt.json' and path.parent.parent == ROOT/'target/evaluation/inprocess' and
         re.fullmatch('[0-9a-f]{64}', expected_sha256) is not None and
         fact(path)['sha256'] == expected_sha256, 'explicit whole private PF receipt identity')
    actual = decode(path.read_bytes()); directory = path.parent
    need(actual['schema'] == 1 and actual['profile'] == 'bounded-fused-owner-v1' and
         actual['status'] == 'observed_unqualified' and actual['revision'] == r['revision'] and
         actual['source'] == r['source'] and actual['cpu'] == r['cpu'] and
         actual['hardware'] == r['hardware'] and actual['bounds'] == BOUNDS and
         actual['source_unchanged'] is True and actual['inputs_unchanged'] is True and
         actual['cleanup_complete'] is True and actual['error'] is None and actual['final_errors'] == [] and
         actual['whole_profile_qualified'] is False and
         actual['direct_prerequisite'] == r['direct_prerequisite'] and
         actual['block_prerequisite'] == r['block_prerequisite'],
         'complete finite PF run on identical clean source, CPU, hardware, bounds and native41 prerequisite')
    for name, value in actual['inputs'].items():
        need(fact(pin(name)) == value, 'whole retained PF input')
    for name, value in actual['artifacts'].items():
        p = binary(name)
        need(dict(fact(p), mode=p.stat().st_mode & 0o777) == value, 'whole retained PF artifact and mode')
    for lexical, resolved in actual['aliases'].items():
        need(str(pin(lexical)) == resolved, 'PB literal alias still resolves to the same input')
    for name, present in actual['presence'].items():
        need(os.path.lexists(name) == present, 'PB loader configuration presence')
    for name, value in actual['namespace_aliases'].items():
        need(Path(name).is_symlink() and os.readlink(name) == value, 'PB sealed namespace alias')
        need(name not in r['namespace_aliases'] or r['namespace_aliases'][name] == value,
             'same namespace alias across prerequisite cohorts')
        r['namespace_aliases'][name] = value
    build = actual['build']; built = build['artifacts']['decoder.a']
    need(build['status'] == 'passed' and build['command_completed'] is True and
         fact(binary(built['path'])) == fact(archive) == {k: built[k] for k in ('bytes', 'sha256')},
         'same whole actual PF, native41 and fresh probe decoder archive')
    component = actual['fused_component_prerequisite']
    need(fused_component_prerequisite(ROOT/component['file'], component['sha256'],
         r, pin, binary, archive) == component,
         'whole same-source PF component prerequisite re-authenticated without a new child')
    commands = actual['commands']
    # The source-owned complete schedule is supplied by the finite owner, never by a receipt.
    need([(row['name'], row['profile']) for row in commands] == list(fused.COMMAND_SCHEDULE) and
         len({row['name'] for row in commands}) == len(commands), 'entire fixed PF command schedule')
    negative_labels = {'subject-maintained-1-0', 'subject-maintained-2-0'}
    need(len(commands) == 105, 'all original101 plus four actual PF fault/reject children')
    for row in commands:
        expected_exit = 125 if row['name'] in negative_labels else 0
        need(type(row.get('exit')) is int and row['exit'] == row['expected_exit'] == expected_exit and
             row.get('reaped') is True and row.get('timed_out') is False and row.get('error') is None and
             row.get('cleanup_errors') == [] and type(row.get('descriptors')) is list and
             all(d.get('closed') is True for d in row['descriptors']) and
             row['bounds'] == BOUNDS[row['profile']], 'every actual PF child and original bound')
        expected_streams = {'stdout', 'stderr', 'record'} if row['name'] in (
            'subject-maintained-0-0', 'subject-differential-0-0',
            'subject-maintained-1-0', 'subject-maintained-2-0') else {'stdout', 'stderr'}
        need(set(row['captures']) == expected_streams, 'entire actual PF capture population')
        for capture in row['captures'].values():
            q = pin(directory/capture['file'])
            need(q.is_relative_to(directory) and fact(q) == {k: capture[k] for k in ('bytes', 'sha256')},
                 'every retained whole PF capture belongs to this cohort')
    rows = {row['name']: row for row in commands}
    need([(c['lane'], c['mode'], c['control']) for c in actual['cases']] ==
         [('native', 0, 0), ('maintained', 0, 0), ('differential', 0, 0)], 'three complete fixed PF lanes')
    need(fused.APP_COUNTS == {0: 40} and fused.OWNER_COUNTS == {0: 204} and
         fused.PAIR_COUNTS == {0: 36} and fused.TERMINAL_COUNTS == {(0, 0): 73},
         'literal full PF control populations')
    for case in actual['cases']:
        row = rows[case['label']]; lane = case['lane']
        need(case['status'] == fused.EXPECTED_STATUS[lane, 0] and case['launched'] is True and
             case['expected_exit'] == case['exit'] == row['expected_exit'] == row['exit'] == 0 and
             row['profile'] == 'program' and case['timed_out'] is False and
             case['whole_process_ns'] == row['duration_ns'] and
             case['captures'] == {k: {n: v[n] for n in ('bytes', 'sha256')} for k, v in row['captures'].items()},
             'each complete PF subject is its actual bounded child')
        if lane == 'native':
            named(case['application_controls'], 40, row['captures']['stdout']['sha256'])
            need((directory/row['captures']['stderr']['file']).read_bytes() == b'', 'native PF stderr is empty')
            continue
        for key, count, stream, hash_key in (
            ('owner_reader_controls', 204, 'record', 'original_sha256'),
            ('terminal_controls', 73, 'stderr', 'original_stderr_sha256'),
            ('repeat_tls_controls', 33, 'stderr', 'original_stderr_sha256'),
            ('native_probe_controls', 22, 'stderr', 'original_stderr_sha256'),
            ('subentry_controls', 19, 'stderr', 'original_stderr_sha256'),
            ('effect_controls', 12, 'stderr', 'original_stderr_sha256')):
            named(case[key], count, row['captures'][stream]['sha256'], hash_key=hash_key)
        need(case['pair'] == fused.PAIR_EXPECTED, 'whole PF native2838 and generated full-frame result')
        controls = case['pair_controls']; refusals = controls['refusals']
        need(type(refusals) is list and len(refusals) == len(set(refusals)) == 36 and
             all(type(n) is str and n for n in refusals) and controls['native_operations'] == 0,
             'every full-state PF pair refusal control')
        rb = actual['lanes'][lane]['release_build']; mode = 'differential' if lane == 'differential' else 'capture'
        binding = rb['persistent_binding']
        need(rb['status'] == 'passed' and rb['profile'] == 'persistent-fused-'+mode+'-v1' and
             rb['capture'] is True and rb['archive'] == fact(archive) and
             rb['active_domain']['differential'] == (lane == 'differential') and
             all(rb['active_domain'][k] is True and binding[k] is True for k in
                 ('unregistered', 'subentry', 'cross_pair', 'direct_frontier', 'native_probe', 'parse_memo')) and
             binding['bounded_fused'] is True and binding['policy_version'] == 11 and
             rb['bounded_fused'] == dict(version=1, policy_version=11, heads_max=128, shared_boundaries=8,
                                         active_members_max=2, call_ret=False) and
             rb['direct_frontier'] == dict(version=1, policy_version=11, partition='direction-fused',
                 all_arms_directory=False, conditions=16, shared_boundaries=8, typed_external_arms=True,
                 unknown_target='original branch-before full drain') and
             rb['capture_extents']['wire'] == 5421376 and rb['capture_extents']['schema_version'] == 12 and
             rb['capture_extents']['record_limit'] == rb['capture_extents']['stream_strictly_below'] == 4 << 20 and
             128 < row['captures']['record']['bytes'] < 4 << 20,
             'both actual finite PF builds, full protected transcripts and unchanged strict encoded cap')
    negative = fault_cases(actual, rows, directory)
    copy = actual['application_build']['copy_oracle']; copy_row = rows['app-copy-run']
    need(copy['status'] == 'passed' and copy['counts'] == COPY_COUNTS and copy['exit'] == 0 and
         (directory/copy_row['captures']['stdout']['file']).read_bytes() == COPY_STDOUT and
         (directory/copy_row['captures']['stderr']['file']).read_bytes() == b'',
         'complete actual native helper copy oracle remains mandatory')
    seed = actual['seed_prerequisite']; row = rows['seed-prerequisite']
    need(seed['status'] == 'passed' and seed['planned'] == 1 and seed['launched'] is True and
         seed['exit'] == seed['expected_exit'] == row['exit'] == 0 and seed['bounds'] == BOUNDS['seed'] and
         seed['pid'] == row['pid'] and seed['whole_process_ns'] == row['duration_ns'] and
         seed['timed_out'] is False and seed['completed_applications'] == seed['owner_subjects'] == 0 and
         seed['performance_credit'] is False and
         seed['captures'] == {k: {n: v[n] for n in ('bytes', 'sha256')} for k, v in row['captures'].items()} and
         (directory/row['captures']['stderr']['file']).read_bytes() == b'',
         'separate complete independent native PF seed')
    return dict(file=str(path.relative_to(ROOT)), **fact(path), status=actual['status'],
        profile=actual['profile'], archive=fact(archive), commands=len(commands), commands_sha256=digest(commands),
        controls=dict(app=40, owner=204, pair=36, terminal=73, tls=33, probe=22, subentry=19, effects=12),
        fault_controls=negative, fused_component_prerequisite=component,
        whole_profile_qualified=False)


def fault_cases(actual, rows, directory):
    """Keep real write-fault and guard-rejection prefixes separate from mode0."""
    need(fault.ORDER == (('native', 1), ('maintained', 1), ('native', 2), ('maintained', 2)) and
         fault.APP_CONTROL_COUNT == 16 and fault.OWNER_CONTROL_COUNT == 28 and
         fault.PAIR_CONTROL_COUNT == 12 and fault.TERMINAL_CONTROL_COUNT == 92,
         'literal independent four-child PF recovery scope and all additive controls')
    need([(c['lane'], c['mode'], c['control']) for c in actual['fault_cases']] ==
         [(lane, mode, 0) for lane, mode in fault.ORDER],
         'four complete PF native-fault/store-fault/guard-rejection observations')
    native_modes = set()
    for case in actual['fault_cases']:
        lane, mode = case['lane'], case['mode']
        label = 'subject-'+lane+'-'+str(mode)+'-0'; row = rows[label]
        expected_exit = 0 if lane == 'native' else 125
        need(case['label'] == label and case['status'] == fault.EXPECTED_STATUS[lane, mode] and
             case['launched'] is True and case['timed_out'] is False and
             case['expected_exit'] == case['exit'] == row['expected_exit'] == row['exit'] == expected_exit and
             row['profile'] == 'program' and case['whole_process_ns'] == row['duration_ns'] and
             case['captures'] == {k: {n: v[n] for n in ('bytes', 'sha256')} for k, v in row['captures'].items()},
             'every mandatory PF negative is its actual original bounded child')
        if lane == 'native':
            named(case['application_controls'], 16, row['captures']['stdout']['sha256'])
            need((directory/row['captures']['stderr']['file']).read_bytes() == b'',
                 'native original MOV-fault observer has no diagnostic stderr')
            observed = case['native_summary']
            need(set(observed) == {'mode', 'steps', 'full_frames', 'signal', 'fault_pc', 'fault_address',
                 'guest_effects', 'completed_application', 'observer_exit'} and
                 observed['mode'] == mode and observed['steps'] == 6 and observed['full_frames'] == 3 and
                 observed['signal'] == 11 and observed['guest_effects'] == 0 and
                 observed['completed_application'] is False and observed['observer_exit'] == 0 and
                 all(type(observed[k]) is int and 0 < observed[k] < 1 << 47
                     for k in ('fault_pc', 'fault_address')),
                 'original native write-fault reference is a stopped-before-store observation')
            native_modes.add(mode)
            continue
        need(mode in native_modes and 128 < row['captures']['record']['bytes'] < 4 << 20,
             'complete original native reference precedes the strict-cap failed-owner record')
        for key, count, stream, hash_key in (
            ('owner_reader_controls', 28, 'record', 'original_sha256'),
            ('terminal_controls', 92, 'stderr', 'original_stderr_sha256')):
            named(case[key], count, row['captures'][stream]['sha256'], hash_key=hash_key)
        signal, phase = (11, 1) if mode == 1 else (4, 3)
        owner = case['owner_summary']; closed = owner['cleanup_closed_pages']
        need(type(closed) is int and closed in (17, 34) and owner == dict(mode=mode, status=125,
             code=3304, detail=signal, cold_publications=1, generated_entries=1, generated_completed=0,
             completion_permits=0, anchor_released=0, cleanup_closed_pages=closed, interior_signals=0,
             native_fault_signal=11, actual_signal=signal, recovery_phase=phase),
             'exact actual terminal fault/rejection and every installed bank queried NX')
        need(case['pair'] == fault.pair_expected(mode, closed),
             'whole original/generated PF fault pair including all frames and no successful completion')
        controls = case['pair_controls']; names = controls['refusals']
        need(type(names) is list and len(names) == len(set(names)) == 12 and
             all(type(n) is str and n for n in names) and controls['native_operations'] == 0,
             'every independent negative full-state PF pair refusal')
        terminal = case['terminal']
        need(all(terminal[k] == v for k, v in dict(required_terminal_negative=1,
             application_completed=0, generated_completed=0, mode=mode, status=125,
             code=3304, signal=signal).items()) and terminal['whole_profile_qualified'] is False,
             'typed failed terminal prefix remains a failed subject with no completion credit')
    for key, total in (('application_controls', 32), ('owner_reader_controls', 56),
                       ('pair_controls', 24), ('terminal_controls', 184)):
        need(sum(len(c.get(key, {}).get('refusals', [])) for c in actual['fault_cases']) == total,
             'all additive negative controls are retained: '+key)
    return dict(cases=4, native_references=2, expected_failed_subjects=2,
        app=32, owner=56, pair=24, terminal=184,
        qualification_credit=False, performance_credit=False)
