"""Authenticate the whole finite bounded-block run before any real-program probe."""
import os
from pathlib import Path
import re
from page_selected import fact, need
from persistent_dynamic import BOUNDS, digest, named
from direct_frontier_program import decode
import bounded_block_owner_helpers as block
from persistent_active_domain import COPY_COUNTS, COPY_STDOUT

ROOT = Path(__file__).resolve().parents[2]


def block_prerequisite(path, expected_sha256, r, pin, binary, archive):
    """Require current-source native20 and both protected lanes, with native41 intact."""
    path = pin(path)
    need(path.name == 'receipt.json' and path.parent.parent == ROOT/'target/evaluation/inprocess' and
         re.fullmatch('[0-9a-f]{64}', expected_sha256) is not None and
         fact(path)['sha256'] == expected_sha256, 'explicit whole private PB receipt identity')
    actual = decode(path.read_bytes()); directory = path.parent
    need(actual['schema'] == 1 and actual['profile'] == 'bounded-block-owner-v1' and
         actual['status'] == 'observed_unqualified' and actual['revision'] == r['revision'] and
         actual['source'] == r['source'] and actual['cpu'] == r['cpu'] and
         actual['hardware'] == r['hardware'] and actual['bounds'] == BOUNDS and
         actual['source_unchanged'] is True and actual['inputs_unchanged'] is True and
         actual['cleanup_complete'] is True and actual['error'] is None and actual['final_errors'] == [] and
         actual['whole_profile_qualified'] is False and
         actual['direct_prerequisite'] == r['direct_prerequisite'],
         'complete finite PB run on identical clean source, CPU, hardware, bounds and native41 prerequisite')
    for name, value in actual['inputs'].items():
        need(fact(pin(name)) == value, 'whole retained PB input')
    for name, value in actual['artifacts'].items():
        p = binary(name)
        need(dict(fact(p), mode=p.stat().st_mode & 0o777) == value, 'whole retained PB artifact and mode')
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
         'same whole actual PB, native41 and fresh probe decoder archive')
    commands = actual['commands']
    # The source-owned complete schedule is supplied by the finite owner, never by a receipt.
    need([(row['name'], row['profile']) for row in commands] == list(block.COMMAND_SCHEDULE) and
         len({row['name'] for row in commands}) == len(commands), 'entire fixed PB command schedule')
    for row in commands:
        need(type(row.get('exit')) is int and row['exit'] == row['expected_exit'] == 0 and
             row.get('reaped') is True and row.get('timed_out') is False and row.get('error') is None and
             row.get('cleanup_errors') == [] and type(row.get('descriptors')) is list and
             all(d.get('closed') is True for d in row['descriptors']) and
             row['bounds'] == BOUNDS[row['profile']], 'every actual PB child and original bound')
        expected_streams = {'stdout', 'stderr', 'record'} if row['name'] in (
            'subject-maintained-0-0', 'subject-differential-0-0') else {'stdout', 'stderr'}
        need(set(row['captures']) == expected_streams, 'entire actual PB capture population')
        for capture in row['captures'].values():
            q = pin(directory/capture['file'])
            need(q.is_relative_to(directory) and fact(q) == {k: capture[k] for k in ('bytes', 'sha256')},
                 'every retained whole PB capture belongs to this cohort')
    rows = {row['name']: row for row in commands}
    need([(c['lane'], c['mode'], c['control']) for c in actual['cases']] ==
         [('native', 0, 0), ('maintained', 0, 0), ('differential', 0, 0)], 'three complete fixed PB lanes')
    need(block.APP_COUNTS == {0: 40} and block.OWNER_COUNTS == {0: 204} and
         block.PAIR_COUNTS == {0: 36} and block.TERMINAL_COUNTS == {(0, 0): 73},
         'literal full PB control populations')
    for case in actual['cases']:
        row = rows[case['label']]; lane = case['lane']
        need(case['status'] == block.EXPECTED_STATUS[lane, 0] and case['launched'] is True and
             case['expected_exit'] == case['exit'] == row['expected_exit'] == row['exit'] == 0 and
             row['profile'] == 'program' and case['timed_out'] is False and
             case['whole_process_ns'] == row['duration_ns'] and
             case['captures'] == {k: {n: v[n] for n in ('bytes', 'sha256')} for k, v in row['captures'].items()},
             'each complete PB subject is its actual bounded child')
        if lane == 'native':
            named(case['application_controls'], 40, row['captures']['stdout']['sha256'])
            need((directory/row['captures']['stderr']['file']).read_bytes() == b'', 'native PB stderr is empty')
            continue
        for key, count, stream, hash_key in (
            ('owner_reader_controls', 204, 'record', 'original_sha256'),
            ('terminal_controls', 73, 'stderr', 'original_stderr_sha256'),
            ('repeat_tls_controls', 33, 'stderr', 'original_stderr_sha256'),
            ('native_probe_controls', 22, 'stderr', 'original_stderr_sha256'),
            ('subentry_controls', 19, 'stderr', 'original_stderr_sha256'),
            ('effect_controls', 12, 'stderr', 'original_stderr_sha256')):
            named(case[key], count, row['captures'][stream]['sha256'], hash_key=hash_key)
        need(case['pair'] == block.PAIR_EXPECTED, 'whole PB native20 and generated full-frame result')
        controls = case['pair_controls']; refusals = controls['refusals']
        need(type(refusals) is list and len(refusals) == len(set(refusals)) == 36 and
             all(type(n) is str and n for n in refusals) and controls['native_operations'] == 0,
             'every full-state PB pair refusal control')
        rb = actual['lanes'][lane]['release_build']; mode = 'differential' if lane == 'differential' else 'capture'
        binding = rb['persistent_binding']
        need(rb['status'] == 'passed' and rb['profile'] == 'persistent-block-'+mode+'-v1' and
             rb['capture'] is True and rb['archive'] == fact(archive) and
             rb['active_domain']['differential'] == (lane == 'differential') and
             all(rb['active_domain'][k] is True and binding[k] is True for k in
                 ('unregistered', 'subentry', 'cross_pair', 'direct_frontier', 'native_probe', 'parse_memo')) and
             binding['bounded_block'] is True and binding['policy_version'] == 10 and
             rb['bounded_block'] == dict(version=1, policy_version=10, heads_max=128, shared_boundaries=8,
                                         active_members_max=2, call_ret=False) and
             rb['direct_frontier'] == dict(version=1, policy_version=10, partition='first-direct-branch',
                 all_arms_directory=True, conditions=16, shared_boundaries=8, typed_external_arms=True,
                 unknown_target='original branch-before full drain') and
             rb['capture_extents']['wire'] == 5421376 and rb['capture_extents']['schema_version'] == 11 and
             rb['capture_extents']['record_limit'] == rb['capture_extents']['stream_strictly_below'] == 4 << 20 and
             128 < row['captures']['record']['bytes'] < 4 << 20,
             'both actual finite PB builds, full protected transcripts and unchanged strict encoded cap')
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
         'separate complete independent native PB seed')
    return dict(file=str(path.relative_to(ROOT)), **fact(path), status=actual['status'],
        profile=actual['profile'], archive=fact(archive), commands=len(commands), commands_sha256=digest(commands),
        controls=dict(app=40, owner=204, pair=36, terminal=73, tls=33, probe=22, subentry=19, effects=12),
        whole_profile_qualified=False)
