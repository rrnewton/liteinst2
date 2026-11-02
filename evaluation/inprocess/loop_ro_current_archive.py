"""Reuse only the complete current build prefix of a closed RO program receipt."""
import json
from pathlib import Path
import re
from types import SimpleNamespace

from page_selected import ENV, fact, need
from persistent_dynamic import BOUNDS
from persistent_loop_effects_native_prerequisite import archive_join, FEATURES


def current_archive(path, sha, root, pin, binary, aliases):
    # Imported at use time: the real-program collector itself uses build_ro.
    from loop_ro_program_release import SETUP, SCHEDULE
    path = pin(path)
    need(path.name == 'receipt.json' and path.parent.parent == root/'target/evaluation/inprocess'
         and re.fullmatch('[0-9a-f]{64}', sha) and fact(path)['sha256'] == sha,
         'explicit whole closed current-build producer receipt')
    n = json.loads(path.read_bytes()); directory = path.parent
    need(n['schema'] == 1 and n['profile'] == 'loop-ro-program-release-v1'
         and n['status'] in ('failed', 'completed_diagnostic')
         and n['revision'] == n['source']['revision'] and re.fullmatch('[0-9a-f]{40}', n['revision'])
         and n['source']['tracked_clean'] is True and n['source']['head_sources_match'] is True
         and all(n[k] is True for k in ('source_unchanged', 'inputs_unchanged', 'cleanup_complete'))
         and n['final_errors'] == [] and n['bounds'] == BOUNDS
         and all(n[k] is False for k in ('qualification_credit', 'full_state_credit',
                                        'whole_profile_qualified', 'performance_credit'))
         and ((n['status'] == 'completed_diagnostic') == (n['error'] is None)),
         'closed exact-source producer; failed program outcomes remain failed')
    commands = n['commands']
    need(len(commands) == len(SCHEDULE) == 34 and
         tuple((c['name'], c['profile']) for c in commands) == SCHEDULE and len(SETUP) == 20,
         'complete fixed producer schedule and exact twenty-command build prefix')

    def owned(p):
        p = pin(p); key = str(p)
        need(key in n['inputs'] or key in n['artifacts'], 'producer owns every reused compiler input/output')
        if key in n['inputs']:
            need(fact(p) == n['inputs'][key], 'current whole compiler input equals actual build input')
        if key in n['artifacts']:
            need(dict(fact(binary(p)), mode=p.stat().st_mode & 0o777) == n['artifacts'][key],
                 'whole actual retained artifact and mode')
        return p

    def captured(row, stream):
        item = row['captures'][stream]; p = owned(directory/item['file'])
        need(p.parent == directory and fact(p) == {k:item[k] for k in ('bytes', 'sha256')}
             and 0 <= item['bytes'] <= row['capture_limit'], 'whole bounded actual capture')
        return p.read_bytes()

    for i, row in enumerate(commands):
        need(type(row['exit']) is int and row['expected_exit'] == 0
             and row['reaped'] is True and row['error'] is None and row['cleanup_errors'] == []
             and type(row['descriptors']) is list and all(d['closed'] is True for d in row['descriptors'])
             and row['bounds'] == BOUNDS[row['profile']] and row['capture_limit'] == 16 << 20
             and type(row['timed_out']) is bool and set(row['captures']) == {'stdout', 'stderr'}
             and json.loads(owned(directory/(row['name']+'.json')).read_bytes()) == row,
             'every original command and capture is closed, without changing its outcome')
        if i < len(SETUP):
            need(row['exit'] == 0 and row['timed_out'] is False,
                 'all twenty actual archive/compiler-prefix commands succeeded')
        for stream in row['captures']: captured(row, stream)
    b = n['build']; tools = {name:owned(value['path']) for name, value in b['tools'].items()}
    need(all(fact(tools[name]) == {k:v[k] for k in ('bytes', 'sha256')} for name,v in b['tools'].items()),
         'whole actual build tool identities')
    builder = SimpleNamespace(tools=tools, environment=b['environment'], record=b,
        retained=directory/'artifacts', mov_guard=True, linked_epoch=True, scalar_span=True,
        extra_decoder_sources=('region.rs','mov_guard.rs','scalar_read.rs','loop_scalar.rs','byte_mov_guard.rs'),
        decoder_features=FEATURES)
    archive = owned(b['artifacts']['decoder.a']['path']); builder.paths = dict(archive=archive)
    rows = {c['name']:c for c in commands[:len(SETUP)]}; used = []

    def recorded(name, argv, profile='metadata', expected=0, env=None, record=False):
        need(name in rows and name not in used and record is False, 'one exact build-prefix replay, no execution')
        environment = dict(ENV if env is None else env)
        if name.startswith(('resolve-', 'version-')):
            environment = {k:v for k,v in environment.items() if k != 'LI2_DECODER_FEATURES'}
            if name in ('resolve-cargo', 'resolve-rustc'):
                environment = {k:v for k,v in environment.items() if k in ENV or k in ('HOME','CARGO_HOME','RUSTUP_HOME','LI2_MAPS_PROFILE')}
        row = rows[name]
        need(row['argv'] == list(map(str, argv)) and row['environment'] == environment
             and row['profile'] == profile and row['expected_exit'] == expected == 0,
             'whole source-derived compiler argv/environment/profile/outcome '+name)
        used.append(name); return row, captured(row, 'stdout'), captured(row, 'stderr')

    _, names, err = recorded('tracked-input-list', ['git','-C',root,'ls-files','-z',
        'tools/page-entry','evaluation/inprocess'])
    need(names and not err and b'evaluation/inprocess/loop_ro_program_release.py' in names.split(b'\0'),
         'actual installed producer source inventory')
    archive_join(n, directory, builder, archive, owned, owned, recorded, aliases)
    need(set(used) == set(rows) and len(used) == 20, 'all original compiler-prefix checks reused')
    proof = dict(receipt=fact(path), revision=n['revision'], source=n['source'], cpu=n['cpu'],
        hardware=n['hardware'], archive=fact(archive), compiled_sources=b['dep_info'],
        build_prefix=used, producer_status=n['status'], producer_error=n['error'],
        producer_subjects=[dict(name=c['name'], exit=c['exit'], timed_out=c['timed_out'])
                           for c in commands if c['name'] in ('ls-release','true-release')],
        current_compiler_inputs_equal=True, archive_rebuilt_by_consumer=False,
        program_qualification_credit=False, performance_credit=False)
    return builder, archive, proof
