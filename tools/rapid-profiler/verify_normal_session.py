#!/usr/bin/env python3
"""Fresh finite normal-session qualification; no timing or complete-A5 claim."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import argparse
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import traceback

MIB = 1048576
# Exact CLOSED source-v3 census and whole-ELF authority; a successor is explicit.
PYTHON_CONTROLS = 11
SUBJECT_SHA256 = '8a238b77d4cf32c3dcea5aa0fc2a9ec55e58dbc8dc233c7c9d4100e998bd491d'
SESSION_PREFIX = 'normal::session::'
SESSION = tuple(SESSION_PREFIX + name for name in (
    'check::tests::coherent_shift_and_premature_closed_cannot_relabel_sample_population',
    'check::tests::whole_journal_tail_prefix_and_return_word_corruptions_refuse',
    'check::tests::report_payload_sequence_endpoint_and_terminal_are_independently_joined',
    'io::tests::partial_input_eof_and_multiple_lines_preserve_exact_frames',
    'io::tests::full_output_retains_exact_unsent_bytes_then_drains_without_duplication',
    'protocol::tests::exact_requests_include_empty_nul_and_arbitrary_external_ids',
    'protocol::tests::malformed_requests_never_enter_the_population',
    'protocol::tests::duplicate_ids_and_finite_capacity_are_shared_by_calls_and_barriers',
    'tests::accepted_full_queue_retains_pending_before_stop_and_disconnect',
    'tests::guarded_wait_preserves_original_due_end_and_shutdown_boundaries'))
SCHEDULE_PREFIX = 'frontend_native::backoff::driver::schedule::tests::'
SCHEDULE = tuple(SCHEDULE_PREFIX + name for name in (
    'pending_arm_refuses_another_poll_without_count_or_deadline_reset',
    'post_arm_history_observation_accepts_equality_but_refuses_one_nanosecond_late',
    'arm_acknowledgements_require_a_grant_and_cannot_precede_due',
    'missed_original_arm_and_incomplete_epoch_limit_refuse_without_catchup',
    'requested_stop_is_once_only_and_uses_exclusive_original_capped_shutdown',
    'wait_caps_follow_original_due_end_and_stop_without_poll_extension',
    'both_fixed_policies_issue_520_arms_and_complete_only_after_original_end'))
NORMAL_STAGES = ('parser-controls', 'runtime-controls', 'caller-controls', 'state-controls',
    'child-controls', 'caller-build', 'normal-state', 'normal-work', 'drop-sampled', 'drop-closed')
TRIALS = (('full-k10', 'full', 10), ('full-k1000', 'full', 1000),
    ('stop-k10', 'stop', 10), ('duplicate-k10', 'duplicate', 10),
    ('eof-k10', 'eof', 10), ('backpressure-k10', 'backpressure', 10))
STAGES = ('parser-controls', 'session-controls', 'schedule-controls', *(r[0] for r in TRIALS))
PROFILE = dict(opt_level='3', debuginfo=0, test=True, debug_assertions=True, overflow_checks=True)
CSV_FIELDS = ('case', 'outcome', 'k', 'epochs', 'arms', 'actions', 'accepted', 'calls',
    'sampled', 'unsampled', 'batches', 'flushes', 'detach', 'joins', 'maximum_entry_prefix',
    'maximum_batch_calls', 'write_blocked_at_finalize', 'input_bytes', 'transcript_bytes',
    'child_exit', 'normal_reaps', 'rescues')


def digest(path):
    data = path.read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def pairs(items):
    result = {}
    for key, value in items:
        assert key not in result
        result[key] = value
    return result


def decode(data):
    assert len(data) <= 16*MIB
    return json.loads(data, object_pairs_hook=pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def read(path):
    return decode(path.read_bytes())


def integer(value, low=0, high=(1 << 64)-1):
    assert type(value) is int and low <= value <= high
    return value


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'):
        ap.add_argument('--'+name, type=Path, required=True)
    a = ap.parse_args()
    repo = Path(__file__).resolve().parents[2]
    assert Path(__file__).resolve() == repo/'tools/rapid-profiler/verify_normal_session.py'
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    for p in (repo, a.toolchain, a.user_home, a.cargo_home):
        assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    assert a.raw.is_absolute() and a.raw.is_relative_to(repo/'ignored') and not a.raw.exists()
    assert a.raw.parent.resolve(strict=True) == a.raw.parent
    tools = {n: (a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo', 'rustc')}
    tools.update(python=Path(sys.executable).resolve(strict=True),
        **{n: Path('/usr/bin', n).resolve(strict=True) for n in ('git', 'gcc', 'readelf', 'strip')})
    env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home),
        PATH=str(a.toolchain/'bin')+':/usr/bin:/bin', RUSTC=str(a.toolchain/'bin/rustc'),
        CC=str(tools['gcc']), CARGO_TARGET_DIR=str(repo/'target'), CARGO_INCREMENTAL='0',
        CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
        CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true',
        CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true', CARGO_TERM_COLOR='never', LC_ALL='C',
        PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    def command(argv):
        data = subprocess.check_output(argv, cwd=repo, env=env, timeout=15)
        assert len(data) <= 8*MIB
        return data
    def git(*args):
        return command([str(tools['git']), '-C', str(repo), *args])
    assert git('rev-parse', '--show-toplevel').decode().strip() == str(repo)
    assert git('rev-parse', 'HEAD').decode().strip() == a.revision
    assert git('status', '--porcelain', '--untracked-files=no') == b''
    required = {'tools/rapid-profiler/verify_normal_session.py',
        'tools/rapid-profiler/verify_normal_interval.py', 'tools/rapid-profiler/verify_strnlen_interval.py',
        'tools/rapid-profiler/normal-work/session_driver.py', 'tools/rapid-profiler/normal-work/test_session.py',
        'tools/rapid-profiler/selected-work/check_output.py', 'tools/rapid-profiler/normal-work/check_output.py',
        'tools/rapid-profiler/ordinary-interval/normal/session.rs',
        'tools/rapid-profiler/ordinary-interval/normal/session/check.rs',
        'tools/rapid-profiler/ordinary-interval/normal/session/io.rs',
        'tools/rapid-profiler/ordinary-interval/normal/session/protocol.rs',
        'tools/rapid-profiler/ordinary-interval/normal/session/worker.rs',
        'tools/rapid-profiler/src/frontend_native/backoff/driver/schedule.rs',
        'evaluation/admission/processes.py', 'tools/unwind-oracle/bounded_command.py'}
    names = git('ls-files', '-z', '--', 'src', 'tests', 'tools/rapid-profiler', 'Cargo.toml',
        'Cargo.lock', 'README.md', 'build.rs', ':(glob)**/Cargo.toml', *sorted(required)).decode().rstrip('\0').split('\0')
    assert all(names) and len(names) == len(set(names)) and required.issubset(names)
    before = {n: digest(repo/n) for n in names}
    for n in names:
        assert (repo/n).read_bytes() == git('show', a.revision+':'+n)
    for name in ('cc1', 'collect2', 'as', 'ld'):
        reported = command([str(tools['gcc']), '-print-prog-name='+name]).decode('ascii').strip()
        assert reported and '\n' not in reported
        path = Path(reported) if '/' in reported else Path(shutil.which(reported, path=env['PATH']) or '')
        assert path.is_absolute()
        tools[name] = path.resolve(strict=True)
    tool_hashes = {n: digest(p) for n, p in tools.items()}
    # All project imports, including the prerequisite's transitive recipes, are authenticated first.
    processes = load('session_processes', repo/'evaluation/admission/processes.py')
    normal = load('session_normal', repo/'tools/rapid-profiler/verify_normal_interval.py')
    census = load('session_census', repo/'tools/rapid-profiler/selected-work/check_output.py')
    state_check = load('session_state_check', repo/'tools/rapid-profiler/normal-work/check_output.py')
    assert normal.STAGES == NORMAL_STAGES and len(normal.RUNTIME) == 12
    assert normal.RUNTIME[-3:] == (
        'streaming_normal_pending_owner_survives_600_actions_without_return_acknowledgement',
        'streaming_normal_closed_and_removed_records_join_after_repeated_idle_drains',
        'streaming_normal_upper_prefix_corruption_refuses_before_consuming_pending_owner')
    a.raw.mkdir(mode=0o700)
    save(a.raw/'sources-before.json', before)
    save(a.raw/'private-environment.json', dict(env=env, tools={n: str(p) for n, p in tools.items()}))
    result = dict(schema=1, status='FAILED', stage='setup', revision=a.revision,
        scope='Finite externally driven normal-caller sessions; raw callbacks and caller acknowledgements. No throughput, accuracy, general-application, unload or complete-A5 claim.',
        command=['$PYTHON', '-B', '$REPO/tools/rapid-profiler/verify_normal_session.py',
            '--revision', a.revision, '--raw', '$RAW', '--toolchain', '$TOOLCHAIN',
            '--user-home', '$USER_HOME', '--cargo-home', '$CARGO_HOME'],
        sources=dict(count=len(before), manifest=digest(a.raw/'sources-before.json')),
        tools=tool_hashes, prerequisite=dict(status='UNRUN'),
        stages=[dict(name=n, status='UNRUN') for n in STAGES],
        trials=[dict(name=n, mode=m, k=k, status='UNRUN') for n, m, k in TRIALS])
    artifacts = {}
    def pin(path, expected=None):
        value = digest(path)
        if expected is not None: assert value == expected
        if path in artifacts: assert artifacts[path] == value
        artifacts[path] = value
        return value
    def unchanged():
        assert git('rev-parse', 'HEAD').decode().strip() == a.revision
        assert git('status', '--porcelain', '--untracked-files=no') == b''
        assert {n: digest(repo/n) for n in names} == before
        assert {n: digest(p) for n, p in tools.items()} == tool_hashes
        assert all(digest(p) == h for p, h in artifacts.items())
        assert sorted(os.sched_getaffinity(0)) == cpus
    def public(value):
        value = str(value)
        for name, path in tools.items():
            if value == str(path): return '$'+name.upper()
        for path, token in ((a.raw, '$RAW'), (repo, '$REPO'), (a.toolchain, '$TOOLCHAIN'),
                            (a.cargo_home, '$CARGO_HOME'), (a.user_home, '$USER_HOME')):
            if value == str(path) or value.startswith(str(path)+'/'):
                return token+value[len(str(path)):]
        assert not value.startswith('/') and '/home/' not in value and '@' not in value
        return value
    def closed_ok(closed):
        assert type(closed['exit_code']) is int and closed['exit_code'] == 0
        assert closed['termination'] is None and closed['cleanup_complete'] is True
        assert type(closed['reaped_descendants']) is int and closed['reaped_descendants'] == 0
    try:
        cpus = sorted(os.sched_getaffinity(0))[:4]
        assert len(cpus) == 4
        os.sched_setaffinity(0, cpus)
        assert sorted(os.sched_getaffinity(0)) == cpus
        logs_root = repo/'target/evaluation'; logs_root.mkdir(parents=True, exist_ok=True)
        assert logs_root.resolve(strict=True) == logs_root
        logs = Path(tempfile.mkdtemp(prefix='normal-session-', dir=logs_root))
        nested = a.raw/'normal-prerequisite'
        argv = [str(tools['python']), '-B', str(repo/'tools/rapid-profiler/verify_normal_interval.py'),
            '--revision', a.revision, '--raw', str(nested), '--toolchain', str(a.toolchain),
            '--user-home', str(a.user_home), '--cargo-home', str(a.cargo_home)]
        result['stage'] = 'normal-prerequisite'; result['prerequisite']['status'] = 'FAILED'
        request = dict(argv=argv, env=env, affinity=cpus, wall_seconds=1800, output_bytes=8*MIB)
        save(a.raw/'prerequisite-command.json', request); pin(a.raw/'prerequisite-command.json')
        unchanged()
        closed = processes.run_command(argv, env, logs/'prerequisite.log', 1800, 8*MIB)
        (a.raw/'prerequisite.log').write_bytes((logs/'prerequisite.log').read_bytes())
        save(a.raw/'prerequisite-closed.json', closed); closed_ok(closed); unchanged()
        assert closed['private_log_sha256'] == digest(a.raw/'prerequisite.log')['sha256']
        old = read(nested/'result.json'); pin(nested/'result.json')
        assert old['status'] == 'PASS' and old['stage'] == 'complete' and old['revision'] == a.revision
        assert old['command'] == ['$PYTHON', '-B', '$REPO/tools/rapid-profiler/verify_normal_interval.py',
            '--revision', a.revision, '--raw', '$RAW', '--toolchain', '$TOOLCHAIN',
            '--user-home', '$USER_HOME', '--cargo-home', '$CARGO_HOME']
        assert tuple(s['name'] for s in old['stages']) == NORMAL_STAGES
        assert all(s['status'] == 'PASS' for s in old['stages'])
        assert old['closure'] == dict(owned_stages=10, nested_normal_helpers=46, nested_outer_owners=48, rescues=0)
        assert old['controls']['parser'] == 9
        for label, count, prefix, methods in (
            ('runtime', 12, 'frontend_native::always_on::normal::tests::', normal.RUNTIME),
            ('caller', 4, 'normal::caller::tests::', normal.CALLER),
            ('state', 8, 'oracle::native_ordinary::normal_caller::tests::', normal.STATE),
            ('child', 2, 'normal_check::tests::', normal.CHILD)):
            control = old['controls'][label]
            assert control['status'] == 'PASS' and control['passed'] == count
            assert control['failed'] == control['ignored'] == 0
            assert len(control['names']) == len(set(control['names'])) == count
            assert set(control['names']) == {prefix+n for n in methods}
        assert {k: old['native'][k] for k in ('pairs', 'stable_pairs', 'crossed_pairs', 'children',
            'target_calls', 'target_returns', 'outer_returns', 'helper_joins')} == dict(
                pairs=17, stable_pairs=16, crossed_pairs=1, children=34, target_calls=68,
                target_returns=68, outer_returns=34, helper_joins=1)
        assert old['work'] == dict(original_calls=8, installed_calls=8, next_entry_acknowledgements=7,
            checkpoint_acknowledgements=1, sampled=4, function_closed=2, removed=2, generations=2,
            events=16, journal_words=512, reports=2, worker_joins=1)
        assert old['abandonment'] == dict(cases=2, original_calls=16, installed_calls=4, checkpoints=0,
            pending_after_tls_exit=2, reattach_refusals=2, worker_joins=2)
        for path in (nested/'sources-before.json', nested/'sources-after.json'):
            pin(path)
        prior_sources = read(nested/'sources-before.json')
        assert prior_sources == read(nested/'sources-after.json')
        assert all(before[n] == h for n, h in prior_sources.items())
        assert old['sources'] == dict(count=len(prior_sources), manifest=digest(nested/'sources-before.json'))
        # The normal prerequisite delegates fixture and Cargo artifact custody to its fresh strnlen child.
        fixture = nested/'strnlen-prerequisite'
        fixture_result = read(fixture/'result.json')
        pin(fixture/'result.json', old['prerequisite']['result'])
        assert fixture_result['revision'] == a.revision and fixture_result['status'] == 'PASS'
        assert fixture_result['stage'] == 'complete' and fixture_result['tools'] == old['tools'] == tool_hashes
        assert fixture_result['closure'] == old['prerequisite']['closure'] == dict(
            owned_stages=24, nested_owned_stages=22, normal_helpers=46, outer_owners=48, rescues=0)
        private = read(fixture/'private-environment.json'); pin(fixture/'private-environment.json')
        assert private == dict(env=env, affinity=cpus, tools={n: str(p) for n, p in tools.items()})
        result['versions'] = old['versions']
        result['hardware'] = {k: old['hardware'][k] for k in ('architecture', 'vendor', 'family', 'model', 'stepping')}
        result['hardware'].update(qualification_affinity_cpus=4, session_worker_cpus=1, session_controller_cpus=1)
        result['prerequisite'] = dict(status='PASS', result=digest(nested/'result.json'),
            command=digest(a.raw/'prerequisite-command.json'), closed=pin(a.raw/'prerequisite-closed.json'),
            log=pin(a.raw/'prerequisite.log'), closure=old['closure'], runtime_controls=12,
            stable_pairs=16, crossed_pairs=1, functional_originals=8, functional_installed=8, abandonment_cases=2)
        selection = read(fixture/'selection.json'); pin(fixture/'selection.json', fixture_result['selection']['manifest'])
        assert selection['revision'] == a.revision and selection['label'] == 'freebsd-strnlen-14.1-v1'
        assert integer(selection['length']) == 41
        va, offset = integer(selection['elf_va']), integer(selection['file_offset'])
        assert va == 4096
        for key in ('label', 'elf_va', 'length', 'file_offset', 'selected_code'):
            assert selection[key] == fixture_result['selection'][key]
        candidate, trusted = fixture/'candidate.so', fixture/'final.so'
        pin(candidate, fixture_result['selection']['candidate']); pin(trusted, fixture_result['selection']['final'])
        assert digest(trusted) == selection['final'] == old['artifacts']['subject']
        assert digest(trusted)['sha256'] == SUBJECT_SHA256
        assert candidate.read_bytes() == trusted.read_bytes()
        assert (candidate.stat().st_dev, candidate.stat().st_ino) != (trusted.stat().st_dev, trusted.stat().st_ino)
        code = trusted.read_bytes()[offset:offset+41]
        assert len(code) == 41 and code[34] == code[40] == 0xc3
        assert dict(bytes=41, sha256=hashlib.sha256(code).hexdigest()) == selection['selected_code']
        # The instruction validator, not a search for opcode bytes, owns the complete RET union.
        state = nested/'normal-state'
        table = nested/'normal-pairs.csv'; pin(table, old['outputs']['normal-pairs.csv'])
        for stream in ('stdout', 'stderr'):
            path = state/(stream+'.txt')
            record = next(r for r in old['stages'] if r['name'] == 'normal-state')
            pin(path, record[stream])
        rows, totals = state_check.state(table.read_bytes(), (state/'stdout.txt').read_bytes(),
            (state/'stderr.txt').read_bytes(), 41)
        assert set(r['ret_offset0'] for r in rows) == {34, 40}
        assert all(r['ret_offset0'] == (34 if r['bound'] == 0 or r['value0'] < r['bound'] else 40) for r in rows)
        assert all(old['native'][key] == value for key, value in totals.items())
        result['selection'] = dict(manifest=digest(fixture/'selection.json'), candidate=digest(candidate),
            final=digest(trusted), selected_code=selection['selected_code'], elf_va=va, length=41,
            return_offsets=[34, 40], qualification_result=digest(nested/'result.json'))
        binary = repo/'target/release/ordinary-interval'
        pin(binary, fixture_result['artifacts']['ordinary-interval']['binary'])
        assert digest(binary) == old['artifacts']['ordinary-interval']
        assert fixture_result['artifacts']['ordinary-interval']['profile'] == dict(PROFILE, test=False)
        result['binary'] = dict(content=digest(binary), profile=dict(PROFILE, test=False))

        def stage(name, argv):
            unchanged(); result['stage'] = name
            row = next(r for r in result['stages'] if r['name'] == name)
            assert row['status'] == 'UNRUN'
            row.update(status='FAILED', command=[public(v) for v in argv], cpu_seconds=20,
                wall_seconds=30, file_bytes=4*MIB, owner_wall_seconds=55)
            d = a.raw/name; d.mkdir(); (d/'tmp').mkdir()
            request = dict(argv=[str(v) for v in argv], cwd=str(repo), env=dict(env, TMPDIR=str(d/'tmp')),
                stdout=str(d/'stdout.txt'), stderr=str(d/'stderr.txt'), cpu_seconds=20,
                wall_seconds=30, file_bytes=4*MIB)
            save(d/'request.json', request); pin(d/'request.json')
            parent = [str(tools['python']), '-B', str(repo/'tools/unwind-oracle/bounded_command.py'),
                '--request', str(d/'request.json'), '--receipt', str(d/'receipt.json')]
            parent_request = dict(argv=parent, env=env, affinity=cpus, wall_seconds=55, output_bytes=MIB)
            save(d/'parent-command.json', parent_request); pin(d/'parent-command.json')
            closed = processes.run_command(parent, env, logs/(name+'.log'), 55, MIB)
            (d/'parent.log').write_bytes((logs/(name+'.log')).read_bytes())
            save(d/'parent-closed.json', closed); closed_ok(closed)
            assert closed['private_log_sha256'] == digest(d/'parent.log')['sha256']
            assert read(d/'request.json') == request
            assert read(d/'parent-command.json') == parent_request
            receipt = read(d/'receipt.json')
            assert type(receipt['exit']) is int and receipt['exit'] == 0
            assert receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
            assert receipt['absence_proof'] == 'ECHILD'
            assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
            assert receipt['cleanup_error'] is receipt['aborted'] is None
            assert receipt['request_sha256'] == digest(d/'request.json')['sha256']
            assert receipt['helper_sha256'] == before['tools/unwind-oracle/bounded_command.py']['sha256']
            assert read(d/'parent.log') == dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)
            for stream in ('stdout', 'stderr'):
                assert receipt[stream+'_sha256'] == digest(d/(stream+'.txt'))['sha256']
            row.update({n: pin(d/file) for n, file in (('receipt', 'receipt.json'),
                ('request', 'request.json'), ('parent_command', 'parent-command.json'),
                ('closed', 'parent-closed.json'), ('parent', 'parent.log'),
                ('stdout', 'stdout.txt'), ('stderr', 'stderr.txt'))})
            unchanged()
            return d, row

        d, row = stage('parser-controls', [tools['python'], '-B', repo/'tools/rapid-profiler/normal-work/test_session.py'])
        assert (d/'stdout.txt').read_bytes() == b''
        assert re.fullmatch(rb'\.{'+str(PYTHON_CONTROLS).encode()+rb'}\n-+\nRan '+str(PYTHON_CONTROLS).encode()+
            rb' tests in [0-9]+\.[0-9]+s\n\nOK\n', (d/'stderr.txt').read_bytes())
        row.update(status='PASS', passed=PYTHON_CONTROLS)
        for name, old_label, target, source, kind, crate_type, prefix, methods in (
            ('session', 'work-validator', 'ordinary-interval', 'ordinary-interval/main.rs', 'bin', 'bin', SESSION_PREFIX, SESSION),
            ('schedule', 'whole-front', 'rapid_profiler', 'src/lib.rs', 'lib', 'lib', SCHEDULE_PREFIX, SCHEDULE)):
            built = fixture/(old_label+'-build')/'stdout.txt'
            listing = fixture/(old_label+'-list')
            for suffix, path in (('build', built), ('list', listing/'stdout.txt')):
                record = next(r for r in fixture_result['stages'] if r['name'] == old_label+'-'+suffix)
                pin(path, record['stdout'])
            messages = [decode(line) for line in built.read_bytes().splitlines()]
            assert messages[-1] == dict(reason='build-finished', success=True)
            products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == target and m['profile']['test']]
            assert len(products) == 1
            p = products[0]; test_binary = Path(p['executable'])
            assert test_binary.resolve(strict=True) == test_binary and test_binary.parent == repo/'target/release/deps'
            assert re.fullmatch(re.escape(target.replace('-', '_'))+'-[0-9a-f]+', test_binary.name)
            assert p['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml')
            assert p['target']['src_path'] == str(repo/'tools/rapid-profiler'/source)
            assert p['target']['kind'] == [kind] and p['target']['crate_types'] == [crate_type]
            assert p['profile'] == PROFILE and type(p['fresh']) is bool
            assert type(p['profile']['debuginfo']) is int and p['profile']['test'] is True
            assert p['profile']['debug_assertions'] is p['profile']['overflow_checks'] is True
            assert p['fresh'] is fixture_result['artifacts'][old_label]['cargo_fresh']
            assert fixture_result['artifacts'][old_label]['profile'] == PROFILE
            pin(test_binary, fixture_result['artifacts'][old_label]['binary'])
            record = next(r for r in fixture_result['stages'] if r['name'] == old_label+'-list')
            pin(listing/'stderr.txt', record['stderr'])
            inventory = census.census((listing/'stdout.txt').read_bytes(), (listing/'stderr.txt').read_bytes())
            assert set(n for n in inventory if n.startswith(prefix)) == set(methods)
            d, row = stage(name+'-controls', [test_binary, prefix, '--test-threads=1'])
            row.update(census.controls((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(), methods, inventory),
                binary=digest(test_binary), profile=PROFILE, full_census=len(inventory), cargo_fresh=p['fresh'])
        numeric = []
        for trial, (name, mode, k) in zip(result['trials'], TRIALS):
            trial['status'] = 'FAILED'
            output = a.raw/name/'producer'
            argv = [tools['python'], '-B', repo/'tools/rapid-profiler/normal-work/session_driver.py',
                '--binary', binary, '--candidate', candidate, '--trusted', trusted,
                '--elf-va', str(va), '--length', '41', '--output', output, '--k', str(k), '--mode', mode]
            d, row = stage(name, argv)
            assert (d/'stderr.txt').read_bytes() == b''
            summary = read(output/'result.json')
            assert decode((d/'stdout.txt').read_bytes()) == summary
            assert summary['status'] == 'PASS' and summary['mode'] == mode and summary['k'] == k
            assert integer(summary['normal_reaps']) == 1 and integer(summary['rescues']) == 0
            assert summary['rescue'] is False and type(summary['child_exit']) is int
            assert integer(summary['input_bytes'], 1) > 0
            transcript = pin(output/'stdout.txt'); errors = pin(output/'stderr.txt')
            assert transcript == dict(bytes=integer(summary['transcript_bytes'], 1, 4*MIB), sha256=summary['transcript_sha256'])
            metadata = pin(output/'result.json')
            outcome = 'EXPECTED_REFUSAL' if mode in ('duplicate', 'eof') else 'COMPLETE'
            public_summary = {key: summary[key] for key in ('input_bytes', 'transcript_bytes', 'child_exit', 'normal_reaps', 'rescues')}
            if outcome == 'EXPECTED_REFUSAL':
                assert summary['control'] == mode and summary['expected_refusal'] is True
                assert type(summary['exit_code']) is int and summary['exit_code'] == summary['child_exit'] == 1
                assert b'DONE,' not in (output/'stdout.txt').read_bytes()
                error = (output/'stderr.txt').read_bytes()
                assert b'normal-session FAILED:' in error
                assert (b'duplicate request ID' if mode == 'duplicate' else b'overlong or unterminated request') in error
            else:
                assert type(summary['child_exit']) is int and summary['child_exit'] == 0 and errors['bytes'] == 0
                for key in ('arms', 'actions', 'accepted', 'calls', 'sampled', 'unsampled', 'batches',
                            'flushes', 'detach', 'joins', 'maximum_entry_prefix', 'maximum_batch_calls', 'write_blocked_at_finalize'):
                    public_summary[key] = integer(summary[key])
                expected_calls, expected_flushes = (40, 5) if mode == 'full' else ((64, 0) if mode == 'stop' else (1024, 1))
                assert summary['calls'] == expected_calls and summary['flushes'] == expected_flushes
                assert summary['accepted'] == expected_calls+expected_flushes
                assert summary['sampled']+summary['unsampled'] == expected_calls
                assert summary['detach'] == summary['joins'] == 1
                assert summary['actions'] == summary['arms']+1 and 1 <= summary['arms'] <= 520
                assert 1 <= summary['batches'] <= expected_calls <= 4*summary['batches']
                assert 1 <= summary['maximum_batch_calls'] <= 4
                assert summary['maximum_entry_prefix'] <= summary['actions']
                owners = summary['owners']
                assert set(owners).issubset({'sampled', 'closed', 'removed', 'initial'})
                assert all(type(n) is int and n > 0 for n in owners.values()) and sum(owners.values()) == expected_calls
                assert owners.get('sampled', 0) == summary['sampled']
                assert summary['stop_reason'] == ('Requested' if mode == 'stop' else 'EpochLimit')
                if mode != 'stop': assert summary['arms'] == 520
                if mode == 'full': assert summary['maximum_entry_prefix'] >= 513
                if mode == 'backpressure': assert summary['write_blocked_at_finalize'] > 0
                public_summary.update(owners=owners, stop_reason=summary['stop_reason'])
            trial.update(status='PASS', outcome=outcome, summary=public_summary,
                result=metadata, transcript=transcript, stderr=errors)
            row['status'] = 'PASS'
            numeric.append(dict(case=name, outcome=outcome, k=k, epochs=520,
                **{key: public_summary[key] for key in CSV_FIELDS[4:] if key in public_summary}))
            unchanged()
        with (a.raw/'sessions.csv').open('x', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS, lineterminator='\n')
            writer.writeheader(); writer.writerows(numeric)
        unchanged()
        save(a.raw/'sources-after.json', {n: digest(repo/n) for n in names})
        assert all(r['status'] == 'PASS' for r in result['stages']+result['trials'])
        result.update(status='PASS', stage='complete', output=digest(a.raw/'sessions.csv'),
            closure=dict(owned_stages=len(STAGES), normal_helper_reaps=len(STAGES), absence='ECHILD',
                producer_child_reaps=len(TRIALS), producer_rescues=0, owner_rescues=0),
            prior_failures='Fresh attempt only; no retries, population substitution or discarded failures.',
            limits=dict(epochs=520, period_ms=10, arm_lateness_ms=2, shutdown_seconds=2,
                producer_cpu_seconds=20, producer_wall_seconds=30, producer_file_bytes=4*MIB,
                backpressure_stdout_delay_ms=250),
            interpretation='Full input/journal/Report checks remain source-attested; the producer independently joins its intended request population. Prior native state evidence covers its fixed calls, not this session. EAGAIN count is an actual transport counter, not a throughput score.')
    except BaseException as error:
        result['error_type'] = type(error).__name__
        (a.raw/'failure.txt').write_text(traceback.format_exc())
    finally:
        # Only the fixed-field receipt and six numeric rows are public candidates.
        # Logs, child streams, private paths, complete source manifests and nested trails stay ignored.
        save(a.raw/'result.json', result)
    print('normal-session-qualification '+result['status']+' stage='+result['stage'])
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
