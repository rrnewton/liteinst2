#!/usr/bin/env python3
"""Fresh T1 prerequisite then bounded T2 controls/cohorts; no performance/full-A5 claim."""
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
PYTHON_CONTROLS = 15
SDK_PREFIX = 'frontend_native::always_on::normal::two_callers::'
OWNER_PREFIX = 'frontend_native::module::ordinary::two_callers::tests::'
SDK = (OWNER_PREFIX+'two_caller_contract_refuses_missing_facts_before_source_access',
    *(SDK_PREFIX+'tests::'+name for name in (
        'two_caller_profile_requires_exact_site_limits_and_concurrent_mode',
        'two_registration_limit_and_identity_reuse_refuse_without_recycling',
        'two_pending_owners_confirm_locally_with_retained_dropped_and_closed_results')))
NATIVE = tuple(SDK_PREFIX+'native::'+name for name in (
    'two_caller_native_k1_first_worker_zero', 'two_caller_native_k1_first_worker_one',
    'two_caller_native_closed_owners_fill_e4_until_local_confirmation'))
CONSUMER_PREFIX = 'normal::session::two::'
CONSUMER = tuple(CONSUMER_PREFIX+name for name in (
    'tests::partial_broadcast_full_acknowledgements_and_stop_keep_exact_custody',
    'tests::full_call_and_partial_disconnected_broadcast_never_reroute_or_disappear',
    'tests::complete_output_envelope_retains_maximum_ids_and_population',
    'check::tests::global_slots_and_retained_ranks_accept_out_of_order_but_refuse_corruption',
    'check::tests::both_dispositions_join_actual_registration_sequence_and_raw_endpoints',
    'check::tests::local_identity_acknowledgement_and_whole_page_cannot_cross_workers'))
TRIALS = (('full-k10', 'full', 10), ('full-k1000', 'full', 1000), ('stop-k10', 'stop', 10),
    ('duplicate-k10', 'duplicate', 10), ('eof-k10', 'eof', 10), ('backpressure-k10', 'backpressure', 10))
STAGES = ('parser-controls', 'sdk-controls', 'consumer-controls', 'native-k1-zero', 'native-k1-one',
    'native-e4', *(row[0] for row in TRIALS))
EXACT_PREFIX = CONSUMER_PREFIX+'exact::tests::'
EXACT_CONSUMER = tuple(EXACT_PREFIX+n for n in (
    'exact_subject_authenticates_every_byte_head_extent_and_return',
    'exact_domain_refusal_precedes_actual_shared_id_acceptance',
    'exact_value_validator_checks_the_complete_input_and_full_u64_result',
    'exact_return_validator_refuses_other_exits_and_address_overflow',
    'exact_metadata_keeps_fixed_selection_labels_and_extents_distinct',
    'exact_output_envelope_preserves_legacy_and_all_capacity_refusals'))
EXACT_STATE = (
    'oracle::native_ordinary::normal_caller::exact_tests::exact_normal_closed_cases_input_and_counts',
    'oracle::native_ordinary::normal_caller::exact_tests::exact_normal_pair_rejects_count_step_return_value_or_reap_drift',
    'exact_body::tests::exact_normal_source_requires_all_bytes_heads_and_ret36',
    'exact_body::tests::exact_normal_body_accepts_two_real_continuation_shapes_and_closed_lengths',
    'exact_body::tests::exact_normal_body_mutations_refuse_without_omitted_suffix_or_read',
    'exact_truth::tests::literal_one_iteration_trace_includes_real_ret_read',
    'exact_truth::tests::every_length_matches_algebra_input_order_and_scalar_model',
    'exact_truth::tests::unsigned_loop_comparison_is_independent_of_input_xor_zero_flag',
    'exact_truth::tests::changed_opcode_displacement_immediate_and_extent_all_refuse',
    'exact_truth::tests::invalid_length_and_address_wrap_refuse')
EXACT_TRIALS = tuple(('exact-'+schedule+'-k'+str(k), schedule, k)
    for schedule in ('short', 'long', 'alternating', 'late-long') for k in (10, 1000))
EXACT_STAGES = ('exact-fixture-controls', 'exact-parser-controls', 'exact-native-parser-controls',
    'exact-consumer-controls', 'exact-state-controls', 'exact-build', 'exact-state',
    *(row[0] for row in EXACT_TRIALS))
FIELDS = ('case', 'outcome', 'k', 'epochs', 'arms', 'actions', 'accepted', 'calls', 'admitted',
    'retained', 'dropped', 'unsampled', 'batches', 'flushes', 'cancelled', 'unfinished', 'detaches',
    'joins', 'worker1_calls', 'worker2_calls', 'maximum_entry_prefix', 'maximum_batch_calls',
    'write_blocked_at_finalize', 'input_bytes', 'transcript_bytes', 'child_exit', 'normal_reaps', 'rescues')


def digest(path):
    data = path.read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True)
    ap.add_argument('--exact-work', action='store_true', help='Also require all eight fixed Exact37 work cohorts')
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'):
        ap.add_argument('--'+name, type=Path, required=True)
    a = ap.parse_args()
    repo = Path(__file__).resolve().parents[2]
    assert Path(__file__).resolve() == repo/'tools/rapid-profiler/verify_normal_session_two.py'
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    for p in (repo, a.toolchain, a.user_home, a.cargo_home):
        assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    assert a.raw.is_absolute() and a.raw.is_relative_to(repo/'ignored') and not a.raw.exists()
    assert a.raw.parent.resolve(strict=True) == a.raw.parent
    tools = {n: (a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo', 'rustc')}
    tools.update(python=Path(sys.executable).resolve(strict=True),
        **{n: Path('/usr/bin', n).resolve(strict=True) for n in ('git', 'gcc', 'readelf', 'strip')})
    env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home), PATH=str(a.toolchain/'bin')+':/usr/bin:/bin',
        RUSTC=str(a.toolchain/'bin/rustc'), CC=str(tools['gcc']), CARGO_TARGET_DIR=str(repo/'target'),
        CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
        CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true',
        CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true', CARGO_TERM_COLOR='never', LC_ALL='C',
        PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    def command(argv):
        data = subprocess.check_output(argv, cwd=repo, env=env, timeout=15)
        assert len(data) <= 8*MIB
        return data
    def git(*args): return command([str(tools['git']), '-C', str(repo), *args])
    assert git('rev-parse', '--show-toplevel').decode().strip() == str(repo)
    assert git('rev-parse', 'HEAD').decode().strip() == a.revision
    assert git('status', '--porcelain', '--untracked-files=no') == b''
    required = {'tools/rapid-profiler/verify_normal_session.py', 'tools/rapid-profiler/verify_normal_session_two.py',
        'tools/rapid-profiler/normal-work/check_session_two.py', 'tools/rapid-profiler/normal-work/session_two_driver.py',
        'tools/rapid-profiler/normal-work/test_session_two.py', 'tools/rapid-profiler/normal-work/session_driver.py',
        'tools/rapid-profiler/normal-work/exact_fixture.py', 'tools/rapid-profiler/normal-work/exact_session.py',
        'tools/rapid-profiler/selected-work/provenance.py',
        'tools/rapid-profiler/src/frontend_native/always_on/normal/two_callers.rs',
        'tools/rapid-profiler/src/frontend_native/always_on/normal/two_callers/native.rs',
        'tools/rapid-profiler/ordinary-interval/normal/session/two.rs',
        'tools/rapid-profiler/ordinary-interval/normal/session/two/check.rs',
        'tools/rapid-profiler/ordinary-interval/normal/session/two/worker.rs',
        'evaluation/admission/processes.py', 'tools/unwind-oracle/bounded_command.py'}
    if a.exact_work:
        required.update('tools/rapid-profiler/normal-work/'+n for n in (
            'test_exact_fixture.py', 'test_exact_session.py', 'exact_native.py', 'test_exact_native.py'))
        required.update(('tools/rapid-profiler/exact-work/exact_work.S',
            'tools/rapid-profiler/verify_ordinary_interval.py', 'tools/rapid-profiler/selected-work/test_provenance.py'))
    names = git('ls-files', '-z', '--', 'src', 'tests', 'tools/rapid-profiler', 'Cargo.toml', 'Cargo.lock',
        'README.md', 'build.rs', ':(glob)**/Cargo.toml', *sorted(required)).decode().rstrip('\0').split('\0')
    assert all(names) and len(names) == len(set(names)) and required.issubset(names)
    before = {n: digest(repo/n) for n in names}
    for n in names: assert (repo/n).read_bytes() == git('show', a.revision+':'+n)
    for name in ('cc1', 'collect2', 'as', 'ld'):
        reported = command([str(tools['gcc']), '-print-prog-name='+name]).decode('ascii').strip()
        assert reported and '\n' not in reported
        path = Path(reported) if '/' in reported else Path(shutil.which(reported, path=env['PATH']) or '')
        assert path.is_absolute(); tools[name] = path.resolve(strict=True)
    tool_hashes = {n: digest(p) for n, p in tools.items()}
    # Authenticate every project dependency before import; imports run no workload.
    prior = load('two_prior', repo/'tools/rapid-profiler/verify_normal_session.py')
    processes = load('two_processes', repo/'evaluation/admission/processes.py')
    census = load('two_census', repo/'tools/rapid-profiler/selected-work/check_output.py')
    if a.exact_work:
        # Canonical checker name serves the single reducer import, after Git authentication.
        assert 'check_session_two' not in sys.modules
        sys.modules['check_session_two'] = load('check_session_two', repo/'tools/rapid-profiler/normal-work/check_session_two.py')
        exact_work = load('two_exact_work', repo/'tools/rapid-profiler/normal-work/exact_session.py')
        exact_fixture = load('two_exact_fixture', repo/'tools/rapid-profiler/normal-work/exact_fixture.py')
        exact_native = load('two_exact_native', repo/'tools/rapid-profiler/normal-work/exact_native.py')
        shared = load('two_exact_flags', repo/'tools/rapid-profiler/verify_ordinary_interval.py')
    assert prior.TRIALS == TRIALS and len(prior.SESSION) == 19 and len(prior.SCHEDULE) == 7
    read, decode, integer, profile = prior.read, prior.decode, prior.integer, prior.PROFILE
    a.raw.mkdir(mode=0o700)
    save(a.raw/'sources-before.json', before)
    save(a.raw/'private-environment.json', dict(env=env, tools={n: str(p) for n, p in tools.items()}))
    result = dict(schema=1, status='FAILED', stage='setup', revision=a.revision,
        command=['$PYTHON', '-B', '$REPO/tools/rapid-profiler/verify_normal_session_two.py', '--revision', a.revision,
            '--raw', '$RAW', '--toolchain', '$TOOLCHAIN', '--user-home', '$USER_HOME', '--cargo-home', '$CARGO_HOME'],
        scope='Bounded two ordinary callers with complete external population; source-attested journal/receipt checks. No all-interleaving, timing, performance, executable reclamation or full-A5 claim.',
        sources=dict(count=len(before), manifest=digest(a.raw/'sources-before.json')), tools=tool_hashes,
        prerequisite=dict(status='UNRUN'), stages=[dict(name=n, status='UNRUN') for n in STAGES],
        trials=[dict(name=n, mode=m, k=k, status='UNRUN') for n, m, k in TRIALS])
    if a.exact_work:
        result['command'].append('--exact-work')
        result['stages'].extend(dict(name=n, status='UNRUN') for n in EXACT_STAGES)
        result['exact_work'] = dict(status='UNRUN', selection=dict(status='UNRUN'), native=dict(status='UNRUN'),
            trials=[dict(name=n, schedule=s, k=k, status='UNRUN') for n, s, k in EXACT_TRIALS],
            interpretation='Original-body semantic work, including RET; no hardware retired-instruction or duration truth. Exact signed retained-minus-population mean instruction error; zero retained remains unresolved.')
    artifacts = {}
    def pin(path, expected=None):
        got = digest(path)
        if expected is not None: assert got == expected
        if path in artifacts: assert artifacts[path] == got
        artifacts[path] = got
        return got
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
            if value == str(path) or value.startswith(str(path)+'/'): return token+value[len(str(path)):]
        assert not value.startswith('/') and '/home/' not in value and '@' not in value
        return value
    def closed_ok(closed):
        assert type(closed['exit_code']) is int and closed['exit_code'] == 0
        assert closed['termination'] is None and closed['cleanup_complete'] is True
        assert type(closed['reaped_descendants']) is int and closed['reaped_descendants'] == 0
    try:
        cpus = sorted(os.sched_getaffinity(0))[:4]
        assert len(cpus) == 4; os.sched_setaffinity(0, cpus)
        log_root = repo/'target/evaluation'; log_root.mkdir(parents=True, exist_ok=True)
        assert log_root.resolve(strict=True) == log_root
        logs = Path(tempfile.mkdtemp(prefix='normal-session-two-', dir=log_root))
        nested = a.raw/'single-prerequisite'
        argv = [str(tools['python']), '-B', str(repo/'tools/rapid-profiler/verify_normal_session.py'),
            '--revision', a.revision, '--raw', str(nested), '--toolchain', str(a.toolchain),
            '--user-home', str(a.user_home), '--cargo-home', str(a.cargo_home)]
        result['stage'] = 'single-prerequisite'; result['prerequisite']['status'] = 'FAILED'
        request = dict(argv=argv, env=env, affinity=cpus, wall_seconds=1800, output_bytes=8*MIB)
        save(a.raw/'prerequisite-command.json', request); pin(a.raw/'prerequisite-command.json')
        unchanged()
        closed = processes.run_command(argv, env, logs/'prerequisite.log', 1800, 8*MIB)
        (a.raw/'prerequisite.log').write_bytes((logs/'prerequisite.log').read_bytes())
        save(a.raw/'prerequisite-closed.json', closed); closed_ok(closed); unchanged()
        assert closed['private_log_sha256'] == digest(a.raw/'prerequisite.log')['sha256']
        old = read(nested/'result.json'); pin(nested/'result.json')
        assert old['status'] == 'PASS' and old['stage'] == 'complete' and old['revision'] == a.revision
        assert old['command'] == ['$PYTHON', '-B', '$REPO/tools/rapid-profiler/verify_normal_session.py',
            '--revision', a.revision, '--raw', '$RAW', '--toolchain', '$TOOLCHAIN', '--user-home', '$USER_HOME', '--cargo-home', '$CARGO_HOME']
        assert tuple(r['name'] for r in old['stages']) == prior.STAGES
        assert all(r['status'] == 'PASS' for r in old['stages']+old['trials'])
        assert tuple((r['name'], r['mode'], r['k']) for r in old['trials']) == TRIALS
        assert old['closure'] == dict(owned_stages=10, normal_helper_reaps=10, absence='ECHILD', producer_child_reaps=6, producer_rescues=0, owner_rescues=0)
        assert old['tools'] == tool_hashes
        sources = read(nested/'sources-before.json')
        pin(nested/'sources-before.json', old['sources']['manifest']); pin(nested/'sources-after.json')
        assert sources == read(nested/'sources-after.json') and old['sources']['count'] == len(sources)
        assert all(before[n] == h for n, h in sources.items())
        result['hardware'] = dict(old['hardware'], session_worker_cpus=2, session_controller_cpus=1)
        result['versions'] = old['versions']
        result['prerequisite'] = dict(status='PASS', result=digest(nested/'result.json'), closure=old['closure'],
            command=pin(a.raw/'prerequisite-command.json'), closed=pin(a.raw/'prerequisite-closed.json'), log=pin(a.raw/'prerequisite.log'),
            inherited_normal_state=dict(stable_pairs=16, crossed_pairs=1, scope='fixed prerequisite calls, not concurrent external population'))
        fixture = nested/'normal-prerequisite/strnlen-prerequisite'
        fixture_result = read(fixture/'result.json')
        normal_result = read(nested/'normal-prerequisite/result.json')
        pin(nested/'normal-prerequisite/result.json', old['prerequisite']['result'])
        pin(fixture/'result.json', normal_result['prerequisite']['result'])
        assert normal_result['revision'] == fixture_result['revision'] == a.revision
        assert normal_result['status'] == fixture_result['status'] == 'PASS'
        assert normal_result['tools'] == fixture_result['tools'] == tool_hashes
        assert normal_result['stage'] == fixture_result['stage'] == 'complete'
        assert {key: normal_result['native'][key] for key in ('pairs', 'stable_pairs', 'crossed_pairs', 'children',
            'target_calls', 'target_returns', 'outer_returns', 'helper_joins')} == dict(pairs=17, stable_pairs=16,
                crossed_pairs=1, children=34, target_calls=68, target_returns=68, outer_returns=34, helper_joins=1)
        selection = read(fixture/'selection.json'); pin(fixture/'selection.json', old['selection']['manifest'])
        assert selection['revision'] == a.revision and selection['label'] == 'freebsd-strnlen-14.1-v1'
        assert integer(selection['elf_va']) == 4096 and integer(selection['length']) == 41
        candidate, trusted = fixture/'candidate.so', fixture/'final.so'
        pin(candidate, old['selection']['candidate']); pin(trusted, old['selection']['final'])
        assert digest(trusted) == selection['final'] and digest(trusted)['sha256'] == prior.SUBJECT_SHA256
        assert candidate.read_bytes() == trusted.read_bytes()
        assert (candidate.stat().st_dev, candidate.stat().st_ino) != (trusted.stat().st_dev, trusted.stat().st_ino)
        offset = integer(selection['file_offset']); code = trusted.read_bytes()[offset:offset+41]
        assert len(code) == 41 and code[34] == code[40] == 0xc3
        assert dict(bytes=41, sha256=hashlib.sha256(code).hexdigest()) == selection['selected_code'] == old['selection']['selected_code']
        result['selection'] = old['selection']
        binary = repo/'target/release/ordinary-interval'
        pin(binary, old['binary']['content']); assert old['binary']['profile'] == dict(profile, test=False)
        result['binary'] = old['binary']

        def stage(name, argv, extra=None):
            unchanged(); result['stage'] = name
            row = next(r for r in result['stages'] if r['name'] == name); assert row['status'] == 'UNRUN'
            row.update(status='FAILED', command=[public(v) for v in argv], cpu_seconds=20, wall_seconds=30, file_bytes=4*MIB, owner_wall_seconds=55)
            d = a.raw/name; d.mkdir(); (d/'tmp').mkdir()
            stage_env = dict(env, TMPDIR=str(d/'tmp')); stage_env.update(extra or {})
            if extra: row['fixture_env'] = {k: public(v) for k, v in extra.items()}
            request = dict(argv=[str(v) for v in argv], cwd=str(repo), env=stage_env,
                stdout=str(d/'stdout.txt'), stderr=str(d/'stderr.txt'), cpu_seconds=20, wall_seconds=30, file_bytes=4*MIB)
            save(d/'request.json', request); pin(d/'request.json')
            parent = [str(tools['python']), '-B', str(repo/'tools/unwind-oracle/bounded_command.py'), '--request', str(d/'request.json'), '--receipt', str(d/'receipt.json')]
            parent_request = dict(argv=parent, env=env, affinity=cpus, wall_seconds=55, output_bytes=MIB)
            save(d/'parent-command.json', parent_request); pin(d/'parent-command.json')
            closed = processes.run_command(parent, env, logs/(name+'.log'), 55, MIB)
            (d/'parent.log').write_bytes((logs/(name+'.log')).read_bytes())
            save(d/'parent-closed.json', closed); closed_ok(closed)
            assert closed['private_log_sha256'] == digest(d/'parent.log')['sha256']
            assert read(d/'request.json') == request and read(d/'parent-command.json') == parent_request
            receipt = read(d/'receipt.json')
            assert type(receipt['exit']) is int and receipt['exit'] == 0
            assert receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
            assert receipt['absence_proof'] == 'ECHILD'
            assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
            assert receipt['cleanup_error'] is receipt['aborted'] is None
            assert receipt['request_sha256'] == digest(d/'request.json')['sha256']
            assert receipt['helper_sha256'] == before['tools/unwind-oracle/bounded_command.py']['sha256']
            assert read(d/'parent.log') == dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)
            for stream in ('stdout', 'stderr'): assert receipt[stream+'_sha256'] == digest(d/(stream+'.txt'))['sha256']
            row.update({n: pin(d/file) for n, file in (('receipt', 'receipt.json'), ('request', 'request.json'),
                ('parent_command', 'parent-command.json'), ('closed', 'parent-closed.json'), ('parent', 'parent.log'),
                ('stdout', 'stdout.txt'), ('stderr', 'stderr.txt'))})
            unchanged(); return d, row

        d, row = stage('parser-controls', [tools['python'], '-B', repo/'tools/rapid-profiler/normal-work/test_session_two.py'])
        assert (d/'stdout.txt').read_bytes() == b''
        assert re.fullmatch(rb'\.{15}\n-+\nRan 15 tests in [0-9]+\.[0-9]+s\n\nOK\n', (d/'stderr.txt').read_bytes())
        row.update(status='PASS', passed=PYTHON_CONTROLS)
        products = {}
        artifact_groups = (
            ('work-validator', 'ordinary-interval', 'ordinary-interval/main.rs', 'bin', 'bin'),
            ('whole-front', 'rapid_profiler', 'src/lib.rs', 'lib', 'lib'))
        if a.exact_work:
            artifact_groups += (('state-validator', 'frontend-native-calibrations', 'native-interval/calibrations.rs', 'test', 'bin'),)
        for label, target, source, kind, crate_type in artifact_groups:
            built = fixture/(label+'-build')/'stdout.txt'; listing = fixture/(label+'-list')
            for suffix, path in (('build', built), ('list', listing/'stdout.txt')):
                record = next(r for r in fixture_result['stages'] if r['name'] == label+'-'+suffix); pin(path, record['stdout'])
            messages = [decode(line) for line in built.read_bytes().splitlines()]
            assert messages[-1] == dict(reason='build-finished', success=True)
            found = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == target and m['profile']['test']]
            assert len(found) == 1
            p = found[0]; test_binary = Path(p['executable'])
            assert test_binary.resolve(strict=True) == test_binary and test_binary.parent == repo/'target/release/deps'
            assert re.fullmatch(re.escape(target.replace('-', '_'))+'-[0-9a-f]+', test_binary.name)
            assert p['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml') and p['target']['src_path'] == str(repo/'tools/rapid-profiler'/source)
            assert p['target']['kind'] == [kind] and p['target']['crate_types'] == [crate_type] and p['profile'] == profile
            assert type(p['fresh']) is bool and type(p['profile']['debuginfo']) is int and p['profile']['test'] is True
            assert p['profile']['debug_assertions'] is p['profile']['overflow_checks'] is True
            assert fixture_result['artifacts'][label]['profile'] == profile and p['fresh'] is fixture_result['artifacts'][label]['cargo_fresh']
            pin(test_binary, fixture_result['artifacts'][label]['binary'])
            record = next(r for r in fixture_result['stages'] if r['name'] == label+'-list'); pin(listing/'stderr.txt', record['stderr'])
            inventory = census.census((listing/'stdout.txt').read_bytes(), (listing/'stderr.txt').read_bytes())
            products[target] = (test_binary, inventory, p['fresh'])
        library, lib_inventory, lib_fresh = products['rapid_profiler']
        consumer, bin_inventory, bin_fresh = products['ordinary-interval']
        assert {n for n in lib_inventory if n.startswith(SDK_PREFIX) or n.startswith(OWNER_PREFIX)} == set(SDK+NATIVE)
        assert {n for n in bin_inventory if n.startswith(CONSUMER_PREFIX) and not n.startswith(EXACT_PREFIX)} == set(CONSUMER)
        assert {n for n in bin_inventory if n.startswith(EXACT_PREFIX)} == set(EXACT_CONSUMER)
        for name, artifact, inventory, methods, fresh in (
            ('sdk-controls', library, lib_inventory, SDK, lib_fresh), ('consumer-controls', consumer, bin_inventory, CONSUMER, bin_fresh)):
            d, row = stage(name, [artifact, *methods, '--exact', '--test-threads=1'])
            row.update(census.controls((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(), methods, inventory),
                binary=digest(artifact), profile=profile, full_census=len(inventory), cargo_fresh=fresh)
        fixture_env = dict(RAPID_NORMAL_TWO_CANDIDATE=str(candidate), RAPID_NORMAL_TWO_EXPECTED=str(trusted), RAPID_NORMAL_TWO_ELF_VA='4096', RAPID_NORMAL_TWO_LENGTH='41')
        for name, method in zip(('native-k1-zero', 'native-k1-one', 'native-e4'), NATIVE):
            d, row = stage(name, [library, method, '--exact', '--ignored', '--test-threads=1'], fixture_env)
            row.update(census.controls((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(), (method,), lib_inventory),
                binary=digest(library), profile=profile, full_census=len(lib_inventory), actual_caller_threads=2,
                required_worker_joins=2, internal_absolute_seconds=15, interpretation='Source-attested public owner controls; no new traced full-state population.')
        numeric = []
        for trial, (name, mode, k) in zip(result['trials'], TRIALS):
            trial['status'] = 'FAILED'; output = a.raw/name/'producer'
            d, row = stage(name, [tools['python'], '-B', repo/'tools/rapid-profiler/normal-work/session_two_driver.py',
                '--binary', binary, '--candidate', candidate, '--trusted', trusted, '--elf-va', '4096', '--length', '41',
                '--output', output, '--k', str(k), '--mode', mode])
            assert (d/'stderr.txt').read_bytes() == b''
            summary = read(output/'result.json'); assert decode((d/'stdout.txt').read_bytes()) == summary
            assert summary['status'] == 'PASS' and summary['mode'] == mode and summary['k'] == k
            assert integer(summary['normal_reaps']) == 1 and integer(summary['rescues']) == 0 and summary['absence'] == 'ECHILD'
            assert summary['rescue'] is False and type(summary['child_exit']) is int and integer(summary['input_bytes'], 1) > 0
            transcript, errors, metadata = pin(output/'stdout.txt'), pin(output/'stderr.txt'), pin(output/'result.json')
            assert transcript == dict(bytes=integer(summary['transcript_bytes'], 1, 4*MIB), sha256=summary['transcript_sha256'])
            outcome = 'EXPECTED_REFUSAL' if mode in ('duplicate', 'eof') else 'COMPLETE'
            public_summary = {key: summary[key] for key in ('input_bytes', 'transcript_bytes', 'child_exit', 'normal_reaps', 'rescues')}
            if outcome == 'EXPECTED_REFUSAL':
                assert summary['control'] == mode and summary['expected_refusal'] is True
                assert type(summary['exit_code']) is int and summary['exit_code'] == summary['child_exit'] == 1
                assert b'DONE,' not in (output/'stdout.txt').read_bytes()
                error = (output/'stderr.txt').read_bytes()
                assert b'normal-session-two FAILED:' in error
                assert (b'duplicate request ID' if mode == 'duplicate' else b'overlong or unterminated request') in error
            else:
                assert summary['child_exit'] == 0 and errors['bytes'] == 0
                expected_calls, expected_flushes = (40, 5) if mode == 'full' else ((64, 0) if mode == 'stop' else (1024, 1))
                assert summary['calls'] == expected_calls and summary['flushes'] == expected_flushes and summary['accepted'] == expected_calls+expected_flushes
                assert summary['admitted'] == summary['retained']+summary['dropped'] and summary['calls'] == summary['admitted']+summary['unsampled']
                assert summary['cancelled'] == summary['unfinished'] == 0 and summary['detaches'] == summary['joins'] == 2
                assert summary['actions'] == summary['arms']+1 and 1 <= summary['arms'] <= 520
                assert summary['stop_reason'] == ('Requested' if mode == 'stop' else 'EpochLimit')
                if mode != 'stop': assert summary['arms'] == 520
                assert 1 <= summary['maximum_batch_calls'] <= 4 and 1 <= summary['batches'] <= expected_calls <= 4*summary['batches']
                workers = summary['workers']; assert len(workers) == 2
                for w in workers:
                    assert set(w) == {'worker', 'registration', 'tid', 'calls', 'completed', 'unsampled', 'batches', 'maximum_entry_prefix'}
                    for value in w.values(): integer(value)
                    assert w['maximum_entry_prefix'] <= summary['actions']
                assert [w['worker'] for w in workers] == [w['registration'] for w in workers] == [1, 2]
                assert [w['calls'] for w in workers] == [expected_calls//2]*2
                assert workers[0]['tid'] != workers[1]['tid'] and all(integer(w['tid'], 1, (1 << 31)-1) for w in workers)
                for w in workers:
                    assert w['completed']+w['unsampled'] == w['calls'] and 1 <= w['batches'] <= w['calls'] <= 4*w['batches']
                for key in ('batches', 'completed', 'unsampled'):
                    assert sum(w[key] for w in workers) == summary['admitted' if key == 'completed' else key]
                if mode == 'full': assert all(w['maximum_entry_prefix'] >= 513 for w in workers)
                if mode == 'backpressure': assert summary['write_blocked_at_finalize'] > 0
                owners = summary['owners']; assert set(owners).issubset({'sampled', 'closed', 'removed', 'initial'})
                assert all(type(n) is int and n > 0 for n in owners.values()) and sum(owners.values()) == expected_calls
                assert owners.get('sampled', 0) == summary['admitted']
                for key in FIELDS[4:]:
                    if key in summary: public_summary[key] = integer(summary[key])
                public_summary.update(worker1_calls=workers[0]['calls'], worker2_calls=workers[1]['calls'], owners=owners, stop_reason=summary['stop_reason'])
            trial.update(status='PASS', outcome=outcome, summary=public_summary, result=metadata, transcript=transcript, stderr=errors)
            row['status'] = 'PASS'
            numeric.append(dict(case=name, outcome=outcome, k=k, epochs=520,
                **{key: public_summary[key] for key in FIELDS[4:] if key in public_summary}))
            unchanged()
        with (a.raw/'sessions-two.csv').open('x', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator='\n'); writer.writeheader(); writer.writerows(numeric)
        if a.exact_work:
            group = result['exact_work']; group['status'] = 'FAILED'
            for name, script, count in (
                ('exact-fixture-controls', 'test_exact_fixture.py', 4),
                ('exact-parser-controls', 'test_exact_session.py', 8),
                ('exact-native-parser-controls', 'test_exact_native.py', 8)):
                d, row = stage(name, [tools['python'], '-B', repo/'tools/rapid-profiler/normal-work'/script])
                assert (d/'stdout.txt').read_bytes() == b''
                assert re.fullmatch(rb'\.{'+str(count).encode()+rb'}\n-+\nRan '+str(count).encode()+rb' tests in [0-9]+\.[0-9]+s\n\nOK\n', (d/'stderr.txt').read_bytes())
                row.update(status='PASS', passed=count)
            calibration, inventory, fresh = products['frontend-native-calibrations']
            prefixes = ('oracle::native_ordinary::normal_caller::exact_tests::', 'exact_body::', 'exact_truth::')
            assert {n for n in inventory if n.startswith(prefixes)} == set(EXACT_STATE)
            for name, artifact, listing, methods, cargo_fresh in (
                ('exact-consumer-controls', consumer, bin_inventory, EXACT_CONSUMER, bin_fresh),
                ('exact-state-controls', calibration, inventory, EXACT_STATE, fresh)):
                d, row = stage(name, [artifact, *methods, '--exact', '--test-threads=1'])
                row.update(census.controls((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(), methods, listing),
                    binary=digest(artifact), profile=profile, full_census=len(listing), cargo_fresh=cargo_fresh)

            # Independent complete ELF authority exists and is hashed BEFORE any candidate copy.
            exact_final, exact_candidate = a.raw/'exact-final.so', a.raw/'exact-candidate.so'
            d, row = stage('exact-build', [tools['gcc'], *shared.CFLAGS,
                repo/'tools/rapid-profiler/exact-work/exact_work.S', '-o', exact_final])
            assert (d/'stdout.txt').read_bytes() == (d/'stderr.txt').read_bytes() == b''
            final_hash = pin(exact_final); assert 0 < final_hash['bytes'] <= MIB
            details = exact_fixture.describe(exact_final.read_bytes())
            assert details['final'] == final_hash and details['length'] == 37
            exact_selection = a.raw/'exact-selection.json'
            save(exact_selection, dict(details, revision=a.revision))
            manifest = pin(exact_selection)
            unchanged()
            with exact_candidate.open('xb') as stream: stream.write(exact_final.read_bytes())
            candidate_hash = pin(exact_candidate, final_hash)
            assert exact_fixture.authenticate(exact_candidate, exact_final, details['elf_va'], 37,
                exact_selection, manifest['sha256']) == details
            row['status'] = 'PASS'
            group['selection'] = dict(status='PASS', **details, candidate=candidate_hash, manifest=manifest,
                build_stage='exact-build', assembly=before['tools/rapid-profiler/exact-work/exact_work.S'])
            normal_dir = nested/'normal-prerequisite'
            caller_final, caller_candidate = normal_dir/'caller.so', normal_dir/'caller-candidate.so'
            pin(caller_final, normal_result['artifacts']['caller'])
            pin(caller_candidate, normal_result['artifacts']['caller'])
            assert caller_candidate.read_bytes() == caller_final.read_bytes()
            assert (caller_candidate.stat().st_dev, caller_candidate.stat().st_ino) != (caller_final.stat().st_dev, caller_final.stat().st_ino)
            native_binary = repo/'target/release/frontend-native-oracle'
            native_artifact = fixture_result['artifacts']['frontend-native-oracle']
            pin(native_binary, native_artifact['binary'])
            assert digest(native_binary) == normal_result['artifacts']['frontend-native-oracle']
            assert native_artifact['profile'] == dict(profile, test=False)
            assert type(native_artifact['cargo_fresh']) is bool
            output = a.raw/'exact-native-output'
            d, row = stage('exact-state', [native_binary, 'normal-exact-state', exact_candidate, exact_final,
                str(details['elf_va']), '37', caller_candidate, caller_final, output])
            native_table = output/'normal-exact-pairs.csv'
            observed = exact_native.check(native_table.read_bytes(), (d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes())
            assert observed['status'] == 'FUNCTIONAL_PASS' and observed['pairs'] == 4
            group['native'] = dict(observed, table=pin(native_table), binary=native_artifact,
                caller=digest(caller_final), internal_absolute_seconds_per_pair=15, cumulative_steps_per_child=20000,
                scope='Four fixed original/installed ordinary-call pairs, separate from the concurrent external population.')
            row['status'] = 'PASS'
            tables = []
            assert exact_work.SCHEDULES == ('short', 'long', 'alternating', 'late-long')
            for trial, (name, schedule, k) in zip(group['trials'], EXACT_TRIALS):
                trial['status'] = 'FAILED'; output = a.raw/name/'producer'
                # Freeze all complete inputs/IDs independently before the producer process.
                planned = exact_work.commands(schedule, k)
                intended = (json.dumps([list(c[:3])+[c[3].hex()] if c[0] == 'CALL' else list(c)
                    for c in planned], separators=(',', ':'))+'\n').encode('ascii')
                assert len(planned) == 49 and 0 < len(intended) <= 16384
                d, row = stage(name, [tools['python'], '-B', repo/'tools/rapid-profiler/normal-work/session_two_driver.py',
                    '--binary', binary, '--candidate', exact_candidate, '--trusted', exact_final,
                    '--elf-va', str(details['elf_va']), '--length', '37', '--output', output,
                    '--k', str(k), '--mode', 'exact', '--schedule', schedule,
                    '--selection', exact_selection, '--selection-sha256', manifest['sha256']])
                assert (d/'stderr.txt').read_bytes() == (output/'stderr.txt').read_bytes() == b''
                summary = read(output/'result.json'); assert decode((d/'stdout.txt').read_bytes()) == summary
                assert summary['status'] == 'PASS' and summary['mode'] == 'exact' and summary['schedule'] == schedule and summary['k'] == k
                assert type(summary['child_exit']) is int and summary['child_exit'] == 0
                assert summary['normal_reaps'] == 1 and summary['rescues'] == 0 and summary['absence'] == 'ECHILD' and summary['rescue'] is False
                transcript = (output/'stdout.txt').read_bytes()
                checked, work_rows = exact_work.measure(transcript.decode('ascii'), schedule, k, 520)
                assert all(summary[key] == value for key, value in checked.items())
                assert summary['work_rows'] == work_rows
                for key, value in dict(calls=48, accepted=49, flushes=1, arms=520, actions=521, detaches=2, joins=2).items():
                    assert integer(summary[key]) == value
                assert summary['stop_reason'] == 'EpochLimit' and summary['cancelled'] == summary['unfinished'] == 0
                assert (output/'intended.json').read_bytes() == intended
                assert summary['intended_bytes'] == len(intended) and summary['intended_sha256'] == hashlib.sha256(intended).hexdigest()
                wire = b''.join((f'CALL {c[1]} {c[2]} {c[3].hex()}\n' if c[0] == 'CALL'
                    else f'FLUSH {c[1]}\n').encode('ascii') for c in planned)
                assert integer(summary['input_bytes']) == len(wire)
                assert pin(output/'stdout.txt') == dict(bytes=integer(summary['transcript_bytes'], 1, 4*MIB), sha256=summary['transcript_sha256'])
                work_table = exact_work.encode(work_rows)
                assert (output/'work.csv').read_bytes() == work_table
                assert pin(output/'work.csv') == dict(bytes=integer(summary['work_bytes'], 1, 8192), sha256=summary['work_sha256'])
                assert exact_fixture.authenticate(exact_candidate, exact_final, details['elf_va'], 37,
                    exact_selection, manifest['sha256']) == details
                trial.update(status='PASS', result=pin(output/'result.json'), transcript=pin(output/'stdout.txt'),
                    stderr=pin(output/'stderr.txt'), intended=pin(output/'intended.json'), work=pin(output/'work.csv'),
                    counts={key: summary[key] for key in ('calls', 'admitted', 'retained', 'dropped', 'unsampled',
                        'batches', 'arms', 'actions', 'flushes', 'detaches', 'joins', 'normal_reaps', 'rescues')})
                tables.append(work_table); row['status'] = 'PASS'; unchanged()
            assert len(tables) == 8 and all(t.splitlines()[0] == tables[0].splitlines()[0] for t in tables)
            combined = tables[0]+b''.join(t.split(b'\n', 1)[1] for t in tables[1:])
            assert len(combined.splitlines()) == 25 and len(combined) <= 8*8192
            (a.raw/'exact-work.csv').write_bytes(combined)
            assert all(t['status'] == 'PASS' for t in group['trials'])
            group.update(status='PASS', output=pin(a.raw/'exact-work.csv'), rows=24, population_calls=384,
                closure=dict(owned_stages=15, normal_helper_reaps=15, absence='ECHILD', native_child_reaps=8,
                    producer_child_reaps=8, producer_rescues=0, owner_rescues=0))
        unchanged(); save(a.raw/'sources-after.json', {n: digest(repo/n) for n in names})
        assert tuple(r['name'] for r in result['stages']) == STAGES+(EXACT_STAGES if a.exact_work else ())
        assert all(r['status'] == 'PASS' for r in result['stages']+result['trials'])
        result.update(status='PASS', stage='complete', output=digest(a.raw/'sessions-two.csv'),
            closure=dict(owned_stages=len(result['stages']), normal_helper_reaps=len(result['stages']), absence='ECHILD',
                producer_child_reaps=14 if a.exact_work else 6, producer_rescues=0, owner_rescues=0),
            limits=dict(epochs=520, period_ms=10, arm_lateness_ms=2, shutdown_seconds=2, producer_absolute_seconds=15,
                producer_cpu_seconds=20, producer_wall_seconds=30, producer_file_bytes=4*MIB, backpressure_stdout_delay_ms=250),
            prior_failures='Fresh attempt only; no retry, omitted population or discarded failure.',
            interpretation='Complete intended external population plus source-attested full journal/Report checks. Three finite two-thread owner controls and fixed inherited state cases do not establish arbitrary concurrent interleavings or full A5.')
    except BaseException as error:
        result['error_type'] = type(error).__name__; (a.raw/'failure.txt').write_text(traceback.format_exc())
    finally:
        save(a.raw/'result.json', result)
    print('normal-session-two-qualification '+result['status']+' stage='+result['stage'])
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
