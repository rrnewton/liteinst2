#!/usr/bin/env python3
"""Fresh release qualification of normal C callers; no performance claim."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import traceback

MIB = 1048576
CALLER_FLAGS = ['-O2', '-fPIC', '-fno-stack-protector', '-fno-asynchronous-unwind-tables',
    '-fno-unwind-tables', '-fcf-protection=none', '-Wall', '-Wextra', '-Werror',
    '-shared', '-nostdlib', '-Wl,-Bsymbolic,--no-undefined,--build-id=none,-z,relro,-z,now,-z,noexecstack']
RUNTIME = ('pending_ret_is_not_completion_and_k1_next_entry_finishes_before_admission',
    'pending_function_closed_retains_epoch_permit_after_report_retirement',
    'old_a_and_b_pending_receipts_keep_original_owner_across_rearm_c',
    'geometry_duplicate_ret_recursion_and_wrong_ack_refuse_before_consumption',
    'thirty_two_call_bound_preserves_last_return_and_rejects_next_admission',
    'checkpoint_validates_whole_journal_and_pending_identity_before_finish',
    'allocation_refusal_and_caught_busy_unwind_keep_pending_first_error',
    'transfer_reuses_buffers_without_resetting_absolute_identity_or_model_sequence',
    'gated_site_cannot_be_relabelled_into_normal_preparation',
    'streaming_normal_pending_owner_survives_600_actions_without_return_acknowledgement',
    'streaming_normal_closed_and_removed_records_join_after_repeated_idle_drains',
    'streaming_normal_upper_prefix_corruption_refuses_before_consuming_pending_owner')
CALLER = ('normal_caller_literal_body_and_every_changed_byte_refuse',
    'normal_caller_dynamic_refuses_load_time_execution_and_dependencies',
    'normal_caller_mapping_requires_complete_exact_rx_owner',
    'normal_caller_complete_elf_refuses_wrong_symbol_body_load_and_dynamic')
STATE = ('normal_ready_refuses_wrong_caller_maps_and_extents',
    'normal_wire_refuses_truncation_tail_and_journal_profile',
    'normal_transfers_refuse_wrong_target_word_rsp_and_order',
    'normal_epilogue_data_and_pending_journal_refuse',
    'normal_original_caller_transition_effects_refuse',
    'normal_control_ack_refuses_wrong_stage_identity_owner_and_tail',
    'normal_population_refuses_missing_second_body_order_and_coverage',
    'normal_mode_and_completion_counts_preserve_fixed_bounds')
CHILD = ('normal_native_rows_require_exact_next_entry_and_checkpoint',
    'normal_native_rows_bind_continuation_owner_prefix_and_complete_journal')
STAGES = ('parser-controls', 'runtime-controls', 'caller-controls', 'state-controls',
    'child-controls', 'caller-build', 'normal-state', 'normal-work', 'drop-sampled', 'drop-closed')


# Independent closed lists: no import of the external-session producer/recipe.
EXACT_PREFIXES = ('oracle::native_ordinary::normal_caller::exact_tests::', 'exact_body::', 'exact_truth::')
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
REFERENCE_WITNESS_PREFIX = 'oracle::native_ordinary::normal_caller::reference::tests::'
REFERENCE_WITNESS = tuple(REFERENCE_WITNESS_PREFIX+n for n in (
    'ready_envelope_requires_owned_cells_and_exact_tail',
    'helper_effects_preserve_complete_state',
    'rdtscp_outputs_require_actual_width_and_store_identity',
    'reader_restoration_and_head_order_are_exact',
    'calls_returns_keep_actual_words_and_full_stack',
    'postflight_requires_outer_return_and_complete_cells',
    'cell_page_requires_full_guards_and_disjoint_ranges',
    'pair_counts_require_all_heads_readers_stores_and_reaps'))
REFERENCE_GEOMETRY_NAMES = ('normal_reference_body_every_opcode_bit_and_extent',
    'normal_reference_labels_require_exact_addresses_and_no_wrap',
    'normal_reference_reader_boundaries_and_cell_isolation',
    'normal_reference_fresh_identity_phase_stack_result_and_canary',
    'normal_reference_endpoint_high_words_aux_and_regression',
    'normal_reference_zero_and_full_width_endpoints_are_retained')
REFERENCE_GEOMETRY_PREFIX = 'oracle::native_ordinary::normal_caller::reference::bytes::tests::'
REFERENCE_GEOMETRY = tuple(REFERENCE_GEOMETRY_PREFIX+n for n in REFERENCE_GEOMETRY_NAMES)
REFERENCE_OWNER_PREFIX = 'normal::caller::reference::tests::'
REFERENCE_OWNER = tuple(REFERENCE_OWNER_PREFIX+n for n in (
    'reference_owner_profiles_keep_exact_function_body_and_legacy_identity',
    'reference_owner_all_hidden_labels_require_exact_shape_and_address',
    'reference_owner_linker_localization_is_closed_not_candidate_selected',
    'reference_owner_retains_segment_dynamic_cet_and_section_refusals'))
REFERENCE_OWNER_GEOMETRY_PREFIX = 'normal::caller::reference_bytes::tests::'
REFERENCE_OWNER_GEOMETRY = tuple(REFERENCE_OWNER_GEOMETRY_PREFIX+n for n in REFERENCE_GEOMETRY_NAMES)
REFERENCE_CHILD_PREFIX = 'normal_check::reference_tests::'
REFERENCE_CHILD = tuple(REFERENCE_CHILD_PREFIX+n for n in (
    'normal_reference_rows_require_fixed_continuations_and_complete_journal',
    'normal_reference_postflight_requires_exact_cells_identity_stack_and_order'))
REFERENCE_STAGES = ('reference-fixture-controls', 'reference-exact-parser-controls',
    'reference-parser-controls', 'reference-exact-controls', 'reference-witness-controls',
    'reference-geometry-controls', 'reference-owner-controls', 'reference-owner-geometry-controls',
    'reference-child-controls', 'reference-exact-build', 'reference-caller-build',
    'reference-old-exact-state', 'reference-state')


REFERENCE_WORK_STAGES = ('reference-work-parser-controls', 'reference-work-controls', 'reference-work')
REFERENCE_WORK_PREFIXES = ('normal::reference::', 'normal::caller::reference_bytes::returned_tests::')
REFERENCE_WORK_CONTROLS = (
    'normal::reference::tests::fixed_population_preserves_inputs_scalars_and_complete_work',
    'normal::reference::tests::full_cell_page_guards_and_disjoint_extents_are_required',
    'normal::reference::tests::original_rows_keep_sdk_fields_absent_and_full_width_endpoints',
    'normal::reference::check::tests::reference_population_requires_all48_ordered_case_identity_and_values',
    'normal::reference::check::tests::reference_record_joins_stack_continuation_owner_ack_and_metadata',
    'normal::reference::check::tests::reference_journal_checks_every_word_and_coherent_prefix_corruption',
    'normal::reference::check::tests::reference_report_requires_all_slots_ranks_payloads_and_terminal_identity',
    'normal::reference::check::tests::reference_history_requires_exact_publish_remove_and_no_failed_owner',
    'normal::reference::check::tests::reference_gap_arithmetic_retains_zero_and_refuses_aux_order_or_overflow',
    'normal::caller::reference_bytes::returned_tests::returned_view_requires_exact_identity_phase_value_and_cell_words',
    'normal::caller::reference_bytes::returned_tests::returned_view_checks_whole_stack_range_without_wrap_or_holes',
    'normal::caller::reference_bytes::returned_tests::returned_view_retains_zero_full_width_and_refuses_reversed_endpoints',
    'normal::reference::hardware::tests::admission_requires_every_explicit_feature_and_user_access',
)


REFERENCE_LEG_STAGES = ('reference-leg-parser-controls', 'reference-leg-controls',
    'reference-leg-original', 'reference-leg-installed')
REFERENCE_LEG_PREFIXES = ('normal::reference::leg::', 'normal::reference::check::leg_tests::')
REFERENCE_LEG_CONTROLS = (
    'normal::reference::leg::tests::leg_arguments_require_closed_phase_mode_and_canonical_nonzero_trial',
    'normal::reference::leg::tests::leg_storage_requires_exact_fresh_or_completed_prefix',
    'normal::reference::leg::tests::leg_rows_and_terminal_preserve_manifest_and_original_absence',
    'normal::reference::check::leg_tests::leg_valid_local_population_and_zero_endpoints',
    'normal::reference::check::leg_tests::leg_identity_and_48_row_boundary_are_distinct',
    'normal::reference::check::leg_tests::leg_population_scalar_case_and_order_are_exact',
    'normal::reference::check::leg_tests::leg_clock_aux_stack_and_pair_rsp_are_exact',
    'normal::reference::check::leg_tests::installed_leg_keeps_metadata_record_and_full_journal_joins',
    'normal::reference::check::leg_tests::installed_leg_keeps_report_and_history_joins',
)


OBSERVER_WORK_STAGES = ('observer-work-parser-controls', 'observer-work-controls',
    'observer-work-native', 'observer-work-always-on')
OBSERVER_WORK_PREFIX = 'normal::observer::tests::'
OBSERVER_WORK_CONTROLS = tuple(OBSERVER_WORK_PREFIX+n for n in (
    'fixed_population_modes_and_scalar_work_are_exact',
    'batch_metadata_keeps_lifetime_identity_across_all128_drains',
    'records_refuse_wrong_owner_continuation_stack_and_acknowledgement',
    'journal_checks_all512_words_including_tail_and_absolute_slots',
    'reports_and_history_require_all3072_payloads_and_two_actions',
    'population_refuses_missing_duplicate_and_changed_returns',
    'wire_native_absence_and_raw_full_width_endpoints_are_exact'))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    data = path.read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True)
    ap.add_argument('--reference-exact', action='store_true', help='Append four old Exact37 and four reference Exact37 pairs after all ordinary prerequisites.')
    ap.add_argument('--reference-work', action='store_true', help='Require --reference-exact and append the finite uncalibrated24+24 ordinary-call collector.')
    ap.add_argument('--reference-leg', action='store_true', help='Require --reference-work and --reference-exact; append fresh qualification/trial1 original and installed processes,24 calls each.')
    ap.add_argument('--observer-work', action='store_true', help='Require all reference prerequisites; append fresh native and always-on processes with3072 calls each.')
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'):
        ap.add_argument('--'+name, type=Path, required=True)
    a = ap.parse_args()
    assert not a.reference_work or a.reference_exact, '--reference-work requires --reference-exact'
    assert not a.reference_leg or (a.reference_work and a.reference_exact), '--reference-leg requires --reference-work and --reference-exact'
    assert not a.observer_work or (a.reference_leg and a.reference_work and a.reference_exact), '--observer-work requires --reference-leg, --reference-work and --reference-exact'
    repo = Path(__file__).resolve().parents[2]
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    for p in (repo, a.toolchain, a.user_home, a.cargo_home):
        assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    assert a.raw.is_absolute() and a.raw.is_relative_to(repo/'ignored') and not a.raw.exists()
    assert a.raw.parent.resolve(strict=True) == a.raw.parent
    env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home),
        PATH=str(a.toolchain/'bin')+':/usr/bin:/bin', RUSTC=str(a.toolchain/'bin/rustc'),
        CC=str(Path('/usr/bin/gcc').resolve(strict=True)), CARGO_TARGET_DIR=str(repo/'target'),
        CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true',
        CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0',
        CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        CARGO_TERM_COLOR='never', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    def git(*args):
        data = subprocess.check_output(['/usr/bin/git', '-C', str(repo), *args], env=env, timeout=15)
        assert len(data) <= MIB
        return data
    assert git('rev-parse', '--show-toplevel').decode().strip() == str(repo)
    assert git('rev-parse', 'HEAD').decode().strip() == a.revision
    assert git('status', '--porcelain', '--untracked-files=no') == b''
    required = {'tools/rapid-profiler/verify_normal_interval.py',
        'tools/rapid-profiler/ordinary-interval/joined_task.rs',
        'tools/rapid-profiler/verify_strnlen_interval.py', 'evaluation/admission/processes.py',
        'tools/unwind-oracle/bounded_command.py', 'tools/rapid-profiler/selected-work/check_output.py',
        'tools/rapid-profiler/normal-work/check_output.py', 'tests/call_tree_truth.rs'}
    if a.reference_exact:
        required.update('tools/rapid-profiler/'+name for name in (
            'verify_ordinary_interval.py', 'exact-work/exact_work.S',
            'normal-work/exact_fixture.py', 'normal-work/test_exact_fixture.py',
            'normal-work/exact_native.py', 'normal-work/test_exact_native.py',
            'normal-work/reference_native.py', 'normal-work/test_reference_native.py',
            'normal-work/reference_caller.S', 'normal-work/reference_bytes.rs',
            'normal-work/reference_owner.rs', 'native-interval/normal/reference.rs'))
        required.update(('tests/support/native_normal_reference.rs',
            'tests/support/native_normal_reference_tests.rs'))
    if a.reference_work:
        required.update('tools/rapid-profiler/'+name for name in (
            'normal-work/reference_work.py', 'normal-work/test_reference_work.py',
            'ordinary-interval/normal/reference.rs', 'ordinary-interval/normal/reference/check.rs'))
    if a.reference_leg:
        required.update('tools/rapid-profiler/'+name for name in (
            'normal-work/reference_leg.py', 'normal-work/test_reference_leg.py',
            'ordinary-interval/normal/reference/leg.rs',
            'ordinary-interval/normal/reference/check/leg_tests.rs'))
    if a.observer_work:
        required.update('tools/rapid-profiler/'+name for name in (
            'normal-work/observer_work.py', 'normal-work/test_observer_work.py',
            'ordinary-interval/normal/observer.rs'))
    names = git('ls-files', '-z', '--', 'src', 'tests/support', 'tools/rapid-profiler',
        'Cargo.toml', 'Cargo.lock', 'README.md', 'build.rs', ':(glob)**/Cargo.toml', *sorted(required)).decode().rstrip('\0').split('\0')
    assert all(names) and len(names) == len(set(names)) and required.issubset(names)
    before = {name: digest(repo/name) for name in names}
    for name in names:
        assert (repo/name).read_bytes() == git('show', a.revision+':'+name)
    # Every imported source and transitive prerequisite is authenticated first.
    processes = load('normal_processes', repo/'evaluation/admission/processes.py')
    census = load('normal_census', repo/'tools/rapid-profiler/selected-work/check_output.py')
    check = load('normal_output', repo/'tools/rapid-profiler/normal-work/check_output.py')
    prior = load('normal_prior', repo/'tools/rapid-profiler/verify_strnlen_interval.py')
    if a.reference_exact:
        shared = load('normal_reference_shared', repo/'tools/rapid-profiler/verify_ordinary_interval.py')
        exact_fixture = load('normal_reference_fixture', repo/'tools/rapid-profiler/normal-work/exact_fixture.py')
        exact_native = load('normal_reference_exact_output', repo/'tools/rapid-profiler/normal-work/exact_native.py')
        reference_native = load('normal_reference_output', repo/'tools/rapid-profiler/normal-work/reference_native.py')
    if a.reference_work:
        reference_work = load('normal_reference_work_output', repo/'tools/rapid-profiler/normal-work/reference_work.py')
    if a.reference_leg:
        reference_leg = load('normal_reference_leg_output', repo/'tools/rapid-profiler/normal-work/reference_leg.py')
    if a.observer_work:
        observer_work = load('normal_observer_work_output', repo/'tools/rapid-profiler/normal-work/observer_work.py')
    a.raw.mkdir(mode=0o700)
    save(a.raw/'sources-before.json', before)
    result = dict(schema=1, status='FAILED', stage='setup', revision=a.revision,
        scope='One bounded scalar leaf called by real C code; no arbitrary-application, accuracy, performance or complete-A5 claim.',
        command=['$PYTHON', '-B', '$REPO/tools/rapid-profiler/verify_normal_interval.py',
            '--revision', a.revision, '--raw', '$RAW', '--toolchain', '$TOOLCHAIN',
            '--user-home', '$USER_HOME', '--cargo-home', '$CARGO_HOME'], stages=[],
        sources=dict(count=len(before), manifest=digest(a.raw/'sources-before.json')))
    if a.reference_exact:
        result['command'].append('--reference-exact')
        result['reference_exact'] = dict(status='UNRUN', required_stages=list(REFERENCE_STAGES),
            stages=[dict(name=name, status='UNRUN') for name in REFERENCE_STAGES],
            subject=dict(status='UNRUN'), caller=dict(status='UNRUN'),
            old_exact=dict(status='UNRUN', required_pairs=4), reference=dict(status='UNRUN', required_pairs=4),
            scope='Fixed physical reference-reader/store/return provenance and complete architectural comparisons; no duration accuracy, performance or complete-A5 claim.')
    if a.reference_work:
        result['command'].append('--reference-work')
        result['reference_work'] = dict(status='UNRUN', required_stages=list(REFERENCE_WORK_STAGES),
            stages=[dict(name=name, status='UNRUN') for name in REFERENCE_WORK_STAGES],
            collector=dict(status='UNRUN', originals=24, installed=24),
            scope='Finite one-caller raw reference/callback enclosures and complete functional joins only; no calibrated accuracy, perturbation, session-temporal, performance or full-A5 claim.')
    if a.reference_leg:
        result['command'].append('--reference-leg')
        result['reference_leg'] = dict(status='UNRUN', required_stages=list(REFERENCE_LEG_STAGES),
            stages=[dict(name=name, status='UNRUN') for name in REFERENCE_LEG_STAGES],
            legs=[dict(status='UNRUN', phase='qualification', trial=1, leg=leg, calls=24)
                for leg in ('original', 'installed')],
            scope='Two fresh finite single-leg processes with all24 raw rows each. No calibration campaign, estimate, cross-process clock/address identity, accuracy, performance or full-A5 claim.')
    if a.observer_work:
        result['command'].append('--observer-work')
        result['observer_work'] = dict(status='UNRUN', required_stages=list(OBSERVER_WORK_STAGES),
            stages=[dict(name=name, status='UNRUN') for name in OBSERVER_WORK_STAGES],
            modes=[dict(status='UNRUN', mode=mode, calls=3072) for mode in ('native', 'always-on')],
            scope='Two fresh processes with the same3072 actual calls;128 always-on journal drains retain lifetime identity. Functional qualification only; no performance or full-A5 claim.')
    artifacts = {}
    tool_paths = {}
    def unchanged():
        assert git('rev-parse', 'HEAD').decode().strip() == a.revision
        assert git('status', '--porcelain', '--untracked-files=no') == b''
        assert {n: digest(repo/n) for n in names} == before
        assert all(digest(p) == value for p, value in artifacts.items())
        if tool_paths:
            assert {n: digest(p) for n, p in tool_paths.items()} == result['tools']
    def public(value):
        value = str(value)
        for n, path in tool_paths.items():
            if value == str(path): return '$'+n.upper()
        for path, token in ((a.raw, '$RAW'), (repo, '$REPO'), (a.toolchain, '$TOOLCHAIN'),
                            (a.cargo_home, '$CARGO_HOME'), (a.user_home, '$USER_HOME')):
            if value == str(path) or value.startswith(str(path)+'/'):
                return token+value[len(str(path)):]
        assert not value.startswith('/') and '/home/' not in value and '@' not in value
        return value
    def closed_ok(closed):
        assert closed['exit_code'] == 0 and closed['termination'] is None
        assert closed['cleanup_complete'] is True and closed['reaped_descendants'] == 0
    try:
        logs_root = repo/'target/evaluation'
        logs_root.mkdir(parents=True, exist_ok=True)
        assert logs_root.resolve(strict=True) == logs_root
        logs = Path(tempfile.mkdtemp(prefix='normal-interval-', dir=logs_root))
        cpus = sorted(os.sched_getaffinity(0))[:4]
        assert len(cpus) == 4
        os.sched_setaffinity(0, cpus)
        nested = a.raw/'strnlen-prerequisite'
        args = [sys.executable, '-B', str(repo/'tools/rapid-profiler/verify_strnlen_interval.py'),
            '--revision', a.revision, '--raw', str(nested), '--toolchain', str(a.toolchain),
            '--user-home', str(a.user_home), '--cargo-home', str(a.cargo_home)]
        result['stage'] = 'strnlen-prerequisite'
        save(a.raw/'prerequisite-command.json', dict(argv=args, env=env, affinity=cpus, wall_seconds=1800))
        closed = processes.run_command(args, env, logs/'prerequisite.log', 1800, 8*MIB)
        (a.raw/'prerequisite.log').write_bytes((logs/'prerequisite.log').read_bytes())
        save(a.raw/'prerequisite-closed.json', closed); closed_ok(closed); unchanged()
        old = json.loads((nested/'result.json').read_bytes())
        artifacts[nested/'result.json'] = digest(nested/'result.json')
        assert old['revision'] == a.revision and old['status'] == 'PASS' and old['stage'] == 'complete'
        assert tuple(s['name'] for s in old['stages']) == prior.STAGES
        assert all(s['status'] == 'PASS' for s in [*old['stages'], *old['prerequisites'].values(), *old['qualifications'].values()])
        assert old['closure'] == dict(owned_stages=24, nested_owned_stages=22, normal_helpers=46, outer_owners=48, rescues=0)
        prior_sources = json.loads((nested/'sources-before.json').read_bytes())
        assert prior_sources == json.loads((nested/'sources-after.json').read_bytes())
        assert all(before[n] == h for n, h in prior_sources.items())
        assert old['sources'] == dict(count=len(prior_sources), manifest=digest(nested/'sources-before.json'))
        private = json.loads((nested/'private-environment.json').read_bytes())
        assert private['env'] == env and private['affinity'] == cpus
        tool_paths.update({n: Path(p) for n, p in private['tools'].items()})
        assert {n: digest(p) for n, p in tool_paths.items()} == old['tools']
        result.update(tools=old['tools'], versions=old['versions'], hardware=old['hardware'],
            prerequisite=dict(result=digest(nested/'result.json'), closed=digest(a.raw/'prerequisite-closed.json'),
                command=digest(a.raw/'prerequisite-command.json'), closure=old['closure']))
        result['hardware']['description'] = 'AMD EPYC Zen 5 dev host' if (
            old['hardware']['vendor'], old['hardware']['family'], old['hardware']['model']) == (
                'AuthenticAMD', 26, 17) else 'x86-64 development host'
        def stage(name, argv, cpu=20, wall=30, cap=MIB):
            unchanged(); result['stage'] = name
            row = dict(name=name, status='FAILED', command=[public(v) for v in argv],
                       cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
            result['stages'].append(row)
            d = a.raw/name; d.mkdir(); (d/'tmp').mkdir()
            request = dict(argv=[str(v) for v in argv], cwd=str(repo), env=dict(env, TMPDIR=str(d/'tmp')),
                stdout=str(d/'stdout.txt'), stderr=str(d/'stderr.txt'), cpu_seconds=cpu,
                wall_seconds=wall, file_bytes=cap)
            save(d/'request.json', request)
            helper = repo/'tools/unwind-oracle/bounded_command.py'
            parent = [str(tool_paths['python']), '-B', str(helper), '--request', str(d/'request.json'), '--receipt', str(d/'receipt.json')]
            closed = processes.run_command(parent, env, logs/(name+'.log'), wall+25, MIB)
            (d/'parent.log').write_bytes((logs/(name+'.log')).read_bytes())
            save(d/'parent-closed.json', closed); closed_ok(closed)
            assert json.loads((d/'request.json').read_bytes()) == request
            receipt = json.loads((d/'receipt.json').read_bytes())
            assert receipt['exit'] == 0 and receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
            assert receipt['absence_proof'] == 'ECHILD' and receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
            assert receipt['cleanup_error'] is receipt['aborted'] is None
            assert receipt['request_sha256'] == digest(d/'request.json')['sha256']
            assert receipt['helper_sha256'] == before['tools/unwind-oracle/bounded_command.py']['sha256']
            assert json.loads((d/'parent.log').read_bytes()) == dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)
            for stream in ('stdout', 'stderr'):
                assert receipt[stream+'_sha256'] == digest(d/(stream+'.txt'))['sha256']
            row.update({n: digest(d/file) for n, file in (('receipt','receipt.json'),
                ('request','request.json'), ('closed','parent-closed.json'), ('stdout','stdout.txt'), ('stderr','stderr.txt'))})
            unchanged(); row['status'] = 'PASS'
            return d
        python = str(tool_paths['python'])
        d = stage('parser-controls', [python, '-B', repo/'tools/rapid-profiler/normal-work/test_output.py'], 10, 15)
        assert (d/'stdout.txt').read_bytes() == b''
        assert re.fullmatch(rb'\.{9}\n-+\nRan 9 tests in [0-9]+\.[0-9]+s\n\nOK\n', (d/'stderr.txt').read_bytes())
        result['controls'] = dict(parser=9)
        for label, old_label, prefix, methods, target, source, kind in (
            ('runtime', 'whole-front', 'frontend_native::always_on::normal::tests::', RUNTIME, 'rapid_profiler', 'src/lib.rs', 'lib'),
            ('caller', 'work-validator', 'normal::caller::tests::', CALLER, 'ordinary-interval', 'ordinary-interval/main.rs', 'bin'),
            ('state', 'state-validator', 'oracle::native_ordinary::normal_caller::tests::', STATE, 'frontend-native-calibrations', 'native-interval/calibrations.rs', 'test'),
            ('child', 'state-validator', 'normal_check::tests::', CHILD, 'frontend-native-calibrations', 'native-interval/calibrations.rs', 'test')):
            messages = [json.loads(s) for s in (nested/(old_label+'-build')/'stdout.txt').read_text().splitlines()]
            assert messages[-1] == dict(reason='build-finished', success=True)
            products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == target and m['profile']['test']]
            assert len(products) == 1
            product = products[0]; binary = Path(product['executable'])
            assert binary.resolve(strict=True) == binary and binary.parent == repo/'target/release/deps'
            assert product['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml')
            assert product['target']['src_path'] == str(repo/'tools/rapid-profiler'/source)
            assert product['target']['kind'] == [kind]
            assert product['profile'] == dict(opt_level='3', debuginfo=0, test=True, debug_assertions=True, overflow_checks=True)
            assert old['artifacts'][old_label]['profile'] == product['profile']
            artifacts[binary] = digest(binary); assert artifacts[binary] == old['artifacts'][old_label]['binary']
            listing = nested/(old_label+'-list')
            inventory = census.census((listing/'stdout.txt').read_bytes(), (listing/'stderr.txt').read_bytes())
            expected = tuple(prefix+n for n in methods)
            assert set(n for n in inventory if n.startswith(prefix)) == set(expected)
            d = stage(label+'-controls', [binary, prefix, '--test-threads=1'])
            result['controls'][label] = census.controls((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(), expected, inventory)
        artifacts[nested/'selection.json'] = digest(nested/'selection.json')
        assert artifacts[nested/'selection.json'] == old['selection']['manifest']
        selection = json.loads((nested/'selection.json').read_bytes())
        assert selection['revision'] == a.revision and selection['label'] == 'freebsd-strnlen-14.1-v1'
        assert all(selection[key] == old['selection'][key]
                   for key in ('label', 'elf_va', 'length', 'selected_code', 'file_offset'))
        subject, trusted = nested/'candidate.so', nested/'final.so'
        for name, path in (('candidate', subject), ('final', trusted)):
            artifacts[path] = digest(path); assert artifacts[path] == old['selection'][name]
        assert subject.read_bytes() == trusted.read_bytes() and subject.stat().st_ino != trusted.stat().st_ino
        caller = a.raw/'caller.so'
        d = stage('caller-build', [tool_paths['gcc'], *CALLER_FLAGS, repo/'tools/rapid-profiler/normal-work/caller.c', '-o', caller])
        assert (d/'stdout.txt').read_bytes() == (d/'stderr.txt').read_bytes() == b''
        artifacts[caller] = digest(caller); assert 0 < artifacts[caller]['bytes'] <= MIB
        candidate = a.raw/'caller-candidate.so'
        with candidate.open('xb') as f: f.write(caller.read_bytes())
        assert candidate.read_bytes() == caller.read_bytes() and candidate.stat().st_ino != caller.stat().st_ino
        artifacts[candidate] = digest(candidate)
        binaries = {n: repo/'target/release'/n for n in ('ordinary-interval', 'frontend-native-oracle')}
        for name, binary in binaries.items():
            artifacts[binary] = digest(binary); assert artifacts[binary] == old['artifacts'][name]['binary']
            assert old['artifacts'][name]['profile'] == dict(opt_level='3', debuginfo=0, test=False, debug_assertions=True, overflow_checks=True)
        argv = [subject, trusted, str(selection['elf_va']), str(selection['length']), candidate, caller]
        output = a.raw/'normal-output'
        d = stage('normal-state', [binaries['frontend-native-oracle'], 'normal-state', *argv, output], 90, 90)
        table = (output/'normal-pairs.csv').read_bytes()
        native, totals = check.state(table, (d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(), selection['length'])
        (a.raw/'normal-pairs.csv').write_bytes(table)
        d = stage('normal-work', [binaries['ordinary-interval'], 'normal-work', *argv])
        assert (d/'stderr.txt').read_bytes() == b''
        work, table = check.functional((d/'stdout.txt').read_bytes()); check.join(native, work)
        (a.raw/'normal-rows.csv').write_bytes(table)
        for name, owner in (('sampled', 'sampled'), ('closed', 'function-closed')):
            d = stage('drop-'+name, [binaries['ordinary-interval'], 'normal-drop-'+name, *argv])
            assert (d/'stderr.txt').read_bytes() == b''
            check.lifecycle((d/'stdout.txt').read_bytes(), owner)
        if a.reference_exact:
            group = result['reference_exact']; group['status'] = 'FAILED'
            def reference_stage(name, argv):
                # The section's predeclared rows retain all absent stages as UNRUN.
                pending = next(r for r in group['stages'] if r['name'] == name)
                assert pending['status'] == 'UNRUN'
                pending['status'] = 'FAILED'
                try:
                    d = stage(name, argv, 20, 30, MIB)
                finally:
                    if result['stages'] and result['stages'][-1]['name'] == name:
                        pending.update(result['stages'][-1])
                        pending['status'] = 'FAILED'
                        result['stages'][-1]['status'] = 'FAILED'
                return d, pending, result['stages'][-1]
            def reference_done(pending, row, **values):
                pending.update(values); row.update(values)
                pending['status'] = row['status'] = 'PASS'
            for name, script, count in (
                ('reference-fixture-controls', 'test_exact_fixture.py', 4),
                ('reference-exact-parser-controls', 'test_exact_native.py', 8),
                ('reference-parser-controls', 'test_reference_native.py', 9)):
                d, pending, row = reference_stage(name, [python, '-B', repo/'tools/rapid-profiler/normal-work'/script])
                assert (d/'stdout.txt').read_bytes() == b''
                assert re.fullmatch(rb'\.{'+str(count).encode()+rb'}\n-+\nRan '+str(count).encode()+rb' tests in [0-9]+\.[0-9]+s\n\nOK\n', (d/'stderr.txt').read_bytes())
                reference_done(pending, row, passed=count)
            def reference_product(label, target, source, kind, crate_types):
                # These same-revision builds/lists just completed in the mandatory
                # prerequisite. Join their exact receipts before reusing either.
                for suffix in ('-build', '-list'):
                    records = [s for s in old['stages'] if s['name'] == label+suffix]
                    assert len(records) == 1 and records[0]['status'] == 'PASS'
                    record = records[0]; directory = nested/(label+suffix)
                    for key, file in (('request','request.json'), ('receipt','receipt.json'),
                            ('parent_closed','parent-closed.json'), ('stdout','stdout.txt'), ('stderr','stderr.txt')):
                        artifacts[directory/file] = digest(directory/file)
                        assert artifacts[directory/file] == record[key]
                    closed_ok(json.loads((directory/'parent-closed.json').read_bytes()))
                    receipt = json.loads((directory/'receipt.json').read_bytes())
                    assert receipt['exit'] == 0 and receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
                    assert receipt['absence_proof'] == 'ECHILD' and receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
                    assert receipt['cleanup_error'] is receipt['aborted'] is None
                    assert receipt['request_sha256'] == artifacts[directory/'request.json']['sha256']
                    assert receipt['helper_sha256'] == before['tools/unwind-oracle/bounded_command.py']['sha256']
                    assert all(receipt[s+'_sha256'] == artifacts[directory/(s+'.txt')]['sha256'] for s in ('stdout', 'stderr'))
                messages = [json.loads(line) for line in (nested/(label+'-build')/'stdout.txt').read_text().splitlines()]
                assert messages[-1] == dict(reason='build-finished', success=True)
                products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == target and m['profile']['test']]
                assert len(products) == 1
                product = products[0]; binary = Path(product['executable'])
                profile = dict(opt_level='3', debuginfo=0, test=True, debug_assertions=True, overflow_checks=True)
                assert product['profile'] == profile and type(product['fresh']) is bool
                assert product['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml')
                assert product['target']['src_path'] == str(repo/'tools/rapid-profiler'/source)
                assert product['target']['kind'] == [kind] and product['target']['crate_types'] == [crate_types]
                assert binary.resolve(strict=True) == binary and binary.parent == repo/'target/release/deps'
                assert re.fullmatch(re.escape(target.replace('-', '_'))+'-[0-9a-f]+', binary.name)
                artifacts[binary] = digest(binary)
                authority = old['artifacts'][label]
                assert authority == dict(binary=artifacts[binary], profile=profile, cargo_fresh=product['fresh'])
                listing = nested/(label+'-list')
                inventory = census.census((listing/'stdout.txt').read_bytes(), (listing/'stderr.txt').read_bytes())
                return binary, inventory, dict(authority, full_census=len(inventory), listing=digest(listing/'stdout.txt'))
            calibration = reference_product('state-validator', 'frontend-native-calibrations',
                'native-interval/calibrations.rs', 'test', 'bin')
            ordinary_test = reference_product('work-validator', 'ordinary-interval',
                'ordinary-interval/main.rs', 'bin', 'bin')
            for name, product, prefixes, methods in (
                ('reference-exact-controls', calibration, EXACT_PREFIXES, EXACT_STATE),
                ('reference-witness-controls', calibration, (REFERENCE_WITNESS_PREFIX,), REFERENCE_WITNESS),
                ('reference-geometry-controls', calibration, (REFERENCE_GEOMETRY_PREFIX,), REFERENCE_GEOMETRY),
                ('reference-owner-controls', ordinary_test, (REFERENCE_OWNER_PREFIX,), REFERENCE_OWNER),
                ('reference-owner-geometry-controls', ordinary_test, (REFERENCE_OWNER_GEOMETRY_PREFIX,), REFERENCE_OWNER_GEOMETRY),
                ('reference-child-controls', calibration, (REFERENCE_CHILD_PREFIX,), REFERENCE_CHILD)):
                binary, inventory, authority = product
                assert {n for n in inventory if n.startswith(prefixes)} == set(methods)
                d, pending, row = reference_stage(name, [binary, *methods, '--exact', '--test-threads=1'])
                checked = census.controls((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(), methods, inventory)
                reference_done(pending, row, controls=checked, artifact=authority)

            exact_final, exact_candidate = a.raw/'reference-exact-final.so', a.raw/'reference-exact-candidate.so'
            d, pending, row = reference_stage('reference-exact-build', [tool_paths['gcc'], *shared.CFLAGS,
                repo/'tools/rapid-profiler/exact-work/exact_work.S', '-o', exact_final])
            assert (d/'stdout.txt').read_bytes() == (d/'stderr.txt').read_bytes() == b''
            artifacts[exact_final] = digest(exact_final)
            assert 0 < artifacts[exact_final]['bytes'] <= MIB
            details = exact_fixture.describe(exact_final.read_bytes())
            assert details['final'] == artifacts[exact_final] and details['length'] == 37
            selection_file = a.raw/'reference-exact-selection.json'
            save(selection_file, dict(details, revision=a.revision))
            artifacts[selection_file] = digest(selection_file)
            unchanged() # Trusted entire ELF/descriptor is frozen BEFORE candidate creation.
            with exact_candidate.open('xb') as stream: stream.write(exact_final.read_bytes())
            artifacts[exact_candidate] = digest(exact_candidate)
            assert artifacts[exact_candidate] == artifacts[exact_final]
            assert exact_fixture.authenticate(exact_candidate, exact_final, details['elf_va'], 37,
                selection_file, artifacts[selection_file]['sha256']) == details
            group['subject'] = dict(status='PASS', **details, candidate=artifacts[exact_candidate],
                manifest=artifacts[selection_file], source=before['tools/rapid-profiler/exact-work/exact_work.S'])
            unchanged()
            reference_done(pending, row, selection=group['subject'])

            reference_final, reference_candidate = a.raw/'reference-caller.so', a.raw/'reference-caller-candidate.so'
            d, pending, row = reference_stage('reference-caller-build', [tool_paths['gcc'], *CALLER_FLAGS,
                repo/'tools/rapid-profiler/normal-work/reference_caller.S', '-o', reference_final])
            assert (d/'stdout.txt').read_bytes() == (d/'stderr.txt').read_bytes() == b''
            artifacts[reference_final] = digest(reference_final)
            assert 0 < artifacts[reference_final]['bytes'] <= MIB
            caller_authority = a.raw/'reference-caller-authority.json'
            save(caller_authority, dict(schema=1, revision=a.revision, final=artifacts[reference_final],
                source=before['tools/rapid-profiler/normal-work/reference_caller.S'],
                geometry_source=before['tools/rapid-profiler/normal-work/reference_bytes.rs'],
                build_stage='reference-caller-build', symbol='normal_reference_caller',
                closed_body_bytes=295, required_labels=32,
                scope='Complete independently built ELF authority; actual owner must authenticate body, all labels and live mapping before invocation.'))
            artifacts[caller_authority] = digest(caller_authority)
            unchanged() # No helper candidate or address is an authority input.
            with reference_candidate.open('xb') as stream: stream.write(reference_final.read_bytes())
            artifacts[reference_candidate] = digest(reference_candidate)
            assert artifacts[reference_candidate] == artifacts[reference_final]
            assert reference_candidate.read_bytes() == reference_final.read_bytes()
            assert (reference_candidate.stat().st_dev, reference_candidate.stat().st_ino) != (reference_final.stat().st_dev, reference_final.stat().st_ino)
            group['caller'] = dict(status='PASS', final=artifacts[reference_final], candidate=artifacts[reference_candidate],
                authority=artifacts[caller_authority], body_bytes=295, labels=32,
                scope='Successful reference-state additionally authenticates the actual owner/body/labels. No stand-alone native claim from this build.')
            unchanged()
            reference_done(pending, row, caller=group['caller'])

            for name, route, helper_candidate, helper_final, directory, filename, parser, expected in (
                ('reference-old-exact-state', 'normal-exact-state', candidate, caller,
                    'reference-old-exact-output', 'normal-exact-pairs.csv', exact_native, 1696),
                ('reference-state', 'normal-reference-state', reference_candidate, reference_final,
                    'reference-native-output', 'normal-reference-pairs.csv', reference_native, 1736)):
                cohort = group['old_exact' if expected == 1696 else 'reference']
                cohort['status'] = 'FAILED'
                assert exact_fixture.authenticate(exact_candidate, exact_final, details['elf_va'], 37,
                    selection_file, artifacts[selection_file]['sha256']) == details
                output = a.raw/directory
                d, pending, row = reference_stage(name, [binaries['frontend-native-oracle'], route,
                    exact_candidate, exact_final, str(details['elf_va']), '37', helper_candidate, helper_final, output])
                raw_table = output/filename
                table = raw_table.read_bytes()
                observed = parser.check(table, (d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes())
                assert observed['status'] == 'FUNCTIONAL_PASS' and observed['pairs'] == 4 and observed['children'] == 8
                assert observed['comparisons'] == expected
                artifacts[raw_table] = digest(raw_table)
                exported = a.raw/filename
                with exported.open('xb') as stream: stream.write(table)
                artifacts[exported] = digest(exported); assert artifacts[exported] == artifacts[raw_table]
                cohort.update(observation={k:v for k,v in observed.items() if k != 'rows'}, table=artifacts[exported],
                    binary=artifacts[binaries['frontend-native-oracle']], helper=artifacts[helper_final],
                    source_stage=name, absolute_seconds_per_pair=15, continuous_steps_per_child=20000,
                    process_cpu_seconds=20, process_wall_seconds=30)
                unchanged()
                cohort['status'] = 'PASS'
                reference_done(pending, row, pairs=4, comparisons=expected, table=artifacts[exported])
            assert tuple(r['name'] for r in group['stages']) == REFERENCE_STAGES
            assert all(r['status'] == 'PASS' for r in group['stages'])
            assert group['old_exact']['status'] == group['reference']['status'] == 'PASS'
            group.update(status='PASS', closure=dict(owned_stages=13, normal_helpers=13, outer_owners=13, rescues=0),
                complete_populations=dict(old_exact_pairs=4, reference_pairs=4, children=16,
                    old_exact_comparisons=1696, reference_comparisons=1736,
                    reference_reader_checks=32, reference_output_stores=96, reference_returned_cells=16))
        if a.reference_work:
            assert result['reference_exact']['status'] == 'PASS'
            # Reuse the same bounded stage/receipt helpers with a distinct group
            # declared UNRUN before any observation. Prior group remains complete.
            group = result['reference_work']; group['status'] = 'FAILED'
            d, pending, row = reference_stage('reference-work-parser-controls',
                [python, '-B', repo/'tools/rapid-profiler/normal-work/test_reference_work.py'])
            assert (d/'stdout.txt').read_bytes() == b''
            assert re.fullmatch(rb'\.{10}\n-+\nRan 10 tests in [0-9]+\.[0-9]+s\n\nOK\n', (d/'stderr.txt').read_bytes())
            reference_done(pending, row, passed=10)
            binary, inventory, authority = ordinary_test
            # New leg namespaces are always compiled under this broad prefix.
            # Require their exact union: no subset check or hidden extra controls.
            # This old stage still runs only the unchanged thirteen work methods.
            assert {n for n in inventory if n.startswith(REFERENCE_WORK_PREFIXES)} == set(REFERENCE_WORK_CONTROLS + REFERENCE_LEG_CONTROLS)
            d, pending, row = reference_stage('reference-work-controls',
                [binary, *REFERENCE_WORK_CONTROLS, '--exact', '--test-threads=1'])
            controls = census.controls((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(),
                REFERENCE_WORK_CONTROLS, inventory)
            reference_done(pending, row, controls=controls, artifact=authority)
            assert exact_fixture.authenticate(exact_candidate, exact_final, details['elf_va'], 37,
                selection_file, artifacts[selection_file]['sha256']) == details
            group['collector']['status'] = 'FAILED'
            d, pending, row = reference_stage('reference-work', [binaries['ordinary-interval'],
                'normal-reference-work', exact_candidate, exact_final, str(details['elf_va']), '37',
                reference_candidate, reference_final])
            observed = reference_work.check((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes())
            assert observed['status'] == 'FUNCTIONAL_PASS' and len(observed['rows']) == 48
            assert (observed['originals'], observed['installed'], observed['records']) == (24, 24, 24)
            exported = a.raw/'normal-reference-rows.csv'
            with exported.open('xb') as stream: stream.write(observed['table'])
            artifacts[exported] = digest(exported)
            group['collector'].update(
                observation={k:v for k,v in observed.items() if k not in ('rows', 'table')},
                table=artifacts[exported], binary=artifacts[binaries['ordinary-interval']],
                subject=artifacts[exact_final], selection=artifacts[selection_file],
                helper=artifacts[reference_final], helper_authority=artifacts[caller_authority],
                source_stage='reference-work', process_cpu_seconds=20, process_wall_seconds=30,
                file_bytes=MIB)
            unchanged()
            group['collector']['status'] = 'PASS'
            reference_done(pending, row, originals=24, installed=24, rows=48, table=artifacts[exported])
            assert tuple(r['name'] for r in group['stages']) == REFERENCE_WORK_STAGES
            assert all(r['status'] == 'PASS' for r in group['stages'])
            group.update(status='PASS', closure=dict(owned_stages=3, normal_helpers=3, outer_owners=3, rescues=0))
        if a.reference_leg:
            assert result['reference_exact']['status'] == result['reference_work']['status'] == 'PASS'
            group = result['reference_leg']; group['status'] = 'FAILED'
            d, pending, row = reference_stage('reference-leg-parser-controls',
                [python, '-B', repo/'tools/rapid-profiler/normal-work/test_reference_leg.py'])
            assert (d/'stdout.txt').read_bytes() == b''
            assert re.fullmatch(rb'\.{12}\n-+\nRan 12 tests in [0-9]+\.[0-9]+s\n\nOK\n', (d/'stderr.txt').read_bytes())
            reference_done(pending, row, passed=12)
            binary, inventory, authority = ordinary_test
            assert {n for n in inventory if n.startswith(REFERENCE_LEG_PREFIXES)} == set(REFERENCE_LEG_CONTROLS)
            d, pending, row = reference_stage('reference-leg-controls',
                [binary, *REFERENCE_LEG_CONTROLS, '--exact', '--test-threads=1'])
            controls = census.controls((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(),
                REFERENCE_LEG_CONTROLS, inventory)
            reference_done(pending, row, controls=controls, artifact=authority)
            assert [(c['phase'], c['trial'], c['leg']) for c in group['legs']] == [
                ('qualification', 1, 'original'), ('qualification', 1, 'installed')]
            for cohort in group['legs']:
                assert cohort['status'] == 'UNRUN'
                cohort['status'] = 'FAILED'
                phase, trial, leg = cohort['phase'], cohort['trial'], cohort['leg']
                assert exact_fixture.authenticate(exact_candidate, exact_final, details['elf_va'], 37,
                    selection_file, artifacts[selection_file]['sha256']) == details
                name = 'reference-leg-'+leg
                d, pending, row = reference_stage(name, [binaries['ordinary-interval'],
                    'normal-reference-leg', phase, str(trial), leg,
                    exact_candidate, exact_final, str(details['elf_va']), '37',
                    reference_candidate, reference_final])
                observed = reference_leg.check((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(),
                    phase, trial, leg)
                assert observed['status'] == 'FUNCTIONAL_PASS' and len(observed['rows']) == observed['calls'] == 24
                assert (observed['phase'], observed['trial'], observed['leg']) == (phase, trial, leg)
                assert (observed['helper_calls'], observed['reference_cells'], observed['records']) == (12, 24, 0 if leg == 'original' else 24)
                exported = a.raw/('normal-reference-leg-'+leg+'.csv')
                with exported.open('xb') as stream: stream.write(observed['table'])
                artifacts[exported] = digest(exported)
                cohort.update(observation={k:v for k,v in observed.items() if k not in ('rows', 'table')},
                    table=artifacts[exported], binary=artifacts[binaries['ordinary-interval']],
                    subject=artifacts[exact_final], selection=artifacts[selection_file],
                    helper=artifacts[reference_final], helper_authority=artifacts[caller_authority],
                    source_stage=name, process_cpu_seconds=20, process_wall_seconds=30, file_bytes=MIB)
                unchanged()
                cohort['status'] = 'PASS'
                reference_done(pending, row, phase=phase, trial=trial, leg=leg, calls=24, rows=24, table=artifacts[exported])
            assert tuple(r['name'] for r in group['stages']) == REFERENCE_LEG_STAGES
            assert all(r['status'] == 'PASS' for r in group['stages']) and all(c['status'] == 'PASS' for c in group['legs'])
            group.update(status='PASS', closure=dict(owned_stages=4, normal_helpers=4, outer_owners=4, rescues=0))
        if a.observer_work:
            assert all(result[name]['status'] == 'PASS' for name in ('reference_exact', 'reference_work', 'reference_leg'))
            group = result['observer_work']; group['status'] = 'FAILED'
            d, pending, row = reference_stage('observer-work-parser-controls',
                [python, '-B', repo/'tools/rapid-profiler/normal-work/test_observer_work.py'])
            assert (d/'stdout.txt').read_bytes() == b''
            assert re.fullmatch(rb'\.{11}\n-+\nRan 11 tests in [0-9]+\.[0-9]+s\n\nOK\n', (d/'stderr.txt').read_bytes())
            reference_done(pending, row, passed=11)
            binary, inventory, authority = ordinary_test
            assert {n for n in inventory if n.startswith(OBSERVER_WORK_PREFIX)} == set(OBSERVER_WORK_CONTROLS)
            d, pending, row = reference_stage('observer-work-controls',
                [binary, *OBSERVER_WORK_CONTROLS, '--exact', '--test-threads=1'])
            controls = census.controls((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(),
                OBSERVER_WORK_CONTROLS, inventory)
            reference_done(pending, row, controls=controls, artifact=authority)
            assert [c['mode'] for c in group['modes']] == ['native', 'always-on']
            for cohort in group['modes']:
                assert cohort['status'] == 'UNRUN'
                cohort['status'] = 'FAILED'
                mode = cohort['mode']
                assert exact_fixture.authenticate(exact_candidate, exact_final, details['elf_va'], 37,
                    selection_file, artifacts[selection_file]['sha256']) == details
                name = 'observer-work-'+mode
                d, pending, row = reference_stage(name, [binaries['ordinary-interval'],
                    'normal-observer-work', mode, exact_candidate, exact_final, str(details['elf_va']), '37',
                    candidate, caller])
                observed = observer_work.check((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(), mode)
                assert observed['status'] == 'FUNCTIONAL_PASS' and observed['mode'] == mode
                assert len(observed['rows']) == observed['calls'] == 3072
                assert (observed['helper_calls'], observed['instructions'], observed['records'], observed['batches']) == (
                    1536, 614400, 0 if mode == 'native' else 3072, 0 if mode == 'native' else 128)
                exported = a.raw/('normal-observer-work-'+mode+'.csv')
                with exported.open('xb') as stream: stream.write(observed['table'])
                artifacts[exported] = digest(exported)
                cohort.update(observation={k:v for k,v in observed.items() if k not in ('rows', 'table')},
                    table=artifacts[exported], binary=artifacts[binaries['ordinary-interval']],
                    subject=artifacts[exact_final], selection=artifacts[selection_file],
                    helper=artifacts[caller], helper_candidate=artifacts[candidate],
                    source_stage=name, process_cpu_seconds=20, process_wall_seconds=30, file_bytes=MIB)
                unchanged()
                cohort['status'] = 'PASS'
                reference_done(pending, row, mode=mode, calls=3072, rows=3072, table=artifacts[exported])
            assert tuple(r['name'] for r in group['stages']) == OBSERVER_WORK_STAGES
            assert all(r['status'] == 'PASS' for r in group['stages']) and all(c['status'] == 'PASS' for c in group['modes'])
            group.update(status='PASS', closure=dict(owned_stages=4, normal_helpers=4, outer_owners=4, rescues=0))
        unchanged(); save(a.raw/'sources-after.json', {n: digest(repo/n) for n in names})
        assert tuple(r['name'] for r in result['stages']) == STAGES + (REFERENCE_STAGES if a.reference_exact else ()) + (REFERENCE_WORK_STAGES if a.reference_work else ()) + (REFERENCE_LEG_STAGES if a.reference_leg else ()) + (OBSERVER_WORK_STAGES if a.observer_work else ()) and all(r['status'] == 'PASS' for r in result['stages'])
        result.update(status='PASS', stage='complete',
            artifacts=dict(subject=artifacts[trusted], caller=artifacts[caller], **{n: artifacts[p] for n, p in binaries.items()}),
            outputs={n: digest(a.raw/n) for n in ('normal-pairs.csv', 'normal-rows.csv')},
            native=dict(pairs=17, stable_pairs=16, crossed_pairs=1, children=34, target_calls=68,
                target_returns=68, outer_returns=34, helper_joins=1, **totals),
            work=dict(original_calls=8, installed_calls=8, next_entry_acknowledgements=7,
                checkpoint_acknowledgements=1, sampled=4, function_closed=2, removed=2,
                generations=2, events=16, journal_words=512, reports=2, worker_joins=1),
            abandonment=dict(cases=2, original_calls=16, installed_calls=4, checkpoints=0,
                pending_after_tls_exit=2, reattach_refusals=2, worker_joins=2),
            closure=dict(owned_stages=10 + (len(REFERENCE_STAGES) if a.reference_exact else 0) + (len(REFERENCE_WORK_STAGES) if a.reference_work else 0) + (len(REFERENCE_LEG_STAGES) if a.reference_leg else 0) + (len(OBSERVER_WORK_STAGES) if a.observer_work else 0), nested_normal_helpers=46, nested_outer_owners=48, rescues=0),
            prior_failures='Fresh attempt with no retries; prior failures remain failures.')
    except BaseException as error:
        result['error_type'] = type(error).__name__
        (a.raw/'failure.txt').write_text(traceback.format_exc())
    finally:
        save(a.raw/'result.json', result)
    print('normal-interval '+result['status']+' stage='+result['stage'])
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
