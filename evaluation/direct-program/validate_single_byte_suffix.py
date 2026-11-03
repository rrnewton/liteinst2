#!/usr/bin/env python3
"""Explicit single-byte suffix controls through the physical-window validator."""
import importlib.util
from pathlib import Path
import re
import sys

SOURCE = Path(__file__).with_name('validate_physical_window.py')
spec = importlib.util.spec_from_file_location('single_byte_suffix_physical_controls', SOURCE)
physical = importlib.util.module_from_spec(spec)
spec.loader.exec_module(physical)

# Four additions share the existing core module and its one inherited command.
# Keep all eight original expected names; the inherited validator checks all 12.
CORE_ADDITIONS = (
    'single_byte_suffix_preserves_exact_plan_and_releases_only_real_fetch_footprint',
    'single_byte_suffix_never_exempts_true_overlap_or_already_claimed_pending',
    'single_byte_suffix_keeps_full_source_staleness_and_coverage_guards',
    'single_byte_suffix_keeps_default_fallback_and_short_window_bytes_exact',
)
core_prefix, core_cases = physical.CONTROLS['physical-core']
assert core_prefix == 'quiescent::artifact_window::physical::tests::'
assert len(core_cases) == len(set(core_cases)) == 8
assert len(CORE_ADDITIONS) == len(set(CORE_ADDITIONS)) == 4
assert not set(core_cases).intersection(CORE_ADDITIONS)
physical.CONTROLS = dict(physical.CONTROLS)
physical.CONTROLS['physical-core'] = (core_prefix, (*core_cases, *CORE_ADDITIONS))

CONTROLS = {
    'suffix60-frontend': ('grouped_artifact_frontend::suffix60::tests::', (
        'suffix60_group_mode_changes_only_the_actual_suffix_store',
        'suffix60_policy_and_portable_binding_are_explicit_with_all_old_bounds',
        'suffix60_group_profile_keeps_singleton_artifacts_and_storage_unchanged',
        'suffix60_later_refusal_and_carrier_failure_atomically_withhold_every_member',
    )),
    'suffix60-cli': ('grouped_suffix60_tests::', (
        'suffix60_cli_has_an_exact_separate_selector_and_storage_arity',
        'suffix60_cli_authenticates_new_mode_in_portable_and_embedded_metadata',
    )),
    'suffix60-router-native': ('entry_router::imp::single_byte_suffix_native_tests::', (
        'single_byte_suffix_every_selected_and_unselected_entry_uses_production_router',
        'single_byte_suffix_page_last_byte_is_ud_with_guarded_successor',
        'single_byte_suffix_later_ret_fault_preserves_prior_pop_and_callback_state',
        'single_byte_suffix_page_edge_later_ret_fault_preserves_uncommitted_state',
    )),
}
PYTHON_CONTROLS = (
    'test_suffix60_exact_profile_preserves_all_atomic_outcomes_and_storage',
    'test_suffix60_stale_mode_binding_and_repinned_policy_are_refused',
    'test_suffix60_retains_full_membership_routes_and_numeric_ceiling',
    'test_suffix60_refusal_bytes_and_atomic_withholding_are_never_promoted',
)

COMMANDS = list(physical.COMMANDS)
for row in (
    ('suffix60-frontend', ['cargo', 'test', '-p', 'liteinst-rewrite', '--lib',
                           'grouped_artifact_frontend::suffix60::tests::'], 180),
    ('suffix60-cli', ['cargo', 'test', '-p', 'liteinst-rewrite', '--example',
                      'disassembly_sites', 'grouped_suffix60_tests::'], 180),
    ('suffix60-router-native', ['cargo', 'test', '-p', 'liteinst2', '--lib',
                                'entry_router::imp::single_byte_suffix_native_tests::'], 180),
    ('suffix60-linkage-python', ['/usr/bin/python3.9', '-I', '-B',
                                 'evaluation/direct-program/test_grouped_suffix60_linkage.py', '-v'], 180),
):
    COMMANDS.insert(-2, row)
assert len(COMMANDS) == len({row[0] for row in COMMANDS}) == 46


def validate_result(name, raw):
    physical.validate_result(name, raw)
    if name in CONTROLS:
        cases = CONTROLS[name][1]
        rows = re.findall(rb'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', raw, re.M)
        assert rows == [(str(len(cases)).encode(), b'0', b'0')], 'exact suffix60 control population must run'
    for control, (prefix, cases) in CONTROLS.items():
        if name in (control, 'workspace'):
            for case in cases:
                assert raw.splitlines().count(('test ' + prefix + case + ' ... ok').encode()) == 1, 'suffix60 control missing: ' + case
    if name == 'suffix60-linkage-python':
        assert re.findall(rb'^Ran (\d+) tests in ', raw, re.M) == [b'4'] and raw.rstrip().endswith(b'OK')
        for case in PYTHON_CONTROLS:
            assert raw.splitlines().count((case + ' (__main__.GroupedSuffix60Linkage) ... ok').encode()) == 1, 'suffix60 Python control missing: ' + case


if __name__ == '__main__':
    assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode
    assert sys.argv.count('--focused') <= 1
    focused = '--focused' in sys.argv
    if focused:
        sys.argv.remove('--focused')
    alphabet = physical.alphabet
    minimum = alphabet.minimum
    ledger = minimum.ledger
    grouped = ledger.upstream.program.grouped
    # All 215 prior controls, plus 4 core/4 frontend/2 CLI/4 native/4 Python.
    focused_names = ('fmt', *grouped.window.CONTROLS, 'native-stack', *grouped.CONTROLS,
                     'grouped-cli', 'grouped-linkage-python', *ledger.upstream.CONTROLS,
                     'upstream-linkage-python', *ledger.CONTROLS, 'ledger-storage-python',
                     *minimum.CONTROLS, 'min5-linkage-python', *alphabet.CONTROLS,
                     'alphabet-linkage-python', *physical.CONTROLS, 'physical-linkage-python',
                     *CONTROLS, 'suffix60-linkage-python')
    selected = [row for row in COMMANDS if row[0] in focused_names] if focused else COMMANDS
    assert len(selected) == (38 if focused else 46)
    raise SystemExit(grouped.window.stack.cuts.clock.shared.main(
        commands=selected,
        profile='single-byte-suffix-focused-180-v1' if focused else 'single-byte-suffix-correctness-1800-360-v1',
        scope='Focused 233 inherited and single-byte suffix controls only; not full workspace validation.' if focused else
              'Required correctness and every prior physical-window control plus explicit single-byte '
              'suffix core, frontend, CLI/linkage and finite production-router native controls. '
              'No actual-program corpus, runtime exemption, performance or strict A4 qualification.',
        log_namespace='single-byte-suffix', validate_result=validate_result))
