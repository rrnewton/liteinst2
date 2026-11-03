#!/usr/bin/env python3
"""Bounded upstream controls through the unchanged grouped program validator."""
import importlib.util
from pathlib import Path
import re
import sys

SOURCE = Path(__file__).with_name('validate_grouped_program.py')
spec = importlib.util.spec_from_file_location('grouped_upstream_program_controls', SOURCE)
program = importlib.util.module_from_spec(spec)
spec.loader.exec_module(program)
CONTROLS = {
    'upstream-core': ('quiescent::artifact_window::upstream_tests::', (
        'short_span_uses_one_legal_prefix_and_preserves_every_head_and_observer',
        'constrained_offset_refuses_before_prefix_fits_in_the_same_arena',
        'sixty_five_heads_share_one_sixty_four_site_domain_and_retain_omission',
        'block_distance_displacement_call_and_nonfinal_transfer_remain_hard_boundaries',
        'identity_pending_overlay_and_cet_checks_keep_predecessor_unchanged',
        'oversized_certificate_is_not_rescued_by_an_earlier_head_or_unresolved_hook',
        'population_allocation_and_per_head_symbol_failures_are_never_bypassed',
    )),
    'upstream-frontend': ('grouped_artifact_frontend::upstream_tests::', (
        'upstream_short_group_keeps_members_and_routes_unselected_prefix_once',
        'upstream_full_manifest_rejects_consumed_and_straddling_prefix_members',
        'upstream_named_bounds_and_final_carrier_failure_remain_atomic',
        'upstream_nongroup_engine_matches_exact_images_and_outcomes',
    )),
    'upstream-cli': ('grouped_upstream_tests::', (
        'upstream_cli_selector_is_distinct_and_legacy_arguments_are_literal',
        'upstream_cli_short_group_uses_full_union_and_keeps_block_refusal',
        'upstream_cli_metadata_requires_new_policy_identity_and_exact_product',
    )),
}
PYTHON_CONTROLS = (
    'test_upstream_full_partition_preserves_all_local_and_final_outcomes',
    'test_upstream_physical_head_window_schedule_and_limits_are_exact',
    'test_upstream_source_ledger_pin_prevents_coordinated_prefix_omission',
    'test_upstream_full_manifest_includes_already_accepted_prefix_singleton',
)
COMMANDS = list(program.COMMANDS)
for row in (
    ('upstream-core', ['cargo', 'test', '-p', 'liteinst2', '--lib',
                       'quiescent::artifact_window::upstream_tests::'], 180),
    ('upstream-frontend', ['cargo', 'test', '-p', 'liteinst-rewrite', '--lib',
                           'grouped_artifact_frontend::upstream_tests::'], 180),
    ('upstream-cli', ['cargo', 'test', '-p', 'liteinst-rewrite', '--example',
                      'disassembly_sites', 'grouped_upstream_tests::'], 180),
    ('upstream-linkage-python', ['/usr/bin/python3.9', '-I', '-B',
                                 'evaluation/direct-program/test_grouped_upstream_linkage.py', '-v'], 180),
):
    COMMANDS.insert(-2, row)


def validate_result(name, raw):
    program.validate_result(name, raw)
    if name in CONTROLS:
        cases = CONTROLS[name][1]
        rows = re.findall(rb'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', raw, re.M)
        assert rows == [(str(len(cases)).encode(), b'0', b'0')], 'exact upstream control population must run'
    for control, (prefix, cases) in CONTROLS.items():
        if name in (control, 'workspace'):
            for case in cases:
                assert raw.splitlines().count(('test ' + prefix + case + ' ... ok').encode()) == 1, 'upstream control missing: ' + case
    if name == 'upstream-linkage-python':
        assert re.findall(rb'^Ran (\d+) tests in ', raw, re.M) == [b'4'] and raw.rstrip().endswith(b'OK')
        for case in PYTHON_CONTROLS:
            assert raw.splitlines().count((case + ' (__main__.GroupedUpstreamLinkage) ... ok').encode()) == 1, 'upstream Python control missing: ' + case


if __name__ == '__main__':
    assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode
    assert sys.argv.count('--focused') <= 1
    focused = '--focused' in sys.argv
    if focused:
        sys.argv.remove('--focused')
    focused_names = ('fmt', *program.grouped.CONTROLS, 'grouped-cli', 'grouped-linkage-python',
                     *CONTROLS, 'upstream-linkage-python')
    selected = [row for row in COMMANDS if row[0] in focused_names] if focused else COMMANDS
    raise SystemExit(program.grouped.window.stack.cuts.clock.shared.main(
        commands=selected,
        profile='grouped-upstream-focused-180-v1' if focused else 'grouped-upstream-correctness-1800-360-v1',
        scope='Focused 44 inherited and upstream core/frontend/native/CLI/Python controls only; not full workspace validation.' if focused else
              'Required correctness and every prior grouped program control plus bounded upstream '
              'core/frontend/CLI and complete linkage controls. No actual-program corpus, runtime '
              'exemption, performance or strict A4 qualification.',
        log_namespace='grouped-upstream', validate_result=validate_result))
