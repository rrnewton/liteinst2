#!/usr/bin/env python3
"""Integrated grouped program controls through the existing artifact validator."""
import importlib.util
from pathlib import Path
import re
import sys

SOURCE = Path(__file__).with_name('validate_grouped_artifact.py')
spec = importlib.util.spec_from_file_location('grouped_program_controls', SOURCE)
grouped = importlib.util.module_from_spec(spec)
spec.loader.exec_module(grouped)
CLI_CONTROLS = (
    'grouped_cli_selector_keeps_legacy_routes_and_rejects_mixed_or_partial_forms',
    'grouped_cli_uses_actual_typed_route_and_retains_complete_success_and_refusal_census',
    'grouped_cli_metadata_rejects_policy_identity_and_embedded_product_corruption',
)
PYTHON_CONTROLS = (
    'test_full_population_local_acceptance_and_atomic_withholding_are_distinct',
    'test_total_policy_partition_rejects_missing_duplicate_class_and_schedule_changes',
    'test_association_unique_images_all_heads_and_every_observer_field_are_required',
    'test_refused_units_cannot_disappear_or_turn_local_acceptance_into_emission',
    'test_missing_or_stale_complete_metadata_and_final_carrier_identity_refuse',
)
COMMANDS = list(grouped.COMMANDS)
for row in (
    ('grouped-cli', ['cargo', 'test', '-p', 'liteinst-rewrite', '--example',
                     'disassembly_sites', 'grouped_tests::'], 180),
    ('grouped-linkage-python', ['/usr/bin/python3.9', '-I', '-B',
                                'evaluation/direct-program/test_grouped_linkage.py', '-v'], 180),
):
    COMMANDS.insert(-2, row)


def validate_result(name, raw):
    grouped.validate_result(name, raw)
    if name == 'grouped-cli':
        rows = re.findall(rb'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', raw, re.M)
        assert rows == [(b'3', b'0', b'0')], 'all three grouped CLI controls must run'
    if name in ('grouped-cli', 'workspace'):
        for case in CLI_CONTROLS:
            assert raw.splitlines().count(('test grouped_tests::' + case + ' ... ok').encode()) == 1, 'grouped CLI control missing: ' + case
    if name == 'grouped-linkage-python':
        assert re.findall(rb'^Ran (\d+) tests in ', raw, re.M) == [b'5'] and raw.rstrip().endswith(b'OK')
        for case in PYTHON_CONTROLS:
            assert raw.splitlines().count((case + ' (__main__.GroupedLinkage) ... ok').encode()) == 1, 'grouped Python control missing: ' + case


if __name__ == '__main__':
    assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode
    assert sys.argv.count('--focused') <= 1
    focused = '--focused' in sys.argv
    if focused:
        sys.argv.remove('--focused')
    focused_names = ('fmt', *grouped.CONTROLS, 'grouped-cli', 'grouped-linkage-python')
    selected = [row for row in COMMANDS if row[0] in focused_names] if focused else COMMANDS
    raise SystemExit(grouped.window.stack.cuts.clock.shared.main(
        commands=selected,
        profile='grouped-program-focused-180-v1' if focused else 'grouped-program-correctness-1800-360-v1',
        scope='Focused 26 core/frontend/native/CLI/Python controls only; not full workspace validation.' if focused else
              'Required correctness and all prior grouped artifact controls plus typed CLI and '
              'complete policy/association linkage controls. No actual-program corpus, runtime '
              'exemption, performance or strict A4 qualification.',
        log_namespace='grouped-program', validate_result=validate_result))
