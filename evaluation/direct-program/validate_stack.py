#!/usr/bin/env python3
"""Complete jump/register-stack selection and existing core correctness checks."""
import importlib.util
from pathlib import Path
import sys
import re

SOURCE = Path(__file__).resolve().parents[1] / 'shared-cfg/validate_cuts.py'
spec = importlib.util.spec_from_file_location('stack_cut_controls', SOURCE)
cuts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cuts)
COMMANDS = list(cuts.COMMANDS)
COMMANDS.insert(1, ('inventory-python', ['/usr/bin/python3.9', '-I', '-B',
                    'evaluation/direct-program/test_stack_inventory.py'], 180))
NATIVE_CONTROLS = ('jump_stack_native_low_gprs', 'jump_stack_native_high_gprs',
                   'jump_stack_native_rsp_loaded_value', 'jump_stack_native_operand_faults')
COMMANDS.insert(-2, ('native-stack', ['cargo', 'test', '-p', 'liteinst2',
                        '--test', 'quiescent_oracle', 'jump_stack_native_'], 180))
CONTROLS = (
    'jump_fact_matches_the_complete_legacy_mnemonic_population',
    'register_stack_union_keeps_all_registers_and_exact_code_boundaries',
    'jump_stack_import_keeps_complete_union_and_literal_old_inventory',
    'jump_stack_import_preserves_shared_first_errors_and_global_target_checks',
    'jump_stack_import_keeps_every_register_without_legacy_profile_promotion',
    'complete_union_policy_and_shared_manifest_retain_rsp_prefixes_and_classes',
    'union_projection_rejects_class_population_and_policy_replay_mutations',
    'union_fixed_policy_keeps_ordered_permits_caps_and_first_errors',
    'union_actual_fixed_transaction_emits_or_refuses_complete_population',
    'jump_stack_material_selection_joins_every_rpc_patch_and_keeps_caps',
    'jump_stack_input_selectors_keep_pin_type_and_mixed_mode_refusals',
    'jump_stack_material_policy_files_keep_full_counts_on_policy_refusal',
    'jump_stack_rewrite_selector_preserves_old_routes_and_rejects_mixing',
    'jump_stack_rewrite_uses_typed_prepare_and_retains_every_imported_row_on_refusal',
)


def validate_result(name, raw):
    cuts.validate_result(name, raw)
    if name == 'inventory-python':
        assert b'Ran 4 tests in ' in raw and raw.rstrip().endswith(b'OK')
    if name == 'native-stack':
        rows = re.findall(rb'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', raw, re.M)
        assert rows == [(b'4', b'0', b'0')], 'all four native controls must run'
    if name in ('native-stack', 'workspace'):
        for case in NATIVE_CONTROLS:
            assert raw.splitlines().count(('test ' + case + ' ... ok').encode()) == 1, 'native control missing: ' + case
    if name == 'workspace':
        lines = raw.splitlines()
        for case in CONTROLS:
            suffix = ('::' + case + ' ... ok').encode()
            assert sum(line.startswith(b'test ') and line.endswith(suffix)
                       for line in lines) == 1, 'new selection control missing: ' + case


if __name__ == '__main__':
    if not (__debug__ and sys.flags.isolated and sys.dont_write_bytecode):
        raise SystemExit('requires isolated bytecode-free Python with assertions enabled')
    raise SystemExit(cuts.clock.shared.main(
        commands=COMMANDS, profile='jump-stack-selection-correctness-1800-360-v1',
        scope='Separate complete jumps/Push_r64/Pop_r64 selection uses the shared '
              'importer, policy, planner and encoder, with finite native stack/fault controls. No '
              'complete-CFG, runtime exemption, performance or strict A4 qualification.',
        log_namespace='jump-stack-selection', validate_result=validate_result))
