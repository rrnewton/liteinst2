#!/usr/bin/env python3
"""Explicit compact-ledger controls through the unchanged upstream validator."""
import importlib.util
from pathlib import Path
import re
import sys

SOURCE = Path(__file__).with_name('validate_grouped_upstream.py')
spec = importlib.util.spec_from_file_location('ledger_chunks_upstream_controls', SOURCE)
upstream = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upstream)
CONTROLS = {
    'ledger-codec': ('ledger_codec::tests::', (
        'same_real_multi_step_plans_expand_exactly_and_replay_current_overlay',
        'repinned_stale_second_read_fails_overlay_not_only_container_hash',
        'empty_repeated_same_address_and_short_tail_reads_keep_exact_ordinals',
        'table_identity_canonical_ids_reference_order_and_lengths_are_checked',
        'shared_extensions_preserve_grouped_and_fixed_canonical_records',
        'advertised_work_and_aggregate_staging_refuse_without_expansion_allocation',
        'first_codec_error_is_retained_but_existing_semantic_error_still_wins',
    )),
    'ledger-hasher': ('streaming_content_id_tests::', (
        'incremental_empty_boundaries_and_many_updates_equal_exact_content_id',
    )),
    'ledger-storage-cli': ('ledger_storage_tests::', (
        'chunk_storage_selector_is_independent_and_legacy_parse_remains_exact',
        'chunk_storage_actual_group_preserves_inline_plans_images_outcomes_and_bindings',
        'chunk_storage_table_proof_and_physical_embedded_plan_mutations_refuse',
        'chunk_storage_replays_evolving_reads_and_retains_atomic_refusals',
    )),
}
PYTHON_CONTROLS = (
    'test_compact_closure_keeps_every_atomic_outcome_and_legacy_default',
    'test_table_binding_replay_member_and_bundle_pins_must_all_agree',
    'test_storage_version_scope_and_unrecorded_verification_never_pass',
    'test_repinned_current_read_census_and_source_membership_stay_strict',
)
COMMANDS = list(upstream.COMMANDS)
for row in (
    ('ledger-codec', ['cargo', 'test', '-p', 'liteinst-rewrite', '--lib',
                      'ledger_codec::tests::'], 180),
    ('ledger-hasher', ['cargo', 'test', '-p', 'liteinst-artifact', '--lib',
                       'streaming_content_id_tests::'], 180),
    ('ledger-storage-cli', ['cargo', 'test', '-p', 'liteinst-rewrite', '--example',
                            'disassembly_sites', 'ledger_storage_tests::'], 180),
    ('ledger-storage-python', ['/usr/bin/python3.9', '-I', '-B',
                               'evaluation/direct-program/test_ledger_storage.py', '-v'], 180),
):
    COMMANDS.insert(-2, row)


def validate_result(name, raw):
    upstream.validate_result(name, raw)
    if name in CONTROLS:
        cases = CONTROLS[name][1]
        rows = re.findall(rb'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', raw, re.M)
        assert rows == [(str(len(cases)).encode(), b'0', b'0')], 'exact ledger control population must run'
    for control, (prefix, cases) in CONTROLS.items():
        if name in (control, 'workspace'):
            for case in cases:
                assert raw.splitlines().count(('test ' + prefix + case + ' ... ok').encode()) == 1, 'ledger control missing: ' + case
    if name == 'ledger-storage-python':
        assert re.findall(rb'^Ran (\d+) tests in ', raw, re.M) == [b'4'] and raw.rstrip().endswith(b'OK')
        for case in PYTHON_CONTROLS:
            assert raw.splitlines().count((case + ' (__main__.LedgerStorage) ... ok').encode()) == 1, 'ledger Python control missing: ' + case


if __name__ == '__main__':
    assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode
    assert sys.argv.count('--focused') <= 1
    focused = '--focused' in sys.argv
    if focused:
        sys.argv.remove('--focused')
    focused_names = ('fmt', *upstream.program.grouped.CONTROLS, 'grouped-cli', 'grouped-linkage-python',
                     *upstream.CONTROLS, 'upstream-linkage-python', *CONTROLS, 'ledger-storage-python')
    selected = [row for row in COMMANDS if row[0] in focused_names] if focused else COMMANDS
    raise SystemExit(upstream.program.grouped.window.stack.cuts.clock.shared.main(
        commands=selected,
        profile='ledger-chunks-focused-180-v1' if focused else 'ledger-chunks-correctness-1800-360-v1',
        scope='Focused 60 inherited and ledger codec/hasher/CLI/Python controls only; not full workspace validation.' if focused else
              'Required correctness and every prior upstream control plus explicit compact-ledger '
              'codec, streaming hash, current-read and CLI/linkage controls. No actual-program '
              'corpus, runtime exemption, performance or strict A4 qualification.',
        log_namespace='ledger-chunks', validate_result=validate_result))
