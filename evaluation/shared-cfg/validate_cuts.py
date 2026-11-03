#!/usr/bin/env python3
"""Shared local/global disassembly-cut correctness, with prior clock controls."""
import importlib.util
from pathlib import Path
import re
import sys

SOURCE = Path(__file__).with_name('validate_clock.py')
spec = importlib.util.spec_from_file_location('disassembly_cut_clock_controls', SOURCE)
clock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clock)
COMMANDS = list(clock.COMMANDS)
COMMANDS.insert(5, (
    'import-cuts', ['cargo', 'test', '-p', 'liteinst-rewrite', '--lib',
                    'disassembly::tests::imported_cuts_'], 180))
CONTROLS = {
    'graph': ('control_flow::tests::', (
        'shared_cut_collector_keeps_global_direct_facts_separate_from_local_edges',
        'shared_cut_collector_preserves_policy_order_and_first_error',
    )),
    'import-cuts': ('disassembly::tests::', (
        'imported_cuts_keep_cross_region_call_branch_and_xbegin_targets',
        'imported_cuts_keep_global_contradictions_after_all_ledger_and_entry_checks',
    )),
}


def validate_result(name, raw):
    clock.validate_result(name, raw)
    if name == 'import-cuts':
        rows = re.findall(rb'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', raw, re.M)
        assert rows == [(b'2', b'0', b'0')], 'both importer controls must run'
    if name in CONTROLS:
        prefix, cases = CONTROLS[name]
        for case in cases:
            assert raw.splitlines().count(('test ' + prefix + case + ' ... ok').encode()) == 1, 'new cut control missing'


if __name__ == '__main__':
    if not (__debug__ and sys.flags.isolated and sys.dont_write_bytecode):
        raise SystemExit('requires isolated bytecode-free Python with assertions enabled')
    raise SystemExit(clock.shared.main(
        commands=COMMANDS, profile='shared-disassembly-cuts-correctness-1800-360-v1',
        scope='Shared local/global block-cut collection retains distinct target '
              'policies. No new opcode selection, complete-CFG, runtime '
              'page-exemption, throughput or strict claim-4 qualification.',
        log_namespace='shared-disassembly-cuts', validate_result=validate_result))
