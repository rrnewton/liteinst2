#!/usr/bin/env python3
"""Shared CFG correctness for the two owned back-edge clock profiles."""
import importlib.util
from pathlib import Path
import re
import sys

SOURCE = Path(__file__).resolve().parents[1] / 'shared-x86/validate.py'
spec = importlib.util.spec_from_file_location('owned_clock_cfg_validation', SOURCE)
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
COMMANDS = [
    ('fmt', ['cargo', 'fmt', '--check'], 180),
    ('clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'], 180),
    ('check', ['cargo', 'check', '--workspace', '--all-features', '--all-targets'], 180),
    ('graph', ['cargo', 'test', '-p', 'liteinst2', '--lib', 'control_flow::'], 180),
    ('clock', ['cargo', 'test', '-p', 'liteinst2', '--lib', 'backedge_clock::'], 180),
    ('workspace', ['cargo', 'test', '-j', '12', '--workspace', '--no-fail-fast'], 1800),
    ('serial-launch', ['cargo', 'test', '-p', 'liteinst-launch', '--tests', '--', '--test-threads=1', '--nocapture'], 360),
]


def validate_result(name, raw):
    if name in ('graph', 'clock'):
        rows = re.findall(rb'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', raw, re.M)
        assert len(rows) == 1 and int(rows[0][0]) > 0, 'focused target must execute tests'
        assert rows[0][1:] == (b'0', b'0'), 'focused target must have no failures or ignores'
    if name == 'clock':
        prefix = b'test backedge_clock::owned_region::cfg_shared_tests::'
        for case in (
            b'owned_cfg_shared_positive_graphs_and_distinct_scalar_profiles',
            b'owned_cfg_shared_refusals_and_exact_backedge_rosters',
            b'owned_cfg_shared_region_returnability_is_not_added_to_loop',
            b'owned_cfg_shared_size_address_and_supplied_scan_guards',
        ):
            assert raw.splitlines().count(prefix + case + b' ... ok') == 1, 'new CFG control missing'


if __name__ == '__main__':
    if not (__debug__ and sys.flags.isolated and sys.dont_write_bytecode):
        raise SystemExit('requires isolated bytecode-free Python with assertions enabled')
    raise SystemExit(shared.main(
        commands=COMMANDS, profile='owned-clock-shared-cfg-correctness-1800-360-v1',
        scope='Shared CFG construction preserves both existing owned-clock '
              'admission profiles. No broader clock, runtime page-exemption, '
              'throughput or strict claim-4 qualification.',
        log_namespace='owned-clock-shared-cfg', validate_result=validate_result))
