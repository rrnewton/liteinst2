#!/usr/bin/env python3
"""Shared CFG correctness checks using the same bounded validation owner."""
import importlib.util
from pathlib import Path
import re
import sys

SOURCE = Path(__file__).resolve().parents[1] / 'shared-x86/validate.py'
spec = importlib.util.spec_from_file_location('shared_cfg_validation', SOURCE)
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
COMMANDS = [
    ('fmt', ['cargo', 'fmt', '--check'], 180),
    ('clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'], 180),
    ('check', ['cargo', 'check', '--workspace', '--all-features', '--all-targets'], 180),
    ('graph', ['cargo', 'test', '-p', 'liteinst2', '--lib', 'control_flow::'], 180),
    ('whole-function', ['cargo', 'test', '-p', 'liteinst2', '--lib', 'quiescent::whole_function::'], 180),
    ('offline-neighbor', ['cargo', 'test', '-p', 'liteinst-rewrite', '--lib', 'neighbor_catalogue::'], 180),
    ('runtime-ordinary', ['cargo', 'test', '-p', 'rapid-profiler', '--lib', 'frontend_native::module::ordinary::'], 180),
    ('workspace', ['cargo', 'test', '-j', '12', '--workspace', '--no-fail-fast'], 1800),
    ('serial-launch', ['cargo', 'test', '-p', 'liteinst-launch', '--tests', '--', '--test-threads=1', '--nocapture'], 180),
]


def validate_result(name, raw):
    if name in ('graph', 'whole-function', 'offline-neighbor', 'runtime-ordinary'):
        rows = re.findall(rb'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', raw, re.M)
        assert len(rows) == 1 and int(rows[0][0]) > 0, 'focused target must execute tests'
        assert rows[0][1:] == (b'0', b'0'), 'focused target must have no failures or ignores'


if __name__ == '__main__':
    if not (__debug__ and sys.flags.isolated and sys.dont_write_bytecode):
        raise SystemExit('requires isolated bytecode-free Python with assertions enabled')
    raise SystemExit(shared.main(commands=COMMANDS, profile='shared-cfg-correctness-1800-v1',
                                 scope='Shared CFG correctness only; no page-exemption or throughput claim.',
                                 log_namespace='shared-cfg', validate_result=validate_result))
