#!/usr/bin/env python3
"""Shared pun geometry checks; earlier decoder/CFG failures remain recorded."""
import importlib.util
from pathlib import Path
import re
import sys

SOURCE = Path(__file__).resolve().parents[1] / 'shared-x86/validate.py'
spec = importlib.util.spec_from_file_location('shared_pun_validation', SOURCE)
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
COMMANDS = [
    ('fmt', ['cargo', 'fmt', '--check'], 180),
    ('clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'], 180),
    ('check', ['cargo', 'check', '--workspace', '--all-features', '--all-targets'], 180),
    ('core', ['cargo', 'test', '-p', 'liteinst2', '--lib', 'quiescent::'], 180),
    ('offline-permits', ['cargo', 'test', '-p', 'liteinst-rewrite', '--example', 'common_sites'], 180),
    ('workspace', ['cargo', 'test', '-j', '12', '--workspace', '--no-fail-fast'], 1800),
    ('serial-launch', ['cargo', 'test', '-p', 'liteinst-launch', '--tests', '--', '--test-threads=1', '--nocapture'], 360),
]


def validate_result(name, raw):
    if name in ('core', 'offline-permits'):
        rows = re.findall(rb'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', raw, re.M)
        assert len(rows) == 1 and int(rows[0][0]) > 0, 'focused target must execute tests'
        assert rows[0][1:] == (b'0', b'0'), 'focused target must have no failures or ignores'


if __name__ == '__main__':
    if not (__debug__ and sys.flags.isolated and sys.dont_write_bytecode):
        raise SystemExit('requires isolated bytecode-free Python with assertions enabled')
    raise SystemExit(shared.main(
        commands=COMMANDS, profile='shared-pun-correctness-1800-360-v1',
        scope='Shared pun geometry correctness; serial functional completion uses '
              'an explicit 360s operational budget. Earlier 180s failures stand. '
              'No page-exemption, throughput or strict claim-4 qualification.',
        log_namespace='shared-pun', validate_result=validate_result))
