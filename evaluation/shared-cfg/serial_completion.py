#!/usr/bin/env python3
"""One separate functional-completion observation; original 180s failures stand."""
import importlib.util
from pathlib import Path
import sys

SOURCE = Path(__file__).resolve().parents[1] / 'shared-x86/validate.py'
spec = importlib.util.spec_from_file_location('shared_cfg_serial_completion', SOURCE)
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
COMMANDS = [
    ('serial-launch', ['cargo', 'test', '-p', 'liteinst-launch', '--tests', '--',
                       '--test-threads=1', '--nocapture'], 360),
]

if __name__ == '__main__':
    if not (__debug__ and sys.flags.isolated and sys.dont_write_bytecode):
        raise SystemExit('requires isolated bytecode-free Python with assertions enabled')
    raise SystemExit(shared.main(
        commands=COMMANDS, profile='shared-cfg-serial-completion-360-v1',
        scope='One functional-completion attempt under an explicitly expanded 360s '
              'operational budget. Both original 180s serial profiles remain FAILED. '
              'No deadline, performance, page-exemption or strict claim-4 qualification.',
        log_namespace='shared-cfg-serial-completion'))
