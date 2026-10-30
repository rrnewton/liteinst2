#!/usr/bin/env python3
"""Explicit startup build launcher; no producer or candidate dispatch."""
import os
from pathlib import Path
import sys


def argv(values):
    if len(values) != 4:
        raise ValueError('startup build launcher arity')
    _, cargo, root, role = values
    cargo, root = Path(cargo), Path(root)
    if not cargo.is_absolute() or not root.is_absolute() or role not in ('producer', 'verifier'):
        raise ValueError('startup build launcher profile')
    common = [str(cargo), 'build', '--release', '--locked', '--offline']
    if role == 'producer':
        return common + ['--manifest-path', str(root / 'Cargo.toml'), '--package',
                         'liteinst-rewrite', '--features', 'offline-router', '--example', 'offline_router_sites', '--message-format=json']
    return common + ['--manifest-path', str(root / 'evaluation/adjacent-b2/artifact-verifier/Cargo.toml'),
                     '--bin', 'adjacent-b2-artifact-verifier', '--message-format=json']


def main():
    command = argv(sys.argv)
    os.chdir('/')
    os.execv(command[0], command)


if __name__ == '__main__':
    main()
