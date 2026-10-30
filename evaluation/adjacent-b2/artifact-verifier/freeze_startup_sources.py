#!/usr/bin/env python3
"""Freeze the current clean startup source tree; this is not a review approval."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess


def freeze(root, destination):
    git = lambda *args: subprocess.check_output(['git', '-C', str(root), *args], timeout=15)
    if git('diff', '--binary', 'HEAD', '--'):
        raise ValueError('commit the reviewed source changes before freezing')
    revision = git('rev-parse', 'HEAD').decode('ascii').strip()
    custody = root / 'evaluation/adjacent-b2/artifact-verifier/startup_custody.py'
    constants = {}
    for node in ast.parse(custody.read_text()).body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        name = node.targets[0].id
        if name == 'CRATE':
            constants[name] = ast.literal_eval(node.value)
        elif name == 'SOURCE_ROOTS':
            constants[name] = tuple(constants[v.id] if isinstance(v, ast.Name) else ast.literal_eval(v)
                                    for v in node.value.elts)
    roots = constants['SOURCE_ROOTS']
    if not roots or not all(type(p) is str and not p.startswith('/') and '..' not in p.split('/') for p in roots):
        raise ValueError('exact relative source roots')
    names = git('ls-tree', '-r', '--name-only', revision, '--', *roots).decode('utf-8').splitlines()
    digest = lambda raw: hashlib.sha256(raw).hexdigest()
    sources = {}
    for name in names:
        raw = git('show', revision + ':' + name)
        if (root / name).read_bytes() != raw:
            raise ValueError('live source differs from revision: ' + name)
        sources[name] = digest(raw)
    if git('rev-parse', 'HEAD').decode('ascii').strip() != revision or git('diff', '--binary', 'HEAD', '--'):
        raise ValueError('source changed during freeze')
    value = dict(schema='LI2STARTUP-SOURCE-PROFILE-1', profile='startup-main-independent-verifier-source-v1',
        source_revision=revision, sources=sources,
        producer_lock_sha256=sources['Cargo.lock'],
        verifier_lock_sha256=sources['evaluation/adjacent-b2/artifact-verifier/Cargo.lock'])
    raw = (json.dumps(value, indent=2) + '\n').encode('utf-8')
    if (not destination.is_absolute() or not destination.is_relative_to(root / 'ignored') or
            destination.parent.resolve(strict=True) != destination.parent):
        raise ValueError('new output in canonical ignored directory')
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            if stream.write(raw) != len(raw):
                raise OSError('short profile write')
            stream.flush(); os.fsync(stream.fileno())
    finally:
        os.close(fd)
    return dict(revision=revision, files=len(sources), bytes=len(raw), sha256=digest(raw))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(freeze(Path(__file__).resolve().parents[3], args.output)))


if __name__ == '__main__':
    main()
