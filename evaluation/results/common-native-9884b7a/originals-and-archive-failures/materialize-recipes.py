#!/usr/bin/env python3
"""Copy five verified recipe sources to absent fixed ignored paths; run no recipe."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

REVISION = '9884b7a259b4e0ea80d2cca6d726abab4594807a'
MANIFEST_SHA = '4cac85cb124d22cbc42ab74c3913a43b8009f151739609a000f9457e5a11b043'
ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')


def read(path):
    assert path.parent.resolve(strict=True) == path.parent
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_size <= 1024 * 1024
        data = stream.read(1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        assert identity(before) == identity(after) == identity(path.lstat())
        assert len(data) == before.st_size
        return data


def main():
    if sys.flags.optimize:
        raise SystemExit('optimized Python is unsupported; assertions are required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo
    assert repo.is_absolute() and repo.resolve(strict=True) == repo
    packet = Path(__file__).resolve().parent
    manifest_bytes = read(packet / 'recipe-sources.json')
    assert hashlib.sha256(manifest_bytes).hexdigest() == MANIFEST_SHA
    manifest = json.loads(manifest_bytes)
    assert manifest['schema'] == 1 and manifest['tested_revision'] == REVISION
    assert len(manifest['files']) == 5
    git = lambda *argv: subprocess.check_output(['/usr/bin/git', '-C', str(repo), *argv],
        env=ENV, stdin=subprocess.DEVNULL, timeout=15)
    assert git('rev-parse', 'HEAD').decode().strip() == REVISION
    assert git('diff', 'HEAD', '--') == b'', 'clean tracked 9884 source required'
    pending = []
    for row in manifest['files']:
        relative = Path(row['destination'])
        assert not relative.is_absolute() and '..' not in relative.parts
        assert relative.parts[:2] == ('ignored', 'a3') and 'target' not in relative.parts
        source = Path(row['source'])
        assert not source.is_absolute() and source.parts[0] == 'recipe-sources' and '..' not in source.parts
        data = read(packet / source)
        assert len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256']
        assert row['mode'] == 0o644
        destination = repo / relative
        assert not os.path.lexists(destination), 'existing destination is never replaced'
        current = repo
        for part in relative.parts[:-1]:
            current = current / part
            if os.path.lexists(current):
                assert stat.S_ISDIR(current.lstat().st_mode), 'no symlink or non-directory ancestor'
        pending.append((relative, data, row))
    assert len({p for p, _, _ in pending}) == 5
    # All five sources/collisions are checked before any directory or file creation.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    for relative, data, row in pending:
        descriptors = [os.open(repo, flags)]
        try:
            parent = descriptors[0]
            for part in relative.parts[:-1]:
                try:
                    os.mkdir(part, 0o700, dir_fd=parent)
                except FileExistsError:
                    pass
                parent = os.open(part, flags, dir_fd=parent)
                descriptors.append(parent)
            fd = os.open(relative.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fchmod(stream.fileno(), row['mode'])
                os.fsync(stream.fileno())
                owner = os.fstat(stream.fileno())
                actual = (repo / relative).lstat()
                assert (owner.st_dev, owner.st_ino) == (actual.st_dev, actual.st_ino)
            assert read(repo / relative) == data
        finally:
            for fd in reversed(descriptors):
                os.close(fd)
    print(json.dumps(dict(status='FIVE_SOURCE_FILES_COPIED_ONLY', revision=REVISION,
                          files=5, compiler_executions=0, recipe_executions=0)))


if __name__ == '__main__':
    main()
