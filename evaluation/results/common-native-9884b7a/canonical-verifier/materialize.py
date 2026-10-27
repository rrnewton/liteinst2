#!/usr/bin/env python3
"""Copy exact historical canonical-verifier recipes; launch nothing."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

TESTED_REVISION = '9884b7a259b4e0ea80d2cca6d726abab4594807a'
ASSETS = [{'asset': 'build-v1.py', 'sha256': 'fa9de2e9e57f70a3d69575373e0585fbd2bcb86faa0f7533cc6146240af4e2fa', 'bytes': 19084, 'mode': 420, 'destinations': ['ignored/a3/common-native-epoch-v1/core-verifier-canonical-build-proposal-v1/build.py']}, {'asset': 'build-v2.py', 'sha256': '390d7ce6c0782696159ae524415dc3f6d3c2ffe02fad27b3634039442e25eab5', 'bytes': 19114, 'mode': 420, 'destinations': ['ignored/a3/common-native-epoch-v1/core-verifier-canonical-build-proposal-v2/build.py']}, {'asset': 'compiler_entry.py', 'sha256': '70c4f0ec1cfc2f0b0b74c00199927f83e5a7cfbe4bb2d2ce2e3295e9ecea1ee0', 'bytes': 4332, 'mode': 420, 'destinations': ['ignored/a3/common-native-epoch-v1/core-verifier-canonical-build-proposal-v1/compiler_entry.py', 'ignored/a3/common-native-epoch-v1/core-verifier-canonical-build-proposal-v2/compiler_entry.py']}]


def require(value, message):
    if not value:
        raise ValueError(message)


def read_asset(path, row):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size == row['bytes'], 'asset type/length')
        data = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
        fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(fields(before) == fields(after) == fields(path.lstat()), 'asset changed while read')
    require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'], 'asset bytes')
    return data


def parent_fd(root_fd, parts):
    current = os.dup(root_fd)
    try:
        for part in parts:
            try:
                os.mkdir(part, 0o700, dir_fd=current)
            except FileExistsError:
                pass
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = following
        result = current
        current = None
        return result
    finally:
        if current is not None:
            os.close(current)


def main():
    if sys.flags.optimize:
        raise SystemExit('optimized Python is unsupported')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo
    require(repo.is_absolute() and repo.resolve(strict=True) == repo and repo.is_dir(), 'canonical checkout directory required')
    assets_root = Path(__file__).resolve(strict=True).parent / 'recipe-sources'
    data = {r['asset']: read_asset(assets_root / r['asset'], r) for r in ASSETS}
    destinations = [p for r in ASSETS for p in r['destinations']]
    require(len(destinations) == len(set(destinations)) == 4, 'fixed unique output set')
    for relative in destinations:
        parts = Path(relative).parts
        require(parts[:2] == ('ignored', 'a3') and all(p not in ('.', '..', 'target') for p in parts), 'fixed ignored output path')
        for index in range(1, len(parts)):
            path = repo.joinpath(*parts[:index])
            try:
                owner = path.lstat()
            except FileNotFoundError:
                continue
            require(stat.S_ISDIR(owner.st_mode), 'existing output parent is not a real directory')
        try:
            (repo / relative).lstat()
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError('refusing existing recipe destination: ' + relative)
    root_fd = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    written = []
    try:
        for row in ASSETS:
            for relative in row['destinations']:
                path = Path(relative)
                directory = parent_fd(root_fd, path.parts[:-1])
                try:
                    fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, row['mode'], dir_fd=directory)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(data[row['asset']])
                        os.fchmod(stream.fileno(), row['mode'])
                finally:
                    os.close(directory)
                written.append(dict(path=relative, sha256=row['sha256'], bytes=row['bytes'], mode=row['mode']))
    finally:
        os.close(root_fd)
    print(json.dumps(dict(completed=True, scope='source materialization only; no source epoch or runtime admission',
                         tested_revision=TESTED_REVISION, files=written, native_executions=0), sort_keys=True))


if __name__ == '__main__':
    main()
