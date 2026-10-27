#!/usr/bin/env python3
"""Copy the exact historical E9 recipes into an explicit checkout; launch nothing."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

TESTED_REVISION = '9884b7a259b4e0ea80d2cca6d726abab4594807a'
ASSETS = [{'asset': 'runner.py', 'sha256': '3feea2da3dbc4455af5133caebc87441709a8342caa068f215640d3e3b2a6973', 'bytes': 42365, 'mode': 420, 'destinations': ['ignored/a3/e9-common-e9-paired-runner-v2/payload/evaluation/e9-common-app/run_e9_pairs.py']}, {'asset': 'auditor-initial.py', 'sha256': '3d69c425fee567dace19e72fc1cce3e65bc41ef2b8725ce74ed7b10b4c9e8008', 'bytes': 81102, 'mode': 420, 'destinations': ['ignored/a3/e9-common-e9-pair-audit-v1/payload/evaluation/e9-common-app/audit_e9_pairs.py']}, {'asset': 'auditor-hash-reuse.py', 'sha256': '448d255df8220d2a2503ab13b6a2b02482dbca240986416f4c5444669f0da8ad', 'bytes': 81111, 'mode': 420, 'destinations': ['ignored/a3/e9-common-e9-pair-audit-hash-reuse-v2/payload/evaluation/e9-common-app/audit_e9_pairs.py']}, {'asset': 'auditor-sized-read.py', 'sha256': '5cf71fbe47efccd39517228f51c80513d979575ecabdd5057e179a7daa3b8700', 'bytes': 81111, 'mode': 420, 'destinations': ['ignored/a3/e9-common-e9-pair-audit-efficiency-v3/payload/evaluation/e9-common-app/audit_e9_pairs.py']}, {'asset': 'heads.json', 'sha256': '5e8f74c75c8274917f76c5663ad0badb7d1d7d31915fa716d29521e61e75e32c', 'bytes': 16825, 'mode': 420, 'destinations': ['ignored/a3/e9-common-e9-pair-audit-v1/payload/evaluation/e9-common-app/e9-pair-heads.json', 'ignored/a3/e9-common-e9-pair-audit-hash-reuse-v2/payload/evaluation/e9-common-app/e9-pair-heads.json', 'ignored/a3/e9-common-e9-pair-audit-efficiency-v3/payload/evaluation/e9-common-app/e9-pair-heads.json']}, {'asset': 'source-pins.json', 'sha256': '4544269294433e99aa419d8b97c6c56fb7e1adcadeae894a9e4d7fec4fdef8f1', 'bytes': 1780, 'mode': 420, 'destinations': ['ignored/a3/e9-common-e9-pair-audit-v1/payload/evaluation/e9-common-app/e9-pair-source-pins.json', 'ignored/a3/e9-common-e9-pair-audit-hash-reuse-v2/payload/evaluation/e9-common-app/e9-pair-source-pins.json', 'ignored/a3/e9-common-e9-pair-audit-efficiency-v3/payload/evaluation/e9-common-app/e9-pair-source-pins.json']}, {'asset': 'runner-parent.py', 'sha256': 'ef498715a3dc8120725011ab71d0a57dfd16ddc984cdde044fa23aee19146ca8', 'bytes': 1481, 'mode': 420, 'destinations': ['ignored/a3/common-native-epoch-v1/e9-launch-v1/launch.py']}]


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
    assets_root = Path(__file__).resolve(strict=True).parent / 'e9-native-recipes'
    data = {r['asset']: read_asset(assets_root / r['asset'], r) for r in ASSETS}
    destinations = [p for r in ASSETS for p in r['destinations']]
    require(len(destinations) == len(set(destinations)) == 11, 'fixed unique output set')
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
