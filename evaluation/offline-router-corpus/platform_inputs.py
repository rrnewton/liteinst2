#!/usr/bin/env python3
"""Passive fixed-profile GNU platform facts; never a contract or launch approval."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

MIB = 1048576
FILES = ('/lib64/ld-linux-x86-64.so.2', '/lib64/libc.so.6', '/lib64/libgcc_s.so.1',
         '/etc/ld.so.preload', '/etc/ld.so.cache')
DIRECTORIES = ('/usr/lib64', '/usr/lib64/glibc-hwcaps', '/usr/lib64/glibc-hwcaps/x86-64-v4',
    '/usr/lib64/glibc-hwcaps/x86-64-v3', '/usr/lib64/glibc-hwcaps/x86-64-v2',
    '/usr/lib64/tls', '/usr/lib64/tls/x86_64', '/usr/lib64/x86_64')


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(raw): return hashlib.sha256(raw).hexdigest()
def stamp(s): return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def pin(name):
    path = Path(name).resolve(strict=True)
    before = stamp(path.stat())
    need(stat.S_ISREG(before[2]) and before[3] <= 16*MIB, 'bounded regular platform input')
    raw = path.read_bytes()
    need(stamp(path.stat()) == before and len(raw) == before[3], 'stable whole platform file')
    return dict(input=str(name), canonical=str(path), sha256=sha(raw), bytes=before[3],
                device=before[0], inode=before[1], mode=before[2], mtime_ns=before[4], ctime_ns=before[5])


def resolution():
    aliases, directories = [], []
    for name in ('/lib64', '/usr/lib64/libgcc_s.so.1'):
        path = Path(name); before = stamp(path.lstat())
        need(stat.S_ISLNK(before[2]), 'fixed GNU profile alias')
        target = os.readlink(path)
        need(stamp(path.lstat()) == before, 'stable alias')
        aliases.append(dict(path=name, target=target, identity=before))
    for name in DIRECTORIES:
        path = Path(name)
        if not os.path.lexists(path):
            directories.append(dict(path=name, state='ABSENT', identity=None, entries_sha256=None))
            continue
        before = stamp(path.stat())
        need(stat.S_ISDIR(before[2]) and path.resolve(strict=True) == path, 'canonical search directory')
        entries = []
        with os.scandir(path) as iterator:
            for entry in iterator:
                need(len(entries) < 4096, 'unchanged directory-entry cap')
                mode = entry.stat(follow_symlinks=False).st_mode
                kind = ('symlink' if stat.S_ISLNK(mode) else 'directory' if stat.S_ISDIR(mode)
                        else 'file' if stat.S_ISREG(mode) else 'other')
                entries.append(dict(name=entry.name, kind=kind, link=os.readlink(entry.path) if kind == 'symlink' else None))
        entries.sort(key=lambda row: row['name'])
        need(stamp(path.stat()) == before, 'stable search directory')
        raw = json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()
        directories.append(dict(path=name, state='PRESENT', identity=before[:3], entries_sha256=sha(raw), entries=entries))
    return dict(aliases=aliases, search_directories=directories)


def capture(output):
    need(output.is_absolute() and output.parent.resolve(strict=True) == output.parent, 'canonical new output')
    output.mkdir(mode=0o700)
    def save(name, raw):
        with (output/name).open('xb') as stream:
            stream.write(raw)
    def save_json(name, value):
        save(name, (json.dumps(value, indent=2) + '\n').encode())
    commands, files = [], []
    def inspect(argv, name):
        result = subprocess.run(argv, capture_output=True, timeout=10,
                                env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
        need(len(result.stdout) + len(result.stderr) < 8*MIB, 'unchanged inspection-output cap')
        save(name+'.stdout', result.stdout); save(name+'.stderr', result.stderr)
        commands.append(dict(argv=argv, exit=result.returncode, stdout_sha256=sha(result.stdout), stderr_sha256=sha(result.stderr)))
        save_json('command-' + str(len(commands)) + '.json', commands[-1])
        need(result.returncode == 0, 'passive command failure')
    before_resolution = resolution()
    for index, name in enumerate(FILES):
        if not os.path.lexists(name):
            need(name == '/etc/ld.so.preload', 'required platform file')
            files.append(dict(input=name, state='ABSENT')); continue
        row = pin(name)
        if index < 3:
            inspect(['/usr/bin/readelf', '-d', row['canonical']], 'readelf-' + str(index))
            row['readelf_exit'] = 0
        files.append(row)
    inspect(['/sbin/ldconfig', '-p'], 'ldconfig')
    for row in files:
        if row.get('state') == 'ABSENT':
            need(not os.path.lexists(row['input']), 'preload appeared')
        else:
            actual = pin(row['input'])
            need(all(actual[k] == value for k, value in row.items() if k != 'readelf_exit'), 'platform input drift')
    need(resolution() == before_resolution, 'alias/search input drift')
    save_json('commands.json', commands); save_json('resolution.json', before_resolution)
    save_json('receipt.json', dict(kind='PASSIVE_HOST_INPUT_INVENTORY_ONLY', qualification=False, launches=0, files=files))
    print(sha((output/'receipt.json').read_bytes()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    capture(parser.parse_args().output)
