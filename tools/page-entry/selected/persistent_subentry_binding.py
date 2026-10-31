#!/usr/bin/env python3
"""Bind certified-head reuse to the source pair, lifetime and exact build mode."""
import hashlib
import json
from pathlib import Path
import sys

from persistent_startup_binding import LEAVES as STARTUP_LEAVES
from persistent_group_binding import image_identity, need, fact

LEAVES = tuple({'build-persistent-startup.sh':'build-persistent-subentry.sh',
                'persistent_startup_binding.py':'persistent_subentry_binding.py'}.get(n,n)
               for n in STARTUP_LEAVES) + ('persistent_subentry.h','persistent_subentry.inc',
                                         'persistent_subentry_source.inc')
MODES = ('release', 'capture', 'differential', 'counters')


def main():
    need(len(sys.argv) == 6 and sys.argv[5] in MODES,
         'selected directory, actual archive, original image, output directory, mode')
    selected, archive, image, output = (Path(x).resolve(strict=True) for x in sys.argv[1:5])
    mode = sys.argv[5]
    need(selected.is_dir() and archive.is_file() and image.is_file() and output.is_dir(),
         'actual active-domain binding inputs')
    leaves = LEAVES
    if mode != 'release':
        leaves += ('build-persistent-subentry-' + mode + '.sh',)
    if mode == 'counters':
        leaves += ('persistent_group_counters.h', 'persistent_group_counters.inc')
    values = []
    for name in leaves:
        path = selected / name
        need(not path.is_symlink() and path.is_file(), 'regular active-domain policy source')
        values.append(dict(path=name, **fact(path.read_bytes())))
    original = image_identity(image.read_bytes())
    policy = hashlib.sha256(json.dumps(dict(sources=values, original=original, mode=mode),
                          sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    actual_archive = fact(archive.read_bytes())
    literal = lambda value: '{' + ','.join('0x' + value[i:i+2] for i in range(0, 64, 2)) + '}'
    linked = ('#ifndef LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINKED_EPOCH_CONFIG_H\n'
              '#define LI2_LINK_BINDING_VERSION 1\n'
              '#define LI2_LINK_ARCHIVE_SHA256 ' + literal(actual_archive['sha256']) + '\n'
              '#define LI2_LINK_POLICY_SHA256 ' + literal(policy) + '\n#endif\n')
    persistent = ('#ifndef LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PERSISTENT_GROUP_CONFIG_H\n'
                  '#define LI2_PG_BINDING_VERSION 1\n#define LI2_PG_GROUP_BINDING_VERSION 4\n'
                  '#define LI2_PG_ARCHIVE_SHA256 ' + literal(actual_archive['sha256']) + '\n'
                  '#define LI2_PG_POLICY_SHA256 ' + literal(policy) + '\n#endif\n')
    headers = {'linked_epoch_config.h': linked, 'persistent_group_config.h': persistent}
    record = dict(version=1, profile='persistent-subentry-' + mode + '-v1', mode=mode, native_probe=True, parse_memo=True, unregistered=True, subentry=True,
                  archive=actual_archive, policy_sha256=policy, original=original, sources=values,
                  headers={name: fact(text.encode()) for name, text in headers.items()})
    paths = [output / name for name in headers] + [output / 'persistent_subentry_binding.json']
    need(not any(path.exists() for path in paths), 'fresh exclusive active-domain outputs')
    for name, text in headers.items():
        with (output / name).open('x') as stream:
            stream.write(text)
    with paths[-1].open('x') as stream:
        stream.write(json.dumps(record, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
