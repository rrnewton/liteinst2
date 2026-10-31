#!/usr/bin/env python3
"""Exact opt-in two-retained-certificate policy; old profile binders stay unchanged."""
import hashlib
import json
from pathlib import Path
import sys

from persistent_group_binding import GROUP_LEAVES, image_identity, need, fact

LEAVES = tuple({'build-persistent-group.sh': 'build-persistent-retained-two.sh',
    'persistent_group_binding.py': 'persistent_retained_two_binding.py'}.get(name, name)
    for name in GROUP_LEAVES) + ('persistent_group_binding.py', 'linked_jmp_dispatch.h', 'linked_jmp_dispatch.c', 'persistent_retained_two.inc')


def main():
    need(len(sys.argv) == 5, 'selected directory, actual archive, original image, output directory')
    selected, archive, image, output = (Path(x).resolve(strict=True) for x in sys.argv[1:])
    need(selected.is_dir() and archive.is_file() and image.is_file() and output.is_dir(), 'actual resident binding inputs')
    values = []
    for name in LEAVES:
        path = selected/name
        need(not path.is_symlink() and path.is_file(), 'exact regular resident policy source')
        values.append(dict(path=name, **fact(path.read_bytes())))
    original = image_identity(image.read_bytes())
    policy = hashlib.sha256(json.dumps(dict(sources=values, original=original),
                          sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    actual_archive = fact(archive.read_bytes())
    literal = lambda value: '{'+','.join('0x'+value[i:i+2] for i in range(0, 64, 2))+'}'
    linked = ('#ifndef LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINKED_EPOCH_CONFIG_H\n'
              '#define LI2_LINK_BINDING_VERSION 1\n'
              '#define LI2_LINK_ARCHIVE_SHA256 '+literal(actual_archive['sha256'])+'\n'
              '#define LI2_LINK_POLICY_SHA256 '+literal(policy)+'\n#endif\n')
    persistent = ('#ifndef LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PERSISTENT_GROUP_CONFIG_H\n'
                  '#define LI2_PG_BINDING_VERSION 1\n#define LI2_PG_GROUP_BINDING_VERSION 3\n'
                  '#define LI2_PG_ARCHIVE_SHA256 '+literal(actual_archive['sha256'])+'\n'
                  '#define LI2_PG_POLICY_SHA256 '+literal(policy)+'\n#endif\n')
    headers = {'linked_epoch_config.h': linked, 'persistent_group_config.h': persistent}
    record = dict(version=3, profile='persistent-retained-two-v3', archive=actual_archive,
                  policy_sha256=policy, original=original, sources=values,
                  headers={name: fact(text.encode()) for name, text in headers.items()})
    paths = [output/name for name in headers]+[output/'persistent_retained_two_binding.json']
    need(not any(path.exists() for path in paths), 'fresh exclusive resident configuration outputs')
    for name, text in headers.items():
        with (output/name).open('x') as stream:
            stream.write(text)
    with paths[-1].open('x') as stream:
        stream.write(json.dumps(record, sort_keys=True)+'\n')


if __name__ == '__main__':
    main()
