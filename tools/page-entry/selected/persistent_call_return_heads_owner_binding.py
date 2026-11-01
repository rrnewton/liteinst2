#!/usr/bin/env python3
"""Bind only the distinct additional return-head observer and exact full source policy."""
import hashlib
import json
from pathlib import Path
import sys

from persistent_call_binding import LEAVES as CALL_LEAVES
from persistent_group_binding import image_identity, need, fact
from persistent_ret_owner_capture_binding import configuration

LEAVES = tuple({'build-persistent-call.sh':'build-persistent-call-return-heads-owner.sh',
                'persistent_call_binding.py':'persistent_call_return_heads_owner_binding.py'}.get(n,n)
               for n in CALL_LEAVES) + ('persistent_call_binding.py',
                    'persistent_ret_owner_observe.h','persistent_ret_owner_observe.inc',
                    'persistent_ret_owner_memory.h','persistent_ret_owner_memory.inc',
                    'persistent_ret_owner_capture_binding.py','tf_chain.inc',
                    'linked_ret_dispatch.h','linked_ret_dispatch.c',
                    'persistent_ret_resume.h','persistent_ret_resume.inc')
MODES = ('capture', 'differential')


def main():
    need(len(sys.argv) == 6 and sys.argv[5] in MODES,
         'selected directory, actual archive, original image, output directory, mode')
    selected, archive, image, output = (Path(x).resolve(strict=True) for x in sys.argv[1:5])
    mode = sys.argv[5]
    need(selected.is_dir() and archive.is_file() and image.is_file() and output.is_dir(),
         'actual active-domain binding inputs')
    leaves = LEAVES
    if mode == 'differential':
        leaves += ('build-persistent-call-return-heads-owner-differential.sh',)
    need(len(leaves) == len(set(leaves)), 'distinct RET policy inputs')
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
    headers = {'linked_epoch_config.h': linked, 'persistent_group_config.h': persistent,
               'persistent_ret_owner_config.h': configuration(image.read_bytes()).decode()}
    record = dict(version=1, profile='persistent-call-return-heads-owner-' + mode + '-v1', mode=mode, native_probe=True, parse_memo=True, unregistered=True, subentry=True, cross_pair=True, direct_frontier=True, call_dispatch=True, ret_dispatch=True,call_return_heads=True,plan_version=8,
                  maps_differential=mode == 'differential', typed_capture=True, ret_owner_capture=True, capture_schema=1,
                  archive=actual_archive, policy_sha256=policy, original=original, sources=values,
                  headers={name: fact(text.encode()) for name, text in headers.items()})
    paths = [output / name for name in headers] + [output / 'persistent_call_return_heads_owner_binding.json']
    need(not any(path.exists() for path in paths), 'fresh exclusive active-domain outputs')
    for name, text in headers.items():
        with (output / name).open('x') as stream:
            stream.write(text)
    with paths[-1].open('x') as stream:
        stream.write(json.dumps(record, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
