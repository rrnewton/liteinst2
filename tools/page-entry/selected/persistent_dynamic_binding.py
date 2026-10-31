#!/usr/bin/env python3
"""Source-owned configuration for the distinct dynamic adjacent-pair owner.

The entire input ELF is an immutable build input, never an admission receipt.
Source pages and registration authority are authenticated by the runtime at each
actual TRACE. No configured entry RVA or assumed source-page pair is emitted.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys

from persistent_epoch_binding import LEAVES, need, fact

REPLACEMENTS = {
    'persistent_controller.inc': 'persistent_dynamic_controller.inc',
    'build-persistent-epoch.sh': 'build-persistent-dynamic.sh',
    'persistent_epoch_binding.py': 'persistent_dynamic_binding.py',
}
DYNAMIC_LEAVES = tuple(REPLACEMENTS.get(name, name) for name in LEAVES) + (
    'persistent_dynamic_plan.h', 'persistent_dynamic_plan.inc', 'persistent_epoch_binding.py',
)


def image_identity(data):
    def take(at, count):
        need(type(at) is int and type(count) is int and 0 <= at <= len(data) and
             0 <= count <= len(data)-at, 'whole dynamic ELF input range')
        return data[at:at+count]
    h = struct.unpack('<16sHHIQQQIHHHHHH', take(0, 64))
    need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1] in (2, 3) and h[2:4] == (62, 1) and
         h[8:10] == (64, 56) and 0 < h[10] <= 128, 'bounded original x86-64 ET_EXEC or ET_DYN')
    program = take(h[5], h[10]*56)
    loads = [struct.unpack('<IIQQQQQQ', program[i*56:(i+1)*56]) for i in range(h[10])]
    loads = [row for row in loads if row[0] == 1]
    need(loads and all(row[5] <= row[6] and row[3] < 1 << 47 and row[6] <= (1 << 47)-row[3]
                       and row[1] & ~7 == 0 for row in loads), 'bounded actual LOAD extents and flags')
    for row in loads:
        take(row[2], row[5])
    need(any(row[1] & 1 and row[3] <= h[4] < row[3]+row[5] for row in loads),
         'actual ELF entry belongs to a file-backed executable LOAD')
    return dict(image=fact(data), elf_type=h[1], entry=h[4], load_count=len(loads),
                program_headers=fact(program))


def main():
    need(len(sys.argv) == 5, 'selected directory, actual archive, original image, output directory')
    selected, archive, image, output = (Path(x).resolve(strict=True) for x in sys.argv[1:])
    need(selected.is_dir() and archive.is_file() and image.is_file() and output.is_dir(), 'actual binding inputs')
    values = []
    for name in DYNAMIC_LEAVES:
        path = selected/name
        need(not path.is_symlink() and path.is_file(), 'exact regular dynamic policy source')
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
    persistent = ('#ifndef LI2_PERSISTENT_EPOCH_CONFIG_H\n#define LI2_PERSISTENT_EPOCH_CONFIG_H\n'
                  '#define LI2_PE_BINDING_VERSION 1\n#define LI2_PE_DYNAMIC_BINDING_VERSION 1\n'
                  '#define LI2_PE_ARCHIVE_SHA256 '+literal(actual_archive['sha256'])+'\n'
                  '#define LI2_PE_POLICY_SHA256 '+literal(policy)+'\n#endif\n')
    headers = {'linked_epoch_config.h': linked, 'persistent_epoch_config.h': persistent}
    record = dict(version=1, profile='persistent-dynamic-adjacent-two-page-v1', archive=actual_archive,
                  policy_sha256=policy, original=original, sources=values,
                  headers={name: fact(text.encode()) for name, text in headers.items()})
    paths = [output/name for name in headers]+[output/'persistent_epoch_binding.json']
    need(not any(path.exists() for path in paths), 'fresh exclusive dynamic configuration outputs')
    for name, text in headers.items():
        with (output/name).open('x') as stream:
            stream.write(text)
    with paths[-1].open('x') as stream:
        stream.write(json.dumps(record, sort_keys=True)+'\n')


if __name__ == '__main__':
    main()
