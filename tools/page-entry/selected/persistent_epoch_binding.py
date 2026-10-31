#!/usr/bin/env python3
"""Build inputs for one distinct registered two-page persistent primitive."""
import hashlib
import json
from pathlib import Path
import struct
import sys

LEAVES = (
    'decoder/Cargo.toml', 'decoder/src/lib.rs', 'decoder/src/region.rs',
    'decoder/src/mov_guard.rs', 'decoder/src/tf.rs', 'decoder/src/write_footprint.rs',
    'region_decode.h', 'linked_plan.h', 'linked_plan.c', 'linked_source.h',
    'linked_source.inc', 'linked_rseq.h', 'linked_rseq.inc', 'linked_proof.h',
    'linked_proof.inc', 'linked_controller.inc', 'linked_reuse.inc',
    'lifecycle_loader.c', 'span_source.inc', 'rseq_guard.c', 'rseq_region.inc',
    'runtime_loader.c', 'selected_globals.inc', 'selected_chain.inc',
    'native_lifecycle.inc', 'native_pair_lifecycle.inc', 'tf_span_transfer.inc',
    'span_fetch.inc', 'span_fast_bytes.h', 'persistent_plan.h', 'persistent_plan.c',
    'persistent_compact.h', 'persistent_compact.c', 'persistent_lifetime.h',
    'persistent_runtime.h', 'persistent_source.inc', 'persistent_rseq.inc',
    'persistent_controller.inc', 'linked_mov_guard.h', 'linked_mov_guard.c',
    '../bridge.c', 'build-persistent-epoch.sh', 'persistent_epoch_binding.py',
)


def need(value, message):
    if not value:
        raise ValueError(message)


def fact(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def image_identity(data):
    def take(at, count):
        need(0 <= at <= len(data) and 0 <= count <= len(data) - at, 'whole actual ELF range')
        return data[at:at + count]
    h = struct.unpack('<16sHHIQQQIHHHHHH', take(0, 64))
    need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:4] == (2, 62, 1) and
         h[8:10] == (64, 56) and 0 < h[10] <= 32 and h[11] == 64 and 0 < h[12] <= 256,
         'bounded original x86-64 ET_EXEC fixture')
    loads = [struct.unpack('<IIQQQQQQ', take(h[5] + i * 56, 56)) for i in range(h[10])]
    sections = [struct.unpack('<IIQQQQIIQQ', take(h[6] + i * 64, 64)) for i in range(h[12])]
    tables = [s for s in sections if s[1] == 2]
    need(len(tables) == 1, 'one actual symbol table')
    table = tables[0]
    need(table[9] == 24 and table[5] % 24 == 0 and table[6] < len(sections), 'whole symbol entries')
    names_section = sections[table[6]]
    need(names_section[1] == 3, 'actual symbol string table')
    names = take(names_section[4], names_section[5])
    wanted = {b'region_app_head', b'region_app_second_page'}
    symbols = {}
    for at in range(table[4], table[4] + table[5], 24):
        name, info, other, section, address, size = struct.unpack('<IBBHQQ', take(at, 24))
        need(name < len(names) and b'\0' in names[name:], 'bounded whole symbol name')
        name = names[name:names.index(b'\0', name)]
        if name in wanted:
            need(name not in symbols and section, 'unique defined original fixture symbol')
            symbols[name] = (address, size)
    need(set(symbols) == wanted, 'both image-derived persistent source symbols')
    head, size = symbols[b'region_app_head']
    second, _ = symbols[b'region_app_second_page']
    first = head & ~4095
    need(4096 <= first and head == first + 0x200 and size >= 15 and size <= 4096 - 0x200 and
         second == first + 4096 and second + 4096 < 1 << 31, 'two adjacent complete low source pages')
    owners = [s for s in loads if s[0] == 1 and s[1] == 5 and s[5] <= s[6] and
              s[3] <= first and first - s[3] + 8192 <= s[5]]
    need(len(owners) == 1, 'whole two-page source in one actual RX file load')
    for s in loads:
        if s[0] == 1 and s[3] < second + 4096 and first < s[3] + s[6]:
            need(s == owners[0], 'no overlapping source load or writable alias in image')
    segment = owners[0]
    source = take(segment[2] + first - segment[3], 8192)
    need(source[0x1fe:0x200] == b'\x66\x90', 'actual genuine TRACE predecessor')
    return dict(image=fact(data), head_rva=head, second_page_rva=second,
                source_pages=[first, second], source=fact(source))


def main():
    need(len(sys.argv) == 5, 'selected directory, actual archive, original image, output directory')
    selected, archive, image, output = (Path(x).resolve(strict=True) for x in sys.argv[1:])
    need(selected.is_dir() and archive.is_file() and image.is_file() and output.is_dir(), 'actual binding inputs')
    values = []
    for name in LEAVES:
        path = selected / name
        need(not path.is_symlink() and path.is_file(), 'exact regular policy source')
        values.append(dict(path=name, **fact(path.read_bytes())))
    original = image_identity(image.read_bytes())
    policy = hashlib.sha256(json.dumps(dict(sources=values, original=original),
                          sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    actual_archive = fact(archive.read_bytes())
    literal = lambda value: '{' + ','.join('0x' + value[i:i + 2] for i in range(0, 64, 2)) + '}'
    linked = ('#ifndef LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINKED_EPOCH_CONFIG_H\n'
              '#define LI2_LINK_BINDING_VERSION 1\n'
              '#define LI2_LINK_ARCHIVE_SHA256 ' + literal(actual_archive['sha256']) + '\n'
              '#define LI2_LINK_POLICY_SHA256 ' + literal(policy) + '\n#endif\n')
    persistent = ('#ifndef LI2_PERSISTENT_EPOCH_CONFIG_H\n#define LI2_PERSISTENT_EPOCH_CONFIG_H\n'
                  '#define LI2_PE_BINDING_VERSION 1\n'
                  '#define LI2_PE_ARCHIVE_SHA256 ' + literal(actual_archive['sha256']) + '\n'
                  '#define LI2_PE_POLICY_SHA256 ' + literal(policy) + '\n'
                  '#define LI2_PE_APP_HEAD_RVA 0x%xULL\n' % original['head_rva'] +
                  '#define LI2_PE_APP_SECOND_PAGE_RVA 0x%xULL\n' % original['second_page_rva'] + '#endif\n')
    headers = {'linked_epoch_config.h': linked, 'persistent_epoch_config.h': persistent}
    record = dict(version=1, profile='persistent-registered-two-page-v1', archive=actual_archive,
                  policy_sha256=policy, original=original, sources=values,
                  headers={name: fact(text.encode()) for name, text in headers.items()})
    paths = [output / name for name in headers] + [output / 'persistent_epoch_binding.json']
    need(not any(path.exists() for path in paths), 'fresh exclusive configuration outputs')
    for name, text in headers.items():
        with (output / name).open('x') as stream:
            stream.write(text)
    with paths[-1].open('x') as stream:
        stream.write(json.dumps(record, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
