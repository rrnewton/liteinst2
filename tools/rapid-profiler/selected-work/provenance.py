#!/usr/bin/env python3
"""Bounded structural strip validation; trusted build provenance is joined by the runner."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

MIB = 1048576
U64 = 1 << 64
NAME = 'ordinary_checksum_nonempty'
LABEL = 'selected-checksum-v1'
VERSION_SCRIPT = b'{ global: ordinary_checksum; local: *; };\n'


def digest(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def extent(data, start, length):
    assert type(start) is int and type(length) is int
    assert 0 <= start < U64 and 0 <= length < U64 and start + length < U64
    assert start + length <= len(data)
    return data[start:start + length]


def unpack(fmt, data, offset):
    return struct.unpack(fmt, extent(data, offset, struct.calcsize(fmt)))


def cstring(data, offset):
    assert 0 <= offset < len(data)
    end = data.find(b'\0', offset)
    assert end >= offset
    value = data[offset:end].decode('ascii')
    assert all(32 < ord(c) < 127 for c in value)
    return value


def mapped(data, loads, address, size, flags=None):
    assert 0 <= address < U64 and 0 < size < U64 and address + size < U64
    owners = [p for p in loads if p[3] <= address and address + size <= p[3] + p[5]
              and (flags is None or p[1] == flags)]
    assert len(owners) == 1
    p = owners[0]
    offset = p[2] + address - p[3]
    return offset, extent(data, offset, size)


def elf(data):
    assert type(data) is bytes and 64 <= len(data) <= MIB
    h = unpack('<16sHHIQQQIHHHHHH', data, 0)
    assert h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:4] == (3, 62, 1)
    assert h[8:10] == (64, 56) and 1 <= h[10] <= 16
    assert h[11] == 64 and 1 <= h[12] <= 256 and 0 < h[13] < h[12]
    ph = [unpack('<IIQQQQQQ', data, h[5] + i * 56) for i in range(h[10])]
    assert not any(p[0] in (3, 7, 0x6474e553) for p in ph)  # INTERP/TLS/GNU_PROPERTY
    loads = [p for p in ph if p[0] == 1]
    assert loads and sum(p[3] == p[2] == 0 and p[1] == 4 for p in loads) == 1
    for p in loads:
        assert p[1] in (4, 5, 6) and p[5] == p[6] <= 65536 and p[7] == 4096
        assert p[2] % 4096 == p[3] % 4096 and p[3] + p[6] + 4095 < U64
        assert p[5] or p[3] % 4096 == 0
        extent(data, p[2], p[5])
    occupied = sorted((p[3] & ~4095, (p[3] + p[6] + 4095) & ~4095)
                      for p in loads if p[5])
    assert all(a[1] <= b[0] for a, b in zip(occupied, occupied[1:]))
    if h[4]:
        mapped(data, loads, h[4], 1, 5)
    stacks = [p for p in ph if p[0] == 0x6474e551]
    assert len(stacks) == 1 and stacks[0][1] == 6
    dynamics = [p for p in ph if p[0] == 2]
    assert len(dynamics) == 1
    dynamic = dynamics[0]
    offset, values = mapped(data, loads, dynamic[3], dynamic[5])
    assert offset == dynamic[2] and 0 < len(values) <= 4096 and len(values) % 16 == 0
    tags = {}
    ended = False
    for at in range(0, len(values), 16):
        tag, value = unpack('<QQ', values, at)
        if tag == 0:
            assert value == 0
            ended = True
        else:
            assert not ended and tag not in tags
            assert tag in (4, 5, 6, 10, 11, 14, 24, 30, 0x6ffffef5, 0x6ffffffb)
            assert tag != 24 or value == 0
            assert tag != 30 or value & ~8 == 0
            assert tag != 0x6ffffffb or value & ~1 == 0
            tags[tag] = value
    assert ended and all(k in tags for k in (5, 6, 10, 11))
    assert tags[11] == 24 and 0 < tags[10] <= 65536
    assert 4 in tags or 0x6ffffef5 in tags
    assert 24 in tags or tags.get(30, 0) & 8 or tags.get(0x6ffffffb, 0) & 1
    sh = [unpack('<IIQQQQIIQQ', data, h[6] + i * 64) for i in range(h[12])]
    strings = sh[h[13]]
    assert strings[1] == 3
    names = extent(data, strings[4], strings[5])
    sections = [(cstring(names, p[0]), p) for p in sh]
    assert len({name for name, _ in sections}) == len(sections)
    assert not any(name == '.note.gnu.property' or (p[1] in (4, 9, 19) and p[5])
                   for name, p in sections)
    for _, p in sections:
        if p[1] != 8:
            extent(data, p[4], p[5])
    tables = {}
    for name, p in sections:
        if p[1] not in (2, 11):
            continue
        assert name == ('.symtab' if p[1] == 2 else '.dynsym') and p[9] == 24
        assert p[5] >= 24 and p[5] % 24 == 0 and p[6] < len(sh)
        strings = sh[p[6]]
        assert strings[1] == 3
        text = extent(data, strings[4], strings[5])
        rows = []
        for at in range(p[4], p[4] + p[5], 24):
            st_name, info, other, index, value, size = unpack('<IBBHQQ', data, at)
            assert info & 15 != 10  # No IFUNC in either fixture table.
            rows.append((cstring(text, st_name), info, other, index, value, size))
        assert rows[0] == ('', 0, 0, 0, 0, 0)
        tables[name] = rows
    assert '.dynsym' in tables
    by_name = dict(sections)
    dynamic_symbols = by_name['.dynsym']
    dynamic_strings = sh[dynamic_symbols[6]]
    assert dynamic_symbols[3] == tags[6] and dynamic_strings[3] == tags[5]
    assert dynamic_strings[5] == tags[10]
    for p in (dynamic_symbols, dynamic_strings):
        offset, _ = mapped(data, loads, p[3], p[5])
        assert offset == p[4]
    for tag in (4, 0x6ffffef5):
        if tag in tags:
            mapped(data, loads, tags[tag], 16)
    return dict(ph=ph, loads=loads, sections=sections, tables=tables)


def readelf_symbols(text, parsed):
    assert type(text) is bytes and 0 < len(text) <= MIB and text.endswith(b'\n')
    assert all(c == 10 or 32 <= c < 127 for c in text)
    current = None
    counts, rows, columns = {}, {}, set()
    for line in text.decode('ascii').split('\n'):
        if not line:
            continue
        header = re.fullmatch(r"Symbol table '(\.dynsym|\.symtab)' contains ([0-9]+) entries:", line)
        if header:
            current = header[1]
            assert current not in counts
            counts[current] = int(header[2])
            rows[current] = []
            continue
        assert current is not None
        if re.fullmatch(r'\s*Num:\s+Value\s+Size\s+Type\s+Bind\s+Vis\s+Ndx\s+Name', line):
            assert current not in columns and not rows[current]
            columns.add(current)
            continue
        assert current in columns
        row = re.fullmatch(r'\s*([0-9]+):\s+([0-9a-f]+)\s+([0-9]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?\s*', line)
        assert row is not None and int(row[1]) == len(rows[current])
        rows[current].append(row.groups())
    assert set(rows) == columns == set(parsed['tables'])
    for name, symbols in parsed['tables'].items():
        assert counts[name] == len(rows[name]) == len(symbols)
        for printed, binary in zip(rows[name], symbols):
            _, value, size, kind, bind, vis, index, name = printed
            assert int(value, 16) == binary[4] and int(size) == binary[5]
            if binary[0] == NAME or name == NAME:
                assert name == binary[0] == NAME and kind == 'FUNC' and bind == 'LOCAL'
                assert vis == 'DEFAULT' and index.isdecimal() and int(index) == binary[3]
    return rows


def validate(prestrip, final, pre_symbols, final_symbols):
    pre, post = elf(prestrip), elf(final)
    readelf_symbols(pre_symbols, pre)
    readelf_symbols(final_symbols, post)
    assert '.symtab' in pre['tables'] and '.symtab' not in post['tables']
    assert not any(name.startswith(('.debug', '.zdebug')) or name in ('.gnu_debuglink', '.gnu_debugaltlink')
                   for name, _ in post['sections'])
    for p in (pre, post):
        assert not any(s[0] == NAME for s in p['tables']['.dynsym'])
    selected = [s for s in pre['tables']['.symtab'] if s[0] == NAME]
    assert len(selected) == 1
    _, info, other, section, address, size = selected[0]
    assert info == 2 and other == 0 and 0 < section < len(pre['sections'])
    assert 1 <= size <= 256
    code_section = pre['sections'][section][1]
    assert code_section[2] & 6 == 6 and code_section[2] & 1 == 0
    assert code_section[3] <= address and address + size <= code_section[3] + code_section[5]
    before_offset, before_code = mapped(prestrip, pre['loads'], address, size, 5)
    offset, code = mapped(final, post['loads'], address, size, 5)
    assert before_offset == offset and before_code == code
    relevant = (1, 2, 0x6474e551, 0x6474e552)
    geometry = lambda p: [list(h) for h in p['ph'] if h[0] in relevant]
    assert geometry(pre) == geometry(post)
    executable = []
    for load in pre['loads']:
        if load[1] == 5:
            assert extent(prestrip, load[2], load[5]) == extent(final, load[2], load[5])
            executable.append(dict(offset=load[2], elf_va=load[3], **digest(extent(final, load[2], load[5]))))
    assert executable and prestrip != final
    return dict(schema=1, label=LABEL, name=NAME, elf_va=address, length=size,
        file_offset=offset, selected_code=digest(code), prestrip=digest(prestrip), final=digest(final),
        geometry=geometry(post), executable_loads=executable,
        selected_dynamic_definition=False, final_static_symbols=False, final_debug_sections=False,
        scope='Structural strip equality and externally supplied compiler metadata; runner separately binds commands/tools and whole-file authority before candidate copy.')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('prestrip', 'final', 'pre-symbols', 'final-symbols', 'output'):
        ap.add_argument('--' + name, type=Path, required=True)
    a = ap.parse_args()
    def bounded(path):
        with path.open('rb') as stream:
            data = stream.read(MIB + 1)
        assert len(data) <= MIB
        return data
    result = validate(bounded(a.prestrip), bounded(a.final), bounded(a.pre_symbols), bounded(a.final_symbols))
    with a.output.open('x') as stream:
        json.dump(result, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')


if __name__ == '__main__':
    main()
