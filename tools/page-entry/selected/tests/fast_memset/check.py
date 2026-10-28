#!/usr/bin/env python3
"""Offline, exact replay of retained fast-zero records; never runs a fixture."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

HEAD = struct.Struct('<10Q')
ROW = struct.Struct('<9Q32s32s')
TAIL = struct.Struct('<8Q')
ROWS = 273
BYTES = HEAD.size + ROWS * ROW.size + TAIL.size


def need(ok, why):
    if not ok:
        raise ValueError(why)


def read(path, slot, measured):
    raw = Path(path).read_bytes()
    need(len(raw) == BYTES == 37272, 'complete closed record extent')
    h = HEAD.unpack_from(raw)
    need(h == (0x315a53414632494c, 1, BYTES, 0, 0, ROWS, slot,
               int(measured), 256 if measured else 0, 8 if measured else 0),
         'exact successful header; failed records cannot qualify')
    sizes = [0, 1, 7, 8, 15, 16, 63, 64, 65, 2444, 4095, 4096,
             4097, 65536, slot - 1, slot, slot + 1]
    ordinal = 0
    checked = 0
    for n in sizes:
        extent = (n + 64 + 4095) & ~4095
        for fill in (0, 0xa5, 0x100, -1):
            for offset in (0, 1, 7, extent - n):
                row = ROW.unpack_from(raw, HEAD.size + ordinal * ROW.size)
                need(row[:9] == (ordinal, n, extent, offset, fill % (1 << 64),
                                  extent, 1, 0, 0), 'exact range/input/DF/return row')
                before = bytes((i * 29 + ordinal * 17 + 0x3d) & 255
                               for i in range(extent))
                after = before[:offset] + bytes([fill & 255]) * n + before[offset+n:]
                need(row[9] == hashlib.sha256(before).digest(), 'whole before bytes')
                need(row[10] == hashlib.sha256(after).digest(), 'whole after bytes')
                checked += extent
                ordinal += 1
    z = ROW.unpack_from(raw, HEAD.size + ordinal * ROW.size)
    need(z == (272, 0, 0, 0, 0x5a, 0, 1, 0, 0, bytes(32), bytes(32)),
         'exact NULL zero-length row')
    times = TAIL.unpack_from(raw, HEAD.size + ROWS * ROW.size)
    need(all(t > 0 for t in times) if measured else times == (0,) * 8,
         'positive actual measured intervals; zero for unrun measurements')
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'cases': ROWS, 'whole_buffer_bytes_checked': checked,
            'slot_bytes': slot, 'intervals_ns': list(times) if measured else [],
            'fills_per_interval': 256 if measured else 0}, raw[HEAD.size:HEAD.size+ROWS*ROW.size]


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--slot-bytes', type=int, required=True,
                   help='independently read from actual fixture DWARF')
    p.add_argument('--scalar', required=True)
    p.add_argument('--fast', required=True)
    p.add_argument('--scalar-measured')
    p.add_argument('--fast-measured')
    a = p.parse_args()
    need(1 < a.slot_bytes <= 1024*1024, 'bounded actual slot layout')
    need(bool(a.scalar_measured) == bool(a.fast_measured), 'both measurement lanes')
    out = {}
    baseline = None
    for name, path, measured in [('scalar', a.scalar, False), ('fast', a.fast, False),
                                ('scalar_measured', a.scalar_measured, True),
                                ('fast_measured', a.fast_measured, True)]:
        if path is None:
            continue
        out[name], rows = read(path, a.slot_bytes, measured)
        if baseline is None:
            baseline = rows
        need(rows == baseline, 'every input/result/hash byte equals scalar lane')
    print(json.dumps({'status': 'passed', 'records': out}, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
