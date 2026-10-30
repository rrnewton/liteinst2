#!/usr/bin/env python3
"""Fixed compiled-leaf scalar examples; no candidate execution or state authority.

Prepare a complete frozen result table from independent Python byte operations,
then compare every scalar result of a separately owned original/installed run.
The caller separately requires exit 0, empty stderr, bounds and complete owner
closure. This script does not infer any of those facts from stdout.
"""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import argparse
import csv
from pathlib import Path

FUNCTIONS = (101, 202)
LITERALS = (b'', b'a', b'=', b'a=b', b'ABC=def', b'"A=B",C', b'""',
            b'"A""B",c', b'A' * 64, b'=' * 64, b'a' * 63 + b'=', b' ' * 64)


def records(k):
    assert type(k) is int and k in (10, 1000)
    count = max(len(LITERALS), k + 1)
    assert 1 <= count <= min(2048, 4096 // len(FUNCTIONS))
    return tuple(LITERALS[i % len(LITERALS)] for i in range(count))


def values(data):
    assert type(data) is bytes and len(data) <= 64
    # These are independent of both compiled loops and the Rust table consumer.
    found = data.find(b'=')
    return (len(data) if found == -1 else found,
            sum(data.count(bytes([letter])) for letter in range(ord('A'), ord('Z') + 1)))


def table(k):
    rows = records(k)
    lines = [f'LI2SELECTED 1 2 {len(rows)}', 'functions 101 202']
    for i, data in enumerate(rows, 1):
        a, b = values(data)
        lines.append(f'record {i} {data.hex() or "-"} {a} {b}')
    return ('\n'.join(lines) + '\nEND\n').encode('ascii')


def fnv(data):
    value = 14695981039346656037
    for byte in data:
        value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
    return value


def compare(raw, k, original=False):
    """Compare every RESULT/ORIGINAL row; not a substitute for full wire audit."""
    assert type(raw) is bytes and 0 < len(raw) <= 4 * 1024 * 1024
    assert raw.endswith(b'\n') and all(byte == 10 or 0x20 <= byte <= 0x7e for byte in raw)
    lines = raw.decode('ascii').split('\n')[:-1]
    assert all(0 < len(line) <= 349 for line in lines)
    data = records(k)
    if original:
        expected = [f'ORIGINAL,{i},{values(row)[0]},{values(row)[1]}'
                    for i, row in enumerate(data, 1)]
        expected.append(f'ORIGINAL_DONE,{len(data)},{2 * len(data)}')
        assert lines == expected
    else:
        assert lines[0].startswith('READY,selected-session-v1,')
        observed = [line for line in lines if line.startswith('RESULT,')]
        expected = [f'RESULT,{i},{len(row)},{fnv(row)},{values(row)[0]},{values(row)[1]},{2*i-1},{2*i}'
                    for i, row in enumerate(data, 1)]
        assert observed == expected
        done = [line.split(',') for line in lines if line.startswith('DONE,')]
        assert len(done) == 1 and done[0][1:3] == ['COMPLETE', 'Requested']
        assert len(done[0]) == 19
        assert lines[-1] == ','.join(done[0])
        assert done[0][5:9] == [str(len(data)), str(2*len(data)),
                               str(2*len(data)), str(2*len(data))]
        assert all(token == str(int(token)) and 0 <= int(token) <= 2*len(data)
                   for token in done[0][9:11])
        assert sum(map(int, done[0][9:11])) == 2*len(data)
        fields = sum(len(next(csv.reader([row.decode('ascii')], strict=True))) if row else 1
                     for row in data)
        assert done[0][11:14] == [str(len(data)), str(fields), str(sum(map(len, data)))]
        assert done[0][-5:] == ['1', 'none', '1', '1', '1']
    return len(data) * 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    prepare = sub.add_parser('prepare')
    prepare.add_argument('directory', type=Path)
    prepare.add_argument('--k', type=int, choices=(10, 1000), required=True)
    check = sub.add_parser('compare')
    check.add_argument('stdout', type=Path)
    check.add_argument('--k', type=int, choices=(10, 1000), required=True)
    check.add_argument('--original', action='store_true')
    args = parser.parse_args()
    if args.command == 'prepare':
        args.directory.mkdir(parents=True, exist_ok=False)
        (args.directory / 'expected.txt').write_bytes(table(args.k))
        (args.directory / 'stdin.csv').write_bytes(b''.join(row + b'\n' for row in records(args.k)))
    else:
        with args.stdout.open('rb') as source:
            raw = source.read(4 * 1024 * 1024 + 1)
        calls = compare(raw, args.k, args.original)
        print(f'SCALAR_ROWS_MATCH calls={calls}; exit/closure/full-state UNASSERTED')


if __name__ == '__main__':
    main()
