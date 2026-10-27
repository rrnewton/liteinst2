#!/usr/bin/env python3
"""Finite synthetic-byte controls for one exact E9 completion-witness reader."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

if sys.flags.optimize:
    raise SystemExit('optimized Python is unsupported; assertions are required')

READER_SHA256 = '562dc107c3aca9fa92a92973934eb01fc852981dd72743168b4701bbed08a081'
PINS = {'vectors.json': 'bf4965e6897d39702b05128452e9623f6dc12e78a24b07ad7246e29956fb1ce1', 'instructions.tsv': '74afc406acb8eb7742695afdf0e610a7e77afbaa6fb1498463a9e8ae85901fcd', 'FIXTURES.json': '70c567f416c5859b3d46a24c25f39ebba912b5e55c54f16e49af556d24c50d03', 'ORIGINAL-CONTROL-PLAN.json': 'aa08150c46d171c97e0d4cd1aa8eb2ce9a4670d3e5d745f2b8fbfaca2343e802', 'category-coverage.json': '7c6da27d12780f6cbbe2115745e0e20f12147ae995bfa8cb7ec35c0f7991f5b8'}
EXPECTED_CONTROLS = 93
MAX_INPUT_BYTES = 1048576


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def six(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


class Held:
    def __init__(self, path, pin=None):
        self.path = Path(path)
        assert self.path.is_absolute()
        assert os.fsencode(self.path.resolve(strict=True)) == os.fsencode(self.path)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        s = os.fstat(self.fd)
        assert stat.S_ISREG(s.st_mode) and 0 < s.st_size <= MAX_INPUT_BYTES
        self.owner = six(s)
        self.raw = os.pread(self.fd, MAX_INPUT_BYTES + 1, 0)
        assert len(self.raw) == s.st_size
        self.sha = digest(self.raw)
        assert pin is None or self.sha == pin
        self.stable()

    def stable(self):
        assert six(os.fstat(self.fd)) == self.owner
        assert six(os.stat(self.path, follow_symlinks=False)) == self.owner
        assert os.pread(self.fd, MAX_INPUT_BYTES + 1, 0) == self.raw
        assert six(os.fstat(self.fd)) == self.owner

    def record(self):
        return dict(path=str(self.path), bytes=len(self.raw), sha256=self.sha, stat=self.owner)


class SyntheticBytes:
    """Literal byte addresses and explicitly synthetic trampoline intervals only."""
    def __init__(self, segments, intervals=()):
        assert len(segments) <= 128 and len(intervals) <= 8
        self.bytes = {}
        self.intervals = intervals
        for lo, raw in segments:
            data = bytes.fromhex(raw)
            assert type(lo) is int and 0 <= lo < (1 << 47) and len(data) <= 64
            for offset, byte in enumerate(data):
                address = lo + offset
                assert address not in self.bytes, 'overlapping synthetic byte entries'
                self.bytes[address] = byte
        assert len(self.bytes) <= 8192
        assert all(0 <= lo < hi < 1 << 47 for lo, hi in intervals)

    def read(self, pc, size):
        if not (0 < size <= 32):
            return None
        addresses = range(pc, pc + size)
        return bytes(self.bytes[a] for a in addresses) if all(a in self.bytes for a in addresses) else None

    def trampoline(self, pc, size):
        return any(lo <= pc and pc + size <= hi for lo, hi in self.intervals)


def wire(value):
    if isinstance(value, bytes):
        return {'bytes_hex': value.hex()}
    if isinstance(value, tuple):
        return {'tuple': [wire(x) for x in value]}
    if isinstance(value, list):
        return [wire(x) for x in value]
    if isinstance(value, dict):
        return {k: wire(v) for k, v in value.items()}
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def table_heads(raw):
    rows = [r.split('\t') for r in raw.decode('ascii').splitlines()]
    assert len(rows) == 88 and all(len(r) == 14 for r in rows)
    heads = []
    for r in rows[1:]:
        heads.append(dict(id=int(r[0]), pc=int(r[1], 16), length=int(r[2]), file_offset=int(r[3]),
                          function=r[4], code=r[5], mnemonic=r[6], flow=r[7],
                          target=None if r[8] == 'none' else int(r[8], 16),
                          jump=r[11] == 'true', heap=r[12] == 'true'))
    return heads


def expected_for(vector, data):
    action, value = vector['action'], vector['expected']
    if value == 'DIRECT_HEADS':
        return data['direct_heads']
    if value == 'DIRECT_CASES':
        return data['direct_cases']
    if action == 'cases':
        result = list(data['direct_cases'])
        for case, row in value['overrides'].items():
            result[int(case)] = row
        return result
    if action == 'operation' and value is not None:
        return [bytes.fromhex(x) for x in value]
    if action == 'jump' and value is not None:
        return bytes.fromhex(value[0]), value[1]
    if action == 'target' and 'raises' not in value:
        return dict(value, components=[tuple(x) for x in value['components']])
    return value


def call_reader(module, vector, data, heads):
    action, x = vector['action'], vector['inputs']
    if action == 'direct-heads':
        view = SyntheticBytes([[h['pc'], h['code'].hex()] for h in heads])
        return [module['derive'](h, view, None, []) for h in heads]
    if action == 'cases':
        derived = list(data['direct_heads'])
        if 'head_override' in x:
            head = x['head_override']
            derived[head['id'] - 1] = head
        return module['cases'](derived)
    if action == 'operation':
        return module['operation'](heads[x['head_id'] - 1], x['body'])
    if action == 'target':
        return module['target_join'](x['full'].encode('ascii'), x['selection'].encode('ascii'))
    view = SyntheticBytes(x['segments'], x.get('trampoline', []))
    if action == 'jump':
        return module['jump'](view, x['pc'])
    if action == 'route':
        return module['route'](view, x['start'], x['target'])
    assert action == 'derive'
    return module['derive'](heads[x['head_id'] - 1], view, x['outcome'],
                            [tuple(pair) for pair in x['bypass']])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reader', type=Path, required=True)
    parser.add_argument('--new-output', type=Path, required=True)
    args = parser.parse_args()
    fixtures_dir = Path(__file__).resolve().parent
    repo = fixtures_dir.parents[1]
    assert fixtures_dir == repo / 'evaluation' / 'e9-witness-controls'
    output = args.new_output
    assert output.is_absolute() and output.parent.is_dir()
    assert os.fsencode(output.parent.resolve(strict=True) / output.name) == os.fsencode(output)
    assert output.is_relative_to(repo / 'ignored') and not output.is_relative_to(repo / 'target')
    assert not os.path.lexists(output)
    held = {'reader': Held(args.reader, READER_SHA256), 'controls': Held(Path(__file__).resolve())}
    try:
        for name, pin in PINS.items():
            held[name] = Held(fixtures_dir / name, pin)
        data = json.loads(held['vectors.json'].raw)
        categories = json.loads(held['category-coverage.json'].raw)
        prior = json.loads(held['ORIGINAL-CONTROL-PLAN.json'].raw)
        assert data['schema'] == 1 and len(data['controls']) == EXPECTED_CONTROLS
        assert len(data['heads']) == len(data['direct_heads']) == 87 and len(data['direct_cases']) == 176
        assert table_heads(held['instructions.tsv'].raw) == data['heads']
        assert len({v['name'] for v in data['controls']}) == EXPECTED_CONTROLS
        assert [c['name'] for c in categories['categories']] == [c['name'] for c in prior['cases']]
        assert len(categories['categories']) == 24
        assert sorted(name for c in categories['categories'] for name in c['planned_controls']) == sorted(v['name'] for v in data['controls'])
        heads = [dict(h, code=bytes.fromhex(h['code'])) for h in data['heads']]
        # Load the complete exact checked module, with main disabled. No AST extraction,
        # copied reader function, structural reader import, or predicate substitution.
        module = {'__name__': '_exact_e9_witness_controls_', '__file__': str(args.reader)}
        exec(compile(held['reader'].raw, str(args.reader), 'exec'), module)
        assert module['TABLE'] == PINS['instructions.tsv'] and module['MAX_PREFIX'] == 32
        output.mkdir()
        results = []
        for vector in data['controls']:
            expected = expected_for(vector, data)
            row = dict(name=vector['name'], category=vector['category'], action=vector['action'], status='FAIL')
            try:
                try:
                    actual = call_reader(module, vector, data, heads)
                except AssertionError:
                    if expected != {'raises': 'AssertionError'}:
                        raise
                    actual = {'raises': 'AssertionError'}
                assert actual == expected, 'whole fixed expected result mismatch'
                row.update(status='PASS', result_sha256=digest(canonical(wire(actual))))
            except Exception as error:
                row['error'] = type(error).__name__ + ': ' + str(error)
            results.append(row)
        for item in held.values():
            item.stable()
        assert len(results) == EXPECTED_CONTROLS
        passed = sum(r['status'] == 'PASS' for r in results)
        category_rows = []
        for c in categories['categories']:
            selected = [r for r in results if r['name'] in c['planned_controls']]
            category_rows.append(dict(c, actual_pure_controls=len(selected),
                                     actual_status='UNRUN' if not selected else 'PURE_CONTROLS_PASS' if all(r['status']=='PASS' for r in selected) else 'PURE_CONTROL_FAILURE',
                                     whole_product_status='UNRUN'))
        report = dict(schema=1, scope='SYNTHETIC_PURE_BYTE_CONTROLS_ONLY',
                      status='PASS' if passed == EXPECTED_CONTROLS else 'FAIL',
                      controls=EXPECTED_CONTROLS, passed=passed, failed=EXPECTED_CONTROLS-passed,
                      categories=category_rows, results=results,
                      input_records={name:item.record() for name,item in held.items()},
                      structural_validation_executions=0, native_executions=0,
                      native_admission=False, qualification_complete=False)
        (output / 'results.json').write_bytes(canonical(report))
        with (output / 'cases.csv').open('x', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=['name','category','action','status'])
            writer.writeheader()
            writer.writerows({k:r[k] for k in writer.fieldnames} for r in results)
        for item in held.values():
            item.stable()
        print(f'E9 witness pure-byte controls: {passed}/{EXPECTED_CONTROLS} PASS; 24 categories retained; whole-product/native UNRUN')
        return 0 if passed == EXPECTED_CONTROLS else 1
    finally:
        for item in held.values():
            os.close(item.fd)


if __name__ == '__main__':
    raise SystemExit(main())
