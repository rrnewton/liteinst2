#!/usr/bin/env python3
"""Pure controls for the independently authored scalar oracle; no native calls."""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import csv
import unittest
import oracle


class Controls(unittest.TestCase):
    def test_literal_truth_and_fixed_complete_populations(self):
        self.assertEqual(tuple(map(oracle.values, oracle.LITERALS)),
                         ((0, 0), (1, 0), (0, 0), (1, 0), (3, 3), (2, 3),
                          (2, 0), (8, 2), (64, 64), (0, 0), (63, 0), (64, 0)))
        for k, count in ((10, 12), (1000, 1001)):
            rows = oracle.records(k)
            self.assertEqual(len(rows), count)
            self.assertGreater(len(rows), k)
            self.assertEqual(set(rows), set(oracle.LITERALS))
            self.assertLessEqual(2 * len(rows), 4096)
            lines = oracle.table(k).decode('ascii').splitlines()
            self.assertEqual(lines[:2], [f'LI2SELECTED 1 2 {count}', 'functions 101 202'])
            self.assertEqual(lines[-1], 'END')
            self.assertEqual(len(lines), count + 3)
            for i, (line, data) in enumerate(zip(lines[2:-1], rows), 1):
                a, b = oracle.values(data)
                self.assertEqual(line, f'record {i} {data.hex() or "-"} {a} {b}')

    def original(self, k):
        rows = oracle.records(k)
        return ('\n'.join(f'ORIGINAL,{i},{oracle.values(row)[0]},{oracle.values(row)[1]}'
                          for i, row in enumerate(rows, 1)) +
                f'\nORIGINAL_DONE,{len(rows)},{2*len(rows)}\n').encode('ascii')

    def installed(self, k):
        rows = oracle.records(k)
        fields = sum(len(next(csv.reader([row.decode('ascii')], strict=True))) if row else 1 for row in rows)
        lines = [f'READY,selected-session-v1,{k},520,10,2,64,2048,2,1,1,1,1,2,0,1,3,2,1']
        lines.extend(f'RESULT,{i},{len(row)},{oracle.fnv(row)},{oracle.values(row)[0]},{oracle.values(row)[1]},{2*i-1},{2*i}'
                     for i, row in enumerate(rows, 1))
        n = len(rows)
        lines.append(f'DONE,COMPLETE,Requested,1,2,{n},{2*n},{2*n},{2*n},0,{2*n},{n},{fields},{sum(map(len, rows))},1,none,1,1,1')
        # Deliberately only a scalar projection, never a complete wire fixture.
        return ('\n'.join(lines) + '\n').encode('ascii')

    def test_all_original_rows_exact_order_values_and_totals(self):
        for k in (10, 1000):
            raw = self.original(k)
            self.assertEqual(oracle.compare(raw, k, True), 2*len(oracle.records(k)))
            lines = raw.splitlines(keepends=True)
            for bad in (b''.join(lines[1:]), b''.join(lines[:-1]), raw+lines[0],
                        b''.join([lines[1], lines[0], *lines[2:]]),
                        raw.replace(b'ORIGINAL,1,0,0', b'ORIGINAL,1,1,0')):
                with self.assertRaises(AssertionError): oracle.compare(bad, k, True)

    def test_all_installed_values_coordinates_and_completion_are_exact(self):
        for k in (10, 1000):
            raw = self.installed(k)
            self.assertEqual(oracle.compare(raw, k), 2*len(oracle.records(k)))
            lines = raw.splitlines(keepends=True)
            for bad in (b''.join([lines[0], *lines[2:]]), raw+lines[1],
                        b''.join([lines[0], lines[2], lines[1], *lines[3:]]),
                        raw.replace(b',2,3,11,12\n', b',3,2,11,12\n'),
                        raw.replace(b'DONE,COMPLETE,', b'DONE,incomplete,'),
                        raw.replace(b'DONE,COMPLETE,Requested,', b'DONE,COMPLETE,EpochLimit,'),
                        b''.join(lines[:-1]), raw.replace(b'selected-session-v1', b'leaf-set-session-v1')):
                with self.assertRaises(AssertionError): oracle.compare(bad, k)

    def test_framing_and_caps_do_not_promote_incomplete_scalar_output(self):
        raw = self.installed(10)
        for separator in (b'\x00', b'\x0b', b'\x0c', b'\x1c', b'\x1d', b'\x1e', b'\r\n', b'\n\n'):
            with self.assertRaises(AssertionError):
                oracle.compare(raw.replace(b'\n', separator, 1), 10)
            with self.assertRaises(AssertionError):
                oracle.compare(self.original(10).replace(b'\n', separator, 1), 10, True)
        for bad in (b'', raw[:-1], raw.replace(b'\n', b'\r\n'), b'\xff\n',
                    b'A'*350+b'\n'+raw, b'A'*(4*1024*1024+1)):
            with self.assertRaises(AssertionError): oracle.compare(bad, 10)


if __name__ == '__main__':
    unittest.main()
