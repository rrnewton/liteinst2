"""Pure controls for complete timed populations and conservative coverage."""
import copy
import csv
import importlib.util
import io
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('checked', Path(__file__).with_name('check_output.py'))
checked = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checked)


def fixture():
    base = 10
    requests = [0] + [base + n*1000000 for n in (30, 40, 70, 80, 110)]
    actions = [['arm' if i % 2 == 0 else 'disarm', i, i//2+1, request,
        request+1, base if i == 0 else request+2] for i, request in enumerate(requests)]
    calls, reports = [], []
    for i in range(24):
        n, generation, active = (1 if i % 2 == 0 else 64), i//8+1, i%8 < 6
        before = base + (40*(i//8)+(2, 7, 12, 17, 22, 27, 32, 37)[i%8])*1000000
        value = sum((((j*37+11) & 255) ^ 90) for j in range(n)) ^ 0x9e3779b97f4a7c15
        ticks = 10000 + 100*i
        calls.append([1000+i, i+1, n, 'sampled' if active else 'removed', generation,
            i%8 if active else '', before, before+1000, value, 0x8000, 0x7ff8, 0x8000,
            ticks, ticks+50, 3, 3, 0x1000, 0x1024])
        if active:
            reports.append([generation, i%8, 1, len(reports), ticks, ticks+50, i%8, 0])
    terminal = ('timed-work PASS originals=24 calls=24 entries=24 returns=24 sampled=18 unsampled=6 '
        'epochs=3 actions=6 raw_rows=24 reports=18 active_coverage=3 off_coverage=3 windowend_ns=120000010 '
        'worker_cpu=2 controller_cpu=3 input_unchanged=true joined=true')
    return actions, calls, reports, terminal


def encode(value):
    actions, calls, reports, terminal = value
    output = io.StringIO(newline='')
    writer = csv.writer(output, lineterminator='\n')
    for marker, header, rows in [('transitions', checked.TRANSITIONS, actions),
            ('calls', checked.CALLS, calls), ('reports', checked.REPORTS, reports)]:
        output.write('# '+marker+'\n'); writer.writerow(header.split(',')); writer.writerows(rows)
    output.write(terminal+'\n')
    return output.getvalue().encode('ascii')


class TimedProtocol(unittest.TestCase):
    def test_complete_population_and_six_observed_windows(self):
        result = checked.parse(encode(fixture()))
        self.assertEqual((result['sampled'], result['unsampled'], result['coverage']), (18, 6, [6, 2]*3))

    def test_identity_work_stack_owner_clock_and_report_corruption_refuse(self):
        original = fixture()
        changes = [(1, 0, 0, 1001), (1, 0, 1, 2), (1, 0, 2, 64), (1, 0, 3, 'removed'),
            (1, 0, 4, 2), (1, 0, 5, 1), (1, 0, 8, 0), (1, 0, 10, 0x7ff0),
            (1, 0, 11, 0x8008), (1, 0, 14, 2), (1, 0, 17, 0x1025),
            (2, 6, 3, 0), (2, 0, 4, 0), (2, 0, 5, 0), (2, 0, 6, 1), (2, 0, 7, 1),
            (0, 1, 2, 2), (0, 1, 3, 30000011)]
        for table, row, field, value in changes:
            data = copy.deepcopy(original); data[table][row][field] = value
            with self.subTest(table=table, row=row, field=field):
                with self.assertRaises(AssertionError): checked.parse(encode(data))

    def test_missing_extra_rows_or_terminal_claims_never_pass(self):
        for index in (0, 1, 2):
            for extra in (False, True):
                data = copy.deepcopy(fixture())
                if extra: data[index].append(data[index][-1])
                else: data[index].pop()
                with self.assertRaises(AssertionError): checked.parse(encode(data))
        for old, new in [('originals=24', 'originals=18'), ('reports=18', 'reports=17'),
                ('off_coverage=3', 'off_coverage=2'), ('joined=true', 'joined=false'),
                ('worker_cpu=2', 'worker_cpu=3')]:
            data = list(fixture()); data[-1] = data[-1].replace(old, new)
            with self.assertRaises(AssertionError): checked.parse(encode(data))

    def test_elapsed_schedule_does_not_establish_actual_off_coverage(self):
        data = list(fixture())
        # All checksums, owners, ranks, requests and transitions stay intact.
        # Neither final removed call finishes inside the observed last window.
        for index in (22, 23):
            data[1][index][6] += 20000000
            data[1][index][7] += 20000000
        with self.assertRaises(AssertionError): checked.parse(encode(data))

    def test_old_owner_return_can_cross_removal(self):
        data = list(fixture())
        # Call 6 really starts in A and returns after A's removal; the retained
        # owner remains A, and the next call is the already declared off slot.
        data[1][5][7] = 31000010
        result = checked.parse(encode(data))
        self.assertEqual(result['coverage'], [5, 2, 6, 2, 6, 2])


if __name__ == '__main__':
    import sys
    if sys.flags.optimize: raise SystemExit('assertions required')
    unittest.main(verbosity=2)
