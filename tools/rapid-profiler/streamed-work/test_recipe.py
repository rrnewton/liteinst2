"""Fabricated protocol controls only: no native workload or historical run credit."""
import copy
import csv
import importlib.util
import io
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('streamed_check', Path(__file__).with_name('check_output.py'))
checked = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checked)
TABLES = [('transitions', checked.TRANSITIONS), ('calls', checked.CALLS), ('batches', checked.BATCHES),
    ('retirement', checked.RETIREMENT), ('reports', checked.REPORTS)]


def row(header, values):
    assert len(header.split(',')) == len(values)
    return dict(zip(header.split(','), values))


def fixture(late_removed=False):
    base = 10
    actions, calls, batches, retired, reports = [], [], [], [], []
    counts, completed = [0]*20, [0]
    for i in range(40):
        request = 0 if i == 0 else base + (40*(i//2) + (30 if i % 2 else 0))*1000000
        actions.append(row(checked.TRANSITIONS, ['arm' if i % 2 == 0 else 'disarm', i, i//2+1,
            request, request+1, base if i == 0 else request+2]))
    for i in range(160):
        n, epoch, active = (1 if i % 2 == 0 else 64), i//8, i%8 < 6
        before = base + (40*epoch+(2, 7, 12, 17, 22, 27, 32, 37)[i%8])*1000000
        if late_removed and i == 5:
            active, before = False, base+30000100
        value = sum((((j*37+11) & 255) ^ 90) for j in range(n)) ^ 0x9e3779b97f4a7c15
        ticks = 10000 + 100*i
        calls.append(row(checked.CALLS, [1000+i, i+1, n, 'sampled' if active else 'removed', epoch+1,
            counts[epoch] if active else '', before, before+1000, value, 0x8000, 0x7ff8, 0x8000,
            ticks, ticks+50, 3, 3, 0x1000, 0x1024]))
        if active:
            reports.append(row(checked.REPORTS, [epoch+1, counts[epoch], 1, len(reports), ticks, ticks+50, counts[epoch], 0]))
            counts[epoch] += 1
        completed.append(len(reports))
    for i in range(40):
        start, stop = 4*i, 4*(i+1)
        batches.append(row(checked.BATCHES, [i+1, start, stop, 2*start, 2*stop, completed[start], completed[stop],
            stop+1, 11+stop, stop, stop, completed[stop], stop-completed[stop]]))
    record_end = 0
    for i in range(20):
        before = base+(40*i+38)*1000000
        checkpoint = next(c['ordinal'] for c in calls if c['before_ns'] > actions[2*i+1]['after_ns'])
        retired.append(row(checked.RETIREMENT, [i, i+1, checkpoint, before, before+1000,
            before+2000 if i < 17 else '', record_end, record_end+counts[i]]))
        record_end += counts[i]
    return dict(transitions=actions, calls=calls, batches=batches, retirement=retired, reports=reports,
        coverage=([5, 3]+[6, 2]*19 if late_removed else [6, 2]*20), end=800000010,
        sampled=len(reports), removed=160-len(reports), worker=2, controller=3)


def encode(data):
    output = io.StringIO(newline='')
    for label, header in TABLES:
        output.write('# '+label+'\n')
        writer = csv.DictWriter(output, fieldnames=header.split(','), lineterminator='\n')
        writer.writeheader(); writer.writerows(data[label])
    output.write(f"# actual whole-call coverage {data['coverage']}; full journal pages checked in process, not exported; uncalibrated finite trial\n")
    output.write(f"streamed-work PASS originals=160 calls=160 entries=160 returns=160 sampled={data['sampled']} unsampled={data['removed']} "
        f"epochs=20 slots=3 retired=20 replacements=17 batches=40 raw_rows=160 events=320 actions=40 reports={data['sampled']} "
        f"active_coverage=20 off_coverage=20 windowend_ns={data['end']} worker_cpu={data['worker']} controller_cpu={data['controller']} "
        'input_unchanged=true detached=true joined=true\n')
    return output.getvalue().encode('ascii')


class StreamedProtocol(unittest.TestCase):
    def refuse(self, data):
        with self.assertRaises(AssertionError):
            checked.parse(encode(data))

    def test_complete_population_and_nonzero_gate_cursor(self):
        result = checked.parse(encode(fixture()))
        self.assertEqual((result['sampled'], result['unsampled'], result['coverage'], result['gate_sequence_base']),
            (120, 40, [6, 2]*20, 11))
        self.assertEqual((result['original_instructions'], result['original_branches'], result['original_taken'],
            result['input_byte_reads'], result['return_word_reads']), (32000, 5200, 5040, 5200, 160))

    def test_actual_ownership_need_not_be_nominal_and_old_return_can_cross_remove(self):
        result = checked.parse(encode(fixture(late_removed=True)))
        self.assertEqual((result['sampled'], result['unsampled'], result['coverage']), (119, 41, [5, 3]+[6, 2]*19))
        data = fixture(); data['calls'][5]['after_ns'] = 31000010; data['coverage'][0] = 5
        self.assertEqual(checked.parse(encode(data))['coverage'], [5, 2]+[6, 2]*19)

    def test_every_table_missing_extra_and_failure_prefix_refuse(self):
        for label, _ in TABLES:
            for extra in (False, True):
                data = fixture()
                if extra: data[label].append(copy.deepcopy(data[label][-1]))
                else: data[label].pop()
                with self.subTest(table=label, extra=extra): self.refuse(data)
        encoded = encode(fixture())
        for value in (encoded+b'# FAILED unsent owned batch\n', encoded.replace(b'# reports\n', b'# FAILED worker Full\n# reports\n'),
                encoded[:-1], encoded.replace(b'\n', b'\r\n'), encoded.replace(b'PASS originals', b'FAILED originals')):
            with self.assertRaises(AssertionError): checked.parse(value)

    def test_call_identity_work_stack_clocks_and_owner_refuse(self):
        changes = {'external_id': 1001, 'ordinal': 2, 'length': 64, 'owner': 'closed', 'generation': 2,
            'invocation': 1, 'before_ns': 0, 'after_ns': 0, 'value': 0, 'pre_rsp': 0x8008, 'entry_rsp': 0x7ff0,
            'resumed_rsp': 0x8010, 'start_ticks': 10051, 'end_ticks': 9999, 'start_aux': 4, 'end_aux': 2**32,
            'entry_pc': 0x1001, 'return_pc': 0x1025}
        for key, value in changes.items():
            data = fixture(); data['calls'][0][key] = value
            with self.subTest(field=key): self.refuse(data)

    def test_transition_schedule_order_and_generation_refuse(self):
        for key, value in {'action': 'arm', 'index': 2, 'generation': 2, 'requested_ns': 30000011,
                'before_ns': 29999999, 'after_ns': 30000000}.items():
            data = fixture(); data['transitions'][1][key] = value
            with self.subTest(field=key): self.refuse(data)
        data = fixture(); data['transitions'][2]['generation'] = 1; self.refuse(data)

    def test_all_batch_cursors_and_cumulative_counts_refuse_corruption(self):
        for key in checked.BATCHES.split(','):
            data = fixture(); data['batches'][20][key] += 1
            with self.subTest(field=key): self.refuse(data)

    def test_retirement_checkpoint_report_ranges_and_strict_cutoff_refuse(self):
        for key in ('epoch', 'generation', 'checkpoint_ordinal', 'record_start', 'record_end'):
            data = fixture(); data['retirement'][0][key] += 1
            with self.subTest(field=key): self.refuse(data)
        for key, value in [('retire_before_ns', 37000000), ('retire_after_ns', 0),
                ('stage_complete_ns', 110000010), ('stage_complete_ns', '')]:
            data = fixture(); data['retirement'][0][key] = value; self.refuse(data)
        data = fixture(); data['retirement'][-1]['stage_complete_ns'] = data['end']; self.refuse(data)

    def test_each_exported_report_field_and_global_completion_sequence_refuse(self):
        for key in checked.REPORTS.split(','):
            data = fixture(); data['reports'][6][key] += 1
            with self.subTest(field=key): self.refuse(data)
        data = fixture(); data['reports'][6]['start_sequence'] = 0; self.refuse(data)

    def test_one_late_call_and_one_late_retirement_refuse_with_other_window_coverage(self):
        data = fixture()
        data['calls'][-1]['after_ns'] = data['end']+1
        data['coverage'][-1] = 1  # The other off call still establishes this window.
        data['retirement'][-1]['retire_before_ns'] = data['end']+2
        data['retirement'][-1]['retire_after_ns'] = data['end']+3
        self.refuse(data)  # Call guard fails before the separate retirement guard.
        data = fixture(); data['retirement'][-1]['retire_after_ns'] = data['end']+1
        self.refuse(data)

    def test_elapsed_window_does_not_replace_actual_stable_coverage(self):
        data = fixture()
        data['transitions'][-1]['after_ns'] = data['calls'][-2]['before_ns']+500
        data['calls'][-1]['after_ns'] = data['end']
        data['retirement'][-1].update(checkpoint_ordinal=160, retire_before_ns=data['end'], retire_after_ns=data['end'])
        data['coverage'][-1] = 0
        self.refuse(data)  # All ownership/chronology predicates remain possible.

    def test_terminal_counts_numeric_grammar_and_complete_coverage_refuse(self):
        encoded = encode(fixture())
        for old, new in [(b'originals=160', b'originals=159'), (b'epochs=20', b'epochs=19'),
                (b'raw_rows=160', b'raw_rows=159'), (b'events=320', b'events=319'),
                (b'detached=true', b'detached=false'), (b'worker_cpu=2', b'worker_cpu=3'),
                (b'reports=120', b'reports=119'), (b'coverage [6, 2', b'coverage [5, 2'),
                (b'1000,1,1,sampled', b'01000,1,1,sampled'), (b'1000,1,1,sampled', b'"1000",1,1,sampled')]:
            with self.subTest(old=old):
                with self.assertRaises(AssertionError): checked.parse(encoded.replace(old, new, 1))
        data = fixture(); data['calls'][0]['start_ticks'] = 2**64; self.refuse(data)


if __name__ == '__main__':
    if sys.flags.optimize: raise SystemExit('assertions required')
    unittest.main(verbosity=2)
